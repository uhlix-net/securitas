"""Web app: sign-in, current report, scan history, running scans, schedules and administration.

All pages need a signed-in user. Pages are rendered on the server and contain no scripts, so the Content
Security Policy allows none. Every form carries a per-session CSRF token.
"""
import datetime
import ipaddress
import json
import logging
import os
import secrets
import threading
import urllib.parse

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import delete, func, select

from . import __version__, auth, render
from .config import PLATFORMS
from .db import (AuditEvent, LoginState, PlatformResult, RoleMapping, Scan, Schedule, Session, Target, User, audit,
                 get_setting, set_setting, utcnow)
from .jobs import STATUS_LABEL, fmt_time, next_run, valid_cron

log = logging.getLogger("securitas.web")

CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'self'; "
       "frame-ancestors 'none'")
HEADERS = {"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "same-origin",
           "Cache-Control": "no-store", "Content-Security-Policy": CSP, "Cross-Origin-Opener-Policy": "same-origin"}
PLATFORM_LABEL = {"kubernetes": "Kubernetes", "linux": "Linux", "windows": "Windows"}
MESSAGES = {
    "saved": "Saved.", "queued": "Scan queued.", "deleted": "Deleted.", "added": "Added.", "pw": "Password changed.",
    "hostkey": "Host key cleared; the next scan records the key the host presents.",
    "loggedout": "You are signed out.",
}
ERRORS = {
    "csrf": "The form expired. Please try again.", "noplat": "Pick at least one platform.",
    "cron": "That is not a valid cron expression (5 fields: minute hour day month weekday).",
    "exists": "That name is already in use.", "pw": "", "self": "You cannot change or remove your own account here.",
    "lastadmin": "At least one admin must remain.", "host": "Enter a host name.", "group": "Enter a group name.",
    "managed": "This account's password is managed by the deployment (SECURITAS_ADMIN_PASSWORD).",
}


class Redirect(Exception):
    def __init__(self, url):
        self.url = url


class App:
    def __init__(self, cfg, db, jobs):
        self.cfg, self.db, self.jobs = cfg, db, jobs
        self.throttle = auth.Throttle()
        self.oidc = auth.Oidc(cfg.oidc, cfg.base_url, cfg.ca_file) if cfg.oidc.enabled else None
        self.cookie = "__Host-securitas" if cfg.secure_cookies else "securitas"
        self.proxies = [ipaddress.ip_network(p, strict=False) for p in cfg.trusted_proxies]
        self.env = Environment(loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), "templates")),
                               autoescape=select_autoescape(["html"]), trim_blocks=True, lstrip_blocks=True)
        self.env.globals.update(can=auth.can, ROLES=auth.ROLES, ROLE_LABEL=auth.ROLE_LABEL, PLATFORMS=PLATFORMS,
                                PLATFORM_LABEL=PLATFORM_LABEL, STATUS_LABEL=STATUS_LABEL, version=__version__,
                                fmt=lambda d: fmt_time(d, cfg.timezone), cfg=cfg)
        self.css = render.app_css()
        self._pdf = {}
        self._pdf_lock = threading.Lock()

    # ------------------------------------------------------------ helpers

    def ip(self, request):
        host = request.client.host if request.client else ""
        try:
            if self.proxies and any(ipaddress.ip_address(host) in n for n in self.proxies):
                fwd = request.headers.get("x-forwarded-for", "")
                if fwd:
                    return fwd.split(",")[-1].strip()
        except ValueError:
            pass
        return host

    def page(self, request, name, ctx, status=200, refresh=None):
        u = ctx.get("user")
        q = request.query_params
        base = {"request": request, "title": ctx.get("title", ""), "css": self.css, "refresh": refresh,
                "theme": (u.theme if u else "system"), "ok": MESSAGES.get(q.get("ok", ""), ""),
                "err": ERRORS.get(q.get("err", ""), "") or ctx.pop("error", ""), "path": request.url.path}
        body = self.env.get_template(name).render({**base, **ctx})
        return HTMLResponse(body, status_code=status, headers=HEADERS)

    def current(self, request):
        """(user, session) for a valid session cookie, else (None, None)."""
        tok = request.cookies.get(self.cookie)
        if not tok:
            return None, None
        with self.db.Session() as s, s.begin():
            sess = s.get(Session, auth.token_hash(tok))
            if sess is None or sess.expires_at < utcnow():
                return None, None
            user = s.get(User, sess.user_id)
            if user is None or user.disabled or not user.role:
                s.delete(sess)
                return None, None
            if (utcnow() - sess.last_seen).total_seconds() > 60:
                sess.last_seen = utcnow()
            s.expunge(user)
            s.expunge(sess)
            return user, sess

    def need(self, perm):
        def dep(request: Request):
            user, sess = self.current(request)
            if user is None:
                nxt = request.url.path + (("?" + request.url.query) if request.url.query else "")
                raise Redirect("/login?" + urllib.parse.urlencode({"next": nxt}) if request.method == "GET" else "/login")
            if perm and not auth.can(user.role, perm):
                raise HTTPException(403, "Your role (%s) does not allow this." % auth.ROLE_LABEL.get(user.role, user.role))
            request.state.user, request.state.sess = user, sess
            return user
        return dep

    async def csrf(self, request: Request):
        form = await request.form()
        sess = getattr(request.state, "sess", None)
        if sess is None or not secrets.compare_digest(str(form.get("csrf", "")), sess.csrf):
            raise Redirect(add_q(_safe_next(request.headers.get("referer", ""), self.cfg.base_url, "/"), err="csrf"))
        origin = request.headers.get("origin")
        if origin and self.cfg.base_url and origin.rstrip("/") != self.cfg.base_url:
            raise HTTPException(403, "Cross-origin form submission refused.")
        return form

    def audit(self, s, request, action, detail=""):
        u = getattr(request.state, "user", None)
        audit(s, u.username if u else "", self.ip(request), action, detail)

    def mappings(self, s):
        return {m.group.lower(): m.role for m in s.scalars(select(RoleMapping)).all()}

    def local_login_on(self, s):
        return bool(get_setting(s, "local_login", self.cfg.local_login))

    # ------------------------------------------------------------ sign-in

    def start_session(self, s, request, user, method):
        tok = secrets.token_urlsafe(32)
        s.add(Session(id=auth.token_hash(tok), user_id=user.id, csrf=secrets.token_urlsafe(24), method=method,
                      expires_at=utcnow() + datetime.timedelta(hours=self.cfg.session_hours), ip=self.ip(request)))
        user.last_login_at = utcnow()
        audit(s, user.username, self.ip(request), "login", "via %s, role %s" % (method, user.role))
        return tok

    def set_cookie(self, resp, tok):
        resp.set_cookie(self.cookie, tok, max_age=self.cfg.session_hours * 3600, httponly=True,
                        secure=self.cfg.secure_cookies, samesite="lax", path="/")

    def external_user(self, s, info, source):
        """Create or update an LDAP/SSO user. Returns (user, error)."""
        u = s.scalar(select(User).where(User.username == info["username"]))
        if u is not None and u.source == "local":
            return None, "A local account with this name exists, so this sign-in cannot be used for it."
        if u is None:
            u = User(username=info["username"], source=source)
            s.add(u)
        if u.disabled:
            return None, "This account is disabled."
        u.source = source
        u.display_name = info.get("display_name") or u.display_name
        u.email = info.get("email") or u.email
        u.groups = info.get("groups", [])
        u.role = u.role_override or auth.role_from_groups(u.groups, self.mappings(s))
        s.flush()
        if not u.role:
            return None, "Your account has no Securitas role. Ask an admin to add you to a Securitas group."
        return u, ""

    def password_login(self, s, request, username, password):
        """Returns (user, method, error)."""
        u = s.scalar(select(User).where(User.username == username))
        if u is not None and u.source == "local":
            bootstrap = self.cfg.admin_password and u.username == self.cfg.admin_username
            if not (bootstrap or self.local_login_on(s)):
                auth.verify_password("", password)
                return None, "", "Local sign-in is turned off."
            if not auth.verify_password(u.password_hash, password):
                return None, "", "Wrong user name or password."
            if u.disabled or not u.role:
                return None, "", "This account is disabled." if u.disabled else "This account has no role."
            return u, "local", ""
        if self.cfg.ldap.enabled:
            try:
                info = auth.ldap_lookup(self.cfg.ldap, self.cfg.ca_file, username, password)
            except Exception as e:
                log.warning("LDAP sign-in for %s failed: %s", username, e)
                return None, "", "The directory could not be reached. Try again later."
            if info is None:
                return None, "", "Wrong user name or password."
            user, err = self.external_user(s, info, "ldap")
            return user, "ldap", err
        auth.verify_password("", password)
        return None, "", "Wrong user name or password."


def add_q(url, **q):
    return url + ("&" if "?" in url else "?") + urllib.parse.urlencode(q) if q else url


def _safe_next(nxt, base_url, default="/"):
    """Only local paths, so ?next= cannot send people to another site."""
    if not nxt:
        return default
    p = urllib.parse.urlparse(nxt)
    if p.scheme or p.netloc:
        if base_url and nxt.startswith(base_url + "/"):
            p = urllib.parse.urlparse(nxt[len(base_url):])
        else:
            return default
    path = p.path or "/"
    if not path.startswith("/") or path.startswith("//") or "\\" in path:
        return default
    return path + (("?" + p.query) if p.query and "err=" not in p.query and "ok=" not in p.query else "")


def go(url, **q):
    return RedirectResponse(add_q(url, **q), status_code=303, headers=HEADERS)


def create_app(cfg, db, jobs):
    a = App(cfg, db, jobs)
    api = FastAPI(title="Securitas", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    api.state.securitas = a
    V, OP, ADM = a.need("view"), a.need("scan.run"), a.need
    any_user = a.need(None)

    @api.exception_handler(Redirect)
    async def _redir(request, exc):
        return RedirectResponse(exc.url, status_code=303, headers=HEADERS)

    @api.exception_handler(HTTPException)
    async def _http(request, exc):
        user = getattr(request.state, "user", None)
        if exc.status_code in (403, 404) and user is not None:
            return a.page(request, "message.html", {"user": user, "sess": request.state.sess,
                                                    "title": "Not allowed" if exc.status_code == 403 else "Not found",
                                                    "message": exc.detail}, status=exc.status_code)
        return PlainTextResponse(str(exc.detail) + "\n", status_code=exc.status_code, headers=HEADERS)

    @api.middleware("http")
    async def _headers(request, call_next):
        resp = await call_next(request)
        for k, v in HEADERS.items():
            resp.headers.setdefault(k, v)
        return resp

    # ------------------------------------------------------------ health

    @api.get("/healthz")
    def healthz():
        try:
            db.ping()
        except Exception:
            return PlainTextResponse("database unavailable\n", status_code=503)
        return PlainTextResponse("ok\n")

    # ------------------------------------------------------------ sign-in / out

    @api.get("/login")
    def login_page(request: Request, next: str = ""):
        user, _ = a.current(request)
        if user is not None:
            return go(_safe_next(next, cfg.base_url))
        with db.Session() as s:
            local = a.local_login_on(s) or bool(cfg.admin_password)
        pre = secrets.token_urlsafe(16)
        resp = a.page(request, "login.html", {"title": "Sign in", "next": _safe_next(next, cfg.base_url), "pre": pre,
                                              "password_form": local or cfg.ldap.enabled, "sso": a.oidc is not None,
                                              "sso_label": cfg.oidc.label,
                                              "error": LOGIN_ERRORS.get(request.query_params.get("e", ""), "")})
        resp.set_cookie("securitas_pre", pre, max_age=1800, httponly=True, secure=cfg.secure_cookies, samesite="strict", path="/login")
        return resp

    @api.post("/login")
    async def login_post(request: Request):
        form = await request.form()
        username = str(form.get("username", "")).strip().lower()[:255]
        password = str(form.get("password", ""))[:1024]
        nxt = _safe_next(str(form.get("next", "")), cfg.base_url)
        pre = request.cookies.get("securitas_pre", "")
        if not pre or not secrets.compare_digest(pre, str(form.get("pre", ""))):
            return go("/login", next=nxt, e="expired")
        ip = a.ip(request)
        if a.throttle.blocked("ip:" + ip, "user:" + username):
            return go("/login", next=nxt, e="throttled")
        from starlette.concurrency import run_in_threadpool

        def work():
            with db.Session() as s, s.begin():
                user, method, err = a.password_login(s, request, username, password)
                if user is None:
                    audit(s, username, ip, "login.failed", err)
                    return None, err
                a.throttle.clear("user:" + username)
                return a.start_session(s, request, user, method), ""
        tok, err = await run_in_threadpool(work)
        if tok is None:
            a.throttle.fail("ip:" + ip, "user:" + username)
            return go("/login", next=nxt, e=LOGIN_ERROR_CODES.get(err, "denied"))
        resp = go(nxt)
        a.set_cookie(resp, tok)
        resp.delete_cookie("securitas_pre", path="/login")
        return resp

    @api.get("/login/oidc")
    def oidc_start(request: Request, next: str = ""):
        if a.oidc is None:
            raise HTTPException(404, "Single sign-on is not configured.")
        state, nonce, verifier = a.oidc.new_request()
        try:
            url = a.oidc.authorize_url(state, nonce, verifier)
        except Exception as e:
            log.warning("OIDC start failed: %s", e)
            return go("/login", e="ssodown")
        with db.Session() as s, s.begin():
            s.add(LoginState(state=state, nonce=nonce, verifier=verifier))
        resp = RedirectResponse(url, status_code=303, headers=HEADERS)
        resp.set_cookie("securitas_oidc", state + "|" + _safe_next(next, cfg.base_url), max_age=600, httponly=True,
                        secure=cfg.secure_cookies, samesite="lax", path="/auth/oidc")
        return resp

    @api.get("/auth/oidc/callback")
    def oidc_callback(request: Request, code: str = "", state: str = "", error: str = ""):
        if a.oidc is None:
            raise HTTPException(404, "Single sign-on is not configured.")
        ck = request.cookies.get("securitas_oidc", "")
        cstate, _, nxt = ck.partition("|")
        ip = a.ip(request)
        if error:
            with db.Session() as s, s.begin():
                audit(s, "", ip, "login.failed", "SSO provider returned error: %s" % error[:200])
            return go("/login", e="ssodenied")
        if not state or not cstate or not secrets.compare_digest(state, cstate) or not code:
            return go("/login", e="expired")
        with db.Session() as s, s.begin():
            ls = s.get(LoginState, state)
            if ls is None or (utcnow() - ls.created_at).total_seconds() > 600:
                return go("/login", e="expired")
            nonce, verifier = ls.nonce, ls.verifier
            s.delete(ls)
        try:
            info = a.oidc.identity(a.oidc.finish(code, nonce, verifier))
        except Exception as e:
            log.warning("OIDC sign-in failed: %s", e)
            with db.Session() as s, s.begin():
                audit(s, "", ip, "login.failed", "SSO: %s" % str(e)[:300])
            return go("/login", e="ssofailed")
        with db.Session() as s, s.begin():
            user, err = a.external_user(s, info, "oidc")
            if user is None:
                audit(s, info["username"], ip, "login.failed", "SSO: " + err)
                return go("/login", e=LOGIN_ERROR_CODES.get(err, "denied"))
            tok = a.start_session(s, request, user, "sso")
        resp = go(_safe_next(nxt, cfg.base_url))
        a.set_cookie(resp, tok)
        resp.delete_cookie("securitas_oidc", path="/auth/oidc")
        return resp

    @api.post("/logout")
    async def logout(request: Request, user=Depends(any_user)):
        await a.csrf(request)
        with db.Session() as s, s.begin():
            s.execute(delete(Session).where(Session.id == request.state.sess.id))
            audit(s, user.username, a.ip(request), "logout")
        resp = go("/login", ok="loggedout")
        resp.delete_cookie(a.cookie, path="/")
        return resp

    # ------------------------------------------------------------ account

    @api.post("/account/theme")
    async def theme(request: Request, user=Depends(any_user)):
        form = await a.csrf(request)
        t = str(form.get("theme", ""))
        if t in ("system", "light", "dark"):
            with db.Session() as s, s.begin():
                s.get(User, user.id).theme = t
        return go(_safe_next(str(form.get("next", "")), cfg.base_url))

    @api.get("/account")
    def account(request: Request, user=Depends(any_user)):
        return a.page(request, "account.html", {"user": user, "sess": request.state.sess, "title": "Account",
                                                "managed": bool(cfg.admin_password and user.username == cfg.admin_username)})

    @api.post("/account/password")
    async def account_password(request: Request, user=Depends(any_user)):
        form = await a.csrf(request)
        if user.source != "local":
            raise HTTPException(403, "Your password is managed by your directory or identity provider.")
        if cfg.admin_password and user.username == cfg.admin_username:
            return go("/account", err="managed")
        cur, new, again = (str(form.get(k, "")) for k in ("current", "new", "again"))
        with db.Session() as s, s.begin():
            u = s.get(User, user.id)
            if not auth.verify_password(u.password_hash, cur):
                return a.page(request, "account.html", {"user": user, "sess": request.state.sess, "title": "Account",
                                                        "error": "The current password is wrong."})
            prob = auth.password_problem(new) or ("The new passwords do not match." if new != again else "")
            if prob:
                return a.page(request, "account.html", {"user": user, "sess": request.state.sess, "title": "Account", "error": prob})
            u.password_hash = auth.hash_password(new)
            # sign out other sessions
            s.execute(delete(Session).where(Session.user_id == u.id, Session.id != request.state.sess.id))
            a.audit(s, request, "password.changed", u.username)
        return go("/account", ok="pw")

    # ------------------------------------------------------------ current report

    @api.get("/")
    def index(request: Request, user=Depends(V)):
        m = jobs.current_model()
        return a.page(request, "report.html", {"user": user, "sess": request.state.sess, "title": "Report", "model": m,
                                               "body": render.report_body(m), "nav": render.platform_nav(m),
                                               "pdf": "/report.pdf", "pdf_name": render.pdf_name(m)})

    def pdf_response(m, key):
        with a._pdf_lock:
            data = a._pdf.get(key)
        if data is None:
            data = render.render_pdf(render.pdf_html(m, cfg.paper))
            with a._pdf_lock:
                if len(a._pdf) > 20:
                    a._pdf.clear()
                a._pdf[key] = data
        return Response(data, media_type="application/pdf", headers={
            **HEADERS, "Content-Disposition": 'attachment; filename="%s"' % render.pdf_name(m)})

    @api.get("/report.pdf")
    def report_pdf(request: Request, user=Depends(V)):
        m = jobs.current_model()
        return pdf_response(m, ("current", json.dumps(m, sort_keys=True, default=str).__hash__()))

    @api.get("/data.json")
    def data_json(request: Request, user=Depends(V)):
        return JSONResponse(jobs.current_model(), headers=HEADERS)

    # ------------------------------------------------------------ scans

    def scan_or_404(s, sid):
        scan = s.get(Scan, sid)
        if scan is None:
            raise HTTPException(404, "There is no scan #%d." % sid)
        return scan

    @api.get("/scans")
    def scans(request: Request, page: int = 1, user=Depends(V)):
        page = max(1, page)
        with db.Session() as s:
            total = s.scalar(select(func.count(Scan.id)))
            rows = s.scalars(select(Scan).order_by(Scan.id.desc()).offset((page - 1) * 50).limit(50)).all()
            counts = {}
            res = s.execute(select(PlatformResult.scan_id, PlatformResult.platform, PlatformResult.status, PlatformResult.report)
                            .where(PlatformResult.scan_id.in_([r.id for r in rows]))).all() if rows else []
            for sid, p, st, rep in res:
                counts.setdefault(sid, {})[p] = {"status": st, "cves": len((rep or {}).get("cves", [])),
                                                 "kev": sum(1 for c in (rep or {}).get("cves", []) if c.get("kev"))}
            ntargets = {p: s.scalar(select(func.count(Target.id)).where(Target.platform == p, Target.enabled.is_(True)))
                        for p in ("linux", "windows")}
        return a.page(request, "scans.html", {"user": user, "sess": request.state.sess, "title": "Scans", "scans": rows,
                                              "counts": counts, "page": page, "pages": max(1, (total + 49) // 50),
                                              "ntargets": ntargets,
                                              "busy": any(r.status in ("queued", "running") for r in rows)},
                      refresh=15 if any(r.status in ("queued", "running") for r in rows) else None)

    @api.post("/scans")
    async def scan_run(request: Request, user=Depends(OP)):
        form = await a.csrf(request)
        plats = [p for p in PLATFORMS if p in form.getlist("platform")]
        if not plats:
            return go("/scans", err="noplat")
        with db.Session() as s, s.begin():
            scan = jobs.enqueue(s, plats, "manual", user.username)
            a.audit(s, request, "scan.run", "#%d %s" % (scan.id, ", ".join(plats)))
            sid = scan.id
        return go("/scans/%d" % sid, ok="queued")

    @api.get("/scans/{sid}")
    def scan_view(request: Request, sid: int, user=Depends(V)):
        with db.Session() as s:
            scan = scan_or_404(s, sid)
            m = jobs.scan_model(scan) if scan.results else None
            s.expunge_all()
        active = scan.status in ("queued", "running")
        return a.page(request, "scan.html", {"user": user, "sess": request.state.sess, "title": "Scan #%d" % sid, "scan": scan,
                                             "model": m, "body": render.report_body(m) if m and m["platforms"] else "",
                                             "nav": render.platform_nav(m) if m else "", "pdf": "/scans/%d/report.pdf" % sid,
                                             "pdf_name": render.pdf_name(m) if m else ""},
                      refresh=5 if active else None)

    @api.get("/scans/{sid}/report.pdf")
    def scan_pdf(request: Request, sid: int, user=Depends(V)):
        with db.Session() as s:
            scan = scan_or_404(s, sid)
            if not any(r.report for r in scan.results):
                raise HTTPException(404, "This scan has no results.")
            m = jobs.scan_model(scan)
            key = ("scan", sid, scan.status)
        return pdf_response(m, key)

    @api.get("/scans/{sid}/data.json")
    def scan_json(request: Request, sid: int, user=Depends(V)):
        with db.Session() as s:
            scan = scan_or_404(s, sid)
            return JSONResponse(jobs.scan_model(scan), headers=HEADERS)

    # ------------------------------------------------------------ schedules

    @api.get("/schedules")
    def schedules(request: Request, user=Depends(a.need("schedule.edit"))):
        with db.Session() as s:
            rows = {x.platform: x for x in s.scalars(select(Schedule)).all()}
        return a.page(request, "schedules.html", {"user": user, "sess": request.state.sess, "title": "Schedules", "rows": rows})

    @api.post("/schedules/{platform}")
    async def schedule_save(request: Request, platform: str, user=Depends(a.need("schedule.edit"))):
        form = await a.csrf(request)
        if platform not in PLATFORMS:
            raise HTTPException(404, "Unknown platform.")
        cron = " ".join(str(form.get("cron", "")).split())
        enabled = form.get("enabled") == "on"
        if not valid_cron(cron):
            return go("/schedules", err="cron")
        with db.Session() as s, s.begin():
            sc = s.scalar(select(Schedule).where(Schedule.platform == platform))
            if sc is None:
                sc = Schedule(platform=platform, cron=cron)
                s.add(sc)
            sc.cron, sc.enabled = cron, enabled
            sc.next_run = next_run(cron, cfg.timezone)
            a.audit(s, request, "schedule.saved", "%s: %s, %s" % (platform, cron, "on" if enabled else "off"))
        return go("/schedules", ok="saved")

    # ------------------------------------------------------------ admin: targets

    T = a.need("target.edit")

    @api.get("/admin/targets")
    def targets(request: Request, user=Depends(T)):
        with db.Session() as s:
            rows = s.scalars(select(Target).order_by(Target.platform, Target.host)).all()
        return a.page(request, "targets.html", {"user": user, "sess": request.state.sess, "title": "Targets", "rows": rows,
                                                "ssh_ready": bool(cfg.ssh_user and cfg.ssh_key_file),
                                                "winrm_ready": bool(cfg.winrm_user and cfg.winrm_password)})

    @api.post("/admin/targets")
    async def target_add(request: Request, user=Depends(T)):
        form = await a.csrf(request)
        platform, host = str(form.get("platform", "")), str(form.get("host", "")).strip().lower()
        label = str(form.get("label", "")).strip()[:255]
        if platform not in ("linux", "windows"):
            raise HTTPException(400, "Unknown platform.")
        if not host or len(host) > 255 or not all(c.isalnum() or c in ".-_:" for c in host):
            return go("/admin/targets", err="host")
        with db.Session() as s, s.begin():
            if s.scalar(select(Target).where(Target.platform == platform, Target.host == host)):
                return go("/admin/targets", err="exists")
            s.add(Target(platform=platform, host=host, label=label))
            a.audit(s, request, "target.added", "%s %s" % (platform, host))
        return go("/admin/targets", ok="added")

    @api.post("/admin/targets/{tid}")
    async def target_edit(request: Request, tid: int, user=Depends(T)):
        form = await a.csrf(request)
        action = str(form.get("action", ""))
        with db.Session() as s, s.begin():
            t = s.get(Target, tid)
            if t is None:
                raise HTTPException(404, "No such target.")
            if action == "save":
                t.label = str(form.get("label", "")).strip()[:255]
                t.enabled = form.get("enabled") == "on"
                a.audit(s, request, "target.saved", "%s %s %s" % (t.platform, t.host, "on" if t.enabled else "off"))
                msg = "saved"
            elif action == "hostkey":
                t.host_key = ""
                a.audit(s, request, "target.hostkey_reset", t.host)
                msg = "hostkey"
            elif action == "delete":
                if form.get("confirm") != "on":
                    return go("/admin/targets", err="csrf")
                a.audit(s, request, "target.deleted", "%s %s" % (t.platform, t.host))
                s.delete(t)
                msg = "deleted"
            else:
                raise HTTPException(400, "Unknown action.")
        return go("/admin/targets", ok=msg)

    # ------------------------------------------------------------ admin: users

    U = a.need("user.manage")

    def admins_left(s, excluding):
        return s.scalar(select(func.count(User.id)).where(User.role == "admin", User.disabled.is_(False), User.id != excluding))

    @api.get("/admin/users")
    def users(request: Request, user=Depends(U)):
        with db.Session() as s:
            rows = s.scalars(select(User).order_by(User.source, User.username)).all()
        return a.page(request, "users.html", {"user": user, "sess": request.state.sess, "title": "Users", "rows": rows,
                                              "bootstrap": cfg.admin_username if cfg.admin_password else ""})

    @api.post("/admin/users")
    async def user_add(request: Request, user=Depends(U)):
        form = await a.csrf(request)
        uname = str(form.get("username", "")).strip().lower()
        role = str(form.get("role", ""))
        pw = str(form.get("password", ""))
        ctx = {"user": user, "sess": request.state.sess, "title": "Users"}
        err = ""
        if not uname or len(uname) > 64 or not all(c.isalnum() or c in ".-_@" for c in uname):
            err = "User names may contain letters, digits and . - _ @ only."
        elif role not in auth.ROLES:
            err = "Pick a role."
        else:
            err = auth.password_problem(pw)
        with db.Session() as s, s.begin():
            if not err and s.scalar(select(User).where(User.username == uname)):
                err = "That user name is already in use."
            if err:
                ctx["rows"] = s.scalars(select(User).order_by(User.source, User.username)).all()
                ctx["error"] = err
                ctx["bootstrap"] = cfg.admin_username if cfg.admin_password else ""
                return a.page(request, "users.html", ctx, status=400)
            s.add(User(username=uname, display_name=str(form.get("display_name", "")).strip()[:255], source="local",
                       password_hash=auth.hash_password(pw), role=role))
            a.audit(s, request, "user.added", "%s (%s)" % (uname, role))
        return go("/admin/users", ok="added")

    @api.post("/admin/users/{uid}")
    async def user_edit(request: Request, uid: int, user=Depends(U)):
        form = await a.csrf(request)
        action = str(form.get("action", ""))
        if uid == user.id and action in ("role", "disable", "delete"):
            return go("/admin/users", err="self")
        with db.Session() as s, s.begin():
            u = s.get(User, uid)
            if u is None:
                raise HTTPException(404, "No such user.")
            if action == "role":
                role = str(form.get("role", ""))
                if u.source == "local":
                    if role not in auth.ROLES:
                        raise HTTPException(400, "Unknown role.")
                    new = role
                else:
                    if role not in auth.ROLES + ("",):
                        raise HTTPException(400, "Unknown role.")
                    u.role_override = role
                    new = role or auth.role_from_groups(u.groups or [], a.mappings(s))
                if u.role == "admin" and new != "admin" and not admins_left(s, u.id):
                    return go("/admin/users", err="lastadmin")
                u.role = new
                if u.source == "local" and not u.role:
                    u.role = role
                if not u.role:
                    s.execute(delete(Session).where(Session.user_id == u.id))
                a.audit(s, request, "user.role", "%s: %s%s" % (u.username, new or "no role",
                                                               "" if u.source == "local" else " (fixed)" if role else " (from groups)"))
            elif action in ("disable", "enable"):
                if action == "disable" and u.role == "admin" and not admins_left(s, u.id):
                    return go("/admin/users", err="lastadmin")
                u.disabled = action == "disable"
                if u.disabled:
                    s.execute(delete(Session).where(Session.user_id == u.id))
                a.audit(s, request, "user." + action + "d", u.username)
            elif action == "password":
                if u.source != "local":
                    raise HTTPException(400, "Only local accounts have a password here.")
                if cfg.admin_password and u.username == cfg.admin_username:
                    return go("/admin/users", err="managed")
                pw = str(form.get("password", ""))
                prob = auth.password_problem(pw)
                if prob:
                    rows = s.scalars(select(User).order_by(User.source, User.username)).all()
                    return a.page(request, "users.html", {"user": user, "sess": request.state.sess, "title": "Users",
                                                          "rows": rows, "error": prob,
                                                          "bootstrap": cfg.admin_username if cfg.admin_password else ""}, 400)
                u.password_hash = auth.hash_password(pw)
                s.execute(delete(Session).where(Session.user_id == u.id))
                a.audit(s, request, "user.password_reset", u.username)
            elif action == "delete":
                if form.get("confirm") != "on":
                    return go("/admin/users", err="csrf")
                if u.role == "admin" and not admins_left(s, u.id):
                    return go("/admin/users", err="lastadmin")
                if cfg.admin_password and u.username == cfg.admin_username:
                    return go("/admin/users", err="managed")
                a.audit(s, request, "user.deleted", u.username)
                s.delete(u)
            else:
                raise HTTPException(400, "Unknown action.")
        return go("/admin/users", ok="saved" if action != "delete" else "deleted")

    # ------------------------------------------------------------ admin: authentication

    AU = a.need("auth.manage")

    def auth_ctx(s, request, user, **extra):
        return {"user": user, "sess": request.state.sess, "title": "Authentication",
                "maps": s.scalars(select(RoleMapping).order_by(RoleMapping.role.desc(), RoleMapping.group)).all(),
                "local_on": a.local_login_on(s), "ldap": cfg.ldap, "oidc": cfg.oidc, "oidc_on": a.oidc is not None,
                "redirect_uri": a.oidc.redirect_uri if a.oidc else (cfg.base_url + "/auth/oidc/callback"),
                "bootstrap": cfg.admin_username if cfg.admin_password else "", **extra}

    def recompute_roles(s):
        maps = a.mappings(s)
        for u in s.scalars(select(User).where(User.source != "local")).all():
            new = u.role_override or auth.role_from_groups(u.groups or [], maps)
            if new != u.role:
                u.role = new
                if not new:
                    s.execute(delete(Session).where(Session.user_id == u.id))

    @api.get("/admin/auth")
    def auth_page(request: Request, user=Depends(AU)):
        with db.Session() as s:
            return a.page(request, "auth.html", auth_ctx(s, request, user))

    @api.post("/admin/auth/mappings")
    async def mapping_add(request: Request, user=Depends(AU)):
        form = await a.csrf(request)
        group, role = str(form.get("group", "")).strip(), str(form.get("role", ""))
        if not group or len(group) > 255:
            return go("/admin/auth", err="group")
        if role not in auth.ROLES:
            raise HTTPException(400, "Unknown role.")
        with db.Session() as s, s.begin():
            g = auth.group_cn(group)
            m = s.scalar(select(RoleMapping).where(func.lower(RoleMapping.group) == g))
            if m:
                m.role = role
            else:
                s.add(RoleMapping(group=g, role=role))
            s.flush()
            recompute_roles(s)
            if not admins_left(s, -1):
                s.rollback()
                return go("/admin/auth", err="lastadmin")
            a.audit(s, request, "rolemap.saved", "%s -> %s" % (g, role))
        return go("/admin/auth", ok="saved")

    @api.post("/admin/auth/mappings/{mid}/delete")
    async def mapping_delete(request: Request, mid: int, user=Depends(AU)):
        await a.csrf(request)
        with db.Session() as s, s.begin():
            m = s.get(RoleMapping, mid)
            if m is None:
                raise HTTPException(404, "No such mapping.")
            detail = "%s -> %s" % (m.group, m.role)
            s.delete(m)
            s.flush()
            recompute_roles(s)
            if not admins_left(s, -1):
                s.rollback()
                return go("/admin/auth", err="lastadmin")
            a.audit(s, request, "rolemap.deleted", detail)
        return go("/admin/auth", ok="deleted")

    @api.post("/admin/auth/local")
    async def local_toggle(request: Request, user=Depends(AU)):
        form = await a.csrf(request)
        on = form.get("enabled") == "on"
        with db.Session() as s, s.begin():
            set_setting(s, "local_login", on)
            if not on:
                ids = s.scalars(select(User.id).where(User.source == "local", User.username != (cfg.admin_username if cfg.admin_password else ""))).all()
                if ids:
                    s.execute(delete(Session).where(Session.user_id.in_(ids)))
            a.audit(s, request, "auth.local_login", "on" if on else "off")
        return go("/admin/auth", ok="saved")

    @api.post("/admin/auth/ldap-test")
    async def ldap_test(request: Request, user=Depends(AU)):
        form = await a.csrf(request)
        uname = str(form.get("username", "")).strip().lower()[:255]
        result = {"username": uname}
        if not cfg.ldap.enabled:
            result["error"] = "LDAP is not configured."
        elif uname:
            from starlette.concurrency import run_in_threadpool
            try:
                info = await run_in_threadpool(auth.ldap_lookup, cfg.ldap, cfg.ca_file, uname)
                if info is None:
                    result["error"] = "The service account bound, but no single user matched '%s'." % uname
                else:
                    result.update(info)
            except Exception as e:
                result["error"] = str(e) or type(e).__name__
        with db.Session() as s:
            if "groups" in result:
                result["role"] = auth.role_from_groups(result["groups"], a.mappings(s))
            return a.page(request, "auth.html", auth_ctx(s, request, user, test=result))

    # ------------------------------------------------------------ admin: audit

    @api.get("/admin/audit")
    def audit_page(request: Request, page: int = 1, user=Depends(a.need("audit.view"))):
        page = max(1, page)
        with db.Session() as s:
            total = s.scalar(select(func.count(AuditEvent.id)))
            rows = s.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).offset((page - 1) * 100).limit(100)).all()
        return a.page(request, "audit.html", {"user": user, "sess": request.state.sess, "title": "Audit log", "rows": rows,
                                              "page": page, "pages": max(1, (total + 99) // 100)})

    return api


LOGIN_ERRORS = {
    "expired": "The sign-in took too long or the page was open too long. Please try again.",
    "throttled": "Too many failed attempts. Wait 15 minutes and try again.",
    "denied": "Wrong user name or password.",
    "norole": "Your account has no Securitas role. Ask an admin to add you to a Securitas group.",
    "disabled": "This account is disabled.",
    "clash": "A local account with this name exists, so this sign-in cannot be used for it.",
    "localoff": "Local sign-in is turned off.",
    "ldapdown": "The directory could not be reached. Try again later.",
    "ssodown": "The single sign-on provider could not be reached. Try again later.",
    "ssodenied": "The single sign-on provider did not sign you in.",
    "ssofailed": "Single sign-on failed. Ask an admin to check the Securitas log.",
}
LOGIN_ERROR_CODES = {v: k for k, v in LOGIN_ERRORS.items()}
LOGIN_ERROR_CODES.update({
    "Your account has no Securitas role. Ask an admin to add you to a Securitas group.": "norole",
    "This account has no role.": "norole",
})
