"""Web app: sign-in, current report, scan history, running scans, schedules and administration.

All pages need a signed-in user. Pages are rendered on the server and contain no scripts, so the Content
Security Policy allows none. Every form carries a per-session CSRF token.
"""
import copy
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
from sqlalchemy import String, cast, delete, func, select

from . import __version__, auth, charts, compliance, render, report, scan_linux, scan_windows, sources
from .config import PLATFORMS
from .settings import FIELDS, SettingsError
from .db import (AuditEvent, Benchmark, BenchmarkFile, ComplianceResult, ComplianceScan, ComplianceSchedule, LoginState, PlatformResult, ResultStats, RoleMapping,
                 Scan, Schedule, Session, Target, User, audit, get_setting, set_setting, utcnow)
from .jobs import STATUS_LABEL, fmt_time, next_run, valid_cron

log = logging.getLogger("securitas.web")

CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'self'; "
       "frame-ancestors 'none'")
HEADERS = {"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "same-origin",
           "Cache-Control": "no-store", "Content-Security-Policy": CSP, "Cross-Origin-Opener-Policy": "same-origin"}
PLATFORM_LABEL = {"kubernetes": "Kubernetes", "linux": "Linux", "windows": "Windows"}
MESSAGES = {
    "saved": "Saved.", "nochange": "Nothing changed.", "queued": "Scan queued.", "deleted": "Deleted.", "added": "Added.", "pw": "Password changed.",
    "hostkey": "Host key cleared; the next scan records the key the host presents.",
    "loggedout": "You are signed out.",
    "imported": "Benchmark imported.", "activated": "Active benchmark changed.",
}
ERRORS = {
    "csrf": "The form expired. Please try again.", "noplat": "Pick at least one platform or host.",
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
        self.settings = jobs.settings
        self._oidc, self._oidc_key, self._oidc_lock = None, None, threading.Lock()
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
        self._pdf_render_lock = threading.Lock()

    # ------------------------------------------------------------ helpers

    def eff(self):
        """The configuration with the changes saved in Settings applied."""
        return self.settings.effective()

    @property
    def oidc(self):
        """The single sign-on client for the current settings (rebuilt when they change), or None."""
        c = self.eff().oidc
        if not c.enabled:
            return None
        key = (c.issuer, c.client_id, c.client_secret, c.scopes, c.username_claim, c.groups_claim)
        with self._oidc_lock:
            if self._oidc is None or self._oidc_key != key:
                self._oidc, self._oidc_key = auth.Oidc(copy.copy(c), self.cfg.base_url, self.cfg.ca_file), key
            return self._oidc

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
        ldap = self.eff().ldap
        if ldap.enabled:
            try:
                info = auth.ldap_lookup(ldap, self.cfg.ca_file, username, password)
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
        eff = a.eff()
        resp = a.page(request, "login.html", {"title": "Sign in", "next": _safe_next(next, cfg.base_url), "pre": pre,
                                              "password_form": local or eff.ldap.enabled, "sso": a.oidc is not None,
                                              "sso_label": eff.oidc.label,
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
        oidc = a.oidc
        if oidc is None:
            raise HTTPException(404, "Single sign-on is not configured.")
        state, nonce, verifier = oidc.new_request()
        try:
            url = oidc.authorize_url(state, nonce, verifier)
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
        oidc = a.oidc
        if oidc is None:
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
            info = oidc.identity(oidc.finish(code, nonce, verifier))
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

    @api.get("/vulnerabilities")
    def vuln_summary(request: Request, user=Depends(V)):
        m = jobs.current_model()
        rows = report.summary(m)
        tot = {k: sum(r[k] for r in rows) for k in ("systems", "priority", "kev", "critical", "high")}
        rng = request.query_params.get("range", report.DEFAULT_RANGE)
        rng = rng if rng in report.RANGES else report.DEFAULT_RANGE
        return a.page(request, "summary.html", {"user": user, "sess": request.state.sess, "title": "Summary", "model": m,
                                                "rows": rows, "tot": tot, "range": rng,
                                                "range_switch": charts.range_switch(rng, "/vulnerabilities"),
                                                "history": charts.history_svg(jobs.history(rng)),
                                                "pies": charts.pies(report.platform_levels(m))})

    @api.get("/report")
    def current_report(request: Request, user=Depends(V)):
        m = jobs.current_model()
        view = render.parse_view(request.query_params)
        q = render.view_query(view)
        return a.page(request, "report.html", {"user": user, "sess": request.state.sess, "title": "Report", "model": m,
                                               "body": render.report_body(m, view, paged=True), "nav": render.platform_nav(m, view),
                                               "filters": render.filter_form(view, "/report"),
                                               "pdf": "/report.pdf" + ("?" + q if q else ""), "pdf_name": render.pdf_name(m)})

    def pdf_response(m, key, view=None):
        key = key + (render.view_query(view or render.default_view()),)
        with a._pdf_lock:
            data = a._pdf.get(key)
        if data is None:
            with a._pdf_render_lock:          # one PDF at a time: each can take a few hundred MB
                data = render.render_pdf(render.pdf_html(m, cfg.paper, view))
            with a._pdf_lock:
                if len(a._pdf) > 20:
                    a._pdf.clear()
                a._pdf[key] = data
        return Response(data, media_type="application/pdf", headers={
            **HEADERS, "Content-Disposition": 'attachment; filename="%s"' % render.pdf_name(m)})

    @api.get("/report.pdf")
    def report_pdf(request: Request, user=Depends(V)):
        m = jobs.current_model()
        return pdf_response(m, ("current", json.dumps(m, sort_keys=True, default=str).__hash__()),
                            render.parse_view(request.query_params))

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
    def scans(request: Request, page: int = 1, platform: str = "", user=Depends(V)):
        page = max(1, page)
        plat = platform if platform in PLATFORMS else ""
        # platforms is a JSON list; '"linux"' only matches the whole name, and plat is one of PLATFORMS
        where = [cast(Scan.platforms, String).like('%%"%s"%%' % plat)] if plat else []
        with db.Session() as s:
            total = s.scalar(select(func.count(Scan.id)).where(*where))
            rows = s.scalars(select(Scan).where(*where).order_by(Scan.id.desc()).offset((page - 1) * 50).limit(50)).all()
            counts = {}
            res = s.execute(select(PlatformResult.scan_id, PlatformResult.platform, PlatformResult.status,
                                   ResultStats.priority, ResultStats.kev)
                            .outerjoin(ResultStats, ResultStats.result_id == PlatformResult.id)
                            .where(PlatformResult.scan_id.in_([r.id for r in rows]))).all() if rows else []
            pstatus = {}
            for sid, p, st, npri, nkev in res:
                if p == plat:
                    pstatus[sid] = st
                if plat and p != plat:
                    continue          # filtered: the counts are this platform's only
                counts.setdefault(sid, {})[p] = {"status": st, "cves": npri or 0, "kev": nkev or 0}
            ntargets = {p: s.scalar(select(func.count(Target.id)).where(Target.platform == p, Target.enabled.is_(True)))
                        for p in ("linux", "windows")}
        return a.page(request, "scans.html", {"user": user, "sess": request.state.sess, "title": "Scans", "scans": rows,
                                              "counts": counts, "page": page, "pages": max(1, (total + 49) // 50),
                                              "plat": plat, "pstatus": pstatus,
                                              "plat_on": {p: a.eff().platform_on(p) for p in PLATFORMS},
                                              "ntargets": ntargets,
                                              "busy": any(r.status in ("queued", "running") for r in rows)},
                      refresh=15 if any(r.status in ("queued", "running") for r in rows) else None)

    @api.post("/scans")
    async def scan_run(request: Request, user=Depends(OP)):
        form = await a.csrf(request)
        eff = a.eff()
        plats = [p for p in PLATFORMS if p in form.getlist("platform") and eff.platform_on(p)]
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
        view = render.parse_view(request.query_params)
        q = render.view_query(view)
        return a.page(request, "scan.html", {"user": user, "sess": request.state.sess, "title": "Scan #%d" % sid, "scan": scan,
                                             "model": m, "body": render.report_body(m, view, paged=True) if m and m["platforms"] else "",
                                             "filters": render.filter_form(view, "/scans/%d" % sid),
                                             "nav": render.platform_nav(m, view) if m else "",
                                             "pdf": "/scans/%d/report.pdf" % sid + ("?" + q if q else ""),
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
        return pdf_response(m, key, render.parse_view(request.query_params))

    @api.get("/scans/{sid}/data.json")
    def scan_json(request: Request, sid: int, user=Depends(V)):
        with db.Session() as s:
            scan = scan_or_404(s, sid)
            return JSONResponse(jobs.scan_model(scan), headers=HEADERS)

    # ------------------------------------------------------------ schedules

    @api.get("/vulnerabilities/schedules")
    def schedules(request: Request, user=Depends(a.need("schedule.edit"))):
        with db.Session() as s:
            rows = {x.platform: x for x in s.scalars(select(Schedule)).all()}
        return a.page(request, "schedules.html", {"user": user, "sess": request.state.sess, "title": "Vulnerability schedules",
                                                  "rows": rows, "base": "/vulnerabilities/schedules", "kind": "vulnerability"})

    @api.post("/vulnerabilities/schedules/{platform}")
    async def schedule_save(request: Request, platform: str, user=Depends(a.need("schedule.edit"))):
        form = await a.csrf(request)
        if platform not in PLATFORMS:
            raise HTTPException(404, "Unknown platform.")
        cron = " ".join(str(form.get("cron", "")).split())
        enabled = form.get("enabled") == "on"
        if not valid_cron(cron):
            return go("/vulnerabilities/schedules", err="cron")
        with db.Session() as s, s.begin():
            sc = s.scalar(select(Schedule).where(Schedule.platform == platform))
            if sc is None:
                sc = Schedule(platform=platform, cron=cron)
                s.add(sc)
            sc.cron, sc.enabled = cron, enabled
            sc.next_run = next_run(cron, cfg.timezone)
            a.audit(s, request, "schedule.saved", "%s: %s, %s" % (platform, cron, "on" if enabled else "off"))
        return go("/vulnerabilities/schedules", ok="saved")

    # ------------------------------------------------------------ admin: targets

    T = a.need("target.edit")

    @api.get("/targets")
    def targets(request: Request, user=Depends(T)):
        with db.Session() as s:
            rows = s.scalars(select(Target).order_by(Target.platform, Target.host)).all()
        return a.page(request, "targets.html", {"user": user, "sess": request.state.sess, "title": "Targets", "rows": rows,
                                                "ssh_ready": bool(a.eff().ssh_user and (a.eff().ssh_key or a.eff().ssh_key_file)),
                                                "winrm_ready": bool(a.eff().winrm_user and a.eff().winrm_password)})

    @api.post("/targets")
    async def target_add(request: Request, user=Depends(T)):
        form = await a.csrf(request)
        platform, host = str(form.get("platform", "")), str(form.get("host", "")).strip().lower()
        label = str(form.get("label", "")).strip()[:255]
        if platform not in ("linux", "windows"):
            raise HTTPException(400, "Unknown platform.")
        if not host or len(host) > 255 or not all(c.isalnum() or c in ".-_:" for c in host):
            return go("/targets", err="host")
        with db.Session() as s, s.begin():
            if s.scalar(select(Target).where(Target.platform == platform, Target.host == host)):
                return go("/targets", err="exists")
            s.add(Target(platform=platform, host=host, label=label))
            a.audit(s, request, "target.added", "%s %s" % (platform, host))
        return go("/targets", ok="added")

    @api.post("/targets/{tid}")
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
                    return go("/targets", err="csrf")
                a.audit(s, request, "target.deleted", "%s %s" % (t.platform, t.host))
                s.delete(t)
                msg = "deleted"
            else:
                raise HTTPException(400, "Unknown action.")
        return go("/targets", ok=msg)

    # ------------------------------------------------------------ admin: users

    U = a.need("user.manage")

    def admins_left(s, excluding):
        return s.scalar(select(func.count(User.id)).where(User.role == "admin", User.disabled.is_(False), User.id != excluding))

    @api.get("/settings/users")
    def users(request: Request, user=Depends(U)):
        with db.Session() as s:
            rows = s.scalars(select(User).order_by(User.source, User.username)).all()
        return a.page(request, "users.html", {"user": user, "sess": request.state.sess, "title": "Users", "rows": rows,
                                              "bootstrap": cfg.admin_username if cfg.admin_password else ""})

    @api.post("/settings/users")
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
        return go("/settings/users", ok="added")

    @api.post("/settings/users/{uid}")
    async def user_edit(request: Request, uid: int, user=Depends(U)):
        form = await a.csrf(request)
        action = str(form.get("action", ""))
        if uid == user.id and action in ("role", "disable", "delete"):
            return go("/settings/users", err="self")
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
                    return go("/settings/users", err="lastadmin")
                u.role = new
                if u.source == "local" and not u.role:
                    u.role = role
                if not u.role:
                    s.execute(delete(Session).where(Session.user_id == u.id))
                a.audit(s, request, "user.role", "%s: %s%s" % (u.username, new or "no role",
                                                               "" if u.source == "local" else " (fixed)" if role else " (from groups)"))
            elif action in ("disable", "enable"):
                if action == "disable" and u.role == "admin" and not admins_left(s, u.id):
                    return go("/settings/users", err="lastadmin")
                u.disabled = action == "disable"
                if u.disabled:
                    s.execute(delete(Session).where(Session.user_id == u.id))
                a.audit(s, request, "user." + action + "d", u.username)
            elif action == "password":
                if u.source != "local":
                    raise HTTPException(400, "Only local accounts have a password here.")
                if cfg.admin_password and u.username == cfg.admin_username:
                    return go("/settings/users", err="managed")
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
                    return go("/settings/users", err="csrf")
                if u.role == "admin" and not admins_left(s, u.id):
                    return go("/settings/users", err="lastadmin")
                if cfg.admin_password and u.username == cfg.admin_username:
                    return go("/settings/users", err="managed")
                a.audit(s, request, "user.deleted", u.username)
                s.delete(u)
            else:
                raise HTTPException(400, "Unknown action.")
        return go("/settings/users", ok="saved" if action != "delete" else "deleted")

    # ------------------------------------------------------------ admin: authentication

    AU = a.need("auth.manage")

    def auth_ctx(s, request, user, **extra):
        eff = a.eff()
        return {"user": user, "sess": request.state.sess, "title": "Authentication",
                "maps": s.scalars(select(RoleMapping).order_by(RoleMapping.role.desc(), RoleMapping.group)).all(),
                "local_on": a.local_login_on(s), "ldap": eff.ldap, "oidc": eff.oidc, "oidc_on": eff.oidc.enabled,
                "redirect_uri": cfg.base_url + "/auth/oidc/callback",
                "f_ldap": a.settings.describe("ldap"), "f_oidc": a.settings.describe("oidc"),
                "can_store": a.settings.can_store_secrets,
                "bootstrap": cfg.admin_username if cfg.admin_password else "", **extra}

    def recompute_roles(s):
        maps = a.mappings(s)
        for u in s.scalars(select(User).where(User.source != "local")).all():
            new = u.role_override or auth.role_from_groups(u.groups or [], maps)
            if new != u.role:
                u.role = new
                if not new:
                    s.execute(delete(Session).where(Session.user_id == u.id))

    @api.get("/settings/authentication")
    def auth_page(request: Request, user=Depends(AU)):
        with db.Session() as s:
            return a.page(request, "auth.html", auth_ctx(s, request, user))

    @api.post("/settings/authentication/mappings")
    async def mapping_add(request: Request, user=Depends(AU)):
        form = await a.csrf(request)
        group, role = str(form.get("group", "")).strip(), str(form.get("role", ""))
        if not group or len(group) > 255:
            return go("/settings/authentication", err="group")
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
                return go("/settings/authentication", err="lastadmin")
            a.audit(s, request, "rolemap.saved", "%s -> %s" % (g, role))
        return go("/settings/authentication", ok="saved")

    @api.post("/settings/authentication/mappings/{mid}/delete")
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
                return go("/settings/authentication", err="lastadmin")
            a.audit(s, request, "rolemap.deleted", detail)
        return go("/settings/authentication", ok="deleted")

    @api.post("/settings/authentication/local")
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
        return go("/settings/authentication", ok="saved")

    @api.post("/settings/authentication/ldap-test")
    async def ldap_test(request: Request, user=Depends(AU)):
        form = await a.csrf(request)
        uname = str(form.get("username", "")).strip().lower()[:255]
        result = {"username": uname}
        ldap = a.eff().ldap
        if not ldap.enabled:
            result["error"] = "LDAP is not configured or is turned off."
        elif uname:
            from starlette.concurrency import run_in_threadpool
            try:
                info = await run_in_threadpool(auth.ldap_lookup, ldap, cfg.ca_file, uname)
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

    # ------------------------------------------------------------ settings: menu, saving, old addresses

    SETTINGS_PAGES = [
        ("users", "Users", "user.manage", "Local accounts (add, reset passwords, disable), and LDAP and SSO users with their roles."),
        ("authentication", "Authentication", "auth.manage", "Local sign-in, LDAP and single sign-on settings, group to role mappings."),
        ("credentials", "Scan credentials", "credentials.edit", "The SSH account and key for Linux scans and the WinRM account for Windows scans, with a connection test."),
    ]
    a.env.globals["SETTINGS_PAGES"] = SETTINGS_PAGES
    a.env.globals["settings_for"] = lambda role: [p for p in SETTINGS_PAGES if auth.can(role, p[2])]
    # Top-level sections and their pages: (path, label, permission). Vulnerability scans and reports keep their
    # old addresses (/, /report, /scans) so bookmarks and PDF links still work.
    a.env.globals["SECTIONS"] = {
        "vulnerabilities": [("/vulnerabilities", "Summary", "view"), ("/report", "Report", "view"), ("/scans", "Scans", "view"),
                            ("/vulnerabilities/schedules", "Schedules", "schedule.edit"),
                            ("/vulnerabilities/sources", "Sources", "view")],
        "compliance": [("/compliance", "Summary", "view"), ("/compliance/report", "Report", "view"),
                       ("/compliance/scans", "Scans", "view"), ("/compliance/schedules", "Schedules", "schedule.edit"),
                       ("/compliance/benchmarks", "Benchmarks", "view")],
    }
    # Top menu after Vulnerabilities and Compliance: (path, label, permission); Settings comes last.
    a.env.globals["TOP_PAGES"] = [("/targets", "Targets", "target.edit"), ("/audit", "Audit log", "audit.view")]

    @api.get("/settings/compliance/{bid}")
    def old_benchmark(bid: int):
        return RedirectResponse("/compliance/benchmarks/%d" % bid, status_code=301, headers=HEADERS)

    @api.get("/settings")
    def settings_index(request: Request, user=Depends(a.need("settings.view"))):
        return a.page(request, "settings.html", {"user": user, "sess": request.state.sess, "title": "Settings"})

    for old, new_path in (("/admin/users", "/settings/users"), ("/admin/auth", "/settings/authentication"),
                          ("/admin/targets", "/targets"), ("/admin/audit", "/audit"),
                          ("/schedules", "/vulnerabilities/schedules"), ("/settings/schedules", "/vulnerabilities/schedules"),
                          ("/settings/targets", "/targets"), ("/settings/audit", "/audit"), ("/settings/sources", "/vulnerabilities/sources"),
                          ("/settings/compliance", "/compliance/benchmarks")):
        api.add_api_route(old, (lambda target: (lambda: RedirectResponse(target, status_code=301, headers=HEADERS)))(new_path),
                          methods=["GET"], include_in_schema=False)

    async def save_settings(request, user, group, back, ctx_fn):
        """Save one settings form; re-render the page with the error when a value is not valid."""
        form = await a.csrf(request)
        try:
            with db.Session() as s, s.begin():
                changed = a.settings.save(s, group, form, user.username)
                if changed:
                    a.audit(s, request, "settings." + group, ", ".join(changed))
        except SettingsError as e:
            with db.Session() as s:
                return a.page(request, ctx_fn[0], {**ctx_fn[1](s, request, user), "error": str(e)}, status=400)
        a.settings.bump()
        return go(back, ok="saved" if changed else "nochange")

    @api.post("/settings/authentication/ldap")
    async def ldap_save(request: Request, user=Depends(AU)):
        return await save_settings(request, user, "ldap", "/settings/authentication", ("auth.html", auth_ctx))

    @api.post("/settings/authentication/oidc")
    async def oidc_save(request: Request, user=Depends(AU)):
        return await save_settings(request, user, "oidc", "/settings/authentication", ("auth.html", auth_ctx))

    @api.post("/settings/authentication/oidc-test")
    async def oidc_test(request: Request, user=Depends(AU)):
        await a.csrf(request)
        c = a.eff().oidc
        result = {}
        if not (c.issuer and c.client_id):
            result["error"] = "Single sign-on needs an issuer URL and a client ID."
        else:
            from starlette.concurrency import run_in_threadpool
            try:
                meta = await run_in_threadpool(auth.Oidc(copy.copy(c), cfg.base_url, cfg.ca_file).metadata)
                result = {"issuer": meta.get("issuer"), "authorization_endpoint": meta.get("authorization_endpoint"),
                          "token_endpoint": meta.get("token_endpoint"),
                          "match": meta.get("issuer", "").rstrip("/") == c.issuer.rstrip("/")}
            except Exception as e:
                result["error"] = str(e) or type(e).__name__
        with db.Session() as s:
            return a.page(request, "auth.html", auth_ctx(s, request, user, sso_test=result))

    # ------------------------------------------------------------ settings: scan credentials

    CR = a.need("credentials.edit")

    def cred_ctx(s, request, user, **extra):
        eff = a.eff()
        return {"user": user, "sess": request.state.sess, "title": "Scan credentials",
                "f_linux": a.settings.describe("linux"), "f_windows": a.settings.describe("windows"),
                "key_file": cfg.ssh_key_file, "can_store": a.settings.can_store_secrets,
                "targets": s.scalars(select(Target).where(Target.enabled.is_(True)).order_by(Target.platform, Target.host)).all(),
                "known_hosts": bool(eff.ssh_known_hosts), **extra}

    @api.get("/settings/credentials")
    def credentials(request: Request, user=Depends(CR)):
        with db.Session() as s:
            return a.page(request, "credentials.html", cred_ctx(s, request, user))

    @api.post("/settings/credentials/linux")
    async def cred_linux(request: Request, user=Depends(CR)):
        return await save_settings(request, user, "linux", "/settings/credentials", ("credentials.html", cred_ctx))

    @api.post("/settings/credentials/windows")
    async def cred_windows(request: Request, user=Depends(CR)):
        return await save_settings(request, user, "windows", "/settings/credentials", ("credentials.html", cred_ctx))

    @api.post("/settings/credentials/test")
    async def cred_test(request: Request, user=Depends(CR)):
        form = await a.csrf(request)
        try:
            tid = int(form.get("target", "0"))
        except ValueError:
            tid = 0
        with db.Session() as s:
            t = s.get(Target, tid)
            if t is None:
                raise HTTPException(404, "No such target.")
            target = {"id": t.id, "host": t.host, "label": t.label, "host_key": t.host_key, "platform": t.platform}
        eff = a.eff()
        from starlette.concurrency import run_in_threadpool

        def work():
            if target["platform"] == "linux":
                if not eff.ssh_user or not (eff.ssh_key or eff.ssh_key_file):
                    raise RuntimeError("no SSH user or key is set")
                return scan_linux.test_host(eff, target, jobs._record_key)
            if not eff.winrm_user or not eff.winrm_password:
                raise RuntimeError("no WinRM user or password is set")
            return scan_windows.test_host(eff, target["host"])
        try:
            result = {"host": target["host"], "ok": await run_in_threadpool(work)}
        except Exception as e:
            result = {"host": target["host"], "error": ("%s: %s" % (type(e).__name__, e)) if str(e) else type(e).__name__}
        with db.Session() as s:
            a.audit(s, request, "credentials.test", "%s %s: %s" % (target["platform"], target["host"],
                                                                   "OK" if "ok" in result else "failed"))
            s.commit()
            return a.page(request, "credentials.html", cred_ctx(s, request, user, test=result))

    # ------------------------------------------------------------ settings: sources

    def sources_ctx(s, request, user, **extra):
        eff = a.eff()
        _, src, _ = jobs.feeds.ranker()
        st = sources.status(eff, src)
        for item in sources.SOURCES:
            if item.get("platform"):
                r = s.scalar(select(PlatformResult).where(PlatformResult.platform == item["platform"])
                             .order_by(PlatformResult.id.desc()).limit(1))
                if r is not None:
                    st.setdefault(item["id"], {})["last_scan"] = (r.scanned_at, r.scan_id, r.status)
        return {"user": user, "sess": request.state.sess, "title": "Sources", "sources": sources.SOURCES,
                "tools": sources.TOOLS, "status": st, "scripts": sources.scripts(eff),
                "f": a.settings.describe("sources"), "eff": eff, "repos": eff.linux_repos,
                "namespaces": eff.namespaces, **extra}

    @api.get("/vulnerabilities/sources")
    def sources_page(request: Request, user=Depends(V)):
        with db.Session() as s:
            return a.page(request, "sources.html", sources_ctx(s, request, user))

    @api.post("/vulnerabilities/sources")
    async def sources_save(request: Request, user=Depends(a.need("sources.edit"))):
        resp = await save_settings(request, user, "sources", "/vulnerabilities/sources", ("sources.html", sources_ctx))
        jobs.clear_cache()
        return resp

    # ------------------------------------------------------------ settings: compliance benchmark library

    CE = a.need("compliance.edit")

    def bench_or_404(s, bid):
        b = s.get(Benchmark, bid)
        if b is None:
            raise HTTPException(404, "There is no benchmark #%d." % bid)
        return b

    def compliance_ctx(s, request, user, **extra):
        from sqlalchemy.orm import selectinload
        rows = s.scalars(select(Benchmark).options(selectinload(Benchmark.rules))
                         .order_by(Benchmark.platform, Benchmark.os_key, Benchmark.name, Benchmark.uploaded_at.desc())).all()
        return {"user": user, "sess": request.state.sess, "title": "Compliance", "rows": rows,
                "counts": {b.id: compliance.counts(b) for b in rows}, "platforms": compliance.PLATFORMS,
                "profiles": compliance.PROFILES, "name": lambda b: compliance.display_name(b, cfg.timezone),
                "max_mb": compliance.MAX_ZIP // (1024 * 1024), **extra}

    @api.get("/compliance/benchmarks")
    def compliance_page(request: Request, user=Depends(V)):
        with db.Session() as s:
            return a.page(request, "compliance.html", compliance_ctx(s, request, user))

    @api.post("/compliance/benchmarks")
    async def compliance_upload(request: Request, user=Depends(CE)):
        # parse the multipart body once with a size limit that fits a role zip; a.csrf reuses the parsed form
        await request.form(max_files=1, max_fields=10, max_part_size=compliance.MAX_ZIP + 1)
        form = await a.csrf(request)
        up = form.get("file")
        err, data, fname = "", b"", ""
        if up is None or not hasattr(up, "read"):
            err = "Choose a zip file to upload."
        else:
            fname = os.path.basename(str(up.filename or ""))[:255]
            try:
                data = await up.read(compliance.MAX_ZIP + 1)
            finally:
                await up.close()
            if not data:
                err = "The file is empty."
        from starlette.concurrency import run_in_threadpool
        parsed = None
        if not err:
            try:
                parsed = await run_in_threadpool(compliance.parse_zip, data, fname)
            except compliance.BenchmarkError as e:
                err = str(e)
        with db.Session() as s, s.begin():
            if parsed is not None:
                try:
                    b = compliance.store(s, parsed, data, user.username, cfg.timezone)
                    a.audit(s, request, "benchmark.uploaded", "%s (%s, %d rules, sha256 %s)%s"
                            % (b.key, b.filename, b.rule_count, b.sha256[:16], ", active for " + b.os_label if b.active else ""))
                    bid = b.id
                except compliance.BenchmarkError as e:
                    err = str(e)
            if err:
                a.audit(s, request, "benchmark.upload_failed", "%s: %s" % (fname or "no file", err[:300]))
        if err:
            with db.Session() as s:
                return a.page(request, "compliance.html", compliance_ctx(s, request, user, error=err), status=400)
        return go("/compliance/benchmarks/%d" % bid, ok="imported")

    RULE_STATES = ("on", "off", "override")

    @api.get("/compliance/benchmarks/{bid}")
    def benchmark_page(request: Request, bid: int, user=Depends(V)):
        q = request.query_params
        f = {"q": q.get("q", "").strip()[:100], "section": q.get("section", ""), "level": q.get("level", ""),
             "kind": q.get("kind", ""), "state": q.get("state", "")}
        with db.Session() as s:
            b = bench_or_404(s, bid)
            sections = sorted({r.section for r in b.rules}, key=lambda x: int(x) if x.isdigit() else 0)
            shown = []
            for r in b.rules:
                on = compliance.rule_on(r, b.profile)
                if f["q"] and f["q"].lower() not in (r.rule_id + " " + r.title).lower():
                    continue
                if f["section"] and r.section != f["section"]:
                    continue
                if f["level"] in compliance.LEVEL_TAGS and f["level"] not in (r.levels or []):
                    continue
                if f["kind"] in ("PATCH", "AUDIT") and r.kind != f["kind"]:
                    continue
                if f["state"] == "on" and not on or f["state"] == "off" and on or f["state"] == "override" and r.override is None:
                    continue
                shown.append((r, on))
            others = s.scalars(select(Benchmark).where(Benchmark.os_key == b.os_key, Benchmark.id != b.id)
                               .order_by(Benchmark.uploaded_at.desc())).all()
            ctx = {"user": user, "sess": request.state.sess, "title": b.key, "b": b, "c": compliance.counts(b),
                   "shown": shown, "f": f, "sections": sections, "profiles": compliance.profiles_for(b.platform),
                   "level_tags": [t for t in compliance.LEVEL_TAGS if any(t in (r.levels or []) for r in b.rules)], "states": RULE_STATES, "others": others,
                   "name": lambda b: compliance.display_name(b, cfg.timezone),
                   "day": lambda b: compliance.upload_date(b, cfg.timezone), "filtered": any(f.values()),
                   "query": urllib.parse.urlencode({k: v for k, v in f.items() if v})}
            return a.page(request, "benchmark.html", ctx)

    @api.post("/compliance/benchmarks/{bid}")
    async def benchmark_edit(request: Request, bid: int, user=Depends(CE)):
        form = await a.csrf(request)
        action = str(form.get("action", ""))
        back = "/compliance/benchmarks/%d" % bid
        nxt = str(form.get("query", ""))
        with db.Session() as s, s.begin():
            b = bench_or_404(s, bid)
            if action == "activate":
                compliance.activate(s, b)
                a.audit(s, request, "benchmark.activated", "%s for %s" % (b.key, b.os_label))
                msg = "activated"
            elif action == "deactivate":
                b.active = False
                a.audit(s, request, "benchmark.deactivated", "%s; %s has no active benchmark" % (b.key, b.os_label))
                msg = "saved"
            elif action == "profile":
                p = str(form.get("profile", ""))
                if p not in compliance.profiles_for(b.platform):
                    raise HTTPException(400, "Unknown profile.")
                if p == b.profile:
                    msg = "nochange"
                else:
                    a.audit(s, request, "benchmark.profile", "%s: %s -> %s" % (b.key, b.profile, p))
                    b.profile = p
                    msg = "saved"
            elif action == "rules":
                shown = set(form.getlist("shown"))
                checked = set(form.getlist("rule"))
                n = compliance.set_rules(b, shown, checked)
                if n:
                    a.audit(s, request, "benchmark.rules", "%s: %d rule(s) changed, %d now on"
                            % (b.key, n, compliance.counts(b)["on"]))
                msg = "saved" if n else "nochange"
            elif action == "reset":
                n = sum(1 for r in b.rules if r.override is not None)
                for r in b.rules:
                    r.override = None
                if n:
                    a.audit(s, request, "benchmark.rules_reset", "%s: %d override(s) removed" % (b.key, n))
                msg = "saved" if n else "nochange"
            elif action == "delete":
                if form.get("confirm") != "on":
                    return go(back, err="csrf")
                a.audit(s, request, "benchmark.deleted", "%s (%s, uploaded %s by %s, sha256 %s)%s"
                        % (b.key, b.filename, compliance.upload_date(b, cfg.timezone), b.uploaded_by, b.sha256[:16],
                           "; it was the active benchmark for " + b.os_label if b.active else ""))
                s.delete(b)
                return go("/compliance/benchmarks", ok="deleted")
            else:
                raise HTTPException(400, "Unknown action.")
        q = urllib.parse.parse_qs(nxt)
        safe = urllib.parse.urlencode({k: v[0] for k, v in q.items() if k in ("q", "section", "level", "kind", "state")})
        return go(back + ("?" + safe if safe else ""), ok=msg)

    @api.get("/compliance/benchmarks/{bid}/download")
    def benchmark_download(request: Request, bid: int, user=Depends(CE)):
        with db.Session() as s:
            b = bench_or_404(s, bid)
            f = s.scalar(select(BenchmarkFile).where(BenchmarkFile.benchmark_id == b.id, BenchmarkFile.kind == "role"))
            if f is None:
                raise HTTPException(404, "The original file of this benchmark is not stored.")
            data, fname = f.data, f.filename or (b.key + ".zip")
            a.audit(s, request, "benchmark.downloaded", b.key)
            s.commit()
        safe = "".join(ch for ch in fname if ch.isalnum() or ch in "._-") or "benchmark.zip"
        return Response(data, media_type="application/zip",
                        headers={**HEADERS, "Content-Disposition": 'attachment; filename="%s"' % safe})

    # ------------------------------------------------------------ compliance: summary, report and scans

    COMPLIANCE_CHECKER = {
        "linux": "Checked over SSH with Goss and the benchmark's Ansible-Lockdown audit content. Ansible installs both on "
                 "each host, root-owned, with one sudo rule that lets the scan account run only "
                 "/usr/local/sbin/securitas-cis-audit.",
        "windows": "Checked over WinRM with syver (the Goss fork for Windows) and the benchmark's Ansible-Lockdown audit "
                   "content. Ansible installs both on each host, writable by administrators only, with a scheduled task "
                   "that runs the audit as SYSTEM; the scan account may only start that task and read its result. "
                   "Domain controllers get the domain controller rules, member servers the member server rules.",
        "kubernetes": "The cluster is not checked yet: results will come from Trivy Operator's CIS report (k8s-cis), "
                      "which needs compliance reports turned on in the operator.",
    }
    from . import scan_compliance
    a.env.globals.update(CSTATUS_LABEL=scan_compliance.STATUS_LABEL)

    def compliance_systems(s):
        """Enabled targets matched to active benchmarks, each with its newest compliance result."""
        plan, active = jobs.compliance_plan(s)
        for p, lst in plan.items():
            latest = jobs.latest_compliance(s, p)
            for x in lst:
                x["result"] = latest.get(x["host"])
        return plan, active

    def platform_row(p, lst):
        res = [x["result"] for x in lst if x.get("result")]
        scores = [r.counts.get("score") for r in res if r.counts.get("score") is not None]
        return {"id": p, "title": PLATFORM_LABEL[p], "systems": len(lst) if p != "kubernetes" else None,
                "matched": sum(1 for x in lst if x["bench"]), "checked": len(res),
                "benchmarks": sorted({x["bench"].key for x in lst if x["bench"]}),
                "passed": sum(r.counts.get("pass", 0) for r in res), "failed": sum(r.counts.get("fail", 0) for r in res),
                "score": round(sum(scores) / len(scores), 1) if scores else None,
                "last": max((r.scanned_at for r in res), default=None), "checker": p in jobs.compliance_scanners,
                "note": COMPLIANCE_CHECKER[p]}

    @api.get("/compliance")
    def compliance_summary(request: Request, user=Depends(V)):
        with db.Session() as s:
            systems, active = compliance_systems(s)
            rows = [platform_row(p, systems.get(p, [])) for p in ("linux", "windows", "kubernetes")]
            sched = {x.platform: x for x in s.scalars(select(ComplianceSchedule)).all()}
            ctx = {"user": user, "sess": request.state.sess, "title": "Compliance summary", "rows": rows,
                   "active": sorted(active.values(), key=lambda b: (b.platform, b.os_key)),
                   "counts": {b.id: compliance.counts(b) for b in active.values()}, "sched": sched,
                   "nbench": s.scalar(select(func.count(Benchmark.id))), "profiles": compliance.PROFILES,
                   "name": lambda b: compliance.display_name(b, cfg.timezone)}
            return a.page(request, "compliance_summary.html", ctx)

    @api.get("/compliance/report")
    def compliance_report(request: Request, user=Depends(V)):
        with db.Session() as s:
            systems, active = compliance_systems(s)
            ctx = {"user": user, "sess": request.state.sess, "title": "Compliance report", "systems": systems,
                   "active": sorted(active.values(), key=lambda b: (b.platform, b.os_key)),
                   "counts": {b.id: compliance.counts(b) for b in active.values()}, "checker": COMPLIANCE_CHECKER,
                   "profiles": compliance.PROFILES, "name": lambda b: compliance.display_name(b, cfg.timezone)}
            return a.page(request, "compliance_report.html", ctx)

    @api.get("/compliance/scans")
    def compliance_scans(request: Request, page: int = 1, user=Depends(V)):
        page = max(1, page)
        with db.Session() as s:
            systems, _ = jobs.compliance_plan(s)
            ntargets = {p: len(v) for p, v in systems.items()}
            matched = {p: sum(1 for x in v if x["bench"]) for p, v in systems.items()}
            pickable = {p: [{"host": x["host"], "label": x["label"], "key": x["bench"].key} for x in v if x["bench"]]
                        for p, v in systems.items()}
            total = s.scalar(select(func.count(ComplianceScan.id)))
            rows = s.scalars(select(ComplianceScan).order_by(ComplianceScan.id.desc()).offset((page - 1) * 50).limit(50)).all()
            stats = {}
            for r in s.scalars(select(ComplianceResult).where(ComplianceResult.scan_id.in_([x.id for x in rows]))).all() if rows else []:
                d = stats.setdefault(r.scan_id, {"hosts": 0, "done": 0, "pass": 0, "fail": 0, "scores": []})
                d["hosts"] += 1
                if r.status == "done":
                    d["done"] += 1
                    d["pass"] += r.counts.get("pass", 0)
                    d["fail"] += r.counts.get("fail", 0)
                    if r.counts.get("score") is not None:
                        d["scores"].append(r.counts["score"])
            s.expunge_all()
        busy = any(r.status in ("queued", "running") for r in rows)
        return a.page(request, "compliance_scans.html", {
            "user": user, "sess": request.state.sess, "title": "Compliance scans", "ntargets": ntargets, "matched": matched,
            "checker": COMPLIANCE_CHECKER, "has_checker": {p: p in jobs.compliance_scanners for p in PLATFORMS},
            "scans": rows, "stats": stats, "page": page, "pages": max(1, (total + 49) // 50), "busy": busy,
            "pickable": pickable},
            refresh=15 if busy else None)

    @api.post("/compliance/scans")
    async def compliance_scan_run(request: Request, user=Depends(OP)):
        form = await a.csrf(request)
        picked = set(form.getlist("host"))
        with db.Session() as s, s.begin():
            plan, _ = jobs.compliance_plan(s)
            if picked:
                # only the hosts ticked: their platforms follow from the hosts; the platform boxes are ignored
                hosts = {x["host"]: p for p, lst in plan.items() for x in lst if x["host"] in picked and x["bench"]}
                plats = [p for p in PLATFORMS if p in hosts.values() and p in jobs.compliance_scanners]
            else:
                hosts = {}
                plats = [p for p in PLATFORMS if p in form.getlist("platform") and p in jobs.compliance_scanners]
            if not plats:
                return go("/compliance/scans", err="noplat")
            scan = jobs.enqueue_compliance(s, plats, "manual", user.username, hosts=list(hosts))
            a.audit(s, request, "compliance_scan.run", "#%d %s%s" % (scan.id, ", ".join(plats),
                                                                     ": " + ", ".join(sorted(hosts)) if hosts else ""))
            sid = scan.id
        return go("/compliance/scans/%d" % sid, ok="queued")

    def cscan_or_404(s, sid):
        scan = s.get(ComplianceScan, sid)
        if scan is None:
            raise HTTPException(404, "There is no compliance scan #%d." % sid)
        return scan

    @api.get("/compliance/scans/{sid}")
    def compliance_scan_view(request: Request, sid: int, user=Depends(V)):
        with db.Session() as s:
            scan = cscan_or_404(s, sid)
            results = list(scan.results)
            s.expunge_all()
        active = scan.status in ("queued", "running")
        return a.page(request, "compliance_scan.html", {"user": user, "sess": request.state.sess,
                                                        "title": "Compliance scan #%d" % sid, "scan": scan, "results": results},
                      refresh=5 if active else None)

    @api.get("/compliance/scans/{sid}/hosts/{rid}")
    def compliance_host_view(request: Request, sid: int, rid: int, user=Depends(V)):
        st = request.query_params.get("status", "")
        q = request.query_params.get("q", "").strip()[:100]
        with db.Session() as s:
            r = s.get(ComplianceResult, rid)
            if r is None or r.scan_id != sid:
                raise HTTPException(404, "No such result.")
            s.expunge(r)
        rules = [x for x in r.rules or [] if (not st or x.get("status") == st)
                 and (not q or q.lower() in (x.get("id", "") + " " + x.get("title", "")).lower())]
        order = {k: i for i, k in enumerate(scan_compliance.STATUSES)}
        if not st:
            rules.sort(key=lambda x: (order.get(x.get("status"), 9), compliance.sort_key(x["id"]) if x.get("id") else ""))
        return a.page(request, "compliance_host.html", {"user": user, "sess": request.state.sess,
                                                        "title": "%s · compliance scan #%d" % (r.host, sid), "r": r,
                                                        "rules": rules, "st": st, "q": q, "statuses": scan_compliance.STATUSES})

    # ------------------------------------------------------------ home and about

    def compliance_charts(s):
        systems, _ = compliance_systems(s)
        rows = [platform_row(p, systems.get(p, [])) for p in ("linux", "windows", "kubernetes")]
        pies, bars = [], []
        for p in ("linux", "windows"):
            res = [x["result"] for x in systems.get(p, []) if x.get("result")]
            if not res:
                continue
            lv = {k: sum(r.counts.get(k, 0) for r in res) for k, _ in charts.RESULTS}
            pies.append({"id": p, "title": PLATFORM_LABEL[p], "total": sum(lv.values()), "levels": lv})
            bars += [{"host": r.host, "pass": r.counts.get("pass", 0), "fail": r.counts.get("fail", 0),
                      "score": r.counts.get("score"), "href": "/compliance/scans/%d/hosts/%d" % (r.scan_id, r.id)} for r in res]
        return rows, charts.result_pies(pies), charts.score_bars(bars) if bars else ""

    @api.get("/")
    def home(request: Request, user=Depends(V)):
        m = jobs.current_model()
        vrows = report.summary(m)
        vtot = {k: sum(r[k] for r in vrows) for k in ("systems", "priority", "kev", "critical", "high")}
        rng = request.query_params.get("range", report.DEFAULT_RANGE)
        rng = rng if rng in report.RANGES else report.DEFAULT_RANGE
        with db.Session() as s:
            crows, cpies, cbars = compliance_charts(s)
        scores = [r["score"] for r in crows if r["score"] is not None]
        ctot = {"systems": sum(r["systems"] or 0 for r in crows), "checked": sum(r["checked"] for r in crows),
                "failed": sum(r["failed"] for r in crows), "score": round(sum(scores) / len(scores), 1) if scores else None}
        return a.page(request, "home.html", {
            "user": user, "sess": request.state.sess, "title": "Home", "model": m, "vrows": vrows, "vtot": vtot,
            "range": rng, "range_switch": charts.range_switch(rng, "/"), "history": charts.history_svg(jobs.history(rng)),
            "vpies": charts.pies(report.platform_levels(m)), "crows": crows, "ctot": ctot, "cpies": cpies, "cbars": cbars})

    @api.get("/about")
    def about(request: Request, user=Depends(any_user)):
        eff = a.eff()
        with db.Session() as s:
            nb = s.scalar(select(func.count(Benchmark.id)))
        return a.page(request, "about.html", {"user": user, "sess": request.state.sess, "title": "About",
                                              "db_kind": db.engine.dialect.name, "nbench": nb,
                                              "platforms_on": [p for p in PLATFORMS if eff.platform_on(p)],
                                              "checkers": [p for p in PLATFORMS if p in jobs.compliance_scanners]})

    @api.get("/compliance/schedules")
    def compliance_schedules(request: Request, user=Depends(a.need("schedule.edit"))):
        with db.Session() as s:
            rows = {x.platform: x for x in s.scalars(select(ComplianceSchedule)).all()}
        return a.page(request, "schedules.html", {"user": user, "sess": request.state.sess, "title": "Compliance schedules",
                                                  "rows": rows, "base": "/compliance/schedules", "kind": "compliance",
                                                  "checker": COMPLIANCE_CHECKER,
                                                  "has_checker": {p: p in jobs.compliance_scanners for p in PLATFORMS}})

    @api.post("/compliance/schedules/{platform}")
    async def compliance_schedule_save(request: Request, platform: str, user=Depends(a.need("schedule.edit"))):
        form = await a.csrf(request)
        if platform not in PLATFORMS:
            raise HTTPException(404, "Unknown platform.")
        cron = " ".join(str(form.get("cron", "")).split())
        enabled = form.get("enabled") == "on"
        if not valid_cron(cron):
            return go("/compliance/schedules", err="cron")
        with db.Session() as s, s.begin():
            sc = s.scalar(select(ComplianceSchedule).where(ComplianceSchedule.platform == platform))
            if sc is None:
                sc = ComplianceSchedule(platform=platform, cron=cron)
                s.add(sc)
            sc.cron, sc.enabled = cron, enabled
            sc.next_run = next_run(cron, cfg.timezone)
            a.audit(s, request, "compliance_schedule.saved", "%s: %s, %s" % (platform, cron, "on" if enabled else "off"))
        return go("/compliance/schedules", ok="saved")

    # ------------------------------------------------------------ admin: audit

    @api.get("/audit")
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
