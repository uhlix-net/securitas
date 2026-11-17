"""Serve the report read-only (GET and HEAD only) and rebuild it on a schedule."""
import html
import json
import logging
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__, feeds, k8s, render, report

log = logging.getLogger("securitas")

HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-cache",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; "
                               "form-action 'none'; frame-ancestors 'none'",
}


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.html = self.pdf = self.json = None
        self.pdf_name = "securitas-report.pdf"
        self.error = ""
        self.updated = 0.0

    def placeholder(self):
        msg = "The first report is being built. Reload this page in a minute."
        if self.error:
            msg = "The report could not be built yet: " + self.error
        return ("<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
                "<title>Securitas</title><body style='font:15px system-ui,sans-serif;margin:40px'><h1>Securitas</h1>"
                "<p>%s</p>" % html.escape(msg)).encode()


def refresh(cfg, state):
    t0 = time.time()
    warnings = []
    reports = k8s.list_reports(cfg)
    extras = report.load_extra(cfg.extra_dir, warnings) if cfg.extra_dir else []
    ids = report.vuln_ids(reports) | {str(c.get("cve", "")).strip() for p in extras for c in p["cves"]}
    kev, kev_src = feeds.kev(cfg, warnings)
    epss, epss_src = feeds.epss(cfg, ids, warnings)
    model = report.build(cfg, reports, kev, kev_src, epss, epss_src, extras, warnings)
    page = render.render_html(model, cfg.paper)
    pdf = render.render_pdf(page)
    with state.lock:
        state.html, state.pdf = page.encode(), pdf
        state.json = json.dumps(model, indent=1).encode()
        state.pdf_name = render.pdf_name(model)
        state.updated, state.error = time.time(), ""
    log.info("report built: %d reports, %s, %.1fs", len(reports),
             ", ".join("%s %d priority" % (p["id"], len(p["cves"])) for p in model["platforms"]), time.time() - t0)


def refresh_loop(cfg, state):
    while True:
        try:
            refresh(cfg, state)
        except Exception as e:  # keep serving the last good report
            log.exception("refresh failed")
            with state.lock:
                state.error = str(e)
        time.sleep(cfg.refresh_seconds)


def make_handler(state):
    class Handler(BaseHTTPRequestHandler):
        server_version = "securitas/" + __version__
        sys_version = ""

        def _send(self, code, body, ctype, head, extra=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in {**HEADERS, **(extra or {})}.items():
                self.send_header(k, v)
            self.end_headers()
            if not head:
                self.wfile.write(body)

        def _route(self, head):
            path = self.path.split("?", 1)[0]
            with state.lock:
                page, pdf, data, name = state.html, state.pdf, state.json, state.pdf_name
            if path in ("/", "/index.html"):
                self._send(200, page or state.placeholder(), "text/html; charset=utf-8", head)
            elif path == "/report.pdf":
                if pdf:
                    self._send(200, pdf, "application/pdf", head, {"Content-Disposition": 'attachment; filename="%s"' % name})
                else:
                    self._send(503, b"The report is not ready yet.\n", "text/plain; charset=utf-8", head)
            elif path == "/data.json":
                if data:
                    self._send(200, data, "application/json", head)
                else:
                    self._send(503, b"{}", "application/json", head)
            elif path == "/healthz":
                self._send(200, b"ok\n", "text/plain; charset=utf-8", head)
            else:
                self._send(404, b"Not found\n", "text/plain; charset=utf-8", head)

        def do_GET(self):
            self._route(False)

        def do_HEAD(self):
            self._route(True)

        def _deny(self):
            self._send(405, b"Method not allowed\n", "text/plain; charset=utf-8", False, {"Allow": "GET, HEAD"})

        do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = _deny

        def log_message(self, fmt, *args):
            if not self.path.startswith("/healthz"):
                log.info("%s %s", self.address_string(), fmt % args)

    return Handler


def serve(cfg):
    os.makedirs(cfg.data_dir, exist_ok=True)
    state = State()
    threading.Thread(target=refresh_loop, args=(cfg, state), daemon=True).start()
    httpd = ThreadingHTTPServer(("", cfg.port), make_handler(state))
    log.info("securitas %s listening on :%d, refresh every %ds", __version__, cfg.port, cfg.refresh_seconds)
    httpd.serve_forever()
