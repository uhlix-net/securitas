"""Read Trivy Operator VulnerabilityReports from the Kubernetes API. Read-only: list calls only."""
import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request

GROUP, VERSION = "aquasecurity.github.io", "v1alpha1"
SA = "/var/run/secrets/kubernetes.io/serviceaccount"


def _opener(ctx):
    # No proxy for the API server, even when HTTPS_PROXY is set for the feed downloads.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))


def list_reports(cfg):
    if cfg.reports_file:
        with open(cfg.reports_file) as f:
            return json.load(f).get("items", [])
    if cfg.api_url:
        base, ctx, token = cfg.api_url.rstrip("/"), ssl.create_default_context(), None
    else:
        host = os.environ.get("KUBERNETES_SERVICE_HOST")
        if not host:
            raise RuntimeError("not running in a cluster: set SECURITAS_API_URL or SECURITAS_REPORTS_FILE")
        if ":" in host:
            host = f"[{host}]"
        base = f"https://{host}:{os.environ.get('KUBERNETES_SERVICE_PORT', '443')}"
        ctx = ssl.create_default_context(cafile=os.path.join(SA, "ca.crt"))
        token = open(os.path.join(SA, "token")).read().strip()  # re-read each time: projected tokens rotate
    op = _opener(ctx)
    paths = [f"/apis/{GROUP}/{VERSION}/namespaces/{urllib.parse.quote(ns)}/vulnerabilityreports" for ns in cfg.namespaces] \
        or [f"/apis/{GROUP}/{VERSION}/vulnerabilityreports"]
    items = []
    for path in paths:
        cont = ""
        while True:
            q = "?limit=200" + ("&continue=" + urllib.parse.quote(cont) if cont else "")
            headers = {"Accept": "application/json"}
            if token:
                headers["Authorization"] = "Bearer " + token
            try:
                with op.open(urllib.request.Request(base + path + q, headers=headers), timeout=60) as r:
                    doc = json.load(r)
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    raise RuntimeError("VulnerabilityReport API not found: is Trivy Operator installed?") from None
                if e.code in (401, 403):
                    raise RuntimeError(f"not allowed to list VulnerabilityReports (HTTP {e.code}): check the RBAC rules") from None
                raise
            items += doc.get("items", [])
            cont = (doc.get("metadata") or {}).get("continue") or ""
            if not cont:
                break
    return items
