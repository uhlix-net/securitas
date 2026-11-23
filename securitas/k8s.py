"""Kubernetes API calls: read Trivy Operator VulnerabilityReports (list only), and read / replace the ingress TLS
Secrets named in SECURITAS_TLS_SECRETS (Settings > Certificates; the chart's Role allows only get and patch on
exactly those Secrets)."""
import base64
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


def _api(cfg):
    """(base URL, SSL context, bearer token or None) for the in-cluster API, or SECURITAS_API_URL."""
    if cfg.api_url:
        return cfg.api_url.rstrip("/"), ssl.create_default_context(), None
    host = os.environ.get("KUBERNETES_SERVICE_HOST")
    if not host:
        raise RuntimeError("not running in a cluster")
    if ":" in host:
        host = f"[{host}]"
    base = f"https://{host}:{os.environ.get('KUBERNETES_SERVICE_PORT', '443')}"
    ctx = ssl.create_default_context(cafile=os.path.join(SA, "ca.crt"))
    return base, ctx, open(os.path.join(SA, "token")).read().strip()


def _namespace(cfg):
    if cfg.namespace:
        return cfg.namespace
    try:
        return open(os.path.join(SA, "namespace")).read().strip()
    except OSError:
        raise RuntimeError("the pod's namespace is not known (SECURITAS_NAMESPACE)") from None


def _secret_call(cfg, name, method="GET", body=None):
    if name not in cfg.tls_secrets:
        raise RuntimeError("%s is not one of the TLS Secrets Securitas may manage" % name)
    base, ctx, token = _api(cfg)
    url = "%s/api/v1/namespaces/%s/secrets/%s" % (base, urllib.parse.quote(_namespace(cfg)), urllib.parse.quote(name))
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/strategic-merge-patch+json"
    try:
        with _opener(ctx).open(urllib.request.Request(url, data=data, headers=headers, method=method), timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise RuntimeError("Secret %s does not exist in namespace %s" % (name, _namespace(cfg))) from None
        if e.code in (401, 403):
            raise RuntimeError("not allowed to %s Secret %s (HTTP %d): check the chart's ingress.manageCertificates Role"
                               % ("read" if method == "GET" else "change", name, e.code)) from None
        raise


def get_tls_secret(cfg, name):
    """(tls.crt PEM bytes, has a key) of a managed TLS Secret. The key itself is never returned."""
    doc = _secret_call(cfg, name)
    d = doc.get("data") or {}
    return base64.b64decode(d.get("tls.crt", "")), bool(d.get("tls.key"))


def put_tls_secret(cfg, name, cert_pem, key_pem):
    """Replace tls.crt and tls.key of a managed TLS Secret (the ingress controller picks it up by itself)."""
    _secret_call(cfg, name, "PATCH", {"data": {"tls.crt": base64.b64encode(cert_pem).decode(),
                                               "tls.key": base64.b64encode(key_pem).decode()}})
