"""Sign-in: local accounts, LDAP (Active Directory) and OpenID Connect single sign-on. Roles and permissions.

Roles (lowest to highest): viewer, operator, admin. LDAP and SSO users get the highest role mapped from their
groups at each sign-in, unless an admin set a fixed role for them. A user with no role cannot sign in.
"""
import base64
import collections
import hashlib
import json
import logging
import re
import secrets
import ssl
import threading
import time
import urllib.parse

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

log = logging.getLogger(__name__)

ROLES = ("viewer", "operator", "admin")
ROLE_LABEL = {"viewer": "Viewer", "operator": "Operator", "admin": "Admin"}
PERMISSIONS = {
    "view": "viewer",            # current report, history, PDF export
    "scan.run": "operator",
    "schedule.edit": "operator",
    "target.edit": "admin",
    "user.manage": "admin",
    "auth.manage": "admin",
    "audit.view": "admin",
    "settings.view": "viewer",     # the Settings menu; each page has its own permission (viewers see Sources)
    "credentials.edit": "admin",
    "sources.edit": "admin",
    "compliance.edit": "admin",    # upload, activate, configure and remove benchmarks (viewers can browse them)
    "compliance.exception": "admin",
    "tls.manage": "admin",         # Settings > Certificates: replace the web site's TLS certificate   # accept a failed rule (baseline or server exception); viewers can read them
}
_ph = PasswordHasher()
_DUMMY = _ph.hash(secrets.token_urlsafe(16))   # verified on unknown users so timing does not reveal them


def rank(role):
    return ROLES.index(role) if role in ROLES else -1


def can(role, perm):
    return rank(role) >= rank(PERMISSIONS[perm])


def hash_password(pw):
    return _ph.hash(pw)


def verify_password(stored, pw):
    try:
        return _ph.verify(stored or _DUMMY, pw) and bool(stored)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_problem(pw):
    if len(pw) < 12:
        return "Use at least 12 characters."
    if len(pw) > 256:
        return "Use at most 256 characters."
    return ""


def group_cn(g):
    """'CN=Securitas-Admins,OU=Groups,DC=example' -> 'securitas-admins'; plain names are lower-cased."""
    m = re.match(r"\s*cn=((?:\\.|[^,])+)", g, re.I)
    return (m.group(1).replace("\\", "") if m else g).strip().lower()


def role_from_groups(groups, mappings):
    """mappings: {group_lower: role}. Returns the highest mapped role or ''."""
    best = ""
    for g in groups:
        r = mappings.get(group_cn(g)) or mappings.get(g.strip().lower())
        if r and rank(r) > rank(best):
            best = r
    return best


class Throttle:
    """Slow down password guessing: after `limit` failures within `window` seconds, refuse for the rest of it."""

    def __init__(self, limit=8, window=900):
        self.limit, self.window = limit, window
        self.fails = collections.defaultdict(list)
        self.lock = threading.Lock()

    def _recent(self, key, now):
        self.fails[key] = [t for t in self.fails[key] if now - t < self.window]
        return self.fails[key]

    def blocked(self, *keys):
        now = time.time()
        with self.lock:
            return any(len(self._recent(k, now)) >= self.limit for k in keys)

    def fail(self, *keys):
        now = time.time()
        with self.lock:
            for k in keys:
                self._recent(k, now).append(now)

    def clear(self, key):
        with self.lock:
            self.fails.pop(key, None)


def ssl_context(ca_file=""):
    ctx = ssl.create_default_context()
    if ca_file:
        ctx.load_verify_locations(cafile=ca_file)
    return ctx


# ---------------------------------------------------------------- LDAP

class LdapError(Exception):
    pass


LDAP_STRATEGY = None   # tests set ldap3.MOCK_SYNC


def _ldap_server(cfg, ca_file):
    import ldap3
    tls = ldap3.Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=ca_file or None, version=ssl.PROTOCOL_TLS_CLIENT)
    u = urllib.parse.urlparse(cfg.url)
    use_ssl = u.scheme == "ldaps"
    port = u.port or (636 if use_ssl else 389)
    return ldap3.Server(u.hostname, port=port, use_ssl=use_ssl, tls=tls, get_info=ldap3.NONE, connect_timeout=10)


def _ldap_conn(cfg, server, user, password):
    import ldap3
    conn = ldap3.Connection(server, user=user or None, password=password or None, receive_timeout=20,
                            raise_exceptions=False, read_only=True, client_strategy=LDAP_STRATEGY or ldap3.SYNC)
    if cfg.start_tls and not server.ssl:
        conn.open()
        if not conn.start_tls():
            raise LdapError("StartTLS failed: %s" % conn.result.get("description"))
    if not conn.bind():
        return None
    return conn


def ldap_lookup(cfg, ca_file, username, password=None, server=None):
    """Find the user with the service account; if `password` is given, also verify it by binding as the user.
    Returns dict(dn, username, display_name, email, groups) or None when the user or password is wrong."""
    import ldap3
    from ldap3.utils.conv import escape_filter_chars
    if password is not None and not password:
        return None                       # an empty password would be an anonymous bind, which "succeeds"
    server = server or _ldap_server(cfg, ca_file)
    svc = _ldap_conn(cfg, server, cfg.bind_dn, cfg.bind_password)
    if svc is None:
        raise LdapError("the service account could not bind (check the bind DN and password)")
    try:
        flt = cfg.user_filter.replace("{username}", escape_filter_chars(username))
        attrs = [cfg.username_attr, cfg.display_attr, cfg.email_attr, "memberOf"]
        svc.search(cfg.user_base, flt, search_scope=ldap3.SUBTREE, attributes=attrs, size_limit=2)
        entries = [e for e in svc.response or [] if e.get("type") == "searchResEntry"]
        if len(entries) != 1:
            return None
        ent = entries[0]
        dn, a = ent["dn"], ent.get("attributes") or {}

        def first(k):
            v = a.get(k)
            if isinstance(v, list):
                v = v[0] if v else ""
            return str(v or "")

        groups = [str(g) for g in (a.get("memberOf") or [])]
        if cfg.nested_groups and cfg.group_base:
            svc.search(cfg.group_base, "(member:1.2.840.113556.1.4.1941:=%s)" % escape_filter_chars(dn),
                       search_scope=ldap3.SUBTREE, attributes=["cn"])
            groups += [e["dn"] for e in svc.response or [] if e.get("type") == "searchResEntry"]
    finally:
        svc.unbind()
    if password is not None:
        uc = _ldap_conn(cfg, server, dn, password)
        if uc is None:
            return None
        uc.unbind()
    return {"dn": dn, "username": (first(cfg.username_attr) or username).lower(), "display_name": first(cfg.display_attr),
            "email": first(cfg.email_attr), "groups": sorted(set(groups), key=str.lower)}


# ---------------------------------------------------------------- OpenID Connect

class OidcError(Exception):
    pass


class Oidc:
    """Authorization code flow with PKCE, state and nonce. The ID token is verified against the provider's keys."""

    def __init__(self, cfg, base_url, ca_file=""):
        self.cfg, self.base_url, self.ca_file = cfg, base_url, ca_file
        self._meta, self._meta_at, self._jwks, self._jwks_at = None, 0, None, 0
        self.lock = threading.Lock()

    @property
    def redirect_uri(self):
        return self.base_url + "/auth/oidc/callback"

    def _client(self):
        import httpx
        return httpx.Client(timeout=20, verify=ssl_context(self.ca_file), follow_redirects=False, trust_env=True)

    def metadata(self):
        with self.lock:
            if self._meta and time.time() - self._meta_at < 3600:
                return self._meta
        url = self.cfg.issuer.rstrip("/") + "/.well-known/openid-configuration"
        with self._client() as c:
            r = c.get(url)
        if r.status_code != 200:
            raise OidcError("provider discovery failed: HTTP %d from %s" % (r.status_code, url))
        meta = r.json()
        for k in ("authorization_endpoint", "token_endpoint", "jwks_uri", "issuer"):
            if not meta.get(k):
                raise OidcError("provider discovery document has no " + k)
        with self.lock:
            self._meta, self._meta_at = meta, time.time()
        return meta

    def jwks(self, force=False):
        with self.lock:
            if self._jwks and not force and time.time() - self._jwks_at < 3600:
                return self._jwks
        with self._client() as c:
            r = c.get(self.metadata()["jwks_uri"])
        r.raise_for_status()
        with self.lock:
            self._jwks, self._jwks_at = r.json(), time.time()
        return self._jwks

    @staticmethod
    def new_request():
        state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
        return state, nonce, verifier

    def authorize_url(self, state, nonce, verifier):
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        q = {"response_type": "code", "client_id": self.cfg.client_id, "redirect_uri": self.redirect_uri,
             "scope": self.cfg.scopes, "state": state, "nonce": nonce,
             "code_challenge": challenge, "code_challenge_method": "S256"}
        ep = self.metadata()["authorization_endpoint"]
        return ep + ("&" if "?" in ep else "?") + urllib.parse.urlencode(q)

    def finish(self, code, nonce, verifier):
        """Exchange the code, verify the ID token, merge userinfo. Returns the claims."""
        from joserfc import jwt
        from joserfc.errors import JoseError
        from joserfc.jwk import KeySet
        meta = self.metadata()
        data = {"grant_type": "authorization_code", "code": code, "redirect_uri": self.redirect_uri,
                "client_id": self.cfg.client_id, "code_verifier": verifier}
        with self._client() as c:
            r = c.post(meta["token_endpoint"], data=data, auth=(self.cfg.client_id, self.cfg.client_secret)
                       if self.cfg.client_secret else None, headers={"Accept": "application/json"})
            if r.status_code != 200:
                raise OidcError("token request failed: HTTP %d %s" % (r.status_code, r.text[:200]))
            tok = r.json()
            if not tok.get("id_token"):
                raise OidcError("the provider returned no ID token")
            rules = jwt.JWTClaimsRegistry(leeway=60, iss={"essential": True, "value": meta["issuer"]},
                                          aud={"essential": True, "value": self.cfg.client_id},
                                          exp={"essential": True}, nonce={"essential": True, "value": nonce})
            claims = None
            for force in (False, True):    # retry once with fresh keys after a key rotation
                try:
                    t = jwt.decode(tok["id_token"], KeySet.import_key_set(self.jwks(force)),
                                   algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "PS256"])
                    rules.validate(t.claims)
                    claims = t.claims
                    break
                except (JoseError, ValueError) as e:
                    if force:
                        raise OidcError("the ID token is not valid: %s" % e) from None
            claims = dict(claims)
            if meta.get("userinfo_endpoint") and tok.get("access_token"):
                u = c.get(meta["userinfo_endpoint"], headers={"Authorization": "Bearer " + tok["access_token"]})
                if u.status_code == 200:
                    info = u.json()
                    if info.get("sub") == claims.get("sub"):
                        for k, v in info.items():
                            claims.setdefault(k, v)
        return claims

    def identity(self, claims):
        uname = str(claims.get(self.cfg.username_claim) or "").strip().lower()
        if not uname:
            raise OidcError("the ID token has no '%s' claim" % self.cfg.username_claim)
        groups = claims.get(self.cfg.groups_claim) or []
        if isinstance(groups, str):
            groups = [groups]
        return {"username": uname, "display_name": str(claims.get("name") or ""), "email": str(claims.get("email") or ""),
                "groups": sorted({str(g) for g in groups}, key=str.lower), "sub": str(claims.get("sub", ""))}


def token_hash(tok):
    return hashlib.sha256(tok.encode()).hexdigest()


__all__ = ["ROLES", "ROLE_LABEL", "PERMISSIONS", "can", "rank", "hash_password", "verify_password", "password_problem",
           "role_from_groups", "group_cn", "Throttle", "ldap_lookup", "LdapError", "Oidc", "OidcError", "token_hash",
           "ssl_context", "json"]
