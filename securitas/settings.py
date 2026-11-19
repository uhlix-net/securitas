"""Settings changed in the web UI.

They are stored in the database (one `settings` row). A field saved here overrides the deployment's value
(Helm values / SECURITAS_* environment); a field never saved, or reverted, falls back to the deployment.
Secrets (passwords, the SSH key, the OIDC client secret) are encrypted with SECURITAS_SECRET_KEY, which the
Helm chart generates, and are never shown again: they can only be replaced or reverted.

The effective configuration is rebuilt after every save, so changes apply without a restart. Securitas runs
one process (the chart runs one replica), so an in-memory cache with a revision counter is enough.
"""
import base64
import copy
import hashlib
import logging
import threading

from .config import PLATFORMS
from .db import get_setting, set_setting, utcnow

log = logging.getLogger("securitas.settings")
ROW = "ui_settings"

# group -> [(field, kind, label)]. kind: text, secret, bool, int, float, choice:<a|b>, keytext (secret, multi-line)
FIELDS = {
    "ldap": [("on", "bool", "Use LDAP sign-in"), ("url", "text", "Server URL"), ("bind_dn", "text", "Bind DN"),
             ("bind_password", "secret", "Bind password"), ("user_base", "text", "User search base"),
             ("user_filter", "text", "User filter"), ("group_base", "text", "Group search base (nested groups)"),
             ("nested_groups", "bool", "Resolve nested groups (Active Directory)"), ("start_tls", "bool", "StartTLS on ldap://")],
    "oidc": [("on", "bool", "Use single sign-on"), ("issuer", "text", "Issuer URL"), ("client_id", "text", "Client ID"),
             ("client_secret", "secret", "Client secret"), ("scopes", "text", "Scopes"),
             ("username_claim", "text", "User name claim"), ("groups_claim", "text", "Groups claim"),
             ("label", "text", "Button label")],
    "linux": [("ssh_user", "text", "SSH user"), ("ssh_key", "keytext", "SSH private key"), ("ssh_port", "int", "SSH port")],
    "windows": [("winrm_user", "text", "WinRM user"), ("winrm_password", "secret", "WinRM password"),
                ("winrm_port", "int", "Port"), ("winrm_ssl", "bool", "HTTPS"),
                ("winrm_auth", "choice:negotiate|ntlm|kerberos|credssp|basic", "Authentication")],
    "sources": [("kev_enabled", "bool", "CISA KEV catalog"), ("epss_enabled", "bool", "FIRST EPSS scores"),
                ("epss_min", "float", "EPSS threshold")] + [("platform_" + p, "bool", p) for p in PLATFORMS],
}
SECRET_KINDS = ("secret", "keytext")


class SettingsError(ValueError):
    pass


def _fernet(key):
    from cryptography.fernet import Fernet
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest()))


def _base_value(cfg, group, name):
    """The deployment's value of a field."""
    if group in ("ldap", "oidc"):
        return getattr(getattr(cfg, group), name)
    if group == "sources" and name.startswith("platform_"):
        return cfg.platform_on(name[len("platform_"):])
    return getattr(cfg, name)


def _set(cfg, group, name, value):
    if group in ("ldap", "oidc"):
        setattr(getattr(cfg, group), name, value)
    elif group == "sources" and name.startswith("platform_"):
        cfg.platforms_enabled[name[len("platform_"):]] = bool(value)
    else:
        setattr(cfg, name, value)


def parse(kind, raw):
    """Form text -> typed value. Raises SettingsError with a message for the page."""
    raw = "" if raw is None else str(raw)
    if kind == "bool":
        return raw == "on"
    if kind == "int":
        try:
            v = int(raw.strip())
        except ValueError:
            raise SettingsError("Enter a whole number.")
        if not 1 <= v <= 65535:
            raise SettingsError("Enter a port between 1 and 65535.")
        return v
    if kind == "float":
        try:
            v = float(raw.strip())
        except ValueError:
            raise SettingsError("Enter a number.")
        if not 0 <= v <= 1:
            raise SettingsError("The EPSS threshold must be between 0 and 1.")
        return v
    if kind.startswith("choice:"):
        if raw not in kind[7:].split("|"):
            raise SettingsError("Pick one of the listed values.")
        return raw
    if kind == "keytext":
        v = raw.strip().replace("\r\n", "\n")
        if v and "PRIVATE KEY-----" not in v:
            raise SettingsError("Paste a private key in OpenSSH or PEM format.")
        return v + "\n" if v else ""
    v = raw.strip()
    if len(v) > 4096:
        raise SettingsError("That value is too long.")
    return v


class Settings:
    def __init__(self, cfg, db):
        self.base, self.db = cfg, db
        self.rev = 0
        self._eff, self._eff_rev = None, -1
        self.lock = threading.Lock()

    # ------------------------------------------------------------ storage

    def _load(self, s=None):
        if s is not None:
            return copy.deepcopy(get_setting(s, ROW, {}) or {})
        with self.db.Session() as ss:
            return copy.deepcopy(get_setting(ss, ROW, {}) or {})

    @property
    def can_store_secrets(self):
        return bool(self.base.secret_key)

    def _decrypt(self, token):
        try:
            return _fernet(self.base.secret_key).decrypt(token.encode()).decode()
        except Exception:
            return None

    # ------------------------------------------------------------ effective configuration

    def effective(self):
        """The deployment's configuration with the UI overrides applied."""
        with self.lock:
            if self._eff is not None and self._eff_rev == self.rev:
                return self._eff
        try:
            data = self._load()
        except Exception as e:                 # database briefly unavailable: use the last known configuration
            log.warning("settings could not be read: %s", e)
            return self._eff or self.base
        cfg = copy.deepcopy(self.base)
        for group, fields in FIELDS.items():
            saved = data.get(group, {})
            for name, kind, _ in fields:
                if name not in saved:
                    continue
                v = saved[name]
                if kind in SECRET_KINDS:
                    v = self._decrypt(v.get("enc", "")) if isinstance(v, dict) else None
                    if v is None:
                        log.warning("the saved %s %s cannot be decrypted (was SECURITAS_SECRET_KEY changed?); "
                                    "the deployment's value is used", group, name)
                        continue
                _set(cfg, group, name, v)
        with self.lock:
            self._eff, self._eff_rev = cfg, self.rev
        return cfg

    def describe(self, group):
        """For the settings pages: per field, the effective value (never for secrets) and where it comes from."""
        data = self._load().get(group, {})
        eff = self.effective()
        out = {}
        for name, kind, label in FIELDS[group]:
            saved = data.get(name)
            src = "ui" if name in data else "deployment"
            meta = saved.get("at", "") if isinstance(saved, dict) else ""
            if kind in SECRET_KINDS:
                if name in data and self._decrypt(saved.get("enc", "") if isinstance(saved, dict) else "") is None:
                    state = "unreadable"
                else:
                    state = "set" if _base_value(eff, group, name) else "not set"
                out[name] = {"kind": kind, "label": label, "secret": True, "state": state, "source": src,
                             "changed": meta, "by": saved.get("by", "") if isinstance(saved, dict) else ""}
            else:
                out[name] = {"kind": kind, "label": label, "secret": False, "value": _base_value(eff, group, name),
                             "source": src, "deployment": _base_value(self.base, group, name)}
        return out

    # ------------------------------------------------------------ changes

    def save(self, s, group, form, user):
        """Apply a settings form inside the caller's transaction. Returns the changed fields (for the audit log).
        Text and other fields are saved when they differ from the effective value; secrets only when a new
        value was typed. A 'revert_<field>' checkbox goes back to the deployment's value.
        The caller must call bump() after the transaction commits, so no reader caches the old values."""
        data = self._load(s)
        saved = data.setdefault(group, {})
        eff = self.effective()
        changed = []
        for name, kind, label in FIELDS[group]:
            if form.get("revert_" + name) == "on":
                if name in saved:
                    del saved[name]
                    changed.append(name + " (reverted)")
                continue
            if kind in SECRET_KINDS:
                raw = form.get(name)
                if raw is None or not str(raw).strip():
                    continue                    # blank: keep the current secret
                if not self.can_store_secrets:
                    raise SettingsError("Secrets cannot be saved: SECURITAS_SECRET_KEY is not set.")
                try:
                    v = parse(kind, raw)
                except SettingsError as e:
                    raise SettingsError("%s: %s" % (label, e))
                token = _fernet(self.base.secret_key).encrypt(v.encode()).decode()
                saved[name] = {"enc": token, "at": utcnow().isoformat(timespec="seconds"), "by": user}
                changed.append(name + " (secret replaced)")
                continue
            if kind != "bool" and name not in form:
                continue
            try:
                v = parse(kind, form.get(name))
            except SettingsError as e:
                raise SettingsError("%s: %s" % (label, e))
            if v != _base_value(eff, group, name):
                saved[name] = v
                changed.append("%s=%s" % (name, v if kind != "text" or len(str(v)) < 120 else str(v)[:117] + "..."))
        if changed:
            set_setting(s, ROW, data)
        return changed

    def bump(self):
        with self.lock:
            self.rev += 1


__all__ = ["Settings", "SettingsError", "FIELDS", "parse"]
