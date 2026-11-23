"""Settings, read from SECURITAS_* environment variables (the Helm chart sets them)."""
import os
import urllib.parse
from dataclasses import dataclass, field

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
MSRC_URL = "https://api.msrc.microsoft.com/cvrf/v3.0"
PLATFORMS = ("kubernetes", "linux", "windows")


def _float(name, default):
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        raise SystemExit(f"{name} must be a number")


def _int(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        raise SystemExit(f"{name} must be a whole number")


def _bool(name, default):
    v = os.environ.get(name)
    if v is None or v == "":
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _secret(name):
    """A secret from NAME, or from the file named by NAME_FILE (Kubernetes Secret mounted as a file)."""
    path = os.environ.get(name + "_FILE")
    if path:
        try:
            with open(path) as f:
                return f.read().strip()
        except OSError as e:
            raise SystemExit(f"{name}_FILE: {e}")
    return os.environ.get(name, "")


def _list(name, default=""):
    return [x.strip() for x in os.environ.get(name, default).split(",") if x.strip()]


@dataclass
class LdapConfig:
    url: str = ""                      # ldaps://dc.example.com:636
    bind_dn: str = ""
    bind_password: str = ""
    user_base: str = ""
    user_filter: str = "(&(objectClass=user)(sAMAccountName={username}))"
    group_base: str = ""               # used for nested group lookup (Active Directory)
    nested_groups: bool = True
    username_attr: str = "sAMAccountName"
    display_attr: str = "displayName"
    email_attr: str = "mail"
    start_tls: bool = False
    on: bool = True                    # switch in Settings > Authentication

    @property
    def enabled(self):
        return bool(self.on and self.url and self.user_base)


@dataclass
class OidcConfig:
    issuer: str = ""                   # https://auth.example.com/application/o/securitas/
    client_id: str = ""
    client_secret: str = ""
    scopes: str = "openid profile email"
    username_claim: str = "preferred_username"
    groups_claim: str = "groups"
    label: str = "Single sign-on"
    on: bool = True                    # switch in Settings > Authentication

    @property
    def enabled(self):
        return bool(self.on and self.issuer and self.client_id)


@dataclass
class Config:
    title: str = "Securitas"
    cluster_name: str = ""
    port: int = 8080
    epss_min: float = 0.10
    namespaces: list = field(default_factory=list)
    kev_url: str = KEV_URL
    epss_url: str = EPSS_URL
    msrc_url: str = MSRC_URL
    kev_max_age: int = 3300          # re-download KEV at most hourly
    epss_max_age: int = 12 * 3600    # EPSS is published daily
    data_dir: str = "/data"
    extra_dir: str = ""              # optional: extra platform JSON files (see README)
    paper: str = "letter"            # PDF page size: letter or A4
    api_url: str = ""                # optional: Kubernetes API URL, e.g. http://127.0.0.1:8001 (kubectl proxy)
    reports_file: str = ""           # optional: read reports from a file instead of the API (testing)

    # Web app
    database_url: str = "sqlite:////data/securitas.db"
    base_url: str = ""               # https://securitas.example.com (needed for single sign-on)
    secure_cookies: bool = True
    session_hours: int = 12
    trusted_proxies: list = field(default_factory=list)  # client addresses allowed to set X-Forwarded-For
    ca_file: str = ""                # extra CA bundle for LDAPS, OIDC and WinRM
    tls_secrets: list = field(default_factory=list)  # ingress TLS Secrets admins may replace (Settings > Certificates)
    tls_hosts: list = field(default_factory=list)    # host names those certificates should cover
    namespace: str = ""              # this pod's namespace (for the TLS Secrets)
    admin_username: str = "admin"
    admin_password: str = ""         # bootstrap: creates or resets this local admin when no local admin can sign in
    role_map: list = field(default_factory=list)  # bootstrap "Group=role" pairs, editable in the UI afterwards
    local_login: bool = True
    ldap: LdapConfig = field(default_factory=LdapConfig)
    oidc: OidcConfig = field(default_factory=OidcConfig)

    # Scans
    timezone: str = "UTC"            # for schedules
    schedules: dict = field(default_factory=dict)  # bootstrap {platform: cron}
    retention_days: int = 365
    workers: int = 1                 # scans run one at a time per worker
    host_concurrency: int = 4
    ssh_user: str = ""
    ssh_key_file: str = ""
    ssh_key: str = ""                # private key text (set in Settings > Scan credentials; wins over ssh_key_file)
    ssh_known_hosts: str = ""        # optional known_hosts file; without it host keys are recorded on first contact
    ssh_port: int = 22
    linux_repos: list = field(default_factory=list)  # optional "name=url" pairs: scan against these repos only
    winrm_user: str = ""
    winrm_password: str = ""
    winrm_port: int = 5986
    winrm_ssl: bool = True
    winrm_auth: str = "negotiate"
    host_timeout: int = 600
    targets: list = field(default_factory=list)  # bootstrap "platform:host[:label]" entries

    # Sources (Vulnerabilities > Sources)
    kev_enabled: bool = True
    epss_enabled: bool = True
    platforms_enabled: dict = field(default_factory=lambda: {p: True for p in PLATFORMS})

    # Encrypts secrets saved in the web UI (the chart generates it)
    secret_key: str = ""

    def platform_on(self, p):
        return bool(self.platforms_enabled.get(p, True))

    @classmethod
    def from_env(cls):
        e = os.environ.get
        c = cls(
            title=e("SECURITAS_TITLE", "Securitas"),
            cluster_name=e("SECURITAS_CLUSTER_NAME", ""),
            port=_int("SECURITAS_LISTEN_PORT", 8080),
            epss_min=_float("SECURITAS_EPSS_MIN", 0.10),
            namespaces=_list("SECURITAS_NAMESPACES"),
            kev_url=e("SECURITAS_KEV_URL", KEV_URL),
            epss_url=e("SECURITAS_EPSS_URL", EPSS_URL),
            msrc_url=e("SECURITAS_MSRC_URL", MSRC_URL),
            data_dir=e("SECURITAS_DATA_DIR", "/data"),
            extra_dir=e("SECURITAS_EXTRA_DIR", ""),
            paper=e("SECURITAS_PAPER", "letter"),
            api_url=e("SECURITAS_API_URL", ""),
            reports_file=e("SECURITAS_REPORTS_FILE", ""),
            base_url=e("SECURITAS_BASE_URL", "").rstrip("/"),
            secure_cookies=_bool("SECURITAS_SECURE_COOKIES", True),
            session_hours=max(1, _int("SECURITAS_SESSION_HOURS", 12)),
            trusted_proxies=_list("SECURITAS_TRUSTED_PROXIES"),
            ca_file=e("SECURITAS_CA_FILE", ""),
            tls_secrets=_list("SECURITAS_TLS_SECRETS"),
            tls_hosts=_list("SECURITAS_TLS_HOSTS"),
            namespace=e("SECURITAS_NAMESPACE", ""),
            admin_username=e("SECURITAS_ADMIN_USERNAME", "admin").strip().lower() or "admin",
            admin_password=_secret("SECURITAS_ADMIN_PASSWORD"),
            role_map=_list("SECURITAS_ROLE_MAP"),
            local_login=_bool("SECURITAS_LOCAL_LOGIN", True),
            ldap=LdapConfig(
                url=e("SECURITAS_LDAP_URL", ""),
                bind_dn=e("SECURITAS_LDAP_BIND_DN", ""),
                bind_password=_secret("SECURITAS_LDAP_BIND_PASSWORD"),
                user_base=e("SECURITAS_LDAP_USER_BASE", ""),
                user_filter=e("SECURITAS_LDAP_USER_FILTER", LdapConfig.user_filter),
                group_base=e("SECURITAS_LDAP_GROUP_BASE", ""),
                nested_groups=_bool("SECURITAS_LDAP_NESTED_GROUPS", True),
                username_attr=e("SECURITAS_LDAP_USERNAME_ATTR", "sAMAccountName"),
                display_attr=e("SECURITAS_LDAP_DISPLAY_ATTR", "displayName"),
                email_attr=e("SECURITAS_LDAP_EMAIL_ATTR", "mail"),
                start_tls=_bool("SECURITAS_LDAP_START_TLS", False),
            ),
            oidc=OidcConfig(
                issuer=e("SECURITAS_OIDC_ISSUER", ""),
                client_id=e("SECURITAS_OIDC_CLIENT_ID", ""),
                client_secret=_secret("SECURITAS_OIDC_CLIENT_SECRET"),
                scopes=e("SECURITAS_OIDC_SCOPES", "openid profile email"),
                username_claim=e("SECURITAS_OIDC_USERNAME_CLAIM", "preferred_username"),
                groups_claim=e("SECURITAS_OIDC_GROUPS_CLAIM", "groups"),
                label=e("SECURITAS_OIDC_LABEL", "Single sign-on"),
            ),
            timezone=e("SECURITAS_TIMEZONE", "UTC"),
            schedules={p: e("SECURITAS_SCHEDULE_" + p.upper(), d) for p, d in
                       (("kubernetes", "5 * * * *"), ("linux", "0 5 * * *"), ("windows", "30 5 * * *"))},
            retention_days=max(1, _int("SECURITAS_RETENTION_DAYS", 365)),
            workers=max(1, _int("SECURITAS_WORKERS", 1)),
            host_concurrency=max(1, _int("SECURITAS_HOST_CONCURRENCY", 4)),
            ssh_user=e("SECURITAS_SSH_USER", ""),
            ssh_key_file=e("SECURITAS_SSH_KEY_FILE", ""),
            ssh_known_hosts=e("SECURITAS_SSH_KNOWN_HOSTS", ""),
            ssh_port=_int("SECURITAS_SSH_PORT", 22),
            linux_repos=_list("SECURITAS_LINUX_REPOS"),
            winrm_user=e("SECURITAS_WINRM_USER", ""),
            winrm_password=_secret("SECURITAS_WINRM_PASSWORD"),
            winrm_port=_int("SECURITAS_WINRM_PORT", 5986),
            winrm_ssl=_bool("SECURITAS_WINRM_SSL", True),
            winrm_auth=e("SECURITAS_WINRM_AUTH", "negotiate"),
            host_timeout=max(30, _int("SECURITAS_HOST_TIMEOUT", 600)),
            targets=_list("SECURITAS_TARGETS"),
            secret_key=_secret("SECURITAS_SECRET_KEY"),
        )
        c.database_url = e("SECURITAS_DATABASE_URL", "") or _db_url_from_parts() or f"sqlite:///{c.data_dir}/securitas.db"
        if c.paper.lower() not in ("letter", "a4"):
            raise SystemExit("SECURITAS_PAPER must be letter or A4")
        if c.winrm_auth not in ("negotiate", "ntlm", "kerberos", "credssp", "basic"):
            raise SystemExit("SECURITAS_WINRM_AUTH must be negotiate, ntlm, kerberos, credssp or basic")
        return c


def _db_url_from_parts():
    host = os.environ.get("SECURITAS_DB_HOST", "")
    if not host:
        return ""
    q = urllib.parse.quote
    user = os.environ.get("SECURITAS_DB_USER", "securitas")
    pw = _secret("SECURITAS_DB_PASSWORD")
    name = os.environ.get("SECURITAS_DB_NAME", "securitas")
    port = os.environ.get("SECURITAS_DB_PORT", "5432")
    ssl = os.environ.get("SECURITAS_DB_SSLMODE", "")
    return f"postgresql+psycopg://{q(user, safe='')}:{q(pw, safe='')}@{host}:{port}/{q(name, safe='')}" + \
        (f"?sslmode={q(ssl)}" if ssl else "")
