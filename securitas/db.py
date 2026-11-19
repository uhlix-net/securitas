"""Database: users, sessions, role mappings, scan targets, schedules, scans and their results, audit log.

PostgreSQL in production (SECURITAS_DATABASE_URL=postgresql+psycopg://...). SQLite works for tests and trials.
"""
import datetime
import threading

from sqlalchemy import (JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, create_engine, event, func,
                        select, text)
from sqlalchemy.types import TypeDecorator
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

JSONType = JSON().with_variant(JSONB(), "postgresql")
SCHEMA_VERSION = 1


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


class TZDateTime(TypeDecorator):
    """Timezone-aware UTC datetimes on every backend (SQLite drops the zone otherwise)."""
    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=datetime.timezone.utc)
        if value is not None and dialect.name == "sqlite":
            value = value.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        return value

    def process_result_value(self, value, dialect):
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=datetime.timezone.utc)
        return value


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(255), unique=True, index=True)   # stored lower-case
    display_name: Mapped[str] = mapped_column(String(255), default="")
    email: Mapped[str] = mapped_column(String(255), default="")
    source: Mapped[str] = mapped_column(String(16))                 # local | ldap | oidc
    password_hash: Mapped[str] = mapped_column(String(255), default="")
    role: Mapped[str] = mapped_column(String(16), default="")       # local users: assigned role
    role_override: Mapped[str] = mapped_column(String(16), default="")  # external users: fixed role, ignores groups
    groups: Mapped[list] = mapped_column(JSONType, default=list)    # external users: groups seen at last login
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    theme: Mapped[str] = mapped_column(String(8), default="system")  # system | light | dark
    created_at: Mapped[datetime.datetime] = mapped_column(TZDateTime(), default=utcnow)
    last_login_at: Mapped[datetime.datetime | None] = mapped_column(TZDateTime(), nullable=True)


class Session(Base):
    __tablename__ = "sessions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # sha256 of the cookie value
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    csrf: Mapped[str] = mapped_column(String(64))
    method: Mapped[str] = mapped_column(String(16), default="")
    created_at: Mapped[datetime.datetime] = mapped_column(TZDateTime(), default=utcnow)
    expires_at: Mapped[datetime.datetime] = mapped_column(TZDateTime())
    last_seen: Mapped[datetime.datetime] = mapped_column(TZDateTime(), default=utcnow)
    ip: Mapped[str] = mapped_column(String(64), default="")
    user: Mapped[User] = relationship()


class LoginState(Base):
    """OIDC authorization requests in flight (state, nonce, PKCE verifier). Deleted when used or after 10 minutes."""
    __tablename__ = "login_states"
    state: Mapped[str] = mapped_column(String(64), primary_key=True)
    nonce: Mapped[str] = mapped_column(String(64))
    verifier: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime.datetime] = mapped_column(TZDateTime(), default=utcnow)


class RoleMapping(Base):
    __tablename__ = "role_mappings"
    id: Mapped[int] = mapped_column(primary_key=True)
    group: Mapped[str] = mapped_column(String(255), unique=True)    # group name (CN), compared case-insensitively
    role: Mapped[str] = mapped_column(String(16))


class Target(Base):
    __tablename__ = "targets"
    id: Mapped[int] = mapped_column(primary_key=True)
    platform: Mapped[str] = mapped_column(String(16), index=True)  # linux | windows
    host: Mapped[str] = mapped_column(String(255))
    label: Mapped[str] = mapped_column(String(255), default="")    # role or description, shown in the report
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    host_key: Mapped[str] = mapped_column(Text, default="")        # linux: SSH host key recorded on first contact
    created_at: Mapped[datetime.datetime] = mapped_column(TZDateTime(), default=utcnow)


class Schedule(Base):
    __tablename__ = "schedules"
    id: Mapped[int] = mapped_column(primary_key=True)
    platform: Mapped[str] = mapped_column(String(16), unique=True)
    cron: Mapped[str] = mapped_column(String(64))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    next_run: Mapped[datetime.datetime | None] = mapped_column(TZDateTime(), nullable=True)
    last_run: Mapped[datetime.datetime | None] = mapped_column(TZDateTime(), nullable=True)


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime.datetime] = mapped_column(TZDateTime(), default=utcnow, index=True)
    started_at: Mapped[datetime.datetime | None] = mapped_column(TZDateTime(), nullable=True)
    finished_at: Mapped[datetime.datetime | None] = mapped_column(TZDateTime(), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)  # queued running done partial failed
    trigger: Mapped[str] = mapped_column(String(16))                # schedule | manual
    requested_by: Mapped[str] = mapped_column(String(255), default="")
    platforms: Mapped[list] = mapped_column(JSONType, default=list)
    log: Mapped[str] = mapped_column(Text, default="")
    error: Mapped[str] = mapped_column(Text, default="")
    results: Mapped[list["PlatformResult"]] = relationship(back_populates="scan", cascade="all, delete-orphan",
                                                           order_by="PlatformResult.id")


class PlatformResult(Base):
    __tablename__ = "platform_results"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    platform: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(16))                 # done | partial | failed
    scanned_at: Mapped[datetime.datetime] = mapped_column(TZDateTime(), default=utcnow)
    raw: Mapped[dict] = mapped_column(JSONType, default=dict)       # all findings, unranked (re-ranked for the current view)
    report: Mapped[dict] = mapped_column(JSONType, default=dict)    # ranked platform section as of the scan
    sources: Mapped[dict] = mapped_column(JSONType, default=dict)   # feed versions used for `report`
    error: Mapped[str] = mapped_column(Text, default="")
    scan: Mapped[Scan] = relationship(back_populates="results")


class ResultStats(Base):
    """Distinct CVE counts of one platform result, by severity level. Kept so the Summary page's history graph
    does not have to load every stored scan. Filled when a result is saved; older results are backfilled at startup."""
    __tablename__ = "result_stats"
    result_id: Mapped[int] = mapped_column(ForeignKey("platform_results.id", ondelete="CASCADE"), primary_key=True)
    platform: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(16))
    scanned_at: Mapped[datetime.datetime] = mapped_column(TZDateTime(), index=True)
    total: Mapped[int] = mapped_column(default=0)
    levels: Mapped[dict] = mapped_column(JSONType, default=dict)    # {"critical": n, "high": n, "medium": n, "low": n, "unknown": n}
    priority: Mapped[int] = mapped_column(default=0)                # priority CVEs in the report as of the scan
    kev: Mapped[int] = mapped_column(default=0)                     # of those, in the CISA KEV catalog


class AuditEvent(Base):
    __tablename__ = "audit"
    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime.datetime] = mapped_column(TZDateTime(), default=utcnow, index=True)
    username: Mapped[str] = mapped_column(String(255), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    action: Mapped[str] = mapped_column(String(64))
    detail: Mapped[str] = mapped_column(Text, default="")


class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(JSONType, default=dict)


class Database:
    def __init__(self, url):
        kw = {"pool_pre_ping": True, "future": True}
        if url.startswith("sqlite"):
            kw["connect_args"] = {"check_same_thread": False}
            if url in ("sqlite://", "sqlite:///:memory:"):
                from sqlalchemy.pool import StaticPool
                kw["poolclass"] = StaticPool
        self.engine = create_engine(url, **kw)
        if url.startswith("sqlite"):
            @event.listens_for(self.engine, "connect")
            def _fk(conn, _):
                conn.execute("PRAGMA foreign_keys=ON")
        self.Session = sessionmaker(self.engine, expire_on_commit=False)
        self._lock = threading.Lock()

    def create(self, wait=120):
        """Create missing tables. Waits up to `wait` seconds for the database to accept connections."""
        import logging
        import time
        deadline = time.time() + wait
        while True:
            try:
                self.ping()
                break
            except Exception as e:
                if time.time() > deadline:
                    raise
                logging.getLogger("securitas").warning("database not reachable yet (%s); retrying", str(e).splitlines()[0][:200])
                time.sleep(3)
        with self._lock:
            Base.metadata.create_all(self.engine)
            with self.Session() as s, s.begin():
                v = s.get(Setting, "schema_version")
                if v is None:
                    s.add(Setting(key="schema_version", value={"v": SCHEMA_VERSION}))

    def ping(self):
        with self.engine.connect() as c:
            c.execute(text("select 1"))


def get_setting(s, key, default=None):
    row = s.get(Setting, key)
    return default if row is None else row.value.get("v", default)


def set_setting(s, key, value):
    row = s.get(Setting, key)
    if row is None:
        s.add(Setting(key=key, value={"v": value}))
    else:
        row.value = {"v": value}


def audit(s, user, ip, action, detail=""):
    s.add(AuditEvent(username=user or "", ip=ip or "", action=action, detail=detail[:4000]))


__all__ = ["Database", "User", "Session", "LoginState", "RoleMapping", "Target", "Schedule", "Scan", "PlatformResult",
           "ResultStats", "AuditEvent", "Setting", "get_setting", "set_setting", "audit", "utcnow", "select", "func"]
