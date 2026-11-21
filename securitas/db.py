"""Database: users, sessions, role mappings, scan targets, schedules, scans and their results, audit log, and the
compliance benchmark library.

PostgreSQL in production (SECURITAS_DATABASE_URL=postgresql+psycopg://...). SQLite works for tests and trials.
"""
import datetime
import threading

from sqlalchemy import (JSON, Boolean, DateTime, ForeignKey, Integer, LargeBinary, String, Text, UniqueConstraint,
                        create_engine, event, func, select, text)
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


class ComplianceSchedule(Base):
    """When each platform gets a compliance scan; separate from the vulnerability scan schedules."""
    __tablename__ = "compliance_schedules"
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


class Benchmark(Base):
    """One uploaded compliance benchmark: an Ansible-Lockdown role zip, named after the role and its version
    (key 'RHEL9-CIS-2.4.2'). Removing it removes its rules and the stored zip."""
    __tablename__ = "benchmarks"
    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(128), unique=True, index=True)    # <name>-<version>
    name: Mapped[str] = mapped_column(String(96))                   # role name, e.g. RHEL9-CIS
    version: Mapped[str] = mapped_column(String(32))                # role (zip) version, e.g. 2.4.2
    kind: Mapped[str] = mapped_column(String(16), default="CIS")
    benchmark_version: Mapped[str] = mapped_column(String(32), default="")   # CIS document version, e.g. v2.0.0
    source: Mapped[str] = mapped_column(String(32), default="ansible-lockdown")
    platform: Mapped[str] = mapped_column(String(16), index=True)  # linux | windows | kubernetes
    os_key: Mapped[str] = mapped_column(String(64), index=True)    # rhel9, windows2022, ...
    os_label: Mapped[str] = mapped_column(String(128), default="")
    profile: Mapped[str] = mapped_column(String(32), default="level1-server")
    active: Mapped[bool] = mapped_column(Boolean, default=False)    # at most one active benchmark per os_key
    rule_count: Mapped[int] = mapped_column(Integer, default=0)
    filename: Mapped[str] = mapped_column(String(255), default="")
    sha256: Mapped[str] = mapped_column(String(64))
    size: Mapped[int] = mapped_column(Integer, default=0)
    meta: Mapped[dict] = mapped_column(JSONType, default=dict)
    uploaded_at: Mapped[datetime.datetime] = mapped_column(TZDateTime(), default=utcnow)
    uploaded_by: Mapped[str] = mapped_column(String(255), default="")
    rules: Mapped[list["BenchmarkRule"]] = relationship(back_populates="benchmark", cascade="all, delete-orphan",
                                                        passive_deletes=True, order_by="BenchmarkRule.sort_key")
    files: Mapped[list["BenchmarkFile"]] = relationship(cascade="all, delete-orphan", passive_deletes=True)


class BenchmarkRule(Base):
    __tablename__ = "benchmark_rules"
    __table_args__ = (UniqueConstraint("benchmark_id", "rule_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    benchmark_id: Mapped[int] = mapped_column(ForeignKey("benchmarks.id", ondelete="CASCADE"), index=True)
    rule_id: Mapped[str] = mapped_column(String(32))                # 1.1.1.1
    sort_key: Mapped[str] = mapped_column(String(64))               # 0001.0001.0001.0001
    section: Mapped[str] = mapped_column(String(8))
    title: Mapped[str] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(String(8))                    # PATCH (automated) | AUDIT (manual check)
    levels: Mapped[list] = mapped_column(JSONType, default=list)    # level1-server, level2-workstation, ...
    refs: Mapped[list] = mapped_column(JSONType, default=list)      # NIST800-53R5_CM-7, ...
    toggle: Mapped[str] = mapped_column(String(128), default="")    # the role variable that turns the rule on
    default_on: Mapped[bool] = mapped_column(Boolean, default=True)  # the role's own default
    override: Mapped[bool | None] = mapped_column(Boolean, nullable=True)  # set here: on/off regardless of profile
    source: Mapped[str] = mapped_column(String(255), default="")    # task file in the role
    benchmark: Mapped[Benchmark] = relationship(back_populates="rules")


class BenchmarkFile(Base):
    """A file kept with a benchmark: the uploaded role zip (later also its audit content)."""
    __tablename__ = "benchmark_files"
    id: Mapped[int] = mapped_column(primary_key=True)
    benchmark_id: Mapped[int] = mapped_column(ForeignKey("benchmarks.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(16), default="role")
    filename: Mapped[str] = mapped_column(String(255))
    sha256: Mapped[str] = mapped_column(String(64))
    size: Mapped[int] = mapped_column(Integer, default=0)
    data: Mapped[bytes] = mapped_column(LargeBinary, deferred=True)
    uploaded_at: Mapped[datetime.datetime] = mapped_column(TZDateTime(), default=utcnow)
    uploaded_by: Mapped[str] = mapped_column(String(255), default="")


class ComplianceScan(Base):
    """One compliance scan: every enabled target of the chosen platforms checked against its active benchmark."""
    __tablename__ = "compliance_scans"
    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime.datetime] = mapped_column(TZDateTime(), default=utcnow, index=True)
    started_at: Mapped[datetime.datetime | None] = mapped_column(TZDateTime(), nullable=True)
    finished_at: Mapped[datetime.datetime | None] = mapped_column(TZDateTime(), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)  # queued running done partial failed
    trigger: Mapped[str] = mapped_column(String(16))                # schedule | manual
    requested_by: Mapped[str] = mapped_column(String(255), default="")
    platforms: Mapped[list] = mapped_column(JSONType, default=list)
    hosts: Mapped[list | None] = mapped_column(JSONType, nullable=True)   # only these hosts; None = every matched host
    log: Mapped[str] = mapped_column(Text, default="")
    error: Mapped[str] = mapped_column(Text, default="")
    results: Mapped[list["ComplianceResult"]] = relationship(back_populates="scan", cascade="all, delete-orphan",
                                                             passive_deletes=True, order_by="ComplianceResult.host")


class ComplianceResult(Base):
    """One host in a compliance scan. Keeps a copy of the benchmark's name, version and rule titles, so the result
    stays readable after the benchmark is removed (benchmark_id is then cleared)."""
    __tablename__ = "compliance_results"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("compliance_scans.id", ondelete="CASCADE"), index=True)
    platform: Mapped[str] = mapped_column(String(16), index=True)
    host: Mapped[str] = mapped_column(String(255), index=True)
    label: Mapped[str] = mapped_column(String(255), default="")
    os: Mapped[str] = mapped_column(String(255), default="")
    benchmark_id: Mapped[int | None] = mapped_column(ForeignKey("benchmarks.id", ondelete="SET NULL"), nullable=True)
    benchmark_key: Mapped[str] = mapped_column(String(128), default="")
    benchmark_name: Mapped[str] = mapped_column(String(255), default="")   # 'RHEL9-CIS 2.4.2 · uploaded 2026-11-20'
    profile: Mapped[str] = mapped_column(String(32), default="")
    status: Mapped[str] = mapped_column(String(16))                 # done | failed | skipped
    error: Mapped[str] = mapped_column(Text, default="")
    scanned_at: Mapped[datetime.datetime] = mapped_column(TZDateTime(), default=utcnow, index=True)
    seconds: Mapped[int] = mapped_column(Integer, default=0)
    counts: Mapped[dict] = mapped_column(JSONType, default=dict)    # pass, fail, skip, notest, checked, score
    rules: Mapped[list] = mapped_column(JSONType, default=list)     # [{id, title, kind, status, tests: [...]}]
    scan: Mapped[ComplianceScan] = relationship(back_populates="results")


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
            self._add_columns()
            with self.Session() as s, s.begin():
                v = s.get(Setting, "schema_version")
                if v is None:
                    s.add(Setting(key="schema_version", value={"v": SCHEMA_VERSION}))

    # Columns added to existing tables after their first release: (table, column, SQLite type, PostgreSQL type).
    # create_all() makes new tables but does not change existing ones.
    ADDED_COLUMNS = [("compliance_scans", "hosts", "JSON", "JSONB")]

    def _add_columns(self):
        from sqlalchemy import inspect
        insp = inspect(self.engine)
        pg = self.engine.dialect.name == "postgresql"
        for table, col, lite, pgtype in self.ADDED_COLUMNS:
            if table in insp.get_table_names() and col not in {c["name"] for c in insp.get_columns(table)}:
                with self.engine.begin() as c:
                    c.execute(text('ALTER TABLE %s ADD COLUMN %s %s' % (table, col, pgtype if pg else lite)))

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
           "ResultStats", "AuditEvent", "Setting", "Benchmark", "BenchmarkRule", "BenchmarkFile", "ComplianceSchedule", "ComplianceScan", "ComplianceResult", "get_setting", "set_setting", "audit", "utcnow", "select", "func"]
