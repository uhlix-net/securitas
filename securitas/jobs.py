"""Scan queue, workers, schedules and the assembled current report."""
import datetime
import logging
import threading
import time
import zoneinfo

from croniter import croniter
from sqlalchemy import delete, select, update

from . import feeds, k8s, report, scan_linux, scan_windows
from .config import PLATFORMS
from .db import PlatformResult, Scan, Schedule, Target, utcnow

log = logging.getLogger("securitas.jobs")
STATUS_LABEL = {"queued": "Queued", "running": "Running", "done": "Done", "partial": "Partial", "failed": "Failed"}


def next_run(cron, tz, after=None):
    zone = zoneinfo.ZoneInfo(tz)
    base = (after or utcnow()).astimezone(zone)
    return croniter(cron, base).get_next(datetime.datetime).astimezone(datetime.timezone.utc)


def valid_cron(cron):
    return croniter.is_valid(cron) and len(cron.split()) == 5


class Feeds:
    """KEV and EPSS, loaded at most every few minutes (the files themselves are re-downloaded hourly / daily)."""

    def __init__(self, cfg):
        self.cfg, self.lock, self.at, self.value = cfg, threading.Lock(), 0, None

    def get(self, force=False):
        with self.lock:
            if self.value is None or force or time.time() - self.at > 300:
                w = []
                kev, kev_src = feeds.kev(self.cfg, w)
                epss, epss_src = feeds.epss(self.cfg, None, w)
                self.value, self.at = (kev, epss, {"kev": kev_src, "epss": epss_src}, w), time.time()
            return self.value

    def ranker(self, force=False):
        kev, epss, src, w = self.get(force)
        return report.Ranker(kev, epss, self.cfg.epss_min), src, list(w)


class Jobs:
    def __init__(self, cfg, db, scanners=None):
        self.cfg, self.db = cfg, db
        self.feeds = Feeds(cfg)
        self.scanners = scanners or {"kubernetes": self._scan_kubernetes, "linux": self._scan_linux,
                                     "windows": self._scan_windows}
        self.wake = threading.Event()
        self.stop = threading.Event()
        self.threads = []
        self._cache = {}
        self._cache_lock = threading.Lock()

    # ------------------------------------------------------------ bootstrap and threads

    def bootstrap(self):
        with self.db.Session() as s, s.begin():
            for p, cron in self.cfg.schedules.items():
                if p in PLATFORMS and cron and not s.scalar(select(Schedule).where(Schedule.platform == p)):
                    if not valid_cron(cron):
                        raise SystemExit("schedule for %s is not a valid 5-field cron expression: %r" % (p, cron))
                    s.add(Schedule(platform=p, cron=cron, enabled=True, next_run=next_run(cron, self.cfg.timezone)))
            if not s.scalar(select(Target.id).limit(1)):
                for t in self.cfg.targets:
                    parts = t.split(":", 2)
                    if len(parts) >= 2 and parts[0] in ("linux", "windows") and parts[1]:
                        s.add(Target(platform=parts[0], host=parts[1].strip(), label=(parts[2] if len(parts) > 2 else "").strip()))
            # scans that were running when the process stopped will not finish
            s.execute(update(Scan).where(Scan.status.in_(("running",))).values(
                status="failed", error="interrupted: Securitas restarted while the scan was running", finished_at=utcnow()))

    def start(self):
        for i in range(self.cfg.workers):
            self.threads.append(threading.Thread(target=self._worker, name="scan-worker-%d" % i, daemon=True))
        self.threads.append(threading.Thread(target=self._scheduler, name="scheduler", daemon=True))
        for t in self.threads:
            t.start()

    def enqueue(self, s, platforms, trigger, user=""):
        scan = Scan(platforms=[p for p in PLATFORMS if p in platforms], trigger=trigger, requested_by=user, status="queued")
        s.add(scan)
        s.flush()
        self.wake.set()
        return scan

    def _scheduler(self):
        last_cleanup = 0
        while not self.stop.is_set():
            try:
                self.run_due()
                if time.time() - last_cleanup > 3600:
                    self.cleanup()
                    last_cleanup = time.time()
            except Exception:
                log.exception("scheduler")
            self.stop.wait(20)

    def run_due(self, now=None):
        now = now or utcnow()
        with self.db.Session() as s:
            due = s.scalars(select(Schedule).where(Schedule.enabled.is_(True), Schedule.next_run <= now)).all()
            for sc in due:
                nxt = next_run(sc.cron, self.cfg.timezone, now)
                # claim atomically, so a second replica does not start the same run
                n = s.execute(update(Schedule).where(Schedule.id == sc.id, Schedule.next_run == sc.next_run)
                              .values(next_run=nxt, last_run=now)).rowcount
                if not n:
                    s.rollback()
                    continue
                queued = [x for x in s.scalars(select(Scan).where(Scan.status.in_(("queued", "running")))).all()
                          if sc.platform in (x.platforms or [])]
                if queued:
                    log.info("schedule %s: a scan of this platform is already queued or running, skipped", sc.platform)
                else:
                    self.enqueue(s, [sc.platform], "schedule")
                s.commit()

    def cleanup(self):
        cutoff = utcnow() - datetime.timedelta(days=self.cfg.retention_days)
        from .db import LoginState, Session as Sess
        with self.db.Session() as s, s.begin():
            # keep the newest successful result of each platform whatever its age
            keep = set()
            for p in PLATFORMS:
                r = self._latest(s, p)
                if r:
                    keep.add(r.scan_id)
            old = [i for i in s.scalars(select(Scan.id).where(Scan.created_at < cutoff)).all() if i not in keep]
            if old:
                s.execute(delete(PlatformResult).where(PlatformResult.scan_id.in_(old)))
                s.execute(delete(Scan).where(Scan.id.in_(old)))
                log.info("removed %d scans older than %d days", len(old), self.cfg.retention_days)
            s.execute(delete(Sess).where(Sess.expires_at < utcnow()))
            s.execute(delete(LoginState).where(LoginState.created_at < utcnow() - datetime.timedelta(minutes=10)))

    def _claim(self):
        with self.db.Session() as s, s.begin():
            q = select(Scan).where(Scan.status == "queued").order_by(Scan.id).limit(1).with_for_update(skip_locked=True)
            scan = s.scalar(q)
            if scan is None:
                return None
            scan.status, scan.started_at = "running", utcnow()
            return scan.id

    def _worker(self):
        while not self.stop.is_set():
            try:
                sid = self._claim()
                if sid is None:
                    self.wake.wait(15)
                    self.wake.clear()
                    continue
                self.run_scan(sid)
            except Exception:
                log.exception("scan worker")
                self.stop.wait(5)

    # ------------------------------------------------------------ running a scan

    def run_scan(self, sid):
        lines, lock = [], threading.Lock()
        last = [0.0]

        def say(msg):
            stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S")
            with lock:
                lines.append("%s %s" % (stamp, msg))
            log.info("scan %d: %s", sid, msg)
            if time.time() - last[0] > 2:
                last[0] = time.time()
                self._save_log(sid, lines)

        with self.db.Session() as s:
            scan = s.get(Scan, sid)
            platforms = list(scan.platforms)
        say("started: " + ", ".join(platforms))
        statuses = []
        rk, src, fw = self.feeds.ranker(force=True)
        say("feeds: %s; %s" % (src["kev"], src["epss"]))
        for p in platforms:
            t0 = time.time()
            status, raw, err = "done", None, ""
            try:
                raw = self.scanners[p](say)
                if raw is None:
                    status, err = "failed", "nothing to scan"
                elif raw.get("failed"):
                    status = "partial" if raw.get("failed") < len(raw.get("systems", [])) else "failed"
                    err = "; ".join(raw.get("warnings", []))[:2000]
            except Exception as e:
                log.exception("scan %d: %s", sid, p)
                status, err = "failed", str(e) or type(e).__name__
            if raw is not None:
                # rank with feeds that include any IDs the scan found
                sec = report.build_platform(raw, rk)
                sec["warnings"] = list(fw) + sec.get("warnings", [])
            else:
                sec = {}
            with self.db.Session() as s, s.begin():
                s.add(PlatformResult(scan_id=sid, platform=p, status=status, raw=raw or {}, report=sec, sources=src, error=err))
            statuses.append(status)
            say("%s: %s in %.0fs%s" % (p, status, time.time() - t0, (": " + err[:300]) if err else ""))
        final = "done" if all(x == "done" for x in statuses) else "failed" if all(x == "failed" for x in statuses) else "partial"
        say("finished: " + final)
        with self.db.Session() as s, s.begin():
            scan = s.get(Scan, sid)
            scan.status, scan.finished_at, scan.log = final, utcnow(), "\n".join(lines)
            if final != "done":
                scan.error = "; ".join("%s %s" % (p, st) for p, st in zip(platforms, statuses) if st != "done")
        with self._cache_lock:
            self._cache.clear()

    def _save_log(self, sid, lines):
        try:
            with self.db.Session() as s, s.begin():
                s.execute(update(Scan).where(Scan.id == sid).values(log="\n".join(lines)))
        except Exception:
            log.exception("saving scan log")

    def _targets(self, platform):
        with self.db.Session() as s:
            return [{"id": t.id, "host": t.host, "label": t.label, "host_key": t.host_key}
                    for t in s.scalars(select(Target).where(Target.platform == platform, Target.enabled.is_(True))
                                       .order_by(Target.host)).all()]

    def _record_key(self, tid, key):
        with self.db.Session() as s, s.begin():
            t = s.get(Target, tid)
            if t and not t.host_key:
                t.host_key = key

    def _scan_kubernetes(self, say):
        reports = k8s.list_reports(self.cfg)
        say("kubernetes: %d vulnerability reports" % len(reports))
        return report.kubernetes_raw(reports, self.cfg.cluster_name)

    def _scan_linux(self, say):
        t = self._targets("linux")
        if not t:
            raise RuntimeError("no Linux targets are configured")
        return scan_linux.scan(self.cfg, t, say, self._record_key)

    def _scan_windows(self, say):
        t = self._targets("windows")
        if not t:
            raise RuntimeError("no Windows targets are configured")
        return scan_windows.scan(self.cfg, t, say)

    # ------------------------------------------------------------ reports

    @staticmethod
    def _latest(s, platform):
        return s.scalar(select(PlatformResult).where(PlatformResult.platform == platform,
                                                     PlatformResult.status.in_(("done", "partial")))
                        .order_by(PlatformResult.id.desc()).limit(1))

    def current_model(self):
        """Newest good result of each platform, re-ranked with the current KEV catalog and EPSS scores."""
        rk, src, warnings = self.feeds.ranker()
        with self.db.Session() as s:
            latest = [r for r in (self._latest(s, p) for p in PLATFORMS) if r is not None]
            key = (tuple(r.id for r in latest), src["kev"], src["epss"], self.feeds.at)
            with self._cache_lock:
                if key in self._cache:
                    return self._cache[key]
            sections = []
            for r in latest:
                sec = report.build_platform(r.raw, rk)
                sec["scanned"] = fmt_time(r.scanned_at, self.cfg.timezone)
                sec["scan_id"] = r.scan_id
                if r.status == "partial":
                    sec["warnings"] = sec.get("warnings", [])
                sections.append(sec)
        if self.cfg.extra_dir:
            for p in report.load_extra(self.cfg.extra_dir, warnings):
                sec = report.build_platform(report.extra_raw(p), rk)
                sec["scanned"] = str(p.get("scan_date", "")) or "imported"
                sections.append(sec)
        m = report.model(self.cfg, sections, src, warnings)
        with self._cache_lock:
            self._cache.clear()
            self._cache[key] = m
        return m

    def scan_model(self, scan):
        """A past scan as it was reported at the time."""
        sections, warnings, src = [], [], {}
        for r in scan.results:
            if not r.report:
                continue
            sec = dict(r.report)
            sec["scanned"] = fmt_time(r.scanned_at, self.cfg.timezone)
            sections.append(sec)
            src = r.sources or src
        return report.model(self.cfg, sections, src or {"kev": "", "epss": ""}, warnings,
                            generated=scan.finished_at or scan.created_at, label="Scan #%d" % scan.id)


def fmt_time(dt, tz="UTC"):
    if not dt:
        return ""
    try:
        z = zoneinfo.ZoneInfo(tz)
    except Exception:
        z = datetime.timezone.utc
    return dt.astimezone(z).strftime("%Y-%m-%d %H:%M %Z")
