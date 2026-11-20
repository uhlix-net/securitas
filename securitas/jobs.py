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
from .db import PlatformResult, ResultStats, Scan, Schedule, Target, utcnow
from .settings import Settings

log = logging.getLogger("securitas.jobs")
STATUS_LABEL = {"queued": "Queued", "running": "Running", "done": "Done", "partial": "Partial", "failed": "Failed"}


def next_run(cron, tz, after=None):
    zone = zoneinfo.ZoneInfo(tz)
    base = (after or utcnow()).astimezone(zone)
    return croniter(cron, base).get_next(datetime.datetime).astimezone(datetime.timezone.utc)


def valid_cron(cron):
    return croniter.is_valid(cron) and len(cron.split()) == 5


class Feeds:
    """KEV and EPSS, loaded at most every few minutes (the files themselves are re-downloaded hourly / daily).
    A source turned off in Vulnerabilities > Sources is not downloaded at all."""

    def __init__(self, settings):
        self.settings, self.lock, self.at, self.value, self.key = settings, threading.Lock(), 0, None, None

    @property
    def cfg(self):
        return self.settings.effective()

    def get(self, force=False):
        cfg = self.cfg
        key = (cfg.kev_enabled, cfg.epss_enabled, cfg.kev_url, cfg.epss_url)
        with self.lock:
            if self.value is None or force or key != self.key or time.time() - self.at > 300:
                w = []
                if cfg.kev_enabled:
                    kev, kev_src = feeds.kev(cfg, w)
                else:
                    kev, kev_src = {}, "CISA KEV catalog turned off"
                if cfg.epss_enabled:
                    epss, epss_src = feeds.epss(cfg, None, w)
                else:
                    epss, epss_src = {}, "EPSS scores turned off"
                if not cfg.kev_enabled and not cfg.epss_enabled:
                    w.append("CISA KEV and EPSS are both turned off (Vulnerabilities > Sources), so every CVE is listed, unranked.")
                self.value, self.at, self.key = (kev, epss, {"kev": kev_src, "epss": epss_src}, w), time.time(), key
            return self.value

    def ranker(self, force=False):
        cfg = self.cfg
        kev, epss, src, w = self.get(force)
        return report.Ranker(kev, epss, cfg.epss_min, cfg.kev_enabled, cfg.epss_enabled), src, list(w)


class Jobs:
    def __init__(self, cfg, db, scanners=None):
        self.cfg, self.db = cfg, db
        self.settings = Settings(cfg, db)
        self.feeds = Feeds(self.settings)
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

    def backfill_stats(self):
        """ResultStats for results saved before 0.4.0, one result at a time (raw results can be large)."""
        with self.db.Session() as s:
            ids = s.scalars(select(PlatformResult.id).outerjoin(ResultStats, ResultStats.result_id == PlatformResult.id)
                            .where(ResultStats.result_id.is_(None)).order_by(PlatformResult.id)).all()
        for rid in ids:
            try:
                with self.db.Session() as s, s.begin():
                    r = s.get(PlatformResult, rid)
                    if r is not None:
                        s.add(ResultStats(result_id=r.id, platform=r.platform, status=r.status, scanned_at=r.scanned_at,
                                          **report.result_stats(r.raw, r.report)))
            except Exception:
                log.exception("backfilling statistics of result %d", rid)
        if ids:
            log.info("history: statistics computed for %d earlier results", len(ids))

    def history(self, rng):
        """Summary page graph: distinct CVEs per platform over the range ('day', 'week' or 'month')."""
        try:
            z = zoneinfo.ZoneInfo(self.cfg.timezone)
        except Exception:
            z = datetime.timezone.utc
        with self.db.Session() as s:
            rows = s.execute(select(ResultStats.platform, ResultStats.scanned_at, ResultStats.total)
                             .where(ResultStats.status.in_(("done", "partial")))
                             .order_by(ResultStats.scanned_at, ResultStats.result_id)).all()
        stats = [(p, at.astimezone(z).date(), total) for p, at, total in rows]
        return report.history(stats, rng, datetime.datetime.now(z).date(), PLATFORMS)

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
                if not self.settings.effective().platform_on(sc.platform):
                    log.info("schedule %s: scanning of this platform is turned off (Vulnerabilities > Sources), skipped", sc.platform)
                elif queued:
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
                if not self.settings.effective().platform_on(p):
                    raise RuntimeError("scanning of this platform is turned off (Vulnerabilities > Sources)")
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
                pr = PlatformResult(scan_id=sid, platform=p, status=status, raw=raw or {}, report=sec, sources=src, error=err)
                s.add(pr)
                s.flush()
                s.add(ResultStats(result_id=pr.id, platform=p, status=status, scanned_at=pr.scanned_at,
                                  **report.result_stats(raw, sec)))
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

    def clear_cache(self):
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
        reports = k8s.list_reports(self.settings.effective())
        say("kubernetes: %d vulnerability reports" % len(reports))
        return report.kubernetes_raw(reports, self.cfg.cluster_name)

    def _scan_linux(self, say):
        t = self._targets("linux")
        if not t:
            raise RuntimeError("no Linux targets are configured")
        return scan_linux.scan(self.settings.effective(), t, say, self._record_key)

    def _scan_windows(self, say):
        t = self._targets("windows")
        if not t:
            raise RuntimeError("no Windows targets are configured")
        return scan_windows.scan(self.settings.effective(), t, say)

    # ------------------------------------------------------------ reports

    @staticmethod
    def _latest(s, platform):
        return s.scalar(select(PlatformResult).where(PlatformResult.platform == platform,
                                                     PlatformResult.status.in_(("done", "partial")))
                        .order_by(PlatformResult.id.desc()).limit(1))

    @staticmethod
    def _newest(s, platform):
        return s.scalar(select(PlatformResult).where(PlatformResult.platform == platform)
                        .order_by(PlatformResult.id.desc()).limit(1))

    def _when(self, r):
        return fmt_time(r.scanned_at, self.cfg.timezone)

    def current_model(self):
        """Newest good result of each platform, re-ranked with the current KEV catalog and EPSS scores."""
        rk, src, warnings = self.feeds.ranker()
        eff = self.settings.effective()
        with self.db.Session() as s:
            pairs = [(self._latest(s, p), self._newest(s, p)) for p in PLATFORMS]
            pairs = [(g, n) for g, n in pairs if n is not None]
            key = (tuple((g.id if g else 0, n.id) for g, n in pairs), src["kev"], src["epss"], self.feeds.at,
                   self.settings.rev)
            with self._cache_lock:
                if key in self._cache:
                    return self._cache[key]
            sections = []
            for good, newest in pairs:
                plat = newest.platform
                if not eff.platform_on(plat):
                    off = "Scanning of %s is turned off (Vulnerabilities > Sources)." % report.PLATFORM_TITLE.get(plat, plat)
                    if good is None:
                        sec = report.failed_platform(plat, off)
                    else:
                        sec = report.build_platform(good.raw, rk)
                        sec["failure"] = off + " The results below are from scan #%d and are no longer updated." % good.scan_id
                        sec["scanned"], sec["scan_id"] = self._when(good), good.scan_id
                    sec["status"], sec["turned_off"] = "off", True
                    sections.append(sec)
                    continue
                if good is None:
                    # never scanned successfully: show the failure instead of leaving the platform out
                    sec = report.failed_platform(newest.platform, newest.error)
                    sec["failure"] = "The latest scan (#%d, %s) failed: %s" % (newest.scan_id, self._when(newest), sec["failure"])
                else:
                    sec = report.build_platform(good.raw, rk)
                    sec["status"] = good.status
                    if good.status == "partial":
                        sec["failure"] = "Scan #%d was only partly successful: %s" % (good.scan_id, good.error or "some systems failed")
                    if newest.id != good.id:
                        sec["status"] = "failed"
                        sec["failure"] = ("The latest scan (#%d, %s) failed: %s. The results below are older, from scan #%d."
                                          % (newest.scan_id, self._when(newest), newest.error or "unknown error", good.scan_id))
                    sec["scanned"] = self._when(good)
                    sec["scan_id"] = good.scan_id
                sections.append(sec)
        if self.cfg.extra_dir:
            for p in report.load_extra(self.cfg.extra_dir, warnings):
                sec = report.build_platform(report.extra_raw(p), rk)
                sec["scanned"] = str(p.get("scan_date", "")) or "imported"
                sections.append(sec)
        m = report.model(eff, sections, src, warnings)
        with self._cache_lock:
            self._cache.clear()
            self._cache[key] = m
        return m

    def scan_model(self, scan):
        """A past scan as it was reported at the time."""
        sections, warnings, src = [], [], {}
        for r in scan.results:
            if r.report:
                sec = dict(r.report)
                if r.status == "partial":
                    sec["failure"] = "Only partly successful: %s" % (r.error or "some systems failed")
            else:
                sec = report.failed_platform(r.platform, r.error)
                sec["failure"] = "This scan failed: %s" % sec["failure"]
            sec["status"] = r.status
            sec["scanned"] = self._when(r)
            sections.append(sec)
            src = r.sources or src
        return report.model(self.settings.effective(), sections, src or {"kev": "", "epss": ""}, warnings,
                            generated=scan.finished_at or scan.created_at, label="Scan #%d" % scan.id)


def fmt_time(dt, tz="UTC"):
    if not dt:
        return ""
    try:
        z = zoneinfo.ZoneInfo(tz)
    except Exception:
        z = datetime.timezone.utc
    return dt.astimezone(z).strftime("%Y-%m-%d %H:%M %Z")
