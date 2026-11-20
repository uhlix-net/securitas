"""Turn scanner findings into the report model, ranked with the CISA KEV catalog and EPSS scores.

A CVE is a *priority* when it is in the CISA KEV catalog or its EPSS score is at least `epss_min`.
Priority CVEs are listed known-exploited first, then by EPSS score.

Scanners return a *raw* platform: every finding, unranked. `build_platform` ranks it. Raw results are kept in
the database so the current view can be re-ranked when the KEV catalog or EPSS scores change, without a rescan.
"""
import collections
import copy
import datetime
import glob
import json
import os

SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "IMPORTANT": 1, "MEDIUM": 2, "MODERATE": 2, "LOW": 3, "UNKNOWN": 4}


# Severity levels shown in the report filter and the charts, most severe first. Vendors name them differently:
# Microsoft and Red Hat say Important and Moderate where Trivy says High and Medium.
LEVELS = [("critical", "Critical"), ("high", "High / Important"), ("medium", "Medium / Moderate"), ("low", "Low"),
          ("unknown", "Unknown")]
LEVEL_KEYS = [k for k, _ in LEVELS]
_LEVEL_OF = {"CRITICAL": "critical", "HIGH": "high", "IMPORTANT": "high", "MEDIUM": "medium", "MODERATE": "medium",
             "LOW": "low"}


def sev_level(s):
    """'Important' -> 'high'; anything unrated -> 'unknown'."""
    return _LEVEL_OF.get((s or "").strip().upper(), "unknown")


def level_counts(severities):
    c = collections.Counter(sev_level(x) for x in severities)
    return {k: c.get(k, 0) for k in LEVEL_KEYS}


def raw_stats(raw):
    """Distinct CVEs of a raw platform and their count per severity level."""
    by = {}
    for f in raw.get("findings") or []:
        by[f["cve"]] = f.get("severity", "")
    return len(by), level_counts(by.values())


def sev_title(s):
    return (s or "Unknown").strip().title() or "Unknown"


def worse(a, b):
    """The more severe of two severity strings."""
    return a if SEV_RANK.get((a or "").upper(), 5) <= SEV_RANK.get((b or "").upper(), 5) else b


class Ranker:
    """kev_on / epss_on: the source switches in Vulnerabilities > Sources. With both off every CVE is a priority,
    because there is nothing left to rank by."""

    def __init__(self, kev, epss, epss_min, kev_on=True, epss_on=True):
        self.kev, self.epss, self.epss_min = (kev if kev_on else {}), (epss if epss_on else {}), epss_min
        self.kev_on, self.epss_on = kev_on, epss_on

    def priority(self, cve):
        if not self.kev_on and not self.epss_on:
            return True
        return (self.kev_on and cve in self.kev) or (self.epss_on and self.epss.get(cve, 0.0) >= self.epss_min)

    def enrich(self, row):
        k = self.kev.get(row["cve"])
        row["kev"] = k.get("dateAdded", "") if k else ""
        row["ransomware"] = bool(k and k.get("knownRansomwareCampaignUse") == "Known")
        row["epss"] = round(self.epss.get(row["cve"], 0.0), 2)
        if not row.get("title") and k:
            row["title"] = k.get("vulnerabilityName", "")
        return row

    @staticmethod
    def order(row):
        return (0 if row["kev"] else 1, -row["epss"], SEV_RANK.get(row["severity"].upper(), 5), row["cve"])


def raw_ids(raw):
    return {f["cve"] for f in raw.get("findings", [])}


def build_platform(raw, rk):
    """Ranked platform section (what the page and the PDF show) from a raw platform."""
    raw = copy.deepcopy(raw)
    systems, total = [], 0
    for s in raw.get("systems", []):
        ids = s.pop("_cves", None)
        total += 1
        if ids is not None:
            s["kev"] = sum(c in rk.kev for c in ids)
            s["priority"] = sum(rk.priority(c) for c in ids)
        if raw.get("systems_filter") == "critical_or_priority" and not (s.get("critical") or s.get("priority")):
            continue
        systems.append(s)
    if raw.get("systems_filter") == "critical_or_priority":
        systems.sort(key=lambda s: (-s.get("kev", 0), -s.get("critical", 0), -s.get("high", 0), s.get("name", "")))
    rows = []
    for f in raw.get("findings", []):
        row = {"cve": f["cve"], "title": f.get("title", ""), "severity": sev_title(f.get("severity", "")),
               "level": sev_level(f.get("severity", "")), "priority": bool(rk.priority(f["cve"])),
               "systems": sorted(f.get("systems", [])), "component": f.get("component", ""), "fix": f.get("fix", ""),
               "status": f.get("status", "Open")}
        rows.append(rk.enrich(row))
    rows.sort(key=lambda r: (0 if r["priority"] else 1,) + Ranker.order(r))
    totals = dict(raw.get("totals", {}))
    if raw.get("findings") is not None:
        totals["In CISA KEV"] = sum(c in rk.kev for c in raw_ids(raw))
    caption = raw.get("systems_caption", "Systems")
    if raw.get("systems_filter") == "critical_or_priority":
        caption = "%s (%d of %d)" % (caption, len(systems), total)
    return {"id": raw["id"], "title": raw["title"], "subtitle": raw.get("subtitle", ""), "totals": totals,
            "system_count": total, "systems_caption": caption, "system_columns": raw.get("system_columns", []), "systems": systems,
            "affected_label": raw.get("affected_label", "Systems"), "cves": rows, "warnings": raw.get("warnings", [])}


PLATFORM_TITLE = {"kubernetes": "Kubernetes", "linux": "Linux", "windows": "Windows"}


def is_priority(row):
    """Results stored before 0.4.0 list priority CVEs only and have no 'priority' field."""
    return row.get("priority", True)


def priority_rows(p):
    return [r for r in p["cves"] if is_priority(r)]


def summary(model):
    """One row per platform for the landing page: status and vulnerability counts from the current report."""
    rows = []
    for p in model["platforms"]:
        pri = priority_rows(p)
        sev = [str(r.get("severity", "")).lower() for r in pri]
        rows.append({"id": p["id"], "title": p["title"], "status": "off" if p.get("turned_off") else p.get("status", "done"),
                     "failure": p.get("failure", ""),
                     "scanned": p.get("scanned", ""), "scan_id": p.get("scan_id"), "no_results": bool(p.get("no_results")),
                     "systems": p.get("system_count", len(p["systems"])), "priority": len(pri),
                     "kev": sum(1 for r in pri if r.get("kev")), "critical": sev.count("critical"),
                     "high": sum(1 for x in sev if x in ("high", "important"))})
    return rows


def result_stats(raw, rep):
    """Values of a ResultStats row for a platform result (raw findings, ranked report section as of the scan)."""
    total, levels = raw_stats(raw or {})
    pri = [r for r in (rep or {}).get("cves", []) if is_priority(r)]
    return {"total": total, "levels": levels, "priority": len(pri), "kev": sum(1 for r in pri if r.get("kev"))}


def platform_levels(model):
    """Pie chart data: per platform with results, the count of its distinct CVEs at every severity level."""
    out = []
    for p in model["platforms"]:
        if p.get("no_results"):
            continue
        out.append({"id": p["id"], "title": p["title"], "total": len(p["cves"]),
                    "levels": level_counts(r.get("severity", "") for r in p["cves"])})
    return out


# History graph ranges: (points, step). Each point is the distinct CVE count of a platform's newest good result
# at or before the end of that day, week or month.
RANGES = {"day": ("Daily", "7 days", 7), "week": ("Weekly", "3 months", 13), "month": ("Monthly", "1 year", 12)}
DEFAULT_RANGE = "week"


def range_points(rng, today):
    """[(label, end date)] oldest first: the end of each day, week (ending today) or calendar month."""
    _, _, n = RANGES[rng]
    if rng == "day":
        return [((today - datetime.timedelta(days=i)).strftime("%b %-d"), today - datetime.timedelta(days=i))
                for i in range(n - 1, -1, -1)]
    if rng == "week":
        return [((today - datetime.timedelta(weeks=i)).strftime("%b %-d"), today - datetime.timedelta(weeks=i))
                for i in range(n - 1, -1, -1)]
    out, y, m = [], today.year, today.month
    for _ in range(n):
        nxt = datetime.date(y + (m == 12), m % 12 + 1, 1)
        out.append((datetime.date(y, m, 1).strftime("%b %Y"), min(nxt - datetime.timedelta(days=1), today)))
        y, m = (y, m - 1) if m > 1 else (y - 1, 12)
    return out[::-1]


def history(stats, rng, today, platforms):
    """stats: [(platform, local scan date, total)] of good results, oldest first.
    Returns {"labels": [...], "series": [{"id", "title", "values": [int or None]}]}: None before a platform's first scan."""
    pts = range_points(rng, today)
    by = collections.defaultdict(list)
    for plat, d, total in stats:
        by[plat].append((d, total))
    series = []
    for plat in platforms:
        rows, vals, i, cur = by.get(plat, []), [], 0, None
        for _, end in pts:
            while i < len(rows) and rows[i][0] <= end:
                cur = rows[i][1]
                i += 1
            vals.append(cur)
        if any(v is not None for v in vals):
            series.append({"id": plat, "title": PLATFORM_TITLE.get(plat, plat.title()), "values": vals})
    return {"labels": [l for l, _ in pts], "series": series, "range": rng}


def failed_platform(platform, error):
    """Section for a platform whose scan produced no results, so the report says so instead of leaving it out."""
    return {"id": platform, "title": PLATFORM_TITLE.get(platform, platform.title()), "subtitle": "", "totals": {},
            "systems_caption": "", "system_columns": [], "systems": [], "system_count": 0, "affected_label": "Systems",
            "cves": [], "warnings": [], "status": "failed", "failure": error or "The scan failed.", "no_results": True}


# ---------------------------------------------------------------- Kubernetes (Trivy Operator)

def image_name(rep):
    r = rep.get("report") or {}
    a = r.get("artifact") or {}
    server = (r.get("registry") or {}).get("server", "")
    name = a.get("repository", "?")
    if a.get("tag"):
        name += ":" + a["tag"]
    elif a.get("digest"):
        name += "@" + a["digest"][:19]
    if server and server not in ("index.docker.io", "docker.io"):
        name = server + "/" + name
    return name


def vuln_ids(reports):
    return {v.get("vulnerabilityID") for rep in reports for v in ((rep.get("report") or {}).get("vulnerabilities") or [])} - {None}


def kubernetes_raw(reports, cluster_name=""):
    findings = collections.defaultdict(dict)   # image -> {(id, package): vulnerability}
    where = collections.defaultdict(set)        # image -> namespaces
    for rep in reports:
        img = image_name(rep)
        where[img].add((rep.get("metadata") or {}).get("namespace", ""))
        for v in (rep.get("report") or {}).get("vulnerabilities") or []:
            if v.get("vulnerabilityID"):
                findings[img][(v["vulnerabilityID"], v.get("resource", ""))] = v

    systems, cves = [], {}
    for img in where:
        vs = findings.get(img, {})
        systems.append({"name": img, "namespaces": ", ".join(sorted(n for n in where[img] if n)),
                        "critical": sum(v.get("severity") == "CRITICAL" for v in vs.values()),
                        "high": sum(v.get("severity") == "HIGH" for v in vs.values()),
                        "status": "Open", "_cves": sorted({c for (c, _) in vs})})
        for (c, pkg), v in vs.items():
            row = cves.get(c)
            if row is None:
                row = cves[c] = {"cve": c, "title": v.get("title") or (v.get("description") or "")[:160],
                                 "severity": "UNKNOWN", "systems": set(), "packages": set(), "fixes": set()}
            if v.get("severity") and SEV_RANK.get(v["severity"], 5) < SEV_RANK.get(row["severity"], 5):
                row["severity"] = v["severity"]
            row["systems"].add(img)
            row["packages"].add(pkg)
            if v.get("fixedVersion"):
                row["fixes"].add(v["fixedVersion"])
    out = []
    for row in cves.values():
        pk, fx = sorted(row.pop("packages")), sorted(row.pop("fixes"))
        row["systems"] = sorted(row["systems"])
        row["component"] = ", ".join(pk[:4]) + (" …" if len(pk) > 4 else "")
        row["fix"] = ("Update the image (package fixed in " + ", ".join(fx)[:80] + ")") if fx else "No fix published"
        row["status"] = "Open"
        out.append(row)
    return {
        "id": "kubernetes",
        "title": "Kubernetes",
        "subtitle": (cluster_name + ": " if cluster_name else "") + "container images, scanned by Trivy Operator",
        "totals": {"Images scanned": len(where), "Distinct vulnerabilities": len(cves),
                   "Critical findings": sum(v.get("severity") == "CRITICAL" for vs in findings.values() for v in vs.values())},
        "systems_caption": "Images with a critical finding or a priority CVE",
        "systems_filter": "critical_or_priority",
        "system_columns": [{"key": "name", "label": "Image", "type": "mono"},
                           {"key": "namespaces", "label": "Namespace", "type": "text"},
                           {"key": "critical", "label": "Critical", "type": "num"},
                           {"key": "high", "label": "High", "type": "num"},
                           {"key": "kev", "label": "In KEV", "type": "hot"},
                           {"key": "priority", "label": "Priority CVEs", "type": "num"},
                           {"key": "status", "label": "Status", "type": "text"}],
        "systems": systems,
        "affected_label": "Images",
        "findings": out,
    }


# ---------------------------------------------------------------- extra platforms from JSON files

def load_extra(directory, warnings):
    """Extra platforms (for example hosts scanned elsewhere), one JSON file each. Already reduced to listed CVEs."""
    out = []
    for path in sorted(glob.glob(os.path.join(directory, "*.json"))):
        name = os.path.basename(path)
        try:
            with open(path) as f:
                p = json.load(f)
            for key in ("id", "title", "cves"):
                if key not in p:
                    raise ValueError(f"missing '{key}'")
            if not isinstance(p["cves"], list) or not all(isinstance(c, dict) and str(c.get("cve", "")).strip() for c in p["cves"]):
                raise ValueError("'cves' must be a list of objects with a 'cve' field")
            cols = p.get("system_columns") or []
            if not all(isinstance(c, dict) and c.get("key") for c in cols):
                raise ValueError("'system_columns' entries need a 'key'")
            out.append(p)
        except Exception as e:
            warnings.append(f"Extra platform file {name} was skipped: {e}")
    return out


def extra_raw(p):
    """An extra-platform file as a raw platform. Its system rows are shown as given."""
    findings = []
    for c in p["cves"]:
        systems = c.get("systems") or []
        findings.append({"cve": str(c["cve"]).strip(), "title": str(c.get("title", "")), "severity": str(c.get("severity", "")),
                         "systems": [str(s) for s in (systems if isinstance(systems, list) else [systems])],
                         "component": str(c.get("component", "")), "fix": str(c.get("fix", "")),
                         "status": str(c.get("status", "Open"))})
    return {"id": str(p["id"]), "title": str(p["title"]), "subtitle": str(p.get("subtitle", "")),
            "totals": {str(k): v for k, v in (p.get("totals") or {}).items()},
            "systems_caption": str(p.get("systems_caption", "Systems")),
            "system_columns": p.get("system_columns") or [], "systems": p.get("systems") or [],
            "affected_label": str(p.get("affected_label", "Systems")), "findings": findings, "extra": True}


# ---------------------------------------------------------------- whole report

def model(cfg, sections, sources, warnings, generated=None, label=""):
    """sections: ranked platform sections, each with 'scanned' (display string) set by the caller."""
    now = generated or datetime.datetime.now(datetime.timezone.utc)
    try:
        import zoneinfo
        now = now.astimezone(zoneinfo.ZoneInfo(cfg.timezone))
    except Exception:
        pass
    return {
        "title": cfg.title,
        "cluster_name": cfg.cluster_name,
        "label": label,
        "generated": now.strftime("%Y-%m-%d %H:%M %Z"),
        "date": now.strftime("%Y-%m-%d"),
        "epss_min": cfg.epss_min,
        "kev_on": getattr(cfg, "kev_enabled", True),
        "epss_on": getattr(cfg, "epss_enabled", True),
        "sources": sources,
        "warnings": warnings,
        "platforms": sections,
    }
