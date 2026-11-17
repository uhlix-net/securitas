"""Build the report model from Trivy VulnerabilityReports, the CISA KEV catalog and EPSS scores.

A CVE is a *priority* when it is in the CISA KEV catalog or its EPSS score is at least `epss_min`.
Priority CVEs are listed known-exploited first, then by EPSS score.
"""
import collections
import datetime
import glob
import json
import os

SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "IMPORTANT": 1, "MEDIUM": 2, "MODERATE": 2, "LOW": 3, "UNKNOWN": 4}


def sev_title(s):
    return (s or "Unknown").strip().title() or "Unknown"


class Ranker:
    def __init__(self, kev, epss, epss_min):
        self.kev, self.epss, self.epss_min = kev, epss, epss_min

    def priority(self, cve):
        return cve in self.kev or self.epss.get(cve, 0.0) >= self.epss_min

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


def kubernetes_platform(reports, rk, cluster_name=""):
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
        crit = sum(v.get("severity") == "CRITICAL" for v in vs.values())
        high = sum(v.get("severity") == "HIGH" for v in vs.values())
        prio = {c for (c, _) in vs if rk.priority(c)}
        if crit or prio:
            systems.append({"name": img, "namespaces": ", ".join(sorted(n for n in where[img] if n)),
                            "critical": crit, "high": high, "kev": sum(c in rk.kev for c in prio),
                            "priority": len(prio), "status": "Open"})
        for (c, pkg), v in vs.items():
            if not rk.priority(c):
                continue
            row = cves.get(c)
            if row is None:
                row = cves[c] = {"cve": c, "title": v.get("title") or (v.get("description") or "")[:160],
                                 "severity": "UNKNOWN", "systems": set(), "packages": set(), "fixes": set()}
            if SEV_RANK.get(v.get("severity", "UNKNOWN"), 5) < SEV_RANK.get(row["severity"], 5):
                row["severity"] = v["severity"]
            row["systems"].add(img)
            row["packages"].add(pkg)
            if v.get("fixedVersion"):
                row["fixes"].add(v["fixedVersion"])
    systems.sort(key=lambda s: (-s["kev"], -s["critical"], -s["high"], s["name"]))

    rows = []
    for row in cves.values():
        pk, fx = sorted(row.pop("packages")), sorted(row.pop("fixes"))
        row["systems"] = sorted(row["systems"])
        row["severity"] = sev_title(row["severity"])
        row["component"] = ", ".join(pk[:4]) + (" …" if len(pk) > 4 else "")
        row["fix"] = ("Update the image (package fixed in " + ", ".join(fx)[:80] + ")") if fx else "No fix published"
        row["status"] = "Open"
        rows.append(rk.enrich(row))
    rows.sort(key=Ranker.order)

    all_ids = {c for vs in findings.values() for (c, _) in vs}
    return {
        "id": "kubernetes",
        "title": "Kubernetes",
        "subtitle": (cluster_name + ": " if cluster_name else "") + "container images, scanned by Trivy Operator",
        "totals": {"Images scanned": len(where), "Distinct vulnerabilities": len(all_ids),
                   "Critical findings": sum(v.get("severity") == "CRITICAL" for vs in findings.values() for v in vs.values()),
                   "In CISA KEV": sum(c in rk.kev for c in all_ids)},
        "systems_caption": "Images with a critical finding or a priority CVE (%d of %d)" % (len(systems), len(where)),
        "system_columns": [{"key": "name", "label": "Image", "type": "mono"},
                           {"key": "namespaces", "label": "Namespace", "type": "text"},
                           {"key": "critical", "label": "Critical", "type": "num"},
                           {"key": "high", "label": "High", "type": "num"},
                           {"key": "kev", "label": "In KEV", "type": "hot"},
                           {"key": "priority", "label": "Priority CVEs", "type": "num"},
                           {"key": "status", "label": "Status", "type": "text"}],
        "systems": systems,
        "affected_label": "Images",
        "cves": rows,
    }


def load_extra(directory, warnings):
    """Extra platforms (for example Linux or Windows hosts scanned elsewhere), one JSON file each."""
    out = []
    for path in sorted(glob.glob(os.path.join(directory, "*.json"))):
        name = os.path.basename(path)
        try:
            p = json.load(open(path))
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


def extra_platform(p, rk):
    rows = []
    for c in p["cves"]:
        cid = str(c["cve"]).strip()
        if not rk.priority(cid):
            continue
        systems = c.get("systems") or []
        rows.append(rk.enrich({"cve": cid, "title": str(c.get("title", "")), "severity": sev_title(str(c.get("severity", ""))),
                               "systems": [str(s) for s in (systems if isinstance(systems, list) else [systems])],
                               "component": str(c.get("component", "")), "fix": str(c.get("fix", "")),
                               "status": str(c.get("status", "Open"))}))
    rows.sort(key=Ranker.order)
    return {"id": str(p["id"]), "title": str(p["title"]), "subtitle": str(p.get("subtitle", "")),
            "totals": {str(k): v for k, v in (p.get("totals") or {}).items()},
            "systems_caption": str(p.get("systems_caption", "Systems")),
            "system_columns": p.get("system_columns") or [], "systems": p.get("systems") or [],
            "affected_label": str(p.get("affected_label", "Systems")), "cves": rows}


def build(cfg, reports, kev, kev_src, epss, epss_src, extras, warnings):
    rk = Ranker(kev, epss, cfg.epss_min)
    now = datetime.datetime.now(datetime.timezone.utc)
    platforms = [kubernetes_platform(reports, rk, cfg.cluster_name)] + [extra_platform(p, rk) for p in extras]
    return {
        "title": cfg.title,
        "cluster_name": cfg.cluster_name,
        "generated": now.strftime("%Y-%m-%d %H:%M UTC"),
        "date": now.strftime("%Y-%m-%d"),
        "epss_min": cfg.epss_min,
        "refresh_seconds": cfg.refresh_seconds,
        "sources": {"kev": kev_src, "epss": epss_src},
        "warnings": warnings,
        "platforms": platforms,
    }
