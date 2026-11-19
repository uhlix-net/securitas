"""CISA KEV and EPSS feeds.

Each download is cached in the data directory. If a download fails, the last good copy is used
and the report says the data is stale. If there is no copy at all, the report is built without
that feed and says so.
"""
import csv
import gzip
import io
import json
import logging
import os
import time
import urllib.request

from . import __version__

log = logging.getLogger(__name__)
UA = f"securitas/{__version__} (+https://github.com/uhlix-net/securitas)"


def _fetch(url, path, max_age):
    """Return (path or None, fresh: bool)."""
    if os.path.exists(path) and time.time() - os.path.getmtime(path) < max_age:
        return path, True
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=120) as r:
            data = r.read()
        if not data:
            raise ValueError("empty response")
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
        return path, True
    except Exception as e:  # network, HTTP or disk error: fall back to the cached copy
        log.warning("download failed for %s: %s", url, e)
        return (path if os.path.exists(path) else None), False


def kev(cfg, warnings):
    """Known Exploited Vulnerabilities: {cveID: entry}, plus a description of the source."""
    path, fresh = _fetch(cfg.kev_url, os.path.join(cfg.data_dir, "kev.json"), cfg.kev_max_age)
    if not path:
        warnings.append("The CISA KEV catalog could not be downloaded, so known-exploited CVEs are not marked.")
        return {}, "CISA KEV catalog unavailable"
    try:
        doc = json.load(open(path))
        entries = {v["cveID"]: v for v in doc.get("vulnerabilities", []) if v.get("cveID")}
    except Exception as e:
        warnings.append(f"The CISA KEV catalog could not be read ({e}).")
        return {}, "CISA KEV catalog unreadable"
    if not fresh:
        warnings.append("The CISA KEV catalog could not be refreshed; the last downloaded copy is used.")
    return entries, "CISA KEV catalog %s (%d entries)" % (doc.get("catalogVersion", "?"), len(entries))


_epss_cache = {"key": None, "scores": {}, "date": "?"}


def epss(cfg, wanted, warnings):
    """EPSS scores: {cve: score} (all CVEs when `wanted` is None), plus a description of the source.
    The parsed file is kept in memory until a newer copy is downloaded."""
    path, fresh = _fetch(cfg.epss_url, os.path.join(cfg.data_dir, "epss.csv.gz"), cfg.epss_max_age)
    if not path:
        warnings.append("EPSS scores could not be downloaded, so CVEs are ranked by CISA KEV only.")
        return {}, "EPSS scores unavailable"
    key = (path, os.path.getmtime(path))
    if _epss_cache["key"] != key:
        scores, score_date = {}, "?"
        try:
            raw = open(path, "rb").read()
            text = gzip.decompress(raw).decode() if raw[:2] == b"\x1f\x8b" else raw.decode()
            lines = io.StringIO(text)
            first = lines.readline()
            if first.startswith("#"):
                for part in first[1:].strip().split(","):
                    k, _, v = part.partition(":")
                    if k == "score_date":
                        score_date = v[:10]
            else:
                lines.seek(0)
            for row in csv.DictReader(lines):
                c = row.get("cve")
                if c:
                    scores[c] = float(row.get("epss") or 0)
        except Exception as e:
            warnings.append(f"EPSS scores could not be read ({e}).")
            return {}, "EPSS scores unreadable"
        _epss_cache.update(key=key, scores=scores, date=score_date)
    if not fresh:
        warnings.append("EPSS scores could not be refreshed; the last downloaded copy is used.")
    allscores = _epss_cache["scores"]
    scores = allscores if wanted is None else {c: allscores[c] for c in wanted if c in allscores}
    return scores, "EPSS scores of %s" % _epss_cache["date"]


# ---------------------------------------------------------------- Microsoft security release data (MSRC CVRF)

MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()


def month_key(doc_id):
    """'2026-Nov' -> (2026, 11); None for ids that are not monthly releases."""
    p = doc_id.split("-")
    if len(p) == 2 and p[0].isdigit() and p[1] in MONTHS:
        return int(p[0]), MONTHS.index(p[1]) + 1
    return None


def _get_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=180) as r:
        return json.load(r)


def _reduce_cvrf(doc):
    """Keep only what the Windows comparison needs: product names, and per CVE the title,
    fixed builds per product and severity per product."""
    products = {}
    for p in ((doc.get("ProductTree") or {}).get("FullProductName") or []):
        if p.get("ProductID"):
            products[p["ProductID"]] = p.get("Value", "")
    vulns = {}
    for v in doc.get("Vulnerability") or []:
        cve = v.get("CVE")
        if not cve:
            continue
        fixes = {}
        for r in v.get("Remediations") or []:
            fb = r.get("FixedBuild")
            if not fb:
                continue
            for pid in r.get("ProductID") or []:
                fixes.setdefault(pid, []).append(fb)
        if not fixes:
            continue
        sev = {}
        for t in v.get("Threats") or []:
            if t.get("Type") == 3:
                for pid in t.get("ProductID") or []:
                    sev[pid] = (t.get("Description") or {}).get("Value", "")
        vulns[cve] = {"title": (v.get("Title") or {}).get("Value", ""), "fixes": fixes, "severity": sev}
    return {"products": products, "vulns": vulns}


def msrc_months(cfg, since, warnings, log_fn=None):
    """Reduced monthly MSRC releases from month `since` ((year, month)) to now: [(id, reduced doc)].
    Each month is cached in the data directory; the newest two months are re-read daily, older ones weekly."""
    d = os.path.join(cfg.data_dir, "msrc")
    os.makedirs(d, exist_ok=True)
    base = cfg.msrc_url.rstrip("/")
    try:
        index = _get_json(base + "/updates")
        ids = sorted({u["ID"] for u in index.get("value", []) if month_key(u.get("ID", "")) and month_key(u["ID"]) >= since},
                     key=month_key)
    except Exception as e:
        log.warning("MSRC index download failed: %s", e)
        ids = sorted({f[:-5] for f in os.listdir(d) if f.endswith(".json") and month_key(f[:-5]) and month_key(f[:-5]) >= since},
                     key=month_key)
        warnings.append("Microsoft security release data could not be downloaded; cached months are used.")
    out = []
    recent = set(ids[-2:])
    for i in ids:
        path = os.path.join(d, i + ".json")
        max_age = 86400 if i in recent else 7 * 86400
        if not (os.path.exists(path) and time.time() - os.path.getmtime(path) < max_age):
            try:
                if log_fn:
                    log_fn("MSRC: downloading %s" % i)
                red = _reduce_cvrf(_get_json(base + "/cvrf/" + i))
                tmp = path + ".tmp"
                with open(tmp, "w") as f:
                    json.dump(red, f)
                os.replace(tmp, path)
            except Exception as e:
                log.warning("MSRC %s download failed: %s", i, e)
                if not os.path.exists(path):
                    warnings.append("Microsoft security release data for %s could not be downloaded." % i)
                    continue
        try:
            out.append((i, json.load(open(path))))
        except Exception as e:
            warnings.append("Microsoft security release data for %s could not be read (%s)." % (i, e))
    return out
