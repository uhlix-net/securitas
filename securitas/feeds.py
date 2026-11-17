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


def epss(cfg, wanted, warnings):
    """EPSS scores for the CVE IDs in `wanted`: {cve: score}, plus a description of the source."""
    path, fresh = _fetch(cfg.epss_url, os.path.join(cfg.data_dir, "epss.csv.gz"), cfg.epss_max_age)
    if not path:
        warnings.append("EPSS scores could not be downloaded, so CVEs are ranked by CISA KEV only.")
        return {}, "EPSS scores unavailable"
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
            if c in wanted:
                scores[c] = float(row.get("epss") or 0)
    except Exception as e:
        warnings.append(f"EPSS scores could not be read ({e}).")
        return {}, "EPSS scores unreadable"
    if not fresh:
        warnings.append("EPSS scores could not be refreshed; the last downloaded copy is used.")
    return scores, f"EPSS scores of {score_date}"
