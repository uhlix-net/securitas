"""Windows scanner: read the OS build over WinRM and compare it with the fixed build of each CVE in
Microsoft's monthly security release data (MSRC CVRF).

Read-only: one PowerShell script reads the OS caption, build and update revision (UBR), installation type,
newest hotfix and installed programs. The account needs WinRM access only (Remote Management Users), not admin.
Third-party software is listed in the raw result but not checked against vendor advisories.
"""
import concurrent.futures
import datetime
import json
import re

from . import feeds
from .report import worse

PS_SCRIPT = r"""
$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$os = Get-CimInstance Win32_OperatingSystem
$hf = Get-CimInstance Win32_QuickFixEngineering | ForEach-Object {
  [datetime]$d = 0; if ([datetime]::TryParse([string]$_.InstalledOn, [ref]$d)) { [pscustomobject]@{id = $_.HotFixID; on = $d} }
} | Sort-Object on -Descending | Select-Object -First 1
$sw = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName } | ForEach-Object { '{0} | {1}' -f $_.DisplayName, $_.DisplayVersion } | Sort-Object -Unique
[ordered]@{
  os = $os.Caption; build = ('{0}.{1}' -f $os.BuildNumber, $cv.UBR); installation = $cv.InstallationType
  display_version = $cv.DisplayVersion; arch = $os.OSArchitecture
  patched = $(if ($hf) { $hf.on.ToString('yyyy-MM-dd') } else { '' }); hotfix = $(if ($hf) { $hf.id } else { '' })
  software = @($sw)
} | ConvertTo-Json -Depth 3 -Compress
"""

EDITIONS = r"(Standard|Datacenter|Essentials|Enterprise|Pro|Professional|Education|Home|Evaluation|Foundation|Azure Edition|IoT|LTSC|N)"


def product_name(info):
    """MSRC product name for the scanned OS, e.g. 'Windows Server 2019 (Server Core installation)'."""
    cap = re.sub(r"^Microsoft\s+", "", (info.get("os") or "").strip())
    core = (info.get("installation") or "").lower() == "server core"
    m = re.match(r"(Windows Server \d{4}(?: R2)?)", cap)
    if m:
        return m.group(1) + (" (Server Core installation)" if core else "")
    m = re.match(r"(Windows 1[01])\b", cap)
    if m:
        arch = (info.get("arch") or "").lower()
        a = "ARM64-based Systems" if "arm" in arch else "x64-based Systems" if "64" in arch else "32-bit Systems"
        return "%s Version %s for %s" % (m.group(1), info.get("display_version") or "", a)
    return ""


def parse_build(s):
    """'10.0.17763.6893' or '17763.6893' -> (17763, 6893)"""
    try:
        p = [int(x) for x in s.split(".")]
    except (AttributeError, ValueError):
        return None
    return (p[2], p[3]) if len(p) == 4 else (p[0], p[1]) if len(p) == 2 else None


def missing(info, months):
    """CVEs whose fixed build for this OS is newer than the installed one: {cve: (severity, month, title)}."""
    name = product_name(info)
    pids = {pid for _, d in months for pid, v in d["products"].items() if v == name}
    if not pids:
        raise RuntimeError("no Microsoft product data for '%s' (from '%s')" % (name or "?", info.get("os")))
    inst = parse_build(info["build"])
    out = {}
    for month, d in months:
        y, mo = feeds.month_key(month)
        for cve, v in d["vulns"].items():
            fixed = None
            for pid in pids & v["fixes"].keys():
                for fb in v["fixes"][pid]:
                    b = parse_build(fb)
                    if b and b[0] == inst[0] and (fixed is None or b < fixed):
                        fixed = b
            if fixed and fixed > inst and cve not in out:
                sev = next((v["severity"][p] for p in pids if v["severity"].get(p)), "")
                out[cve] = (sev, "%d-%02d" % (y, mo), v["title"])
    return out, name


def run_host(cfg, host):
    from pypsrp.client import Client
    c = Client(host, username=cfg.winrm_user, password=cfg.winrm_password, ssl=cfg.winrm_ssl, port=cfg.winrm_port,
               auth=cfg.winrm_auth, cert_validation=(cfg.ca_file or True) if cfg.winrm_ssl else False,
               connection_timeout=20, operation_timeout=cfg.host_timeout, read_timeout=cfg.host_timeout + 30)
    out, streams, had_errors = c.execute_ps(PS_SCRIPT)
    if had_errors:
        errs = "; ".join(str(e) for e in streams.error)[:300]
        raise RuntimeError("PowerShell error: " + errs)
    return json.loads(out)


def scan(cfg, targets, log, warnings_out=None):
    if not cfg.winrm_user or not cfg.winrm_password:
        raise RuntimeError("Windows scans need a WinRM account (SECURITAS_WINRM_USER, SECURITAS_WINRM_PASSWORD)")
    infos, warnings = {}, []
    with concurrent.futures.ThreadPoolExecutor(max_workers=cfg.host_concurrency) as ex:
        futs = {ex.submit(run_host, cfg, t["host"]): t for t in targets}
        for fut in concurrent.futures.as_completed(futs):
            t = futs[fut]
            try:
                infos[t["host"]] = fut.result()
                i = infos[t["host"]]
                log("windows: %s: %s build %s, newest hotfix %s %s" % (t["host"], i["os"], i["build"], i["hotfix"], i["patched"]))
            except Exception as e:
                msg = str(e) or type(e).__name__
                infos[t["host"]] = {"error": msg}
                warnings.append("Windows host %s could not be scanned: %s" % (t["host"], msg))
                log("windows: %s: FAILED %s" % (t["host"], msg))
    ok = {h: i for h, i in infos.items() if "error" not in i}
    months = []
    if ok:
        dates = [i["patched"] for i in ok.values() if i.get("patched")]
        start = min(dates) if dates else (datetime.date.today() - datetime.timedelta(days=730)).isoformat()
        y, m = int(start[:4]), int(start[5:7])
        y, m = (y, m - 1) if m > 1 else (y - 1, 12)     # one month earlier: patches can be installed late
        months = feeds.msrc_months(cfg, (y, m), warnings, log)
        log("windows: Microsoft data for %d months from %d-%02d" % (len(months), y, m))
    systems, findings, all_ids = [], {}, set()
    for t in targets:
        i = infos[t["host"]]
        if "error" in i:
            systems.append({"name": t["host"], "role": t["label"], "os": "", "build": "", "patched": "", "cves": "",
                            "critical": "", "status": "Scan failed", "_cves": []})
            continue
        try:
            miss, name = missing(i, months)
        except Exception as e:
            warnings.append("Windows host %s: %s" % (t["host"], e))
            systems.append({"name": t["host"], "role": t["label"], "os": i["os"], "build": i["build"], "patched": i["patched"],
                            "cves": "", "critical": "", "status": "Not compared", "_cves": []})
            continue
        all_ids |= set(miss)
        systems.append({"name": t["host"], "role": t["label"], "os": name, "build": i["build"], "patched": i["patched"],
                        "cves": len(miss), "critical": sum(v[0] == "Critical" for v in miss.values()),
                        "status": "Up to date" if not miss else "Open", "_cves": sorted(miss),
                        "_software": i.get("software", [])})
        for c, (sev, month, title) in miss.items():
            f = findings.setdefault(c, {"cve": c, "title": title, "severity": sev, "systems": set(), "month": month})
            f["severity"] = worse(sev, f["severity"]) if f["severity"] else sev
            f["systems"].add(t["host"])
            f["month"] = min(f["month"], month)
    rows = []
    for f in findings.values():
        f["systems"] = sorted(f["systems"])
        f.update(component="Windows", fix="Cumulative update %s or later" % f.pop("month"), status="Open")
        rows.append(f)
    for s in systems:
        s.pop("_software", None)   # inventory is not shown; kept out of the stored result to save space
    good = [s for s in systems if s["status"] not in ("Scan failed", "Not compared")]
    return {
        "id": "windows", "title": "Windows",
        "subtitle": "Servers: installed OS build compared with the fixed build of each CVE in Microsoft security release data. "
                    "Third-party software is not checked",
        "totals": {"Servers scanned": len(good), "Distinct CVEs": len(all_ids),
                   "Critical (worst server)": max([s["critical"] for s in good] or [0])},
        "systems_caption": "Servers",
        "system_columns": [{"key": "name", "label": "Server", "type": "mono"}, {"key": "role", "label": "Role", "type": "text"},
                           {"key": "os", "label": "OS", "type": "text"}, {"key": "build", "label": "Build", "type": "mono"},
                           {"key": "patched", "label": "Newest hotfix", "type": "date"},
                           {"key": "cves", "label": "Missing CVE fixes", "type": "num"},
                           {"key": "critical", "label": "Critical", "type": "num"}, {"key": "kev", "label": "In KEV", "type": "hot"},
                           {"key": "priority", "label": "Priority CVEs", "type": "num"},
                           {"key": "status", "label": "Status", "type": "text"}],
        "systems": systems, "affected_label": "Servers", "findings": rows, "warnings": warnings,
        "failed": len(systems) - len(good),
    }
