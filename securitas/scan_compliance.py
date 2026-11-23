"""Compliance checks: Linux hosts against the active CIS benchmark for their OS, with Goss.

On each host, Ansible (uhlix-net/ansible Linux_Securitas_CIS_Audit.yml, or your own equivalent) installs:
  - the Goss binary at /usr/local/bin/goss,
  - the benchmark's Ansible-Lockdown audit content, root-owned, at /opt/securitas-cis/<benchmark key>/,
  - the wrapper /usr/local/sbin/securitas-cis-audit, and one sudo rule that lets the scan account run only it.
The scan account therefore cannot change what runs as root. Securitas signs in over SSH (the same account and key
as the vulnerability scans) and runs `sudo -n /usr/local/sbin/securitas-cis-audit <key> <server|workstation>`,
which runs `goss validate` read-only and prints JSON. Every test carries the CIS rule ID in meta.CIS_ID; a rule
passes when all of its tests pass. Only the rules the benchmark checks (its profile and the choices made in
Compliance > Benchmarks) are counted.
"""
import collections
import concurrent.futures
import json
import re
import shlex

from . import scan_linux

WRAPPER = "/usr/local/sbin/securitas-cis-audit"
STATUSES = ("fail", "accepted", "pass", "skip", "notest")
STATUS_LABEL = {"pass": "Passed", "fail": "Failed", "accepted": "Accepted (exception)", "skip": "Not applicable",
                "notest": "No automated check (manual review)"}
SCOPE_LABEL = {"baseline": "BASELINE EXCEPTION", "server": "SERVER EXCEPTION"}


def remote_command(key, system_type="server"):
    if not re.fullmatch(r"[A-Za-z0-9.-]+", key or ""):
        raise ValueError("bad benchmark key %r" % key)
    return "sudo -n %s %s %s" % (WRAPPER, shlex.quote(key), "workstation" if system_type == "workstation" else "server")


def _ids(v):
    """meta.CIS_ID is a list (["1.1.1.1"]) in most tests and a string ("1.1.1.1" or "1.1, 1.2") in some."""
    vals = v if isinstance(v, list) else [v]
    return [x for item in vals for x in re.split(r"[\s,]+", str(item if item is not None else "").strip())
            if re.fullmatch(r"\d+(?:\.\d+)+", x)]


def _manual(title):
    """The audit content marks rules it cannot check automatically with a placeholder test."""
    return "manual check required" in (title or "").lower()


def parse_goss(text):
    """Goss JSON output -> ({rule_id: [test, ...]}, summary). Raises RuntimeError with the reason otherwise."""
    start = text.find("{")
    if start < 0:
        tail = text.strip()[-400:]
        if "a password is required" in tail or "not allowed to run sudo" in tail or "may not run sudo" in tail:
            raise RuntimeError("sudo refused: the host has no sudo rule for %s (install it with the Ansible playbook)" % WRAPPER)
        if "command not found" in tail or "No such file" in tail:
            raise RuntimeError("%s is not installed on the host (install it with the Ansible playbook)" % WRAPPER)
        raise RuntimeError("no Goss output: " + (tail or "(empty)"))
    try:
        data = json.loads(text[start:])
    except ValueError as e:
        raise RuntimeError("Goss output is not valid JSON (%s): %s" % (e, text[start:start + 200]))
    if "results" not in data:
        raise RuntimeError(str(data.get("error") or "Goss returned no results"))
    by = collections.defaultdict(list)
    for r in data.get("results") or []:
        for rid in _ids((r.get("meta") or {}).get("CIS_ID")):
            res = "manual" if _manual(r.get("title")) else "skip" if r.get("skipped") else "pass" if r.get("successful") else "fail"
            by[rid].append({"title": str(r.get("title") or "")[:300], "result": res,
                            "message": str(r.get("summary-line") or "")[:600], "err": str(r.get("err") or "")[:300]})
    return dict(by), data.get("summary") or {}


def evaluate(rules, by):
    """rules: [{id, title, kind}] that the benchmark checks. Returns (rule results, counts)."""
    out, n = [], dict.fromkeys(STATUSES, 0)
    for r in rules:
        tests = by.get(r["id"], [])
        real = [t for t in tests if t["result"] != "manual"]     # manual placeholders say nothing about the host
        if not real:
            st = "notest"
        elif any(t["result"] == "fail" for t in real):
            st = "fail"
        elif all(t["result"] == "skip" for t in real):
            st = "skip"
        else:
            st = "pass"
        n[st] += 1
        out.append({**r, "status": st, "tests": tests})
    n["checked"] = len(rules)
    rescore(n)
    return out, n


def rescore(n):
    """Score = rules met / rules that could be met: an accepted failure counts as met."""
    met = n.get("pass", 0) + n.get("accepted", 0)
    scored = met + n.get("fail", 0)
    n["score"] = round(100.0 * met / scored, 1) if scored else None


def bench_name(key):
    """'RHEL9-CIS-2.4.2' -> 'RHEL9-CIS': exceptions are kept per benchmark name, not per version."""
    return key.rsplit("-", 1)[0] if "-" in (key or "") else (key or "")


def apply_exceptions(rules, counts, host, exceptions):
    """Mark failed rules that have an exception as Accepted. exceptions: {(rule_id, host or ''): {scope, reason,
    by, at}}; a server exception for this host wins over the baseline one. Changes rules and counts in place."""
    for r in rules:
        if r.get("status") != "fail":
            continue
        x = exceptions.get((r.get("id"), host)) or exceptions.get((r.get("id"), ""))
        if x:
            r["status"], r["exception"] = "accepted", dict(x)
            counts["fail"] = counts.get("fail", 0) - 1
            counts["accepted"] = counts.get("accepted", 0) + 1
    counts.setdefault("accepted", 0)
    rescore(counts)


def run_host(cfg, target, record_key):
    """target: {id, host, host_key, key, system_type, rules}. Returns {"os", "rules", "counts", "goss"}."""
    client = scan_linux.connect(cfg, target, record_key)
    try:
        timeout = max(cfg.host_timeout, 1200)
        _, out, err = client.exec_command("bash -c %s" % shlex.quote(
            'echo "##OS $(. /etc/os-release; echo "$NAME $VERSION_ID")"; ' + remote_command(target["key"], target.get("system_type"))
            + " 2>&1"), timeout=timeout)
        text = out.read().decode(errors="replace")
    finally:
        client.close()
    m = re.match(r"##OS (.*)\n", text)
    os_name = m.group(1).strip() if m else ""
    by, summary = parse_goss(text[m.end():] if m else text)
    rules, counts = evaluate(target["rules"], by)
    return {"os": os_name, "rules": rules, "counts": counts,
            "goss": {k: summary.get(k) for k in ("test-count", "failed-count", "skipped-count", "total-duration")}}


def scan(cfg, targets, log, record_key):
    """targets as for run_host. Returns {host: result or Exception}."""
    if not cfg.ssh_user or not (cfg.ssh_key or cfg.ssh_key_file):
        raise RuntimeError("Linux compliance scans need an SSH user and key (Settings > Scan credentials)")
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, cfg.host_concurrency)) as ex:
        futs = {ex.submit(run_host, cfg, t, record_key): t for t in targets}
        for fut in concurrent.futures.as_completed(futs):
            t = futs[fut]
            try:
                results[t["host"]] = fut.result()
                c = results[t["host"]]["counts"]
                log("linux: %s: %s, %d passed, %d failed, %d not applicable, %d without a check, score %s"
                    % (t["host"], t["key"], c["pass"], c["fail"], c["skip"], c["notest"],
                       "%s%%" % c["score"] if c["score"] is not None else "-"))
            except Exception as e:
                results[t["host"]] = e
                log("linux: %s: failed: %s" % (t["host"], e))
    return results


# ------------------------------------------------------------------ Windows

# On each Windows host Ansible (uhlix-net/ansible Windows_Securitas_CIS_Audit.yml) installs, writable by
# Administrators and SYSTEM only:
#   - syver (the Goss fork with Windows support that the Ansible-Lockdown Windows audits are written for),
#     checksum- and signature-checked, at C:\Program Files\Securitas\CIS\syver\syver.exe
#   - the audit content per benchmark at C:\Program Files\Securitas\CIS\<benchmark key>\
#   - the wrapper C:\Program Files\Securitas\CIS\securitas-cis-audit.ps1, which runs the content's run_audit.ps1
#     and writes C:\ProgramData\Securitas\CIS\<benchmark key>.json
#   - a scheduled task \Securitas\CIS Audit <benchmark key> that runs the wrapper as SYSTEM with that fixed key.
#     The scan account may only start the task (read + execute on the task) and read the output folder.
# That is the Windows counterpart of the Linux sudo rule: the scan account cannot change what runs as SYSTEM.
WIN_TASK_FOLDER = "\\Securitas"
WIN_OUT_DIR = "C:\\ProgramData\\Securitas\\CIS"
WIN_ROLES = {0: "standalone workstation", 1: "member workstation", 2: "standalone server", 3: "member server",
             4: "backup domain controller", 5: "primary domain controller"}

WIN_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$key = '%(key)s'
$name = 'CIS Audit ' + $key
$out = Join-Path '%(out)s' ($key + '.json')
'##ROLE ' + (Get-CimInstance Win32_ComputerSystem).DomainRole
'##OS ' + (Get-CimInstance Win32_OperatingSystem).Caption
# The Task Scheduler COM API checks the task's own permissions. (Get-ScheduledTask goes through the
# root\Microsoft\Windows\TaskScheduler WMI namespace, which a non-admin scan account cannot read.)
$svc = New-Object -ComObject Schedule.Service
$svc.Connect()
try { $task = $svc.GetFolder('%(folder)s').GetTask($name) } catch { '##ERROR the scheduled task %(folder)s\' + $name + ' is not installed, or this account may not see it (install it with the Ansible playbook)'; return }
$t0 = Get-Date
try { $null = $task.Run($null) } catch { '##ERROR this account may not start the scheduled task: ' + $_.Exception.Message; return }
$deadline = $t0.AddSeconds(%(timeout)d)
do {
  Start-Sleep -Seconds 5
  $task = $svc.GetFolder('%(folder)s').GetTask($name)
  $ran = $task.LastRunTime -ge $t0.AddSeconds(-5)
} until ((($task.State -ne 4) -and $ran) -or ((Get-Date) -gt $deadline))
if ($task.State -eq 4) { '##ERROR the audit was still running after %(timeout)d seconds'; return }
'##RESULT ' + $task.LastTaskResult
$f = Get-Item -LiteralPath $out -ErrorAction SilentlyContinue
if (-not $f -or $f.LastWriteTime -lt $t0.AddSeconds(-5)) { '##ERROR the audit wrote no new result (task result ' + $task.LastTaskResult + '); see ' + $key + '.log in %(out)s'; return }
'##JSON'
[System.IO.File]::ReadAllText($out)
"""


def windows_script(key, timeout=3000):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", key or ""):
        raise ValueError("bad benchmark key %r" % key)
    return WIN_SCRIPT % {"key": key, "out": WIN_OUT_DIR, "folder": WIN_TASK_FOLDER, "timeout": int(timeout)}


def parse_windows(text):
    """The script's output -> (domain role number, OS name, Goss JSON text). Raises RuntimeError on ##ERROR."""
    tag = lambda name: (m.group(1).strip() if (m := re.search(r"^##%s (.*)$" % name, text, re.M)) else "")
    if tag("ERROR"):
        raise RuntimeError(tag("ERROR"))
    role = int(tag("ROLE")) if tag("ROLE").isdigit() else -1
    if "##JSON" not in text:
        raise RuntimeError("the audit returned nothing: " + text.strip()[-300:])
    return role, tag("OS"), text.split("##JSON", 1)[1]


def host_kind(role):
    return "domaincontroller" if role >= 4 else "memberserver"


def run_windows_host(cfg, target):
    """target: {host, key, rules_by_kind}. Returns {"os", "rules", "counts", "host_kind", "role"}."""
    from . import scan_windows
    timeout = max(cfg.host_timeout, 3000)
    c = scan_windows.client(cfg, target["host"])
    c.wsman.operation_timeout = 60          # poll; the script itself waits for the task
    out, streams, had_errors = c.execute_ps(windows_script(target["key"], timeout - 60))
    if had_errors and "##JSON" not in out:
        raise RuntimeError("PowerShell error: " + "; ".join(str(e) for e in streams.error)[:300])
    role, os_name, payload = parse_windows(out)
    kind = host_kind(role)
    by, summary = parse_goss(payload)
    rules, counts = evaluate((target.get("rules_by_kind") or {}).get(kind) or target["rules"], by)
    return {"os": os_name, "rules": rules, "counts": counts, "host_kind": kind, "role": WIN_ROLES.get(role, str(role)),
            "goss": {k: summary.get(k) for k in ("test-count", "failed-count", "skipped-count", "total-duration")}}


def scan_windows(cfg, targets, log):
    if not cfg.winrm_user or not cfg.winrm_password:
        raise RuntimeError("Windows compliance scans need a WinRM account (Settings > Scan credentials)")
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, cfg.host_concurrency)) as ex:
        futs = {ex.submit(run_windows_host, cfg, t): t for t in targets}
        for fut in concurrent.futures.as_completed(futs):
            t = futs[fut]
            try:
                results[t["host"]] = r = fut.result()
                c = r["counts"]
                log("windows: %s: %s as %s, %d passed, %d failed, %d not applicable, %d without a check, score %s"
                    % (t["host"], t["key"], r["role"], c["pass"], c["fail"], c["skip"], c["notest"],
                       "%s%%" % c["score"] if c["score"] is not None else "-"))
            except Exception as e:
                results[t["host"]] = e
                log("windows: %s: failed: %s" % (t["host"], e))
    return results
