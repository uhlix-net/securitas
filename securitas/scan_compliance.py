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
STATUSES = ("fail", "pass", "skip", "notest")
STATUS_LABEL = {"pass": "Passed", "fail": "Failed", "skip": "Not applicable", "notest": "No automated check (manual review)"}


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
    scored = n["pass"] + n["fail"]
    n["checked"] = len(rules)
    n["score"] = round(100.0 * n["pass"] / scored, 1) if scored else None
    return out, n


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
