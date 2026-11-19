"""Linux scanner: SSH to each host and list pending security advisories with `dnf updateinfo`.

Read-only: nothing is installed or changed on the host and no root access is needed. Works on RHEL-family
systems with dnf (Rocky, Alma, RHEL, Oracle, Fedora). With `linux_repos` set, the host's own repositories are
ignored and the given ones are used instead (useful when hosts point at a mirror that lags behind upstream).
"""
import collections
import concurrent.futures
import re
import shlex

from .report import worse

SEV_WORDS = ("Critical", "Important", "Moderate", "Low", "Unknown", "None")


def remote_script(repos):
    opts = "--assumeno -q"
    if repos:
        parts = ["--disablerepo=*"]
        for r in repos:
            name, _, url = r.partition("=")
            if not url:
                raise ValueError("linux repo entries must be name=url: %r" % r)
            url = url.replace("{major}", "${MAJ}").replace("{arch}", "${ARCH}")
            parts.append("--repofrompath=%s,%s" % (name.strip(), url.strip()))
            parts.append("--setopt=%s.gpgcheck=0" % name.strip())   # metadata only; nothing is installed
        opts = " ".join(parts) + " " + opts
    # dnf must never read stdin (a GPG prompt would wait forever), hence </dev/null.
    return "\n".join([
        "export LC_ALL=C",
        'MAJ=$(. /etc/os-release; echo "${VERSION_ID%%.*}"); ARCH=$(uname -m)',
        'echo "##OS $(. /etc/os-release; echo "$NAME $VERSION_ID")"',
        'echo "##KERNEL $(uname -r)"',
        'L=$(rpm -qa --last 2>/dev/null | head -1 | sed -E "s/^\\S+\\s+//"); echo "##LASTUPD $(date -d "$L" +%F 2>/dev/null)"',
        'command -v dnf >/dev/null || { echo "##ERROR dnf not found"; exit 0; }',
        "dnf %s updateinfo </dev/null 2>&1" % opts,
        'echo "##LIST"',
        "dnf %s updateinfo list --security --with-cve </dev/null 2>&1" % opts,
        'echo "##END"',
    ])


def strip_version(nevra):
    """'openssl-libs-1:3.2.2-6.el9_5.x86_64' -> 'openssl-libs'"""
    return re.sub(r"-(\d+:)?\d[^-]*-[^-]+$", "", nevra)


def parse(text):
    """Parse the remote script's output. Returns a dict with os, patched, notices, critical, important, cves."""
    def tag(name):
        m = re.search(r"^##%s (.*)$" % name, text, re.M)
        return m.group(1).strip() if m else ""
    if tag("ERROR"):
        raise RuntimeError(tag("ERROR"))
    if "##END" not in text:
        raise RuntimeError("the scan did not finish: " + text.strip()[-300:])
    summary, _, listing = text.partition("##LIST")
    num = lambda pat: int(m.group(1)) if (m := re.search(pat, summary)) else 0
    cves = collections.defaultdict(lambda: {"severity": "", "packages": set(), "updates": set()})
    for m in re.finditer(r"^(CVE-\d+-\d+)\s+(\w+)/Sec\.\s+(\S+)", listing, re.M):
        c = cves[m.group(1)]
        c["severity"] = worse(m.group(2), c["severity"]) if c["severity"] else m.group(2)
        c["packages"].add(strip_version(m.group(3)))
        c["updates"].add(m.group(3))
    if re.search(r"^(Error|Failed to download metadata|Curl error)", listing + summary, re.M) and not cves:
        line = next(l for l in (listing + summary).splitlines() if re.match(r"(Error|Failed|Curl)", l))
        raise RuntimeError("dnf: " + line.strip()[:300])
    return {"os": tag("OS"), "kernel": tag("KERNEL"), "patched": tag("LASTUPD"),
            "notices": num(r"(\d+) Security notice"), "critical": num(r"(\d+) Critical Security notice"),
            "important": num(r"(\d+) Important Security notice"), "cves": dict(cves)}


class HostKeyPolicy:
    """Record the host key on first contact; refuse a changed key afterwards."""

    def __init__(self, known, on_new):
        self.known, self.on_new = known, on_new

    def __call__(self):
        import paramiko
        policy = self

        class P(paramiko.MissingHostKeyPolicy):
            def missing_host_key(self, client, hostname, key):
                line = "%s %s" % (key.get_name(), key.get_base64())
                if policy.known:
                    if line != policy.known:
                        raise paramiko.SSHException("host key for %s changed; an admin must reset it on the Targets page "
                                                    "if the change is expected" % hostname)
                    return
                policy.on_new(line)
        return P()


def run_host(cfg, target, record_key):
    import paramiko
    client = paramiko.SSHClient()
    if cfg.ssh_known_hosts:
        client.load_host_keys(cfg.ssh_known_hosts)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    else:
        client.set_missing_host_key_policy(HostKeyPolicy(target["host_key"], lambda k: record_key(target["id"], k))())
    pkey = paramiko.PKey.from_path(cfg.ssh_key_file)
    try:
        client.connect(target["host"], port=cfg.ssh_port, username=cfg.ssh_user, pkey=pkey, timeout=15,
                       banner_timeout=30, auth_timeout=30, allow_agent=False, look_for_keys=False)
        cmd = "bash -c %s" % shlex.quote(remote_script(cfg.linux_repos))
        _, out, err = client.exec_command(cmd, timeout=cfg.host_timeout)
        text = out.read().decode(errors="replace")
        return parse(text)
    finally:
        client.close()


def scan(cfg, targets, log, record_key):
    """targets: [{id, host, label, host_key}]. Returns a raw platform."""
    if not cfg.ssh_user or not cfg.ssh_key_file:
        raise RuntimeError("Linux scans need an SSH user and key (SECURITAS_SSH_USER, SECURITAS_SSH_KEY_FILE)")
    results, warnings = {}, []
    with concurrent.futures.ThreadPoolExecutor(max_workers=cfg.host_concurrency) as ex:
        futs = {ex.submit(run_host, cfg, t, record_key): t for t in targets}
        for fut in concurrent.futures.as_completed(futs):
            t = futs[fut]
            try:
                results[t["host"]] = fut.result()
                r = results[t["host"]]
                log("linux: %s: %s, %d notices, %d CVEs" % (t["host"], r["os"], r["notices"], len(r["cves"])))
            except Exception as e:
                msg = "%s: %s" % (type(e).__name__, e) if not str(e) else str(e)
                results[t["host"]] = {"error": msg}
                warnings.append("Linux host %s could not be scanned: %s" % (t["host"], msg))
                log("linux: %s: FAILED %s" % (t["host"], msg))
    systems, findings, all_ids = [], {}, set()
    for t in targets:
        r = results[t["host"]]
        if "error" in r:
            systems.append({"name": t["host"], "role": t["label"], "os": "", "patched": "", "notices": "", "critical": "",
                            "important": "", "cves": "", "status": "Scan failed", "_cves": []})
            continue
        ids = sorted(r["cves"])
        all_ids |= set(ids)
        systems.append({"name": t["host"], "role": t["label"], "os": r["os"], "patched": r["patched"], "notices": r["notices"],
                        "critical": r["critical"], "important": r["important"], "cves": len(ids),
                        "status": "Up to date" if not ids else "Open", "_cves": ids})
        for c, v in r["cves"].items():
            f = findings.setdefault(c, {"cve": c, "title": "", "severity": v["severity"], "systems": set(),
                                        "packages": set(), "updates": set(), "status": "Open"})
            f["severity"] = worse(v["severity"], f["severity"])
            f["systems"].add(t["host"])
            f["packages"] |= v["packages"]
            f["updates"] |= v["updates"]
    rows = []
    for f in findings.values():
        pk = sorted(f.pop("packages"), key=len)
        main = [p for p in pk if not any(p != o and p.startswith(o + "-") for o in pk)] or pk
        up = sorted(f.pop("updates"))
        f["systems"] = sorted(f["systems"])
        f["component"] = ", ".join(main[:3]) + (" …" if len(main) > 3 else "")
        f["fix"] = "dnf update: " + ", ".join(up[:3])[:120] + (" …" if len(up) > 3 else "")
        rows.append(f)
    ok = [s for s in systems if s["status"] != "Scan failed"]
    return {
        "id": "linux", "title": "Linux",
        "subtitle": "Servers: installed packages compared with the security advisories in their dnf repositories"
                    if not cfg.linux_repos else "Servers: installed packages compared with upstream security advisories",
        "totals": {"Servers scanned": len(ok), "Distinct CVEs": len(all_ids),
                   "Pending security notices": sum(s["notices"] for s in ok)},
        "systems_caption": "Servers",
        "system_columns": [{"key": "name", "label": "Server", "type": "mono"}, {"key": "role", "label": "Role", "type": "text"},
                           {"key": "os", "label": "OS", "type": "text"}, {"key": "patched", "label": "Last updated", "type": "date"},
                           {"key": "notices", "label": "Security notices", "type": "num"},
                           {"key": "critical", "label": "Critical", "type": "num"},
                           {"key": "important", "label": "Important", "type": "num"},
                           {"key": "cves", "label": "CVEs", "type": "num"}, {"key": "kev", "label": "In KEV", "type": "hot"},
                           {"key": "priority", "label": "Priority CVEs", "type": "num"},
                           {"key": "status", "label": "Status", "type": "text"}],
        "systems": systems, "affected_label": "Servers", "findings": rows, "warnings": warnings,
        "failed": len(systems) - len(ok),
    }
