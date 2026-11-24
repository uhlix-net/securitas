"""Audit content that Securitas copies to Linux hosts at scan time.

An admin uploads the benchmark's Ansible-Lockdown audit zip (e.g. RHEL9-CIS-Audit at a release or commit, as
GitHub offers it) on the benchmark's page. For each scan Securitas builds one bundle from it: the audit files
plus a settings file (vars/CIS.yml) that starts from the audit's own settings, takes the values the uploaded role
zip sets for the same variables, and then the settings an admin chose in Securitas. The bundle is a tar.gz with
plain files and directories only, the same bytes for the same inputs, so its SHA-256 identifies exactly what ran.
On the host the agent wrapper unpacks it as root into a fresh root-only directory, runs Goss and deletes it.
"""
import hashlib
import io
import re
import tarfile
import zipfile

import yaml

from .compliance import BenchmarkError, MAX_ENTRIES, MAX_UNPACKED, MAX_ZIP, _yaml

SKIP_DIRS = (".git/", ".github/", ".gitlab/", "docs/", "images/")
MAX_BUNDLE = 20 * 1024 * 1024          # the wrapper refuses larger bundles
RULE_VAR = re.compile(r"_rule_\d")
# settings Securitas owns or that the role and the audit use differently: never copied from the role
NOT_FROM_ROLE = re.compile(r"(_rule_\d|_level_\d|^benchmark_|^audit_|_audit_|^setup_audit|^run_audit|^fetch_audit|"
                           r"^copy_audit|^goss_|^ansible_)")


def _top_and_files(data):
    if len(data) > MAX_ZIP:
        raise BenchmarkError("The file is larger than %d MB." % (MAX_ZIP // (1024 * 1024)))
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise BenchmarkError("That is not a zip file.") from None
    infos = z.infolist()
    if len(infos) > MAX_ENTRIES:
        raise BenchmarkError("The zip has more than %d entries." % MAX_ENTRIES)
    if sum(i.file_size for i in infos) > MAX_UNPACKED:
        raise BenchmarkError("The zip unpacks to more than %d MB." % (MAX_UNPACKED // (1024 * 1024)))
    tops = {i.filename.split("/", 1)[0] for i in infos}
    if len(tops) != 1 or not all("/" in i.filename for i in infos):
        raise BenchmarkError("The zip must contain one folder with the audit content, like RHEL9-CIS-Audit-<commit>/ "
                             "(the zip GitHub offers for a release or commit).")
    top = tops.pop()
    files = {}
    for i in infos:
        rel = i.filename[len(top) + 1:]
        if i.is_dir() or not rel:
            continue
        if rel.startswith("/") or ".." in rel.split("/") or "\\" in rel:
            raise BenchmarkError("The zip has an unsafe path: %s" % i.filename)
        if (i.external_attr >> 16) & 0o170000 == 0o120000:
            raise BenchmarkError("The zip contains a symbolic link (%s); audit content must be plain files." % i.filename)
        files[rel] = i
    return z, top, files


def parse_audit_zip(data, bench):
    """Check an uploaded audit zip against its benchmark. Returns {top, files, size, commit, vars}."""
    z, top, files = _top_and_files(data)
    if "goss.yml" not in files or "vars/CIS.yml" not in files:
        raise BenchmarkError("This is not Ansible-Lockdown audit content: goss.yml and vars/CIS.yml are missing.")
    v = _yaml(z, files["vars/CIS.yml"])
    if not isinstance(v, dict):
        raise BenchmarkError("vars/CIS.yml is not a list of settings.")
    prefix = (bench.name.split("-")[0] if bench else "").lower()
    if prefix and not any(k.lower().startswith(prefix) for k in v):
        raise BenchmarkError("This audit content does not look like it belongs to %s (no %s* settings in vars/CIS.yml)."
                             % (bench.name, prefix))
    m = re.search(r"-([0-9a-f]{7,40})$", top)
    return {"top": top, "files": sum(1 for r in files if not r.startswith(SKIP_DIRS)),
            "size": sum(i.file_size for i in files.values()), "commit": m.group(1) if m else "",
            "benchmark_version": str(v.get("benchmark_version", "") or "")}


def audit_defaults(data):
    z, _, files = _top_and_files(data)
    v = _yaml(z, files["vars/CIS.yml"])
    return v if isinstance(v, dict) else {}


def role_defaults(data):
    """The role zip's defaults/main settings."""
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return {}
    out = {}
    for i in sorted(z.infolist(), key=lambda i: i.filename):
        rel = i.filename.split("/", 1)[1] if "/" in i.filename else ""
        if (rel.startswith("defaults/main/") or rel == "defaults/main.yml") and rel.endswith((".yml", ".yaml")):
            d = _yaml(z, i)
            if isinstance(d, dict):
                out.update(d)
    return out


def settings(audit_vars, role_vars, overrides):
    """[(name, effective value, source, audit default)] for the on/off settings an admin may change: booleans in
    the audit's vars/CIS.yml that are not per-rule or level switches. source: 'audit', 'role' or 'here'."""
    out = []
    for k in sorted(audit_vars):
        dv = audit_vars[k]
        if not isinstance(dv, bool) or RULE_VAR.search(k) or NOT_FROM_ROLE.search(k):
            continue
        val, src = dv, "audit"
        rv = role_vars.get(k)
        if isinstance(rv, bool) and rv != dv:
            val, src = rv, "role"
        if isinstance(overrides.get(k), bool):
            val, src = overrides[k], "here"
        out.append((k, val, src, dv))
    return out


def effective_vars(audit_vars, role_vars, overrides):
    """vars/CIS.yml for the bundle: the audit's settings, the role's values for the same on/off and number settings
    (never rule or level switches, never text: the role's text values can be Ansible/Jinja expressions that mean
    nothing to the audit), then the admin's on/off choices."""
    v = dict(audit_vars)
    for k, rv in role_vars.items():
        if k in v and not NOT_FROM_ROLE.search(k) and isinstance(rv, (bool, int)) and type(rv) is type(v[k]):
            v[k] = rv
    for k, ov in (overrides or {}).items():
        if k in v and isinstance(ov, bool) and isinstance(v[k], bool):
            v[k] = ov
    return v


# goss.yml includes some check folders only for one choice, e.g. {{ if eq .Vars.rhel9cis_firewall "nftables" }}
# (firewalld or nftables, journald or rsyslog). Securitas runs every automated check, so these include guards
# become {{ if true }}: both alternatives run, and the one a host does not use fails (accept it with an exception).
# Only goss.yml is changed; checks that verify which alternative is in use keep reading the setting.
CHOICE_GUARD = re.compile(r'\{\{\s*if\s+eq\s+\.Vars\.[A-Za-z0-9_]+\s+"[^"]*"\s*\}\}')


def all_alternatives(goss_yml):
    """goss.yml with every either/or include guard turned on. Returns (text, number of guards changed)."""
    return CHOICE_GUARD.subn("{{ if true }}", goss_yml)


def build(audit_zip, vars_dict):
    """(tar.gz bytes, sha256 hex) of the audit content with vars/CIS.yml replaced and goss.yml running both
    alternatives of every either/or include. Deterministic."""
    z, _, files = _top_and_files(audit_zip)
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        dirs = set()
        entries = []
        for rel in sorted(files):
            if rel.startswith(SKIP_DIRS):
                continue
            if rel == "vars/CIS.yml":
                data = yaml.safe_dump(vars_dict, sort_keys=True, default_flow_style=False).encode()
            elif rel == "goss.yml":
                data = all_alternatives(z.read(files[rel]).decode())[0].encode()
            else:
                data = z.read(files[rel])
            entries.append((rel, data))
            parts = rel.split("/")[:-1]
            for n in range(1, len(parts) + 1):
                dirs.add("/".join(parts[:n]))

        def info(name, size=0, d=False):
            ti = tarfile.TarInfo("./" + name)
            ti.type = tarfile.DIRTYPE if d else tarfile.REGTYPE
            ti.mode, ti.size, ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname = (0o755 if d else 0o644), size, 0, 0, 0, "", ""
            return ti
        for d in sorted(dirs):
            tar.addfile(info(d, d=True))
        for rel, data in entries:
            tar.addfile(info(rel, len(data)), io.BytesIO(data))
    gz = io.BytesIO()
    import gzip
    with gzip.GzipFile(fileobj=gz, mode="wb", mtime=0) as g:
        g.write(raw.getvalue())
    out = gz.getvalue()
    if len(out) > MAX_BUNDLE:
        raise BenchmarkError("The audit bundle is larger than %d MB." % (MAX_BUNDLE // (1024 * 1024)))
    return out, hashlib.sha256(out).hexdigest()
