"""Compliance benchmark library: Ansible-Lockdown CIS roles, uploaded as the zip GitHub serves for a release.

Each upload is one benchmark, named after the role and its version (`RHEL9-CIS-2.4.2`), and keeps the original
zip, its SHA-256 and who uploaded it when. Benchmarks can be removed at any time; several versions of the same
role can be loaded side by side, and one benchmark per operating system is the active one.

Only the role's own files are read; nothing in the zip is run or extracted to disk. Rules come from the role's
task names (`1.1.1.1 | PATCH | Ensure cramfs kernel module is not available`), their tags (CIS profile level,
NIST 800-53 mappings) and the on/off switch in `defaults/main` (`rhel9cis_rule_1_1_1_1: true`).
"""
import hashlib
import io
import re
import zipfile

import yaml

MAX_ZIP = 25 * 1024 * 1024          # compressed upload
MAX_UNPACKED = 100 * 1024 * 1024    # sum of uncompressed sizes
MAX_ENTRIES = 5000
MAX_FILE = 5 * 1024 * 1024          # one YAML file

PLATFORMS = ("linux", "windows", "kubernetes")
# Profiles per platform. Linux roles tag rules for servers or workstations. Windows roles tag them for member
# servers or domain controllers; the "auto" profiles pick by each host's role (detected when it is checked).
PLATFORM_PROFILES = {
    "linux": {
        "level1-server": "Level 1 - Server",
        "level2-server": "Level 2 - Server (includes Level 1)",
        "level1-workstation": "Level 1 - Workstation",
        "level2-workstation": "Level 2 - Workstation (includes Level 1)",
    },
    "windows": {
        "level1-auto": "Level 1 - member server or domain controller, by each host's role",
        "level2-auto": "Level 2 - member server or domain controller, by each host's role (includes Level 1)",
        "level1-memberserver": "Level 1 - Member server",
        "level2-memberserver": "Level 2 - Member server (includes Level 1)",
        "level1-domaincontroller": "Level 1 - Domain controller",
        "level2-domaincontroller": "Level 2 - Domain controller (includes Level 1)",
    },
}
PROFILES = {k: v for d in PLATFORM_PROFILES.values() for k, v in d.items()}
DEFAULT_PROFILES = {"linux": "level1-server", "windows": "level1-auto"}
DEFAULT_PROFILE = "level1-server"
LEVEL_TAGS = ("level1-server", "level2-server", "level1-workstation", "level2-workstation",
              "level1-memberserver", "level2-memberserver", "level1-domaincontroller", "level2-domaincontroller",
              "ngws-memberserver", "ngws-domaincontroller")   # ngws: CIS Next Generation Windows Security (optional)
HOST_KINDS = ("memberserver", "domaincontroller")


def profiles_for(platform):
    return PLATFORM_PROFILES.get(platform, PLATFORM_PROFILES["linux"])


def default_profile(platform):
    return DEFAULT_PROFILES.get(platform, DEFAULT_PROFILE)

TOP_RE = re.compile(r"^(?P<name>[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*?-(?P<kind>CIS|STIG))-(?P<version>\d+(?:\.\d+){1,3})$")
SPLIT_RE = re.compile(r"""["']?\s+["']?(?=\d+(?:\.\d+)+\s*\|\s*(?:AUDIT|PATCH)\s*\|)""")
RULE_RE = re.compile(r"^\s*(?P<id>\d+(?:\.\d+)+)\s*\|\s*(?P<type>AUDIT|PATCH)\s*\|\s*(?P<title>.+?)\s*$")

# Operating system each role is written for, from the role name's prefix.
OS_NAMES = [
    (re.compile(r"^RHEL(\d+)$", re.I), "rhel{0}", "RHEL {0} family (RHEL, Rocky, AlmaLinux, Oracle Linux)"),
    (re.compile(r"^(?:AMAZON|AMAZONLINUX|AMAZON)(\d+)$", re.I), "amazon{0}", "Amazon Linux {0}"),
    (re.compile(r"^UBUNTU(\d\d)(\d\d)?$", re.I), "ubuntu{0}", "Ubuntu {0}.04"),
    (re.compile(r"^DEBIAN(\d+)$", re.I), "debian{0}", "Debian {0}"),
    (re.compile(r"^SUSE(\d+)$", re.I), "suse{0}", "SUSE Linux Enterprise {0}"),
    (re.compile(r"^Windows-(\d{4})$", re.I), "windows{0}", "Windows Server {0}"),
    (re.compile(r"^Windows-(\d\d)$", re.I), "windows{0}-client", "Windows {0}"),
]


class BenchmarkError(ValueError):
    """The upload is not a benchmark this version of Securitas can read. The message is shown to the user."""


class _Loader(yaml.SafeLoader):
    """Safe YAML that tolerates Ansible's custom tags (!unsafe, !vault) by reading them as plain values."""


def _any_tag(loader, suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)


_Loader.add_multi_constructor("!", _any_tag)


def _yaml(z, info):
    if info.file_size > MAX_FILE:
        raise BenchmarkError("%s is larger than %d MB." % (info.filename, MAX_FILE // (1024 * 1024)))
    try:
        return yaml.load(z.read(info), Loader=_Loader)   # noqa: S506 - SafeLoader subclass
    except yaml.YAMLError as e:
        raise BenchmarkError("%s is not valid YAML: %s" % (info.filename, str(e).splitlines()[0]))


def sort_key(rule_id):
    """'1.10.2' -> '0001.0010.0002' so rules sort numerically as text."""
    return ".".join("%04d" % int(p) for p in rule_id.split("."))


def os_for(prefix):
    for rx, key, label in OS_NAMES:
        m = rx.match(prefix)
        if m:
            g = [x for x in m.groups() if x]
            return key.format(*g), label.format(*g)
    return prefix.lower(), prefix


def in_profile(levels, profile, host_kind="memberserver"):
    """Is a rule with these level tags part of the profile? Level 2 profiles include their Level 1 rules.
    host_kind ("memberserver" or "domaincontroller") decides the Windows "auto" profiles."""
    lvl, _, kind = profile.partition("-")
    if kind == "auto":
        kind = host_kind if host_kind in HOST_KINDS else "memberserver"
    want = {"level1-" + kind} | ({"level2-" + kind} if lvl == "level2" else set())
    return bool(want & set(levels))


def parse_zip(data, filename=""):
    """Read an Ansible-Lockdown CIS role zip. Returns the benchmark's description and its rules.

    Raises BenchmarkError with a message for the user when the file is not one."""
    if len(data) > MAX_ZIP:
        raise BenchmarkError("The file is larger than %d MB." % (MAX_ZIP // (1024 * 1024)))
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise BenchmarkError("That is not a zip file.")
    infos = z.infolist()
    if len(infos) > MAX_ENTRIES:
        raise BenchmarkError("The zip has more than %d entries." % MAX_ENTRIES)
    if sum(i.file_size for i in infos) > MAX_UNPACKED:
        raise BenchmarkError("The zip unpacks to more than %d MB." % (MAX_UNPACKED // (1024 * 1024)))
    tops = {i.filename.split("/", 1)[0] for i in infos}
    if len(tops) != 1 or not all("/" in i.filename for i in infos):
        raise BenchmarkError("The zip must contain one folder named after the role and version, "
                             "like RHEL9-CIS-2.4.2/ (the zip GitHub offers on a release page).")
    top = tops.pop()
    m = TOP_RE.match(top)
    if not m:
        raise BenchmarkError("The folder in the zip is %r. Expected <role>-<version>, like RHEL9-CIS-2.4.2. "
                             "Download a release (tag), not a branch." % top)
    name, kind, version = m.group("name"), m.group("kind"), m.group("version")
    if top + "/securitas-benchmark.json" in {i.filename for i in infos}:
        return parse_package(z, top, infos, data, filename)
    if kind != "CIS":
        raise BenchmarkError("%s is a STIG role. This version of Securitas reads CIS roles only." % name)
    files = {i.filename[len(top) + 1:]: i for i in infos if not i.is_dir()}

    meta_i = files.get("meta/main.yml")
    if meta_i is None:
        raise BenchmarkError("meta/main.yml is missing, so this does not look like an Ansible role.")
    meta = _yaml(z, meta_i) or {}
    gi = meta.get("galaxy_info") or {}
    plats = [p.get("name", "") for p in gi.get("platforms") or [] if isinstance(p, dict)]
    platform = "windows" if any(p.lower().startswith("windows") for p in plats) or name.lower().startswith("windows") \
        else "linux"

    defaults = {}
    for path, info in sorted(files.items()):
        if (path.startswith("defaults/main/") or path == "defaults/main.yml") and path.endswith((".yml", ".yaml")):
            d = _yaml(z, info)
            if isinstance(d, dict):
                defaults.update(d)
    bench_version = str(defaults.get("benchmark_version", "") or "")

    rules = {}

    def walk(x, path):
        if isinstance(x, list):
            for i in x:
                walk(i, path)
            return
        if not isinstance(x, dict):
            return
        n, tags = x.get("name"), x.get("tags")
        if isinstance(n, str) and isinstance(tags, list):
            tags = [str(t) for t in tags]
            # One task can implement several rules; its name then lists them one after the other (YAML folds the
            # lines of a plain scalar into one), so split before every "<id> | AUDIT|PATCH |".
            n = n.strip()
            if len(n) > 1 and n[0] in "\"'" and n[-1] == n[0]:    # each line quoted: '"1.1 | PATCH | a"\n"1.2 | ..."'
                n = n[1:-1]
            for line in SPLIT_RE.split(n):
                r = RULE_RE.match(line)
                if r and r.group("id") not in rules and "rule_" + r.group("id") in tags:
                    rid = r.group("id")
                    rules[rid] = {"rule_id": rid, "kind": r.group("type"), "title": r.group("title").split(" | ")[0],
                                  "levels": [t for t in LEVEL_TAGS if t in tags],
                                  "refs": sorted({t for t in tags if t.upper().startswith("NIST")}),
                                  "source": path}
        for k in ("block", "rescue", "always"):
            if k in x:
                walk(x[k], path)

    for path, info in sorted(files.items()):
        if path.startswith("tasks/") and path.endswith((".yml", ".yaml")) and "/section" in "/" + path:
            walk(_yaml(z, info), path)
    if not rules:
        raise BenchmarkError("No CIS rules were found in tasks/section_*. Is this an Ansible-Lockdown CIS role?")

    # The role's on/off switch per rule: <prefix>_rule_1_1_1_1. The prefix is whatever precedes _rule_ most often.
    prefixes = {}
    for k in defaults:
        p, sep, rest = str(k).partition("_rule_")
        if sep and re.fullmatch(r"\d+(?:_\d+)+", rest):
            prefixes[p] = prefixes.get(p, 0) + 1
    prefix = max(prefixes, key=prefixes.get) if prefixes else ""
    for rid, r in rules.items():
        var = "%s_rule_%s" % (prefix, rid.replace(".", "_")) if prefix else ""
        r["toggle"] = var
        r["default_on"] = bool(defaults.get(var, True)) if var else True
        r["section"] = rid.split(".")[0]
        r["sort_key"] = sort_key(rid)

    os_key, os_label = os_for(name[:-len("-CIS")])
    changelog = ""
    if "Changelog.md" in files:
        changelog = z.read(files["Changelog.md"]).decode("utf-8", "replace")[:2000]
    return {
        "key": "%s-%s" % (name, version), "name": name, "version": version, "kind": kind,
        "benchmark_version": bench_version, "platform": platform, "os_key": os_key, "os_label": os_label,
        "filename": filename or top + ".zip", "sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
        "meta": {"author": str(gi.get("author", "")), "company": str(gi.get("company", "")),
                 "description": str(gi.get("description", "")), "license": str(gi.get("license", "")),
                 "role_name": str(gi.get("role_name", "")), "namespace": str(gi.get("namespace", "")),
                 "min_ansible_version": str(gi.get("min_ansible_version", "")),
                 "platforms": [{"name": str(p.get("name", "")), "versions": [str(v) for v in p.get("versions") or []]}
                               for p in gi.get("platforms") or [] if isinstance(p, dict)],
                 "toggle_prefix": prefix, "files": len(files), "changelog": changelog},
        "rules": sorted(rules.values(), key=lambda r: r["sort_key"]),
    }


PACKAGE_FORMAT = "securitas-benchmark/1"
ASSESSMENTS = ("Automated", "Manual")


def parse_package(z, top, infos, data, filename=""):
    """A Securitas benchmark package (tools/cis_package.py): the rules as the official CIS document states them
    (ID, title, Automated/Manual, profiles) and the audit checks in audit/. Returns parse_zip's shape plus
    "audit_zip": the checks repacked as an audit zip (one top folder) for audit_bundle."""
    import json
    try:
        pkg = json.loads(z.read(top + "/securitas-benchmark.json"))
    except ValueError:
        raise BenchmarkError("securitas-benchmark.json is not valid JSON.") from None
    if pkg.get("format") != PACKAGE_FORMAT:
        raise BenchmarkError("Unknown package format %r (this Securitas reads %s)." % (pkg.get("format"), PACKAGE_FORMAT))
    name, version = str(pkg.get("name", "")), str(pkg.get("version", ""))
    if "%s-%s" % (name, version) != top or pkg.get("key") != top:
        raise BenchmarkError("The package folder %s does not match its name and version (%s-%s)." % (top, name, version))
    platform = pkg.get("platform")
    if platform not in ("linux", "windows"):
        raise BenchmarkError("Unknown platform %r in the package." % platform)
    rules = []
    seen = set()
    for r in pkg.get("rules") or []:
        rid = str(r.get("id", ""))
        if not re.fullmatch(r"\d+(?:\.\d+)+", rid) or rid in seen:
            raise BenchmarkError("Bad or repeated rule ID %r in the package." % rid)
        seen.add(rid)
        if r.get("assessment") not in ASSESSMENTS:
            raise BenchmarkError("Rule %s: assessment must be Automated or Manual." % rid)
        levels = [p for p in r.get("profiles") or [] if p in LEVEL_TAGS]
        rules.append({"rule_id": rid, "title": str(r.get("title", ""))[:2000], "assessment": r["assessment"],
                      "kind": "PATCH" if r["assessment"] == "Automated" else "AUDIT", "levels": levels, "refs": [],
                      "toggle": "", "default_on": True, "source": "CIS document", "section": rid.split(".")[0],
                      "sort_key": sort_key(rid)})
    if not rules:
        raise BenchmarkError("The package has no rules.")
    # the checks: audit/ repacked as <name>-audit/ so audit_bundle reads them like an uploaded audit zip
    buf = io.BytesIO()
    prefix = top + "/audit/"
    n = 0
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as out:
        for i in infos:
            if i.filename.startswith(prefix) and not i.is_dir():
                out.writestr(top + "-audit/" + i.filename[len(prefix):], z.read(i))
                n += 1
    if not n:
        raise BenchmarkError("The package has no audit/ checks.")
    cis = pkg.get("cis") or {}
    os_key, os_label = os_for(name[:-len("-CIS")] if name.endswith("-CIS") else name)
    return {
        "key": top, "name": name, "version": version, "kind": "CIS", "benchmark_version": str(cis.get("version", "")),
        "platform": platform, "os_key": os_key, "os_label": os_label, "filename": filename or top + ".zip",
        "sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
        "meta": {"package": True, "description": str(cis.get("document", "")), "cis_document": str(cis.get("document", "")),
                 "cis_date": str(cis.get("date", "")), "cis_pdf_sha256": str(cis.get("pdf_sha256", "")),
                 "revision": pkg.get("revision"), "audit_source": str((pkg.get("audit") or {}).get("source", "")),
                 "coverage": pkg.get("coverage") or {}, "created": str(pkg.get("created", "")),
                 "sections": pkg.get("sections") or {}, "files": len(infos)},
        "rules": sorted(rules, key=lambda r: r["sort_key"]), "audit_zip": buf.getvalue(),
    }


def upload_date(b, tz="UTC"):
    """The upload date in Securitas' time zone (SECURITAS_TIMEZONE), so an evening upload keeps its local date."""
    import datetime
    import zoneinfo
    try:
        z = zoneinfo.ZoneInfo(tz)
    except Exception:
        z = datetime.timezone.utc
    return b.uploaded_at.astimezone(z).strftime("%Y-%m-%d")


def display_name(b, tz="UTC"):
    """How a benchmark is named everywhere: 'RHEL9-CIS 2.4.2 · uploaded 2026-11-20'."""
    return "%s %s · uploaded %s" % (b.name, b.version, upload_date(b, tz))


# ------------------------------------------------------------------ database operations

def rule_on(rule, profile, host_kind="memberserver"):
    """Is the rule checked? An override set in Securitas wins; otherwise the role's default and the profile."""
    if rule.override is not None:
        return rule.override
    return rule.default_on and in_profile(rule.levels or [], profile, host_kind)


def checked_rules(b, host_kind="memberserver"):
    """The rules the benchmark checks on a host of this kind, as the checkers take them."""
    return [{"id": r.rule_id, "title": r.title, "kind": r.kind, "assessment": r.assessment or ""}
            for r in b.rules if rule_on(r, b.profile, host_kind)]


def counts(b):
    on = sum(1 for r in b.rules if rule_on(r, b.profile))
    on_dc = sum(1 for r in b.rules if rule_on(r, b.profile, "domaincontroller")) if b.platform == "windows" else on
    return {"total": len(b.rules), "on": on, "on_dc": on_dc, "overrides": sum(1 for r in b.rules if r.override is not None),
            "patch": sum(1 for r in b.rules if r.kind == "PATCH"), "audit": sum(1 for r in b.rules if r.kind == "AUDIT"),
            "automated": sum(1 for r in b.rules if r.assessment == "Automated"),
            "manual": sum(1 for r in b.rules if r.assessment == "Manual")}


def store(s, parsed, data, username, tz="UTC"):
    """Save a parsed upload. Raises BenchmarkError if this role version is already loaded.

    The first benchmark for an operating system becomes its active one."""
    from .db import Benchmark, BenchmarkFile, BenchmarkRule, select
    old = s.scalar(select(Benchmark).where(Benchmark.key == parsed["key"]))
    if old is not None:
        same = old.sha256 == parsed["sha256"]
        raise BenchmarkError("%s is already loaded (uploaded %s by %s)%s. Remove it first to load it again."
                             % (parsed["key"], upload_date(old, tz), old.uploaded_by or "unknown",
                                ", from the same file" if same else ", from a different file with the same version"))
    has_active = s.scalar(select(Benchmark.id).where(Benchmark.os_key == parsed["os_key"], Benchmark.active.is_(True)))
    b = Benchmark(key=parsed["key"], name=parsed["name"], version=parsed["version"], kind=parsed["kind"],
                  benchmark_version=parsed["benchmark_version"], platform=parsed["platform"], os_key=parsed["os_key"],
                  os_label=parsed["os_label"], profile=default_profile(parsed["platform"]), active=not has_active,
                  rule_count=len(parsed["rules"]), filename=parsed["filename"][:255], sha256=parsed["sha256"],
                  size=parsed["size"], meta=parsed["meta"], uploaded_by=username)
    for r in parsed["rules"]:
        b.rules.append(BenchmarkRule(rule_id=r["rule_id"], sort_key=r["sort_key"], section=r["section"], title=r["title"],
                                     kind=r["kind"], levels=r["levels"], refs=r["refs"], toggle=r["toggle"],
                                     default_on=r["default_on"], source=r["source"][:255],
                                     assessment=r.get("assessment", "")))
    b.files.append(BenchmarkFile(kind="package" if parsed.get("audit_zip") else "role", filename=b.filename,
                                 sha256=b.sha256, size=b.size, data=data, uploaded_by=username))
    if parsed.get("audit_zip"):
        from . import audit_bundle
        az = parsed["audit_zip"]
        b.files.append(BenchmarkFile(kind="audit", filename=b.key + "-audit.zip", sha256=hashlib.sha256(az).hexdigest(),
                                     size=len(az), data=az, uploaded_by=username))
        b.meta = {**(b.meta or {}), "audit": audit_bundle.parse_audit_zip(az, b)}
    s.add(b)
    s.flush()
    return b


def activate(s, b):
    """Make b the active benchmark for its operating system (and the others for that OS inactive)."""
    from .db import Benchmark, select
    for o in s.scalars(select(Benchmark).where(Benchmark.os_key == b.os_key, Benchmark.id != b.id)).all():
        o.active = False
    b.active = True


def set_rules(b, shown, checked):
    """Apply the rule checkboxes of one (possibly filtered) page: only the rules in `shown` change.
    A rule is stored as an override only when it differs from what the profile alone gives."""
    changed = 0
    for r in b.rules:
        if r.rule_id not in shown:
            continue
        want = r.rule_id in checked
        natural = r.default_on and in_profile(r.levels or [], b.profile)
        new = None if want == natural else want
        if new != r.override:
            r.override = new
            changed += 1
    return changed


# Operating system names as the vulnerability scans record them, mapped to a benchmark's os_key.
HOST_OS = [
    (re.compile(r"\b(?:Red Hat Enterprise Linux|Rocky Linux|AlmaLinux|Oracle Linux|CentOS Stream)\D*?(\d+)", re.I), "rhel{0}"),
    (re.compile(r"\bAmazon Linux\D*?(\d+)", re.I), "amazon{0}"),
    (re.compile(r"\bUbuntu\D*?(\d\d)\.\d\d", re.I), "ubuntu{0}"),
    (re.compile(r"\bDebian\D*?(\d+)", re.I), "debian{0}"),
    (re.compile(r"\bWindows Server\D*?(\d{4})", re.I), "windows{0}"),
]


def audit_settings_ctx(s, b):
    """(audit file row or None, [(name, value, source, audit default)]) for a benchmark's page."""
    from . import audit_bundle
    from .db import BenchmarkFile, select
    af = s.scalar(select(BenchmarkFile).where(BenchmarkFile.benchmark_id == b.id, BenchmarkFile.kind == "audit"))
    if af is None:
        return None, []
    rf = s.scalar(select(BenchmarkFile).where(BenchmarkFile.benchmark_id == b.id, BenchmarkFile.kind == "role"))
    return af, audit_bundle.settings(audit_bundle.audit_defaults(af.data), audit_bundle.role_defaults(rf.data) if rf else {},
                                     (b.meta or {}).get("audit_settings") or {})


def audit_bundle(s, b):
    """(bundle bytes, sha256) for a benchmark with uploaded audit content, or None."""
    from . import audit_bundle as ab
    from .db import BenchmarkFile, select
    af = s.scalar(select(BenchmarkFile).where(BenchmarkFile.benchmark_id == b.id, BenchmarkFile.kind == "audit"))
    if af is None:
        return None
    rf = s.scalar(select(BenchmarkFile).where(BenchmarkFile.benchmark_id == b.id, BenchmarkFile.kind == "role"))
    v = ab.effective_vars(ab.audit_defaults(af.data), ab.role_defaults(rf.data) if rf else {},
                          (b.meta or {}).get("audit_settings") or {})
    return ab.build(af.data, v)


def os_key_for(os_name):
    """'Rocky Linux 9.6' -> 'rhel9'; 'Windows Server 2022 Standard' -> 'windows2022'; '' when not known."""
    for rx, key in HOST_OS:
        m = rx.search(os_name or "")
        if m:
            return key.format(*m.groups())
    return ""
