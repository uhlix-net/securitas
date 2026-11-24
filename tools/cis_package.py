#!/usr/bin/env python3
"""Build a Securitas benchmark package from the official CIS benchmark PDF and the audit checks.

    python3 tools/cis_package.py --pdf CIS_Red_Hat_Enterprise_Linux_9_Benchmark_v2.0.0.pdf \
        --audit RHEL9-CIS-Audit-<commit>.zip --name RHEL9-CIS --out dist/

Needs pypdf (pip install pypdf). The package (<name>-<CIS version>.zip, one folder of the same name) holds:
  securitas-benchmark.json  every recommendation as the CIS document states it: ID, title, Automated or Manual,
                            profiles (Level 1/2, Server/Workstation), plus the sections, the document's title and
                            version and the PDF's SHA-256. Only these facts are taken from the PDF, no prose.
  audit/                    the Goss checks (e.g. Ansible-Lockdown RHEL9-CIS-Audit at a pinned commit), unchanged
  SOURCES.txt               where both came from, and the cross-check below
The build stops when the PDF and the checks disagree on rule IDs (a check for a rule the document does not have),
and reports Automated recommendations that have no check yet.
"""
import argparse
import datetime
import hashlib
import io
import json
import re
import sys
import zipfile

PROFILE = {"Level 1 - Server": "level1-server", "Level 2 - Server": "level2-server",
           "Level 1 - Workstation": "level1-workstation", "Level 2 - Workstation": "level2-workstation",
           "Level 1 - Member Server": "level1-memberserver", "Level 2 - Member Server": "level2-memberserver",
           "Level 1 - Domain Controller": "level1-domaincontroller", "Level 2 - Domain Controller": "level2-domaincontroller"}
RID = r"\d+(?:\.\d+){1,5}"


def pdf_text(path):
    import pypdf
    r = pypdf.PdfReader(path)
    return "\n".join((p.extract_text() or "") for p in r.pages)


def parse(text):
    """Recommendations from the body of the document: a heading 'ID Title (Automated|Manual)' (the title may wrap)
    followed by 'Profile Applicability:' and its bullet list."""
    head = re.compile(r"(?m)^(%s) ((?:(?!^%s )[\s\S]){3,500}?)\((Automated|Manual)\)\s*\n\s*Profile Applicability:\s*\n"
                      r"((?:\s*•[^\n]*\n)+)" % (RID, RID))
    recs = {}
    for m in head.finditer(text):
        # a title wrapped at a hyphen ("chacha20-\npoly1305") is one word
        rid, title, assess = m.group(1), " ".join(re.sub(r"(\w)-\s*\n\s*", r"\1-", m.group(2)).split()), m.group(3)
        profiles = []
        for b in re.findall(r"•\s*([^\n]+)", m.group(4)):
            b = " ".join(b.split())
            if b not in PROFILE:
                sys.exit("%s: unknown profile %r" % (rid, b))
            profiles.append(PROFILE[b])
        if rid in recs and (recs[rid]["title"], recs[rid]["assessment"]) != (title, assess):
            sys.exit("%s appears twice with different text" % rid)
        recs[rid] = {"id": rid, "title": title, "assessment": assess, "profiles": profiles}
    # section headings from the table of contents: 'ID Title .... page' without (Automated|Manual)
    sections = {}
    for m in re.finditer(r"(?m)^(%s|\d+) ([^\n(]+?)\s*\.{3,}[\s.]*\d+\s*$" % RID, text):
        if m.group(1) not in recs:
            sections.setdefault(m.group(1), " ".join(m.group(2).split()))
    # cross-check with the table of contents
    toc = {m.group(1): m.group(2) for m in re.finditer(r"(?m)^(%s) [^\n]*?\((Automated|Manual)\)\s*\.{3,}" % RID, text)}
    missing = sorted(set(toc) - set(recs), key=sortkey)
    if missing:
        sys.exit("in the table of contents but not parsed from the body: %s" % ", ".join(missing))
    for rid, a in toc.items():
        if recs[rid]["assessment"] != a:
            sys.exit("%s: table of contents says %s, body says %s" % (rid, a, recs[rid]["assessment"]))
    return recs, sections


def sortkey(rid):
    return [int(x) for x in rid.split(".")]


def meta(text):
    """Title, version and date from the cover page ('CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0 - 06-24-2024')."""
    cover = " ".join(text[:text.find("Page 1")].split())
    m = re.search(r"(CIS .+? Benchmark)\s+(v\d+\.\d+\.\d+)(?:\s*-\s*(\d{2}-\d{2}-\d{4}))?", cover)
    if not m:
        sys.exit("could not read the benchmark's title and version from the cover page")
    return {"document": m.group(1), "version": m.group(2), "date": m.group(3) or ""}


def audit_ids(z, top):
    """Rule IDs that have a real check: tests whose meta.CIS_ID names them, except 'Manual Check Required'
    placeholders (they only report that a person must look)."""
    ids = set()
    test = re.compile(r"title:\s*([^\n]+)\n(?:(?!\n\s*title:)[\s\S])*?CIS_ID:\s*(?:\n((?:\s*-\s*[^\n]+\n)+)|['\"]?(%s))" % RID)
    for i in z.infolist():
        if i.filename.endswith(".yml") and "/section_" in i.filename:
            for title, block, one in test.findall(z.read(i).decode(errors="replace")):
                if re.search(r"manual", title, re.I):
                    continue
                ids.update(x.strip().strip("'\"") for x in re.findall(r"-\s*([^\n]+)", block or ""))
                if one:
                    ids.add(one)
    return {x for x in ids if re.fullmatch(RID, x)}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--pdf", required=True)
    ap.add_argument("--audit", required=True, help="the audit checks as a zip with one top folder (GitHub download)")
    ap.add_argument("--name", required=True, help="benchmark name, e.g. RHEL9-CIS (keeps exceptions across versions)")
    ap.add_argument("--platform", default="linux", choices=["linux", "windows"])
    ap.add_argument("--revision", type=int, default=1, help="package revision for the same CIS version")
    ap.add_argument("--out", default=".")
    a = ap.parse_args()
    pdf = open(a.pdf, "rb").read()
    text = pdf_text(a.pdf)
    recs, sections = parse(text)
    doc = meta(text)
    version = doc["version"].lstrip("v")
    key = "%s-%s" % (a.name, version)
    az = zipfile.ZipFile(io.BytesIO(open(a.audit, "rb").read()))
    tops = {i.filename.split("/", 1)[0] for i in az.infolist()}
    if len(tops) != 1:
        sys.exit("the audit zip must have one top folder")
    atop = tops.pop()
    checks = audit_ids(az, atop)
    unknown = sorted(checks - set(recs), key=sortkey)
    if unknown:
        sys.exit("the checks test rules the CIS document does not have: %s" % ", ".join(unknown))
    auto_nocheck = sorted((r for r in recs if recs[r]["assessment"] == "Automated" and r not in checks), key=sortkey)
    manual_check = sorted((r for r in recs if recs[r]["assessment"] == "Manual" and r in checks), key=sortkey)
    rules = [recs[r] for r in sorted(recs, key=sortkey)]
    pkg = {"format": "securitas-benchmark/1", "key": key, "name": a.name, "version": version, "revision": a.revision,
           "platform": a.platform, "kind": "CIS",
           "cis": {"document": doc["document"], "version": doc["version"], "date": doc["date"],
                   "pdf_sha256": hashlib.sha256(pdf).hexdigest()},
           "audit": {"source": atop, "files": sum(1 for i in az.infolist() if not i.is_dir())},
           "created": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "sections": {k: sections[k] for k in sorted(sections, key=sortkey)}, "rules": rules,
           "coverage": {"automated_without_check": auto_nocheck, "manual_with_check": manual_check}}
    src = ("%s, built by Securitas tools/cis_package.py %s\n\nRules: %s %s (%s), PDF SHA-256 %s\n"
           "  %d recommendations: %d Automated, %d Manual (as the document labels them)\n"
           "Checks: %s (%d files), unchanged\n  Automated recommendations without a check yet: %s\n"
           "  Manual recommendations that also have a check: %s\n" % (
               key, pkg["created"], doc["document"], doc["version"], doc["date"] or "date not found",
               pkg["cis"]["pdf_sha256"], len(rules), sum(r["assessment"] == "Automated" for r in rules),
               sum(r["assessment"] == "Manual" for r in rules), atop, pkg["audit"]["files"],
               ", ".join(auto_nocheck) or "none", ", ".join(manual_check) or "none"))
    out = "%s/%s.zip" % (a.out.rstrip("/"), key)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("%s/securitas-benchmark.json" % key, json.dumps(pkg, indent=1))
        z.writestr("%s/SOURCES.txt" % key, src)
        for i in sorted(az.infolist(), key=lambda i: i.filename):
            if i.is_dir():
                continue
            rel = i.filename[len(atop) + 1:]
            if rel.startswith((".git/", ".github/")):
                continue
            z.writestr("%s/audit/%s" % (key, rel), az.read(i))
    print(src)
    print("wrote", out)


if __name__ == "__main__":
    main()
