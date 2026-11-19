"""What Securitas gets its data from, and how each platform is scanned (Settings > Sources).

Kept next to the code so the descriptions match what actually runs: the Linux and Windows sections show the
exact command and script the scanners send.
"""
import datetime
import glob
import os

from . import scan_linux, scan_windows

# Ranking sources can be switched off on their own. Platform sources are what a platform's scan is built on,
# so their switch turns scanning of that platform on or off.
SOURCES = [
    {
        "id": "kev", "name": "CISA Known Exploited Vulnerabilities (KEV) catalog", "kind": "ranking", "setting": "kev_enabled",
        "url_attr": "kev_url", "home": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "refresh": "Downloaded at most once an hour; the last good copy is kept if a download fails.",
        "what": "The US Cybersecurity and Infrastructure Security Agency's list of CVEs that have been exploited in the "
                "wild, with the date each was added and whether it is known to be used by ransomware.",
        "use": "A CVE in the catalog is always a priority, is listed first and is marked 'Known exploited'.",
        "off": "No CVE is marked known-exploited. Priorities then come from EPSS alone (or, with EPSS also off, every "
               "CVE is listed unranked). The catalog is not downloaded while it is off.",
    },
    {
        "id": "epss", "name": "FIRST Exploit Prediction Scoring System (EPSS)", "kind": "ranking", "setting": "epss_enabled",
        "url_attr": "epss_url", "home": "https://www.first.org/epss/",
        "refresh": "Downloaded at most twice a day (EPSS publishes once a day).",
        "what": "A daily score for every published CVE: the estimated probability that it will be exploited in the next "
                "30 days, from FIRST.org.",
        "use": "A CVE whose score is at or above the EPSS threshold is a priority. Scores also order the list after "
               "known-exploited CVEs.",
        "off": "Priorities come from the KEV catalog alone (or, with KEV also off, every CVE is listed unranked). "
               "Scores are not downloaded while it is off.",
    },
    {
        "id": "trivy", "name": "Trivy Operator (Aqua Security)", "kind": "platform", "platform": "kubernetes",
        "setting": "platform_kubernetes", "home": "https://aquasecurity.github.io/trivy-operator/",
        "refresh": "Trivy Operator rescans images on its own schedule (its report TTL) and updates its vulnerability "
                   "database itself; Securitas reads the reports on the Kubernetes schedule.",
        "what": "Trivy Operator, installed in the cluster, scans every container image in use and stores the findings as "
                "VulnerabilityReport objects. Trivy's database combines the NVD, GitHub Security Advisories, operating "
                "system vendors' advisories (Alpine, Debian, Ubuntu, Red Hat and others) and language package advisories.",
        "use": "The Kubernetes section: one row per image with its CVE counts, and the priority CVEs with the affected "
               "images, packages and fixed versions.",
        "off": "Kubernetes is not scanned: scheduled and manual Kubernetes scans are skipped. The last results stay in "
               "the report, marked as no longer updated.",
    },
    {
        "id": "dnf", "name": "dnf security advisories (RHEL family)", "kind": "platform", "platform": "linux",
        "setting": "platform_linux", "home": "https://dnf.readthedocs.io/en/latest/command_ref.html#updateinfo-command-label",
        "refresh": "Read live from the repositories at every Linux scan.",
        "what": "The security advisories (errata) published in the hosts' package repositories, for example Rocky Linux "
                "RLSA or Red Hat RHSA notices, as reported by `dnf updateinfo` on each host. When the repository "
                "override is set, the listed upstream repositories are used instead of the hosts' own.",
        "use": "The Linux section: pending security advisories per host, with the CVEs they fix and their severity.",
        "off": "Linux hosts are not scanned. The last results stay in the report, marked as no longer updated.",
    },
    {
        "id": "msrc", "name": "Microsoft Security Response Center (MSRC) release data", "kind": "platform",
        "platform": "windows", "setting": "platform_windows", "url_attr": "msrc_url",
        "home": "https://msrc.microsoft.com/update-guide/",
        "refresh": "Each monthly release is downloaded once and cached; the two newest months are re-read daily.",
        "what": "Microsoft's monthly security update data (CVRF), listing for every CVE the Windows builds that fix it "
                "and its severity per product.",
        "use": "The Windows section: every CVE whose fixed build is newer than the build a server runs.",
        "off": "Windows servers are not scanned. The last results stay in the report, marked as no longer updated.",
    },
]

TOOLS = {
    "kubernetes": {
        "title": "Kubernetes",
        "how": ["Securitas lists the VulnerabilityReport objects in the cluster through the Kubernetes API, read-only, "
                "with its own service account (permissions: get and list on vulnerabilityreports).",
                "It does not scan images itself; Trivy Operator does that and keeps the reports current.",
                "Only the namespaces in the Helm value config.namespaces are read when it is set; otherwise all."],
    },
    "linux": {
        "title": "Linux",
        "how": ["Securitas connects to each target over SSH with a key, as an account with no root or sudo rights.",
                "The host key is recorded on first contact and checked on every later scan (or taken from a known_hosts "
                "file when one is configured).",
                "It runs one shell script (below). dnf reads repository metadata only; nothing is installed or changed, "
                "and --assumeno answers no to any prompt."],
    },
    "windows": {
        "title": "Windows",
        "how": ["Securitas connects to each target over WinRM (HTTPS on port 5986 by default) as an account with no admin "
                "rights: a member of Remote Management Users, with WMI Enable Account and Remote Enable on root\\cimv2.",
                "It runs one PowerShell script (below) that reads the OS name, build and update revision, installation "
                "type and installed programs. Nothing is installed or changed.",
                "The build is compared with Microsoft's release data; third-party programs are listed but not checked."],
    },
}


def _age(path):
    try:
        return datetime.datetime.fromtimestamp(os.path.getmtime(path), datetime.timezone.utc)
    except OSError:
        return None


def status(cfg, feed_src):
    """Per source: the configured URL and what was last fetched."""
    out = {}
    out["kev"] = {"version": feed_src.get("kev", ""), "fetched": _age(os.path.join(cfg.data_dir, "kev.json"))}
    out["epss"] = {"version": feed_src.get("epss", ""), "fetched": _age(os.path.join(cfg.data_dir, "epss.csv.gz"))}
    months = sorted(os.path.basename(p)[:-5] for p in glob.glob(os.path.join(cfg.data_dir, "msrc", "*.json")))
    newest = max((_age(p) for p in glob.glob(os.path.join(cfg.data_dir, "msrc", "*.json"))), default=None,
                 key=lambda d: d or datetime.datetime.min.replace(tzinfo=datetime.timezone.utc))
    out["msrc"] = {"version": ("%d months cached, %s to %s" % (len(months), months[0], months[-1])) if months else "",
                   "fetched": newest}
    for s in SOURCES:
        if s.get("url_attr"):
            out[s["id"]]["url"] = getattr(cfg, s["url_attr"])
    return out


def scripts(cfg):
    """The exact Linux command script and Windows PowerShell script the scanners send."""
    try:
        linux = scan_linux.remote_script(cfg.linux_repos)
    except ValueError as e:
        linux = "# repository override is invalid: %s" % e
    return {"linux": linux, "windows": scan_windows.PS_SCRIPT.strip()}


__all__ = ["SOURCES", "TOOLS", "status", "scripts"]
