"""Unit tests on synthetic data. Run: python -m unittest discover -s tests"""
import base64
import json
import os
import re
import sys
import tempfile
import time
import unittest
import urllib.parse
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from securitas import auth, feeds, render, report, scan_linux, scan_windows  # noqa: E402
from securitas.config import Config, LdapConfig, OidcConfig  # noqa: E402
from securitas.db import PlatformResult, ResultStats, Scan, func, select  # noqa: E402


def pri(sec):
    """CVE IDs of a platform section's priority rows (the section lists every CVE since 0.4.0)."""
    return [r["cve"] for r in sec["cves"] if r["priority"]]


def vuln(vid, sev, pkg, fixed="", title=""):
    return {"vulnerabilityID": vid, "severity": sev, "resource": pkg, "fixedVersion": fixed, "title": title or f"{vid} in {pkg}"}


def rep(ns, repo, tag, vulns, server="index.docker.io"):
    return {"metadata": {"namespace": ns},
            "report": {"registry": {"server": server}, "artifact": {"repository": repo, "tag": tag}, "vulnerabilities": vulns}}


REPORTS = [
    rep("web", "library/app", "1.0", [vuln("CVE-2099-0001", "CRITICAL", "libfoo", "1.2"),
                                      vuln("CVE-2099-0002", "HIGH", "libbar"),
                                      vuln("CVE-2099-0003", "LOW", "libbaz", "2.0")]),
    rep("db", "library/app", "1.0", [vuln("CVE-2099-0001", "CRITICAL", "libfoo", "1.2")]),
    rep("ops", "team/tool", "2.3", [vuln("CVE-2099-0004", "MEDIUM", "<script>", "", "x <b>y</b>")], server="ghcr.io"),
    rep("clean", "library/quiet", "1", []),
]
KEV = {"CVE-2099-0002": {"cveID": "CVE-2099-0002", "dateAdded": "2099-01-02", "knownRansomwareCampaignUse": "Known",
                         "vulnerabilityName": "Bar flaw"}}
EPSS = {"CVE-2099-0001": 0.42, "CVE-2099-0003": 0.01, "CVE-2099-0004": 0.15}


def ranker():
    return report.Ranker(KEV, EPSS, 0.10)


class Ranking(unittest.TestCase):
    def test_kubernetes(self):
        sec = report.build_platform(report.kubernetes_raw(REPORTS), ranker())
        self.assertEqual(pri(sec), ["CVE-2099-0002", "CVE-2099-0001", "CVE-2099-0004"])
        self.assertEqual([r["cve"] for r in sec["cves"]][-1], "CVE-2099-0003")      # every CVE, non-priority last
        self.assertEqual(sec["totals"]["Images scanned"], 3)
        self.assertEqual(sec["totals"]["In CISA KEV"], 1)
        self.assertEqual([s["name"] for s in sec["systems"]], ["library/app:1.0", "ghcr.io/team/tool:2.3"])
        self.assertEqual(sec["systems"][0]["namespaces"], "db, web")
        self.assertEqual(sec["systems"][0]["kev"], 1)
        self.assertTrue(sec["systems_caption"].endswith("(2 of 3)"))
        top = sec["cves"][0]
        self.assertTrue(top["ransomware"])
        self.assertEqual(top["fix"], "No fix published")

    def test_rerank_without_rescan(self):
        raw = report.kubernetes_raw(REPORTS)
        later = report.Ranker({**KEV, "CVE-2099-0003": {"dateAdded": "2099-02-01"}}, EPSS, 0.10)
        self.assertIn("CVE-2099-0003", pri(report.build_platform(raw, later)))
        self.assertNotIn("CVE-2099-0003", pri(report.build_platform(raw, ranker())))

    def test_html_escaped_and_pdf_name(self):
        cfg = Config()
        sec = report.build_platform(report.kubernetes_raw(REPORTS), ranker())
        m = report.model(cfg, [sec], {"kev": "k", "epss": "e"}, ["<i>warn</i>"])
        body = render.report_body(m)
        self.assertNotIn("<b>y</b>", body)
        self.assertNotIn("<i>warn</i>", body)
        self.assertIn("&lt;script&gt;", body)
        self.assertTrue(render.pdf_name(dict(m, label="Scan #12")).endswith("-scan-12.pdf"))

    def test_extra_platform(self):
        d = tempfile.mkdtemp()
        with open(d + "/a.json", "w") as f:
            json.dump({"id": "linux", "title": "Linux", "cves": [{"cve": "CVE-2099-0002", "systems": ["h1"]},
                                                                 {"cve": "CVE-2099-0003", "systems": "h2"}]}, f)
        with open(d + "/bad.json", "w") as f:
            f.write("{")
        w = []
        ex = report.load_extra(d, w)
        self.assertEqual(len(ex), 1)
        self.assertEqual(len(w), 1)
        sec = report.build_platform(report.extra_raw(ex[0]), ranker())
        self.assertEqual(pri(sec), ["CVE-2099-0002"])

    def test_pdf(self):
        try:
            import weasyprint  # noqa: F401
        except ImportError:
            self.skipTest("WeasyPrint not installed")
        sec = report.build_platform(report.kubernetes_raw(REPORTS), ranker())
        pdf = render.render_pdf(render.pdf_html(report.model(Config(), [sec], {"kev": "", "epss": ""}, [])))
        self.assertTrue(pdf.startswith(b"%PDF"))


LINUX_OUT = """##OS Rocky Linux 9.8
##KERNEL 5.14.0
##LASTUPD 2026-11-09
Updates Information Summary: available
    3 Security notice(s)
        1 Critical Security notice(s)
        2 Important Security notice(s)
##LIST
CVE-2099-1000 Important/Sec. openssl-libs-1:3.2.2-6.el9_5.x86_64
CVE-2099-1000 Important/Sec. openssl-1:3.2.2-6.el9_5.x86_64
CVE-2099-0002 Critical/Sec.  kernel-5.14.0-570.el9.x86_64
##END
"""


class Severity(unittest.TestCase):
    def test_levels(self):
        self.assertEqual([report.sev_level(x) for x in ("CRITICAL", "Important", "high", "Moderate", "MEDIUM", "Low", "", None, "?")],
                         ["critical", "high", "high", "medium", "medium", "low", "unknown", "unknown", "unknown"])
        total, lv = report.raw_stats(report.kubernetes_raw(REPORTS))
        self.assertEqual(total, 4)
        self.assertEqual(lv, {"critical": 1, "high": 1, "medium": 1, "low": 1, "unknown": 0})

    def test_section_lists_every_cve_with_level(self):
        sec = report.build_platform(report.kubernetes_raw(REPORTS), ranker())
        self.assertEqual({r["cve"]: r["level"] for r in sec["cves"]},
                         {"CVE-2099-0001": "critical", "CVE-2099-0002": "high", "CVE-2099-0004": "medium", "CVE-2099-0003": "low"})
        self.assertFalse([r for r in sec["cves"] if r["cve"] == "CVE-2099-0003"][0]["priority"])
        m = report.model(Config(), [sec], {"kev": "", "epss": ""}, [])
        self.assertEqual(report.platform_levels(m)[0]["levels"]["low"], 1)
        self.assertEqual(report.summary(m)[0]["priority"], 3)   # the summary table still counts priority CVEs

    def test_old_stored_reports_count_as_priority(self):
        self.assertTrue(report.is_priority({"cve": "x"}))
        self.assertEqual(report.result_stats({}, {"cves": [{"cve": "a", "kev": "2099-01-01"}, {"cve": "b", "kev": ""}]}),
                         {"total": 0, "levels": {k: 0 for k in report.LEVEL_KEYS}, "priority": 2, "kev": 1})

    def test_filter_and_paging(self):
        sec = report.build_platform(report.kubernetes_raw(REPORTS), ranker())
        m = report.model(Config(), [sec], {"kev": "", "epss": ""}, [])
        v = render.parse_view({"sev": ["critical", "low", "bogus"]})
        self.assertEqual(v["levels"], ["critical", "low"])
        body = render.report_body(m, v)
        self.assertIn("CVE-2099-0003", body)
        self.assertNotIn("CVE-2099-0002", body)
        self.assertIn("2 shown of 4", body)
        self.assertEqual(render.view_query(v), "sev=critical&sev=low")
        v = render.parse_view({"priority": "1"})
        self.assertEqual(v["levels"], report.LEVEL_KEYS)           # no level given: all of them
        self.assertNotIn("CVE-2099-0003", render.report_body(m, v))
        self.assertEqual(render.view_query(render.default_view()), "")
        old, old_pdf = render.PAGE_SIZE, render.PDF_MAX_ROWS
        render.PAGE_SIZE = 3
        try:
            page1 = render.report_body(m, render.default_view(), paged=True)
            page2 = render.report_body(m, render.parse_view({"p_kubernetes": "2"}), paged=True)
        finally:
            render.PAGE_SIZE = old
        self.assertIn("Page 1 of 2", page1)
        self.assertNotIn("CVE-2099-0003", page1)
        self.assertIn("CVE-2099-0003", page2)
        self.assertIn('href="?p_kubernetes=2#kubernetes"', page1)
        render.PDF_MAX_ROWS = 2
        try:
            pdf_body = render.report_body(m, render.default_view())            # not paged: the PDF
        finally:
            render.PDF_MAX_ROWS = old_pdf
        self.assertIn("The first 2 of 4 matching CVEs are listed", pdf_body)
        self.assertNotIn("CVE-2099-0003", pdf_body)


class History(unittest.TestCase):
    def test_points(self):
        import datetime as dt
        today = dt.date(2026, 11, 19)
        pts = report.range_points("day", today)
        self.assertEqual((len(pts), pts[0][1], pts[-1][1]), (7, dt.date(2026, 11, 13), today))
        self.assertEqual(len(report.range_points("week", today)), 13)
        m = report.range_points("month", today)
        self.assertEqual((len(m), m[0][0], m[-1][1]), (12, "Dec 2025", today))
        self.assertEqual(m[-2][1], dt.date(2026, 10, 31))
        self.assertEqual(report.range_points("month", dt.date(2026, 3, 5))[0][1], dt.date(2025, 4, 30))

    def test_carry_forward(self):
        import datetime as dt
        d = lambda x: dt.date(2026, 11, x)
        h = report.history([("windows", d(1), 100), ("windows", d(15), 80), ("windows", d(15), 70), ("linux", d(18), 5)],
                           "day", d(19), ("kubernetes", "linux", "windows"))
        self.assertEqual([s["id"] for s in h["series"]], ["linux", "windows"])   # never scanned: no line
        self.assertEqual(h["series"][1]["values"], [100, 100, 70, 70, 70, 70, 70])  # newest result of the day wins
        self.assertEqual(h["series"][0]["values"], [None] * 5 + [5, 5])

    def test_compliance_history(self):
        import datetime as dt
        d = lambda x: dt.date(2026, 11, x)
        rows = [("linux", "a", d(14), 40.0), ("linux", "b", d(15), 60.0), ("linux", "a", d(17), 80.0),
                ("linux", "c", d(18), None), ("windows", "w", d(19), 90.0)]
        h = report.compliance_history(rows, "day", d(19), ("kubernetes", "linux", "windows"))
        self.assertEqual([s["id"] for s in h["series"]], ["linux", "windows"])
        self.assertEqual(h["series"][0]["values"], [None, 40.0, 50.0, 50.0, 70.0, 70.0, 70.0])   # newest per host, averaged
        self.assertEqual(h["series"][1]["values"], [None] * 6 + [90.0])
        from securitas import charts
        out = charts.history_svg(h, what="Average compliance score per platform", gid="chist", percent=True)
        self.assertIn("<title>Linux, Nov 19: 70.0%</title>", out)
        self.assertIn('aria-labelledby="chist-t"', out)
        self.assertIn(">100%</text>", out)                                                       # fixed 0-100 axis

    def test_svg(self):
        from securitas import charts
        h = {"labels": ["a", "b"], "series": [{"id": "linux", "title": "Linux", "values": [3, 7]}], "range": "week"}
        out = charts.history_svg(h)
        self.assertIn("<svg", out)
        self.assertIn("var(--pl-linux", out)
        self.assertIn("<title>Linux, b: 7 CVEs</title>", out)
        self.assertIn("Show as a table", out)
        self.assertIn("No history yet", charts.history_svg({"labels": [], "series": [], "range": "day"}))
        pie = charts.pie_svg({"id": "k", "title": "K", "total": 4, "levels": {"critical": 1, "high": 3, "medium": 0, "low": 0, "unknown": 0}})
        self.assertEqual(pie.count('class="slice"'), 2)
        self.assertIn("75.0%", pie)
        self.assertIn('class="slice" cx="90"', charts.pie_svg({"id": "k", "title": "K", "total": 2,
                                                               "levels": {"low": 2}}))   # one level: a full circle


class Linux(unittest.TestCase):
    def test_parse(self):
        r = scan_linux.parse(LINUX_OUT)
        self.assertEqual((r["os"], r["patched"], r["notices"], r["critical"], r["important"]), ("Rocky Linux 9.8", "2026-11-09", 3, 1, 2))
        self.assertEqual(sorted(r["cves"]), ["CVE-2099-0002", "CVE-2099-1000"])
        self.assertEqual(r["cves"]["CVE-2099-1000"]["packages"], {"openssl-libs", "openssl"})

    def test_incomplete_output_fails(self):
        with self.assertRaises(RuntimeError):
            scan_linux.parse(LINUX_OUT.replace("##END", ""))

    def test_scan_builds_platform(self):
        cfg = Config(ssh_user="u", ssh_key_file="/k")
        orig = scan_linux.run_host
        scan_linux.run_host = lambda c, t, rk: (_ for _ in ()).throw(OSError("timed out")) if t["host"] == "bad" else scan_linux.parse(LINUX_OUT)
        try:
            raw = scan_linux.scan(cfg, [{"id": 1, "host": "good", "label": "Web", "host_key": ""},
                                        {"id": 2, "host": "bad", "label": "", "host_key": ""}], lambda m: None, None)
        finally:
            scan_linux.run_host = orig
        self.assertEqual(raw["failed"], 1)
        sec = report.build_platform(raw, ranker())
        self.assertEqual(pri(sec), ["CVE-2099-0002"])
        self.assertEqual(sec["systems"][0]["kev"], 1)
        self.assertEqual(sec["systems"][1]["status"], "Scan failed")
        self.assertIn("openssl", [f for f in raw["findings"] if f["cve"] == "CVE-2099-1000"][0]["component"])

    def test_repo_override(self):
        s = scan_linux.remote_script(["up=https://mirror/{major}/BaseOS/{arch}/os/"])
        self.assertIn("--disablerepo=*", s)
        self.assertIn("--repofrompath=up,https://mirror/${MAJ}/BaseOS/${ARCH}/os/", s)
        with self.assertRaises(ValueError):
            scan_linux.remote_script(["nourl"])


class Windows(unittest.TestCase):
    MONTHS = [("2026-Oct", {"products": {"11924": "Windows Server 2022 (Server Core installation)", "11923": "Windows Server 2022"},
                            "vulns": {"CVE-2099-0002": {"title": "Old", "fixes": {"11924": ["10.0.20348.3000"]}, "severity": {"11924": "Critical"}},
                                      "CVE-2099-0009": {"title": "New", "fixes": {"11924": ["10.0.20348.4000"], "11923": ["10.0.20348.4000"]},
                                                        "severity": {"11924": "Important"}}}})]

    def test_product_name(self):
        self.assertEqual(scan_windows.product_name({"os": "Microsoft Windows Server 2022 Standard", "installation": "Server Core"}),
                         "Windows Server 2022 (Server Core installation)")
        self.assertEqual(scan_windows.product_name({"os": "Microsoft Windows Server 2016 Datacenter", "installation": "Server"}),
                         "Windows Server 2016")
        self.assertEqual(scan_windows.product_name({"os": "Microsoft Windows 11 Pro", "display_version": "24H2", "arch": "64-bit"}),
                         "Windows 11 Version 24H2 for x64-based Systems")

    def test_missing(self):
        info = {"os": "Microsoft Windows Server 2022 Standard", "installation": "Server Core", "build": "20348.3453"}
        miss, name = scan_windows.missing(info, self.MONTHS)
        self.assertEqual(sorted(miss), ["CVE-2099-0009"])
        self.assertEqual(miss["CVE-2099-0009"], ("Important", "2026-10", "New"))
        with self.assertRaises(RuntimeError):
            scan_windows.missing({"os": "Something else", "build": "1.2"}, self.MONTHS)

    def test_reduce_cvrf(self):
        doc = {"ProductTree": {"FullProductName": [{"ProductID": "1", "Value": "Windows Server 2025"}]},
               "Vulnerability": [{"CVE": "CVE-2099-0001", "Title": {"Value": "T"},
                                  "Remediations": [{"ProductID": ["1"], "FixedBuild": "10.0.26100.100"}, {"ProductID": ["1"]}],
                                  "Threats": [{"Type": 3, "ProductID": ["1"], "Description": {"Value": "Critical"}}]},
                                 {"CVE": "CVE-2099-0002", "Remediations": [{"ProductID": ["1"]}]}]}
        red = feeds._reduce_cvrf(doc)
        self.assertEqual(red["products"], {"1": "Windows Server 2025"})
        self.assertEqual(list(red["vulns"]), ["CVE-2099-0001"])
        self.assertEqual(red["vulns"]["CVE-2099-0001"]["severity"], {"1": "Critical"})
        self.assertEqual(feeds.month_key("2026-Nov"), (2026, 11))
        self.assertIsNone(feeds.month_key("2017-May-B"))


class Roles(unittest.TestCase):
    def test_permissions(self):
        self.assertTrue(auth.can("viewer", "view"))
        self.assertFalse(auth.can("viewer", "scan.run"))
        self.assertTrue(auth.can("operator", "schedule.edit"))
        self.assertFalse(auth.can("operator", "target.edit"))
        self.assertTrue(auth.can("admin", "user.manage"))
        self.assertFalse(auth.can("", "view"))

    def test_groups(self):
        maps = {"securitas-admins": "admin", "securitas-viewers": "viewer"}
        self.assertEqual(auth.role_from_groups(["CN=Securitas-Viewers,OU=Groups,DC=x", "CN=Securitas-Admins,OU=Groups,DC=x"], maps), "admin")
        self.assertEqual(auth.role_from_groups(["securitas-viewers"], maps), "viewer")
        self.assertEqual(auth.role_from_groups(["Other"], maps), "")
        self.assertEqual(auth.group_cn("CN=A\\, B,OU=x"), "a, b")

    def test_password(self):
        h = auth.hash_password("correct horse battery")
        self.assertTrue(auth.verify_password(h, "correct horse battery"))
        self.assertFalse(auth.verify_password(h, "wrong"))
        self.assertFalse(auth.verify_password("", "anything"))
        self.assertTrue(auth.password_problem("short"))

    def test_throttle(self):
        t = auth.Throttle(limit=2, window=60)
        t.fail("a")
        self.assertFalse(t.blocked("a"))
        t.fail("a")
        self.assertTrue(t.blocked("a", "b"))
        t.clear("a")
        self.assertFalse(t.blocked("a"))


# ---------------------------------------------------------------- web app

ADMIN_PW = "correct-horse-battery-staple"


def fake_kubernetes(say):
    say("fake kubernetes")
    return report.kubernetes_raw(REPORTS)


class FakeFeeds:
    """Test KEV/EPSS data that follows the source switches in Settings, like jobs.Feeds."""

    def __init__(self, settings):
        self.settings, self.at = settings, 1

    def get(self, force=False):
        return KEV, EPSS, {"kev": "test KEV", "epss": "test EPSS"}, []

    def ranker(self, force=False):
        c = self.settings.effective()
        src = {"kev": "test KEV" if c.kev_enabled else "CISA KEV catalog turned off",
               "epss": "test EPSS" if c.epss_enabled else "EPSS scores turned off"}
        return report.Ranker(KEV, EPSS, c.epss_min, c.kev_enabled, c.epss_enabled), src, []


def make_app(**over):
    from securitas.server import build
    over.setdefault("secret_key", "test-secret-key")
    cfg = Config(database_url="sqlite://", data_dir=tempfile.mkdtemp(), secure_cookies=False, admin_password=ADMIN_PW,
                 role_map=["Securitas-Admins=admin", "Securitas-Operators=operator", "Securitas-Viewers=viewer"],
                 base_url="http://testserver",
                 schedules={"kubernetes": "5 * * * *", "linux": "0 5 * * *", "windows": "30 5 * * *"}, **over)
    app, db, jobs = build(cfg, start_threads=False, scanners={"kubernetes": fake_kubernetes})
    jobs.feeds = FakeFeeds(jobs.settings)
    return app, db, jobs, cfg


def client(app):
    from fastapi.testclient import TestClient
    return TestClient(app, base_url="http://testserver")


def login(c, user, pw):
    r = c.get("/login")
    pre = re.search(r'name="pre" value="([^"]+)"', r.text).group(1)
    return c.post("/login", data={"username": user, "password": pw, "pre": pre, "next": "/"}, follow_redirects=False)


def csrf(c, path="/account"):
    return re.search(r'name="csrf" value="([^"]+)"', c.get(path).text).group(1)


class Web(unittest.TestCase):
    def setUp(self):
        self.app, self.db, self.jobs, self.cfg = make_app()
        self.c = client(self.app)

    def test_requires_login(self):
        for p in ("/", "/scans", "/report.pdf", "/data.json", "/settings/users"):
            r = self.c.get(p, follow_redirects=False)
            self.assertEqual(r.status_code, 303, p)
            self.assertTrue(r.headers["location"].startswith("/login"), p)
        self.assertEqual(self.c.get("/healthz").status_code, 200)
        r = self.c.post("/scans", data={"platform": "kubernetes"}, follow_redirects=False)
        self.assertEqual(r.headers["location"], "/login")

    def test_login_and_headers(self):
        self.assertEqual(login(self.c, "admin", "wrong").headers["location"].split("&")[0], "/login?next=%2F")
        r = login(self.c, "admin", ADMIN_PW)
        self.assertEqual(r.headers["location"], "/")
        r = self.c.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("script-src", r.headers["content-security-policy"].replace("default-src 'none'", "script-src"))
        self.assertNotIn("<script", r.text)
        self.assertIn("No scan has finished yet", r.text)

    def test_login_needs_form_token(self):
        r = self.c.post("/login", data={"username": "admin", "password": ADMIN_PW, "pre": "x"}, follow_redirects=False)
        self.assertIn("e=expired", r.headers["location"])

    def test_open_redirect_blocked(self):
        r = self.c.get("/login")
        pre = re.search(r'name="pre" value="([^"]+)"', r.text).group(1)
        r = self.c.post("/login", data={"username": "admin", "password": ADMIN_PW, "pre": pre, "next": "https://evil.example/"},
                        follow_redirects=False)
        self.assertEqual(r.headers["location"], "/")

    def test_csrf_and_scan_history(self):
        login(self.c, "admin", ADMIN_PW)
        r = self.c.post("/scans", data={"platform": "kubernetes"}, follow_redirects=False)
        self.assertIn("err=csrf", r.headers["location"])
        r = self.c.post("/scans", data={"csrf": csrf(self.c), "platform": "kubernetes"}, follow_redirects=False)
        self.assertEqual(r.headers["location"], "/scans/1?ok=queued")
        self.assertIn("http-equiv=\"refresh\"", self.c.get("/scans/1").text)
        sid = self.jobs._claim()
        self.jobs.run_scan(sid)
        page = self.c.get("/scans/1").text
        self.assertIn("CVE-2099-0002", page)
        self.assertNotIn("http-equiv=\"refresh\"", page)
        self.assertIn("CVE-2099-0002", self.c.get("/report").text)
        self.assertIn("#1", self.c.get("/scans").text)
        data = self.c.get("/scans/1/data.json").json()
        self.assertEqual(data["label"], "Scan #1")
        self.assertEqual(self.c.get("/scans/99").status_code, 404)

    def test_theme(self):
        login(self.c, "admin", ADMIN_PW)
        self.assertIn('<html lang="en">', self.c.get("/").text)
        self.c.post("/account/theme", data={"csrf": csrf(self.c), "theme": "dark", "next": "/scans"})
        self.assertIn('data-theme="dark"', self.c.get("/").text)
        self.c.post("/account/theme", data={"csrf": csrf(self.c), "theme": "light", "next": "/"})
        self.assertIn('data-theme="light"', self.c.get("/").text)
        # the login page has no selector and follows the system setting
        self.assertNotIn('action="/account/theme"', client(self.app).get("/login").text)

    def test_rbac(self):
        login(self.c, "admin", ADMIN_PW)
        tok = csrf(self.c)
        for name, role in (("vera", "viewer"), ("otto", "operator")):
            self.c.post("/settings/users", data={"csrf": tok, "username": name, "password": "a-long-password-1", "role": role})
        v = client(self.app)
        self.assertEqual(login(v, "vera", "a-long-password-1").headers["location"], "/")
        self.assertEqual(v.get("/").status_code, 200)
        self.assertEqual(v.get("/scans").status_code, 200)
        self.assertNotIn("Run scan", v.get("/scans").text)
        self.assertEqual(v.post("/scans", data={"csrf": csrf(v), "platform": "kubernetes"}).status_code, 403)
        for p in ("/vulnerabilities/schedules", "/targets", "/settings/users", "/settings/authentication", "/audit"):
            self.assertEqual(v.get(p).status_code, 403, p)
        o = client(self.app)
        login(o, "otto", "a-long-password-1")
        self.assertEqual(o.post("/scans", data={"csrf": csrf(o), "platform": "kubernetes"}, follow_redirects=False).status_code, 303)
        self.assertEqual(o.get("/vulnerabilities/schedules").status_code, 200)
        r = o.post("/vulnerabilities/schedules/linux", data={"csrf": csrf(o), "cron": "15 3 * * 1", "enabled": "on"}, follow_redirects=False)
        self.assertIn("ok=saved", r.headers["location"])
        bad = o.post("/vulnerabilities/schedules/linux", data={"csrf": csrf(o), "cron": "bad"}, follow_redirects=False)
        self.assertEqual(bad.status_code, 400)
        self.assertIn("not a valid cron expression", bad.text)
        for p in ("/targets", "/settings/users", "/settings/authentication", "/audit"):
            self.assertEqual(o.get(p).status_code, 403, p)
        audit = self.c.get("/audit").text
        self.assertIn("scan.run", audit)
        self.assertIn("schedule.saved", audit)

    def test_targets(self):
        login(self.c, "admin", ADMIN_PW)
        tok = csrf(self.c)
        self.c.post("/targets", data={"csrf": tok, "platform": "linux", "host": "web1.example.com", "label": "Web"})
        self.assertIn("err=host", self.c.post("/targets", data={"csrf": tok, "platform": "linux", "host": "bad host;rm"},
                                              follow_redirects=False).headers["location"])
        self.assertIn("web1.example.com", self.c.get("/targets").text)
        self.assertIn("1 target)", self.c.get("/scans").text)

    def test_last_admin_and_self(self):
        login(self.c, "admin", ADMIN_PW)
        r = self.c.post("/settings/users/1", data={"csrf": csrf(self.c), "action": "role", "role": "viewer"}, follow_redirects=False)
        self.assertIn("err=self", r.headers["location"])

    def test_builtin_admin_keeps_role(self):
        login(self.c, "admin", ADMIN_PW)
        self.c.post("/settings/users", data={"csrf": csrf(self.c), "username": "ada", "password": "a-long-password-1", "role": "admin"})
        o = client(self.app)
        login(o, "ada", "a-long-password-1")
        page = o.get("/settings/users").text
        self.assertIn("Built-in admin: always Admin", page)
        self.assertNotIn('aria-label="Role for admin"', page)                       # no role drop-down for it
        self.assertIn('aria-label="Role for ada"', self.c.get("/settings/users").text)   # others keep theirs
        from securitas.db import User
        with self.db.Session() as s:
            uid = s.scalar(select(User.id).where(User.username == "admin"))
        for action in ({"action": "role", "role": "viewer"}, {"action": "disable"}):
            r = o.post("/settings/users/%d" % uid, data={"csrf": csrf(o), **action}, follow_redirects=False)
            self.assertIn("err=builtin", r.headers["location"])
        with self.db.Session() as s:
            u = s.get(User, uid)
            self.assertEqual((u.role, u.disabled), ("admin", False))

    def test_password_change_and_disable(self):
        login(self.c, "admin", ADMIN_PW)
        tok = csrf(self.c)
        self.c.post("/settings/users", data={"csrf": tok, "username": "pat", "password": "first-password-1", "role": "viewer"})
        p = client(self.app)
        login(p, "pat", "first-password-1")
        r = p.post("/account/password", data={"csrf": csrf(p), "current": "first-password-1", "new": "second-password-2",
                                              "again": "second-password-2"}, follow_redirects=False)
        self.assertIn("ok=pw", r.headers["location"])
        self.assertIn("err=managed", self.c.post("/account/password", data={"csrf": tok, "current": ADMIN_PW, "new": "x" * 20,
                                                                            "again": "x" * 20}, follow_redirects=False).headers["location"])
        from securitas.db import User
        with self.db.Session() as s:
            uid = s.query(User).filter_by(username="pat").one().id
        self.c.post("/settings/users/%d" % uid, data={"csrf": tok, "action": "disable"})
        self.assertEqual(p.get("/", follow_redirects=False).status_code, 303)
        self.assertIn("e=", login(client(self.app), "pat", "second-password-2").headers["location"])

    def test_local_login_off(self):
        login(self.c, "admin", ADMIN_PW)
        tok = csrf(self.c)
        self.c.post("/settings/users", data={"csrf": tok, "username": "loc", "password": "local-password-1", "role": "viewer"})
        self.c.post("/settings/authentication/local", data={"csrf": tok})
        self.assertIn("e=localoff", login(client(self.app), "loc", "local-password-1").headers["location"])
        self.assertEqual(login(client(self.app), "admin", ADMIN_PW).headers["location"], "/")   # break-glass

    def _scan(self, plats):
        with self.db.Session() as s, s.begin():
            self.jobs.enqueue(s, plats, "manual", "admin")
        sid = self.jobs._claim()
        self.jobs.run_scan(sid)
        return sid

    def test_summary_landing_page(self):
        login(self.c, "admin", ADMIN_PW)
        self.assertIn("No scan has finished yet", self.c.get("/vulnerabilities").text)
        self.assertIn("No scan has finished yet", self.c.get("/").text)                 # Home says so too
        self._scan(["kubernetes"])
        page = self.c.get("/vulnerabilities").text
        self.assertIn("<title>Summary", page)
        self.assertIn('href="/report#kubernetes"', page)
        m = self.jobs.current_model()
        row = report.summary(m)[0]
        self.assertEqual(row["priority"], len(pri(m["platforms"][0])))
        self.assertEqual(row["kev"], sum(1 for r in m["platforms"][0]["cves"] if r["kev"]))
        self.assertIn('<section id="kubernetes">', self.c.get("/report").text)
        self.assertNotIn("CVE-2099-0002", page)          # the summary lists counts, not CVEs

    def test_summary_charts_and_report_filter(self):
        login(self.c, "admin", ADMIN_PW)
        self.jobs.scanners["kubernetes"] = fake_kubernetes
        with self.db.Session() as s, s.begin():
            self.jobs.enqueue(s, ["kubernetes"], "manual", "admin")
        self.jobs.run_scan(self.jobs._claim())
        page = self.c.get("/vulnerabilities").text
        self.assertIn('id="history"', page)
        self.assertIn('class="on" aria-current="true" href="/vulnerabilities?range=day#history"', page)   # default: daily
        self.assertIn("<title>Kubernetes,", page)
        self.assertIn('id="pie-lv-kubernetes"', page)
        self.assertNotIn("<script", page)
        self.assertIn('aria-current="true" href="/vulnerabilities?range=month#history"', self.c.get("/vulnerabilities?range=month").text)
        self.assertIn('aria-current="true" href="/vulnerabilities?range=day#history"', self.c.get("/vulnerabilities?range=bogus").text)
        rep_ = self.c.get("/report").text
        self.assertIn("CVE-2099-0003", rep_)                       # low, not a priority: listed now
        self.assertIn('name="sev" value="low" checked', rep_)
        rep_ = self.c.get("/report?sev=critical").text
        self.assertNotIn("CVE-2099-0003", rep_)
        self.assertIn('href="/report.pdf?sev=critical"', rep_)
        self.assertNotIn("CVE-2099-0003", self.c.get("/report?priority=1").text)
        with self.db.Session() as s:
            st = s.scalars(select(ResultStats)).all()
        self.assertEqual([(x.platform, x.total, x.priority, x.kev) for x in st], [("kubernetes", 4, 3, 1)])
        self.assertIn(">3<", self.c.get("/scans").text.replace(" ", ""))

    def test_stats_backfill(self):
        with self.db.Session() as s, s.begin():
            sc = Scan(platforms=["kubernetes"], trigger="manual", status="done")
            s.add(sc)
            s.flush()
            raw = report.kubernetes_raw(REPORTS)
            s.add(PlatformResult(scan_id=sc.id, platform="kubernetes", status="done", raw=raw,
                                 report=report.build_platform(raw, ranker()), sources={}))
        self.jobs.backfill_stats()
        self.jobs.backfill_stats()                                 # idempotent
        with self.db.Session() as s:
            self.assertEqual([x.total for x in s.scalars(select(ResultStats)).all()], [4])
        h = self.jobs.history("day")
        self.assertEqual(h["series"][0]["values"][-1], 4)

    def test_scan_history_platform_filter(self):
        login(self.c, "admin", ADMIN_PW)
        self.jobs.scanners["windows"] = self.jobs._scan_windows      # no targets: fails
        k = self._scan(["kubernetes"])
        w = self._scan(["windows"])
        page = self.c.get("/scans").text
        self.assertIn('href="/scans/%d"' % k, page)
        self.assertIn('href="/scans/%d"' % w, page)
        page = self.c.get("/scans?platform=windows").text
        self.assertNotIn('href="/scans/%d' % k, page)
        self.assertIn('href="/scans/%d#windows"' % w, page)
        self.assertIn('<option value="windows" selected>', page)
        self.assertIn("Failed", page)
        page = self.c.get("/scans?platform=linux").text
        self.assertIn("No scans included Linux", page)
        page = self.c.get("/scans?platform=bogus").text          # unknown value: no filter
        self.assertIn('href="/scans/%d"' % k, page)

    def test_failed_platform_shown_in_report(self):
        # Windows has no targets, so its scan fails and it has never had a good result
        login(self.c, "admin", ADMIN_PW)
        self.jobs.scanners["windows"] = self.jobs._scan_windows
        sid = self._scan(["kubernetes", "windows"])
        for path in ("/report", "/scans/%d" % sid):
            page = self.c.get(path).text
            self.assertIn('id="windows"', page, path)
            self.assertIn("Scan failed", page, path)
            self.assertIn("no Windows targets are configured", page, path)
            self.assertIn("CVE-2099-0002", page, path)      # the good platform is still listed
        self.assertIn("Scan failed", render.pdf_html(self.jobs.current_model()))
        summary = self.c.get("/").text
        self.assertIn('href="/report#windows"', summary)
        self.assertIn('href="/report#kubernetes"', summary)
        self.assertIn("Scan failed", summary)
        self.assertIn("No results", summary)

    def test_newer_failure_flags_older_results(self):
        login(self.c, "admin", ADMIN_PW)
        self.jobs.scanners["windows"] = lambda say: dict(fake_kubernetes(say), id="windows", title="Windows")
        good = self._scan(["windows"])
        page = self.c.get("/report").text
        self.assertNotIn("Scan failed", page)

        def broken(say):
            raise RuntimeError("WinRM <refused>")
        self.jobs.scanners["windows"] = broken
        bad = self._scan(["windows"])
        page = self.c.get("/report").text
        self.assertIn("Scan failed", page)
        self.assertIn("The latest scan (#%d" % bad, page)
        self.assertIn("from scan #%d" % good, page)
        self.assertIn("WinRM &lt;refused&gt;", page)        # escaped
        self.assertNotIn("WinRM <refused>", page)
        self.assertIn("CVE-2099-0002", page)                 # older results still shown

    def test_schedule_runs(self):
        from securitas.db import Schedule, Scan, utcnow
        import datetime
        with self.db.Session() as s, s.begin():
            for sc in s.query(Schedule).all():
                sc.next_run = utcnow() - datetime.timedelta(minutes=1)
        self.jobs.run_due()
        self.jobs.run_due()   # a second pass must not queue the same runs again
        with self.db.Session() as s:
            self.assertEqual(sorted(p for x in s.query(Scan).all() for p in x.platforms), ["kubernetes", "linux", "windows"])
            self.assertTrue(all(x.trigger == "schedule" for x in s.query(Scan).all()))
            self.assertTrue(all(sc.next_run > utcnow() for sc in s.query(Schedule).all()))


class Ldap(unittest.TestCase):
    """LDAP sign-in against ldap3's in-memory mock server."""

    def setUp(self):
        import ldap3
        self.app, self.db, self.jobs, self.cfg = make_app(ldap=LdapConfig(
            url="ldaps://dc.example.com", bind_dn="cn=svc,dc=example,dc=com", bind_password="svcpw",
            user_base="ou=users,dc=example,dc=com", nested_groups=False))
        server = ldap3.Server("mock")
        conn = ldap3.Connection(server, client_strategy=ldap3.MOCK_SYNC)
        conn.strategy.add_entry("cn=svc,dc=example,dc=com", {"userPassword": "svcpw", "objectClass": "person"})
        conn.strategy.add_entry("cn=Ann Admin,ou=users,dc=example,dc=com", {
            "userPassword": "ann-password", "objectClass": "user", "sAMAccountName": "ann", "displayName": "Ann Admin",
            "mail": "ann@example.com", "memberOf": ["CN=Securitas-Admins,OU=Groups,DC=example,DC=com"]})
        conn.strategy.add_entry("cn=Nobody,ou=users,dc=example,dc=com", {
            "userPassword": "nobody-password", "objectClass": "user", "sAMAccountName": "nobody", "memberOf": ["CN=Other,DC=x"]})
        self._srv, self._orig_conn = auth._ldap_server, auth._ldap_conn
        auth._ldap_server = lambda cfg, ca: server     # the mock directory lives on the Server object

        def make(cfg, srv, user, pw):
            c = ldap3.Connection(srv, user=user, password=pw, client_strategy=ldap3.MOCK_SYNC, raise_exceptions=False)
            return c if c.bind() else None
        auth._ldap_conn = make

    def tearDown(self):
        auth._ldap_server = self._srv
        auth._ldap_conn = self._orig_conn

    def test_lookup_and_login(self):
        info = auth.ldap_lookup(self.cfg.ldap, "", "ann", "ann-password")
        self.assertEqual(info["display_name"], "Ann Admin")
        self.assertIsNone(auth.ldap_lookup(self.cfg.ldap, "", "ann", "wrong"))
        self.assertIsNone(auth.ldap_lookup(self.cfg.ldap, "", "ann", ""))
        self.assertIsNone(auth.ldap_lookup(self.cfg.ldap, "", "ghost", "x"))
        c = client(self.app)
        self.assertEqual(login(c, "ann", "ann-password").headers["location"], "/")
        self.assertIn("Users", c.get("/settings").text)
        self.assertIn("e=norole", login(client(self.app), "nobody", "nobody-password").headers["location"])

    def test_ldap_settings_in_ui(self):
        c = client(self.app)
        login(c, "admin", ADMIN_PW)
        base = {"url": "ldaps://dc.example.com", "bind_dn": "cn=svc,dc=example,dc=com", "user_base": "ou=users,dc=example,dc=com",
                "user_filter": self.cfg.ldap.user_filter, "group_base": "", "nested_groups": ""}
        post = lambda **d: c.post("/settings/authentication/ldap", data={"csrf": csrf(c, "/settings/authentication"),
                                                                         **{k: v for k, v in {**base, **d}.items() if v != ""}},
                                  follow_redirects=False)
        post()                                                          # "on" unticked: LDAP off
        self.assertIn("e=denied", login(client(self.app), "ann", "ann-password").headers["location"])
        post(on="on", bind_password="wrong-svc-password")               # on, but the bind password is wrong
        self.assertIn("e=ldapdown", login(client(self.app), "ann", "ann-password").headers["location"])
        post(on="on", revert_bind_password="on")                        # back to the deployment's password
        self.assertEqual(login(client(self.app), "ann", "ann-password").headers["location"], "/")
        page = c.get("/settings/authentication").text
        self.assertNotIn("svcpw", page)


class Oidc(unittest.TestCase):
    """Single sign-on against a fake OpenID provider (httpx mock transport), with a real signed ID token."""

    def setUp(self):
        import httpx
        from joserfc import jwt
        from joserfc.jwk import RSAKey
        self.key = RSAKey.generate_key(2048, parameters={"kid": "k1"})
        self.key_json = self.key.as_dict(private=False)
        self.app, self.db, self.jobs, self.cfg = make_app(oidc=OidcConfig(issuer="https://idp.example/app/", client_id="cid",
                                                                         client_secret="csecret", label="Sign in with IdP"))
        self.claims = {"sub": "u1", "preferred_username": "Sam", "name": "Sam Ops", "groups": ["Securitas-Operators"]}
        self.seen = {}
        a = self.app.state.securitas

        def handler(req):
            u = str(req.url)
            if u.endswith("/.well-known/openid-configuration"):
                return httpx.Response(200, json={"issuer": "https://idp.example/app/", "authorization_endpoint": "https://idp.example/authorize",
                                                 "token_endpoint": "https://idp.example/token", "jwks_uri": "https://idp.example/jwks",
                                                 "userinfo_endpoint": "https://idp.example/userinfo"})
            if u.endswith("/jwks"):
                return httpx.Response(200, json={"keys": [self.key_json]})
            if u.endswith("/token"):
                form = dict(urllib.parse.parse_qsl(req.content.decode()))
                self.seen["token"] = form
                self.seen["auth"] = req.headers.get("authorization", "")
                now = int(time.time())
                tok = jwt.encode({"alg": "RS256", "kid": "k1"}, dict(self.claims, iss="https://idp.example/app/", aud="cid", exp=now + 300,
                                                                    iat=now, nonce=self.seen["nonce"]), self.key)
                return httpx.Response(200, json={"id_token": tok, "access_token": "at", "token_type": "Bearer"})
            if u.endswith("/userinfo"):
                return httpx.Response(200, json={"sub": "u1", "email": "sam@example.com"})
            return httpx.Response(404)
        a.oidc._client = lambda: httpx.Client(transport=httpx.MockTransport(handler))

    def flow(self, c):
        r = c.get("/login/oidc?next=/scans", follow_redirects=False)
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(r.headers["location"]).query))
        self.assertEqual(q["code_challenge_method"], "S256")
        self.assertEqual(q["redirect_uri"], "http://testserver/auth/oidc/callback")
        self.seen["nonce"] = q["nonce"]
        return c.get("/auth/oidc/callback?code=abc&state=" + q["state"], follow_redirects=False), q

    def test_sso_login(self):
        c = client(self.app)
        self.assertIn("Sign in with IdP", c.get("/login").text)
        r, q = self.flow(c)
        self.assertEqual(r.headers["location"], "/scans")
        self.assertTrue(self.seen["token"]["code_verifier"])
        self.assertTrue(self.seen["auth"].startswith("Basic "))
        page = c.get("/scans").text
        self.assertIn("Sam Ops", page)
        self.assertIn("Operator", page)
        # the state can be used once only
        self.assertIn("e=expired", c.get("/auth/oidc/callback?code=abc&state=" + q["state"], follow_redirects=False).headers["location"])

    def test_sso_wrong_nonce_or_state(self):
        c = client(self.app)
        r = c.get("/login/oidc", follow_redirects=False)
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(r.headers["location"]).query))
        self.seen["nonce"] = "not-the-nonce"
        self.assertIn("e=ssofailed", c.get("/auth/oidc/callback?code=x&state=" + q["state"], follow_redirects=False).headers["location"])
        r = c.get("/login/oidc", follow_redirects=False)
        self.assertIn("e=expired", client(self.app).get("/auth/oidc/callback?code=x&state=forged", follow_redirects=False).headers["location"])

    def test_sso_no_role_and_local_clash(self):
        self.claims["groups"] = ["Nothing"]
        r, _ = self.flow(client(self.app))
        self.assertIn("e=norole", r.headers["location"])
        self.claims.update(preferred_username="admin", groups=["Securitas-Admins"])
        r, _ = self.flow(client(self.app))
        self.assertIn("e=clash", r.headers["location"])


class SettingsUI(unittest.TestCase):
    """0.3.0: settings saved in the web UI (LDAP, SSO, scan credentials, sources), Settings menu, report summary."""

    def setUp(self):
        self.app, self.db, self.jobs, self.cfg = make_app(ssh_user="deploy-user", winrm_user="deploy@example.com")
        self.c = client(self.app)
        login(self.c, "admin", ADMIN_PW)

    def post(self, path, page, **data):
        return self.c.post(path, data={"csrf": csrf(self.c, page), **data}, follow_redirects=False)

    def stored(self):
        from securitas.db import Setting
        with self.db.Session() as s:
            row = s.get(Setting, "ui_settings")
            return json.dumps(row.value) if row else ""

    def test_text_override_secret_encryption_and_revert(self):
        st = self.jobs.settings
        r = self.post("/settings/credentials/windows", "/settings/credentials", winrm_user="svc@example.com",
                      winrm_password="Sup3r-secret!", winrm_port="5986", winrm_ssl="on", winrm_auth="ntlm")
        self.assertEqual(r.headers["location"], "/settings/credentials?ok=saved")
        eff = st.effective()
        self.assertEqual((eff.winrm_user, eff.winrm_password, eff.winrm_auth), ("svc@example.com", "Sup3r-secret!", "ntlm"))
        self.assertEqual(self.cfg.winrm_user, "deploy@example.com")          # the deployment's value is untouched
        self.assertNotIn("Sup3r-secret!", self.stored())                      # encrypted at rest
        page = self.c.get("/settings/credentials").text
        self.assertNotIn("Sup3r-secret!", page)                               # never shown
        self.assertIn("Set here", page)
        # blank secret keeps the stored one
        self.post("/settings/credentials/windows", "/settings/credentials", winrm_user="svc@example.com", winrm_password="",
                  winrm_port="5986", winrm_ssl="on", winrm_auth="ntlm")
        self.assertEqual(st.effective().winrm_password, "Sup3r-secret!")
        # revert goes back to the deployment
        self.post("/settings/credentials/windows", "/settings/credentials", winrm_user="x", revert_winrm_user="on",
                  revert_winrm_password="on", winrm_port="5986", winrm_ssl="on", winrm_auth="negotiate")
        eff = st.effective()
        self.assertEqual((eff.winrm_user, eff.winrm_password), ("deploy@example.com", ""))
        actions = [a for (a,) in self._audit()]
        self.assertIn("settings.windows", actions)
        self.assertNotIn("Sup3r-secret!", json.dumps(self._audit(detail=True)))

    def _audit(self, detail=False):
        from securitas.db import AuditEvent
        with self.db.Session() as s:
            return [((a.action, a.detail) if detail else (a.action,)) for a in s.query(AuditEvent).all()]

    def test_invalid_values_rejected(self):
        r = self.post("/settings/credentials/windows", "/settings/credentials", winrm_user="u", winrm_port="99999",
                      winrm_ssl="on", winrm_auth="negotiate")
        self.assertEqual(r.status_code, 400)
        self.assertIn("between 1 and 65535", r.text)
        r = self.post("/settings/credentials/linux", "/settings/credentials", ssh_user="u", ssh_port="22",
                      ssh_key="not a key")
        self.assertEqual(r.status_code, 400)
        self.assertIn("private key", r.text)

    def test_ssh_key_pasted_in_ui(self):
        import io
        import paramiko
        k = paramiko.Ed25519Key.from_private_key(io.StringIO(ED25519_KEY))
        self.post("/settings/credentials/linux", "/settings/credentials", ssh_user="scan", ssh_port="22", ssh_key=ED25519_KEY)
        eff = self.jobs.settings.effective()
        from securitas import scan_linux
        self.assertEqual(scan_linux.load_key(eff).get_fingerprint(), k.get_fingerprint())
        self.assertNotIn("PRIVATE KEY", self.stored())
        self.assertNotIn("PRIVATE KEY", self.c.get("/settings/credentials").text)

    def test_secrets_need_the_key(self):
        app, db, jobs, cfg = make_app(secret_key="")
        c = client(app)
        login(c, "admin", ADMIN_PW)
        r = c.post("/settings/credentials/windows", data={"csrf": csrf(c, "/settings/credentials"), "winrm_user": "u",
                                                          "winrm_password": "pw", "winrm_port": "5986", "winrm_ssl": "on",
                                                          "winrm_auth": "negotiate"}, follow_redirects=False)
        self.assertEqual(r.status_code, 400)
        self.assertIn("SECURITAS_SECRET_KEY", r.text)

    def test_oidc_configured_in_ui(self):
        self.assertNotIn("/login/oidc", client(self.app).get("/login").text)
        self.post("/settings/authentication/oidc", "/settings/authentication", on="on", issuer="https://idp.example.com/app/",
                  client_id="abc", client_secret="s3cret", scopes="openid profile email", username_claim="preferred_username",
                  groups_claim="groups", label="Sign in with Example")
        page = client(self.app).get("/login").text
        self.assertIn("/login/oidc", page)
        self.assertIn("Sign in with Example", page)
        self.assertEqual(self.app.state.securitas.oidc.cfg.client_secret, "s3cret")
        # switching it off hides the button again
        self.post("/settings/authentication/oidc", "/settings/authentication", issuer="https://idp.example.com/app/",
                  client_id="abc", scopes="openid profile email", username_claim="preferred_username", groups_claim="groups",
                  label="Sign in with Example")
        self.assertNotIn("/login/oidc", client(self.app).get("/login").text)

    def test_platform_switch(self):
        self.post("/vulnerabilities/sources", "/vulnerabilities/sources", kev_enabled="on", epss_enabled="on", epss_min="0.10",
                  platform_kubernetes="on", platform_linux="on")      # windows off
        self.assertFalse(self.jobs.settings.effective().platform_on("windows"))
        page = self.c.get("/scans").text
        self.assertIn("turned off in", page)
        r = self.post("/scans", "/scans", platform="windows")
        self.assertIn("err=noplat", r.headers["location"])
        from securitas.db import Schedule, Scan, utcnow
        import datetime
        with self.db.Session() as s, s.begin():
            for sc in s.query(Schedule).all():
                sc.next_run = utcnow() - datetime.timedelta(minutes=1)
        self.jobs.run_due()
        with self.db.Session() as s:
            self.assertEqual(sorted(p for x in s.query(Scan).all() for p in x.platforms), ["kubernetes", "linux"])

    def test_turned_off_platform_keeps_old_results_marked(self):
        self.jobs.scanners["windows"] = lambda say: dict(fake_kubernetes(say), id="windows", title="Windows")
        with self.db.Session() as s, s.begin():
            self.jobs.enqueue(s, ["windows"], "manual", "admin")
        self.jobs.run_scan(self.jobs._claim())
        self.post("/vulnerabilities/sources", "/vulnerabilities/sources", kev_enabled="on", epss_enabled="on", epss_min="0.10",
                  platform_kubernetes="on", platform_linux="on")
        page = self.c.get("/report").text
        self.assertIn("Turned off", page)
        self.assertIn("no longer updated", page)
        self.assertIn("Turned off", self.c.get("/").text)

    def test_ranking_switches(self):
        self.jobs.scanners["kubernetes"] = fake_kubernetes
        with self.db.Session() as s, s.begin():
            self.jobs.enqueue(s, ["kubernetes"], "manual", "admin")
        self.jobs.run_scan(self.jobs._claim())
        cves = lambda: pri(self.jobs.current_model()["platforms"][0])
        self.assertIn("CVE-2099-0002", cves())                    # KEV
        self.post("/vulnerabilities/sources", "/vulnerabilities/sources", epss_enabled="on", epss_min="0.10", platform_kubernetes="on",
                  platform_linux="on", platform_windows="on")      # KEV off
        self.assertNotIn("CVE-2099-0002", cves())
        self.assertIn("The CISA KEV catalog is turned off", self.c.get("/report").text)
        self.post("/vulnerabilities/sources", "/vulnerabilities/sources", epss_min="0.10", platform_kubernetes="on", platform_linux="on",
                  platform_windows="on")                           # both off: everything listed
        self.assertEqual(sorted(cves()), ["CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003", "CVE-2099-0004"])
        self.assertIn("every CVE is listed, unranked", self.c.get("/report").text)
        r = self.post("/vulnerabilities/sources", "/vulnerabilities/sources", kev_enabled="on", epss_enabled="on", epss_min="1.5",
                      platform_kubernetes="on", platform_linux="on", platform_windows="on")
        self.assertEqual(r.status_code, 400)

    def test_real_feeds_skip_turned_off_sources(self):
        from securitas import feeds, jobs as jobsmod
        calls = []
        old = feeds.kev, feeds.epss
        feeds.kev = lambda cfg, w: (calls.append("kev"), ({}, "k"))[1]
        feeds.epss = lambda cfg, wanted, w: (calls.append("epss"), ({}, "e"))[1]
        try:
            f = jobsmod.Feeds(self.jobs.settings)
            f.get()
            self.assertEqual(calls, ["kev", "epss"])
            self.post("/vulnerabilities/sources", "/vulnerabilities/sources", epss_enabled="on", epss_min="0.10",
                      platform_kubernetes="on", platform_linux="on", platform_windows="on")
            calls.clear()
            _, _, src, _ = f.get()
            self.assertEqual(calls, ["epss"])
            self.assertIn("turned off", src["kev"])
        finally:
            feeds.kev, feeds.epss = old

    def test_sources_page_documents_scanners(self):
        page = self.c.get("/vulnerabilities/sources").text
        for s in ("CISA Known Exploited", "EPSS", "Trivy Operator", "dnf", "MSRC", "updateinfo list --security",
                  "Win32_OperatingSystem", "How Windows is scanned"):
            self.assertIn(s, page)

    def test_report_starts_with_summary(self):
        self.jobs.scanners["kubernetes"] = fake_kubernetes
        with self.db.Session() as s, s.begin():
            self.jobs.enqueue(s, ["kubernetes"], "manual", "admin")
        sid = self.jobs._claim()
        self.jobs.run_scan(sid)
        for html_text in (self.c.get("/report").text, self.c.get("/scans/%d" % sid).text,
                          render.pdf_html(self.jobs.current_model())):
            self.assertIn('<table class="summary">', html_text)
            self.assertLess(html_text.index('<table class="summary">'), html_text.index('<section id="kubernetes">'))

    def test_menu_redirects_and_permissions(self):
        page = self.c.get("/settings").text
        for label in ("Users", "Authentication", "Scan credentials"):
            self.assertIn(label, page)
        for moved in ('href="/targets"><h3>', 'href="/audit"><h3>', 'href="/vulnerabilities/schedules"><h3>'):
            self.assertNotIn(moved, page)                                    # 0.5.0: own menus now
        self.assertNotIn('href="/vulnerabilities/sources"><h3>', page)        # 0.5.0: Sources moved to Vulnerabilities
        for old, new in (("/admin/users", "/settings/users"), ("/admin/auth", "/settings/authentication"),
                         ("/schedules", "/vulnerabilities/schedules")):
            r = self.c.get(old, follow_redirects=False)
            self.assertEqual((r.status_code, r.headers["location"]), (301, new))
        self.assertIn("Add a local user", self.c.get("/settings/users").text)
        tok = csrf(self.c, "/settings/users")
        self.c.post("/settings/users", data={"csrf": tok, "username": "vic", "password": "a-long-password-1", "role": "viewer"})
        v = client(self.app)
        login(v, "vic", "a-long-password-1")
        page = v.get("/vulnerabilities/sources").text
        self.assertIn('href="/vulnerabilities/sources" class="on">Sources', page)
        self.assertNotIn('href="/settings"', page)          # a viewer has no settings pages, so no Settings menu
        self.assertNotIn("Scan credentials", v.get("/settings").text)
        self.assertEqual(v.get("/vulnerabilities/sources").status_code, 200)
        self.assertEqual(v.get("/settings/credentials").status_code, 403)
        r = v.post("/vulnerabilities/sources", data={"csrf": csrf(v, "/vulnerabilities/sources")}, follow_redirects=False)
        self.assertEqual(r.status_code, 403)


def _ed25519_key():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                                      serialization.NoEncryption()).decode()


ED25519_KEY = _ed25519_key()


if __name__ == "__main__":
    unittest.main()


# ------------------------------------------------------------------ 0.5.0: compliance benchmark library

def role_zip(top="TEST9-CIS-1.2.3", extra=None, defaults=None, platform="EL"):
    """A small Ansible-Lockdown-shaped role: three task styles (plain, multi-rule literal block, nested block)."""
    import io
    import zipfile
    tasks = '''---
- name: "1.1.1 | PATCH | Ensure cramfs is not available"
  when: test9cis_rule_1_1_1
  tags: [level1-server, level1-workstation, patch, rule_1.1.1, NIST800-53R5_CM-7]
  block:
    - name: "1.1.1 | PATCH | Ensure cramfs is not available | Edit modprobe config"
      ansible.builtin.lineinfile: {path: /etc/x, line: y}
- name: |
    "1.1.2 | PATCH | Ensure 'audit log' mode is configured"
    "1.1.3 | AUDIT | Ensure audit log owner is configured"
  when: [test9cis_rule_1_1_2 or test9cis_rule_1_1_3]
  tags: [level2-server, level2-workstation, rule_1.1.2, rule_1.1.3]
  ansible.builtin.file: {path: /x}
- name: Outer block
  block:
    - name: "2.10.1 | PATCH | Ensure ssh is configured"
      when: test9cis_rule_2_10_1
      tags: [level1-server, rule_2.10.1, NIST800-53R5_AC-17]
      ansible.builtin.debug: {msg: !unsafe "{{ x }}"}
'''
    files = {
        "meta/main.yml": "galaxy_info:\n  author: Tester\n  description: Apply the TEST 9 CIS\n  license: MIT\n"
                         "  role_name: test9_cis\n  namespace: ansible-lockdown\n  platforms:\n    - name: %s\n"
                         "      versions: ['9']\n" % platform,
        "defaults/main/main.yml": defaults if defaults is not None else
            "benchmark_version: 'v3.1.0'\ntest9cis_rule_1_1_1: true\ntest9cis_rule_1_1_2: true\n"
            "test9cis_rule_1_1_3: false\ntest9cis_rule_2_10_1: true\n",
        "tasks/section_1/cis_1.1.x.yml": tasks,
        "tasks/main.yml": "- name: not a rule\n  ansible.builtin.debug: {}\n",
        "Changelog.md": "# Changes\n",
    }
    files.update(extra or {})
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for k, v in files.items():
            z.writestr(top + "/" + k, v)
    return buf.getvalue()


REAL_ZIP = os.environ.get("SECURITAS_TEST_RHEL9_CIS", "/mnt/c/Users/huhl/Downloads/RHEL9-CIS-2.4.2.zip")


class ComplianceImport(unittest.TestCase):
    def test_parse(self):
        from securitas import compliance
        b = compliance.parse_zip(role_zip(), "upload.zip")
        self.assertEqual((b["key"], b["name"], b["version"], b["benchmark_version"], b["platform"], b["os_key"]),
                         ("TEST9-CIS-1.2.3", "TEST9-CIS", "1.2.3", "v3.1.0", "linux", "test9"))
        self.assertEqual([r["rule_id"] for r in b["rules"]], ["1.1.1", "1.1.2", "1.1.3", "2.10.1"])
        r = {x["rule_id"]: x for x in b["rules"]}
        self.assertEqual(r["1.1.1"]["title"], "Ensure cramfs is not available")
        self.assertEqual(r["1.1.2"]["title"], "Ensure 'audit log' mode is configured")    # inner quotes kept
        self.assertEqual((r["1.1.3"]["kind"], r["1.1.3"]["default_on"], r["1.1.3"]["toggle"]),
                         ("AUDIT", False, "test9cis_rule_1_1_3"))
        self.assertEqual(r["1.1.1"]["refs"], ["NIST800-53R5_CM-7"])
        self.assertEqual(r["2.10.1"]["section"], "2")
        self.assertEqual(b["meta"]["toggle_prefix"], "test9cis")
        self.assertEqual(len(b["sha256"]), 64)

    def test_profiles(self):
        from securitas.compliance import in_profile
        self.assertTrue(in_profile(["level1-server", "level1-workstation"], "level1-server"))
        self.assertFalse(in_profile(["level2-server"], "level1-server"))
        self.assertTrue(in_profile(["level2-server"], "level2-server"))
        self.assertTrue(in_profile(["level1-server"], "level2-server"))
        self.assertFalse(in_profile(["level1-workstation"], "level2-server"))

    def test_rejects(self):
        import io
        import zipfile
        from securitas.compliance import BenchmarkError, parse_zip
        with self.assertRaisesRegex(BenchmarkError, "not a zip"):
            parse_zip(b"hello")
        with self.assertRaisesRegex(BenchmarkError, "Download a release"):
            parse_zip(role_zip(top="TEST9-CIS-devel"))
        with self.assertRaisesRegex(BenchmarkError, "STIG"):
            parse_zip(role_zip(top="TEST9-STIG-1.0.0"))
        with self.assertRaisesRegex(BenchmarkError, "not valid YAML"):
            parse_zip(role_zip(extra={"tasks/section_9/bad.yml": "- name: [unclosed"}))
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("A-CIS-1.0.0/meta/main.yml", "x: 1")
            z.writestr("B-CIS-1.0.0/meta/main.yml", "x: 1")
        with self.assertRaisesRegex(BenchmarkError, "one folder"):
            parse_zip(buf.getvalue())
        with self.assertRaisesRegex(BenchmarkError, "No CIS rules"):
            parse_zip(role_zip(extra={"tasks/section_1/cis_1.1.x.yml": "- name: nothing\n  debug: {}\n"}))

    def test_windows_platform(self):
        from securitas import compliance
        b = compliance.parse_zip(role_zip(top="Windows-2022-CIS-3.0.0", platform="Windows"))
        self.assertEqual((b["platform"], b["os_key"], b["os_label"]), ("windows", "windows2022", "Windows Server 2022"))

    @unittest.skipUnless(os.path.exists(REAL_ZIP), "real RHEL9-CIS-2.4.2.zip not available")
    def test_real_rhel9_cis(self):
        import yaml
        import zipfile
        from securitas import compliance
        data = open(REAL_ZIP, "rb").read()
        b = compliance.parse_zip(data)
        self.assertEqual((b["key"], b["benchmark_version"], b["os_key"]), ("RHEL9-CIS-2.4.2", "v2.0.0", "rhel9"))
        d = yaml.safe_load(zipfile.ZipFile(REAL_ZIP).read("RHEL9-CIS-2.4.2/defaults/main/main.yml"))
        toggles = {k for k in d if k.startswith("rhel9cis_rule_")}
        self.assertEqual({r["toggle"] for r in b["rules"]}, toggles)      # every switch in the role has its rule
        self.assertTrue(all(r["levels"] for r in b["rules"]))


class ComplianceUI(unittest.TestCase):
    def setUp(self):
        self.app, self.db, self.jobs, self.cfg = make_app()
        self.c = client(self.app)
        login(self.c, "admin", ADMIN_PW)

    def upload(self, data, name="TEST9-CIS-1.2.3.zip", c=None):
        c = c or self.c
        return c.post("/compliance/benchmarks", data={"csrf": csrf(c, "/compliance/benchmarks")},
                      files={"file": (name, data, "application/zip")}, follow_redirects=False)

    def act(self, bid, **data):
        return self.c.post("/compliance/benchmarks/%d" % bid, data={"csrf": csrf(self.c, "/compliance/benchmarks/%d" % bid), **data},
                           follow_redirects=False)

    def bench(self, key):
        from securitas.db import Benchmark
        with self.db.Session() as s:
            b = s.scalar(select(Benchmark).where(Benchmark.key == key))
            return b and (b.id, b.active, b.profile, {r.rule_id: r.override for r in b.rules})

    def test_upload_list_and_details(self):
        data = role_zip()                    # built once: the zip records file times, so a rebuild can differ
        r = self.upload(data)
        self.assertEqual(r.status_code, 303, r.text[:500])
        bid, active, profile, _ = self.bench("TEST9-CIS-1.2.3")
        self.assertEqual(r.headers["location"], "/compliance/benchmarks/%d?ok=imported" % bid)
        self.assertTrue(active)                          # first one for its OS
        self.assertEqual(profile, "level1-server")
        page = self.c.get("/compliance/benchmarks").text
        self.assertIn("TEST9-CIS-1.2.3", page)
        self.assertIn("TEST9-CIS 1.2.3 · uploaded ", page)  # name, version and upload date
        self.assertIn("2 of 4", page)                    # level 1 server: 1.1.1 and 2.10.1
        detail = self.c.get("/compliance/benchmarks/%d" % bid).text
        self.assertIn("Ensure &#39;audit log&#39; mode is configured", detail)
        self.assertIn("v3.1.0", detail)
        self.assertIn("off in role", detail)             # 1.1.3 is off in the role's defaults
        self.assertEqual(self.c.get("/compliance/benchmarks/%d/download" % bid).content, data)
        from securitas.db import AuditEvent
        with self.db.Session() as s:
            self.assertIn("benchmark.uploaded", s.scalars(select(AuditEvent.action)).all())

    def test_duplicate_and_bad_upload(self):
        self.upload(role_zip())
        r = self.upload(role_zip())
        self.assertEqual(r.status_code, 400)
        self.assertIn("already loaded", r.text)
        r = self.upload(b"not a zip", "x.zip")
        self.assertEqual(r.status_code, 400)
        self.assertIn("not a zip file", r.text)

    def test_versions_side_by_side_and_activate(self):
        self.upload(role_zip())
        self.upload(role_zip(top="TEST9-CIS-1.3.0"))
        old, new = self.bench("TEST9-CIS-1.2.3"), self.bench("TEST9-CIS-1.3.0")
        self.assertTrue(old[1])
        self.assertFalse(new[1])                         # the first one stays active
        r = self.act(new[0], action="activate")
        self.assertIn("ok=activated", r.headers["location"])
        self.assertFalse(self.bench("TEST9-CIS-1.2.3")[1])
        self.assertTrue(self.bench("TEST9-CIS-1.3.0")[1])

    def test_profile_rules_and_reset(self):
        self.upload(role_zip())
        bid = self.bench("TEST9-CIS-1.2.3")[0]
        self.act(bid, action="profile", profile="level2-server")
        self.assertEqual(self.bench("TEST9-CIS-1.2.3")[2], "level2-server")
        # filtered page: only section 1 shown; turn 1.1.1 off and 1.1.3 on (off in the role)
        r = self.c.post("/compliance/benchmarks/%d" % bid, data={
            "csrf": csrf(self.c, "/compliance/benchmarks/%d" % bid), "action": "rules", "query": "section=1",
            "shown": ["1.1.1", "1.1.2", "1.1.3"], "rule": ["1.1.2", "1.1.3"]}, follow_redirects=False)
        self.assertEqual(r.headers["location"], "/compliance/benchmarks/%d?section=1&ok=saved" % bid)
        ov = self.bench("TEST9-CIS-1.2.3")[3]
        self.assertEqual(ov, {"1.1.1": False, "1.1.2": None, "1.1.3": True, "2.10.1": None})   # 2.10.1 not shown: untouched
        self.assertIn("Set here", self.c.get("/compliance/benchmarks/%d?state=override" % bid).text)
        self.act(bid, action="reset")
        self.assertEqual(set(self.bench("TEST9-CIS-1.2.3")[3].values()), {None})

    def test_delete(self):
        self.upload(role_zip())
        bid = self.bench("TEST9-CIS-1.2.3")[0]
        self.assertIn("err=csrf", self.act(bid, action="delete").headers["location"])     # needs the confirm box
        r = self.act(bid, action="delete", confirm="on")
        self.assertEqual(r.headers["location"], "/compliance/benchmarks?ok=deleted")
        self.assertIsNone(self.bench("TEST9-CIS-1.2.3"))
        from securitas.db import BenchmarkFile, BenchmarkRule
        with self.db.Session() as s:
            self.assertEqual(s.scalar(select(func.count(BenchmarkRule.id))), 0)
            self.assertEqual(s.scalar(select(func.count(BenchmarkFile.id))), 0)
        self.assertEqual(self.c.get("/compliance/benchmarks/%d" % bid).status_code, 404)

    def test_remove_from_list(self):
        self.upload(role_zip())
        bid = self.bench("TEST9-CIS-1.2.3")[0]
        page = self.c.get("/compliance/benchmarks").text
        self.assertIn('<form method="post" action="/compliance/benchmarks/%d">' % bid, page)
        self.assertIn('name="confirm" required', page)
        tok = csrf(self.c, "/compliance/benchmarks")
        r = self.c.post("/compliance/benchmarks/%d" % bid, data={"csrf": tok, "action": "delete"}, follow_redirects=False)
        self.assertIn("err=csrf", r.headers["location"])                      # unticked: nothing removed
        self.assertIsNotNone(self.bench("TEST9-CIS-1.2.3"))
        r = self.c.post("/compliance/benchmarks/%d" % bid, data={"csrf": tok, "action": "delete", "confirm": "on"},
                        follow_redirects=False)
        self.assertEqual(r.headers["location"], "/compliance/benchmarks?ok=deleted")
        self.assertIsNone(self.bench("TEST9-CIS-1.2.3"))

    def test_menu_bar_subtitle(self):
        page = self.c.get("/compliance/benchmarks").text
        self.assertIn("<small>Vulnerabilities and Compliance</small>", page)

    def test_viewer_can_browse_not_change(self):
        self.upload(role_zip())
        bid = self.bench("TEST9-CIS-1.2.3")[0]
        tok = csrf(self.c)
        self.c.post("/settings/users", data={"csrf": tok, "username": "vic", "password": "a-long-password-1", "role": "viewer"})
        v = client(self.app)
        login(v, "vic", "a-long-password-1")
        page = v.get("/compliance/benchmarks/%d" % bid)
        self.assertEqual(page.status_code, 200)
        self.assertNotIn("Remove benchmark", page.text)
        self.assertNotIn('type="file"', v.get("/compliance/benchmarks").text)
        self.assertEqual(self.upload(role_zip(top="TEST9-CIS-9.9.9"), c=v).status_code, 403)
        r = v.post("/compliance/benchmarks/%d" % bid, data={"csrf": csrf(v, "/compliance/benchmarks/%d" % bid), "action": "delete",
                                                          "confirm": "on"}, follow_redirects=False)
        self.assertEqual(r.status_code, 403)
        self.assertEqual(v.get("/compliance/benchmarks/%d/download" % bid).status_code, 403)

    @unittest.skipUnless(os.path.exists(REAL_ZIP), "real RHEL9-CIS-2.4.2.zip not available")
    def test_real_upload(self):
        r = self.upload(open(REAL_ZIP, "rb").read(), "RHEL9-CIS-2.4.2.zip")
        self.assertEqual(r.status_code, 303, r.text[:800])
        page = self.c.get("/compliance/benchmarks").text
        self.assertIn("RHEL9-CIS-2.4.2", page)
        self.assertIn("237 of 297", page)


class Menus(unittest.TestCase):
    """0.5.0: Vulnerabilities and Compliance are top-level menus; Sources and Benchmarks moved under them."""

    def setUp(self):
        self.app, self.db, self.jobs, self.cfg = make_app()
        self.c = client(self.app)
        login(self.c, "admin", ADMIN_PW)

    def test_top_and_sub_menus(self):
        page = self.c.get("/report").text
        self.assertIn('<a href="/">Home</a>', page)
        self.assertLess(page.index('>Home</a>'), page.index('>Vulnerabilities</a>'))        # Home left of Vulnerabilities
        self.assertIn('<a href="/vulnerabilities" class="on">Vulnerabilities</a>', page)
        self.assertIn('<a href="/about">About</a>', page)
        self.assertIn('<a href="/compliance">Compliance</a>', page)
        self.assertIn('<a href="/report" class="on">Report</a>', page)
        for href in ("/scans", "/vulnerabilities/sources"):
            self.assertIn('href="%s"' % href, page)
        page = self.c.get("/compliance/scans").text
        self.assertIn('<a href="/compliance" class="on">Compliance</a>', page)
        self.assertIn('<a href="/compliance/scans" class="on">Scans</a>', page)
        self.assertIn('<a href="/compliance">Summary</a>', page)             # the Summary tab is not on for /compliance/scans
        self.assertIn('<a href="/compliance/report">Report</a>', page)
        self.assertIn('<a href="/compliance/schedules">Schedules</a>', page)
        page = self.c.get("/vulnerabilities").text
        self.assertIn('<a href="/vulnerabilities" class="on">Summary</a>', page)
        self.assertIn('<a href="/vulnerabilities/schedules">Schedules</a>', page)
        self.assertIn('<a href="/targets">Targets</a>', page)                # top level for admins
        self.assertIn('<a href="/audit">Audit log</a>', page)
        self.assertIn('<a href="/targets" class="on">Targets</a>', self.c.get("/targets").text)
        self.assertNotIn('class="subnav"', self.c.get("/audit").text)
        self.assertIn('href="/compliance/benchmarks"', self.c.get("/compliance/scans").text)
        self.assertNotIn('aria-label="Vulnerabilities"', self.c.get("/account").text)

    def test_old_addresses_redirect(self):
        for old, new in (("/settings/sources", "/vulnerabilities/sources"), ("/settings/compliance", "/compliance/benchmarks"),
                         ("/settings/compliance/7", "/compliance/benchmarks/7"),
                         ("/settings/schedules", "/vulnerabilities/schedules"), ("/settings/targets", "/targets"),
                         ("/settings/audit", "/audit"), ("/admin/targets", "/targets")):
            r = self.c.get(old, follow_redirects=False)
            self.assertEqual((r.status_code, r.headers["location"]), (301, new), old)

    def test_compliance_report_matches_hosts_to_benchmarks(self):
        from securitas.db import PlatformResult, Scan, Target
        with self.db.Session() as s, s.begin():
            s.add_all([Target(platform="linux", host="rocky1"), Target(platform="linux", host="ubu1"),
                       Target(platform="linux", host="new1"), Target(platform="windows", host="win1")])
            sc = Scan(trigger="manual", platforms=["linux"], status="done")
            s.add(sc)
            s.flush()
            s.add(PlatformResult(scan_id=sc.id, platform="linux", status="done",
                                 raw={"systems": [{"name": "rocky1", "os": "Rocky Linux 9.6"},
                                                  {"name": "ubu1", "os": "Ubuntu 22.04.4 LTS"}]}))
        page = self.c.get("/compliance/report").text
        self.assertNotIn("Active benchmarks", page)                                    # removed from the report
        self.c.post("/compliance/benchmarks", data={"csrf": csrf(self.c, "/compliance/benchmarks")},
                    files={"file": ("r.zip", role_zip(top="RHEL9-CIS-1.0.0"), "application/zip")})
        page = self.c.get("/compliance/report").text
        row = lambda host: re.search(r'<td class="mono"><a href="/compliance/targets/\d+">%s</a></td>(.*?)</tr>' % host, page, re.S).group(1)
        self.assertIn("RHEL9-CIS-1.0.0", row("rocky1"))
        self.assertIn("no active benchmark for this OS (ubuntu22)", row("ubu1"))
        self.assertIn("run a vulnerability scan", row("new1"))
        self.assertIn("Not checked", row("win1"))
        self.assertIn("(no checker yet)", self.c.get("/compliance/scans").text)
        summary = self.c.get("/compliance").text
        linux = re.search(r'compliance/report#linux"><strong>Linux</strong></a></td>(.*?)</tr>', summary, re.S).group(1)
        self.assertEqual(re.findall(r'<td class="n">(\d+)</td>', linux), ["3", "1", "0"])   # 3 systems, 1 matched, 0 checked
        self.assertIn("RHEL9-CIS-1.0.0", linux)

    def test_compliance_schedules_are_separate(self):
        from securitas.db import ComplianceSchedule, Schedule
        r = self.c.post("/compliance/schedules/linux", data={"csrf": csrf(self.c, "/compliance/schedules"), "cron": "0 6 * * 0",
                                                             "enabled": "on"}, follow_redirects=False)
        self.assertEqual(r.headers["location"], "/compliance/schedules?ok=saved")
        self.assertEqual(self.c.post("/compliance/schedules/linux", data={"csrf": csrf(self.c, "/compliance/schedules"),
                                                                           "cron": "bad"}, follow_redirects=False).status_code, 400)
        with self.db.Session() as s:
            self.assertEqual(s.scalar(select(ComplianceSchedule.cron).where(ComplianceSchedule.platform == "linux")), "0 6 * * 0")
            self.assertEqual(s.scalar(select(Schedule.cron).where(Schedule.platform == "linux")), "0 5 * * *")   # untouched
        page = self.c.get("/compliance/schedules").text
        self.assertIn("start nothing: Kubernetes.", page)
        self.assertIn("Every Sunday at 06:00", self.c.get("/compliance").text)        # in words, not cron
        self.assertNotIn('name="cron"', page)                                          # no cron field on compliance schedules
        self.assertNotIn('value="advanced"', page)
        self.assertIn('name="cron"', self.c.get("/vulnerabilities/schedules").text)
        self.assertIn('action="/vulnerabilities/schedules/linux"', self.c.get("/vulnerabilities/schedules").text)

    def test_schedule_picker(self):
        from securitas import schedule_ui as su
        from securitas.db import Schedule
        self.assertEqual(su.to_cron({"freq": "hourly", "minute": "15"}), "15 * * * *")
        self.assertEqual(su.to_cron({"freq": "daily", "hour": "5", "minute": "0"}), "0 5 * * *")
        self.assertEqual(su.to_cron({"freq": "weekly", "hour": "5", "minute": "30", "weekday": ["4", "0", "1"]}), "30 5 * * 1,4,0")
        self.assertEqual(su.to_cron({"freq": "monthly", "hour": "23", "minute": "5", "monthday": "28"}), "5 23 28 * *")
        self.assertEqual(su.to_cron({"freq": "advanced", "cron": " 0  5 * * 1-5 "}), "0 5 * * 1-5")
        for bad in ({"freq": "weekly", "hour": "5", "minute": "0"}, {"freq": "monthly", "hour": "5", "minute": "0", "monthday": "31"},
                    {"freq": "daily", "hour": "24", "minute": "0"}, {"freq": "advanced", "cron": "bad"}, {}):
            self.assertRaises(su.ScheduleError, su.to_cron, bad)
        self.assertEqual(su.from_cron("30 5 * * 1,4")["weekdays"], [1, 4])
        self.assertEqual(su.from_cron("0 6 * * 0")["freq"], "weekly")
        self.assertEqual(su.from_cron("0 5 1-7 * 1")["freq"], "advanced")
        self.assertEqual(su.from_cron("*/15 * * * *")["freq"], "advanced")
        self.assertTrue(su.describe("0 5 * * 1,4", "America/New_York").startswith("Every Monday and Thursday at 05:00 E"))
        self.assertEqual(su.describe("0 5 * * 1,2,3,4,5", "UTC"), "Every weekday (Monday to Friday) at 05:00 UTC")
        self.assertEqual(su.describe("0 3 2 * *", "UTC"), "On the 2nd of every month at 03:00 UTC")
        self.assertEqual(len(su.next_runs("0 5 * * *", "UTC")), 3)
        url = "/vulnerabilities/schedules"
        r = self.c.post(url + "/linux", data={"csrf": csrf(self.c, url), "freq": "weekly", "hour": "4", "minute": "45",
                                              "weekday": ["1", "4"], "enabled": "on"}, follow_redirects=False)
        self.assertIn("ok=saved", r.headers["location"])
        with self.db.Session() as s:
            self.assertEqual(s.scalar(select(Schedule.cron).where(Schedule.platform == "linux")), "45 4 * * 1,4")
        page = self.c.get(url).text
        self.assertIn("Every Monday and Thursday at 04:45", page)
        self.assertIn("Next runs:", page)
        self.assertIn('<option value="weekly" selected>', page)
        bad = self.c.post(url + "/linux", data={"csrf": csrf(self.c, url), "freq": "weekly", "hour": "4", "minute": "0"})
        self.assertEqual(bad.status_code, 400)
        self.assertIn("Linux: Tick at least one weekday.", bad.text)

    def test_viewer_menus(self):
        self.c.post("/settings/users", data={"csrf": csrf(self.c), "username": "vic", "password": "a-long-password-1", "role": "viewer"})
        v = client(self.app)
        login(v, "vic", "a-long-password-1")
        page = v.get("/compliance").text
        for hidden in ('href="/targets"', 'href="/audit"', 'href="/compliance/schedules"', 'href="/settings"'):
            self.assertNotIn(hidden, page)
        self.assertEqual(v.get("/compliance/schedules").status_code, 403)
        self.assertEqual(v.get("/targets").status_code, 403)

    def test_os_keys(self):
        from securitas.compliance import os_key_for
        self.assertEqual([os_key_for(x) for x in ("Rocky Linux 9.6", "AlmaLinux 8.10", "Windows Server 2022 Standard", "")],
                         ["rhel9", "rhel8", "windows2022", ""])


GOSS_OUT = json.dumps({"results": [
    {"title": "1.1.1 | Ensure cramfs is not available | disabled", "successful": True, "skipped": False, "result": 0,
     "meta": {"CIS_ID": "1.1.1"}, "summary-line": "ok"},
    {"title": "1.1.1 | Ensure cramfs is not available | blacklist", "successful": False, "skipped": False, "result": 1,
     "meta": {"CIS_ID": "1.1.1"}, "summary-line": "Command: blacklist_cramfs: stdout: patterns not found: [/blacklist cramfs/]"},
    {"title": "2.10.1 | Ensure ssh is configured", "successful": True, "skipped": False, "result": 0, "meta": {"CIS_ID": ["2.10.1"]}},
    {"title": "2.10.1 | Ensure ssh is configured | Manual Check Required", "successful": False, "skipped": False, "result": 1,
     "meta": {"CIS_ID": ["2.10.1"]}},
    {"title": "9.9 | Something | Manual Check Required", "successful": False, "skipped": False, "result": 1, "meta": {"CIS_ID": ["9.9"]}},
    {"title": "1.1.2 | Ensure audit log mode", "successful": False, "skipped": True, "result": 2, "meta": {"CIS_ID": "1.1.2, 1.1.3"}},
    {"title": "Benchmark meta", "successful": True, "skipped": False, "result": 0, "meta": {}},
], "summary": {"test-count": 7, "failed-count": 3, "skipped-count": 1, "total-duration": 1000}})


class ComplianceChecker(unittest.TestCase):
    def test_parse_and_evaluate(self):
        from securitas import scan_compliance as sc
        by, summary = sc.parse_goss("some banner\n" + GOSS_OUT)
        self.assertEqual(sorted(by), ["1.1.1", "1.1.2", "1.1.3", "2.10.1", "9.9"])     # list and string CIS_IDs
        self.assertEqual(summary["test-count"], 7)
        rules, n = sc.evaluate([{"id": "1.1.1", "title": "a", "kind": "PATCH"}, {"id": "2.10.1", "title": "b", "kind": "PATCH"},
                                {"id": "1.1.2", "title": "c", "kind": "PATCH"}, {"id": "9.9", "title": "d", "kind": "AUDIT"}], by)
        # 2.10.1 passes although its manual placeholder "fails"; 9.9 has only a placeholder: no automated check
        self.assertEqual([r["status"] for r in rules], ["fail", "pass", "skip", "notest"])
        self.assertEqual((n["pass"], n["fail"], n["skip"], n["notest"], n["checked"], n["score"]), (1, 1, 1, 1, 4, 50.0))

    def test_parse_errors(self):
        from securitas import scan_compliance as sc
        with self.assertRaisesRegex(RuntimeError, "sudo refused"):
            sc.parse_goss("sudo: a password is required\n")
        with self.assertRaisesRegex(RuntimeError, "not installed"):
            sc.parse_goss("sudo: /usr/local/sbin/securitas-cis-audit: command not found")
        with self.assertRaisesRegex(RuntimeError, "not installed on"):
            sc.parse_goss('{"error": "benchmark RHEL9-CIS-9.9.9 is not installed on this host"}')

    def test_remote_command_is_quoted(self):
        from securitas import scan_compliance as sc
        self.assertEqual(sc.remote_command("RHEL9-CIS-2.4.2"), "sudo -n /usr/local/sbin/securitas-cis-audit RHEL9-CIS-2.4.2 server")
        with self.assertRaises(ValueError):
            sc.remote_command("x; rm -rf /")


class ComplianceScans(unittest.TestCase):
    def setUp(self):
        self.app, self.db, self.jobs, self.cfg = make_app()
        self.c = client(self.app)
        login(self.c, "admin", ADMIN_PW)
        from securitas.db import PlatformResult, Scan, Target
        with self.db.Session() as s, s.begin():
            s.add_all([Target(platform="linux", host="rocky1", label="Web"), Target(platform="linux", host="rocky2"),
                       Target(platform="linux", host="ubu1")])
            sc = Scan(trigger="manual", platforms=["linux"], status="done")
            s.add(sc)
            s.flush()
            s.add(PlatformResult(scan_id=sc.id, platform="linux", status="done", raw={
                "id": "linux", "title": "Linux", "totals": {}, "findings": [], "system_columns": [], "warnings": [], "failed": 0,
                "systems": [{"name": "rocky1", "os": "Rocky Linux 9.9"}, {"name": "rocky2", "os": "Rocky Linux 9.9"},
                            {"name": "ubu1", "os": "Ubuntu 22.04.4 LTS"}]}))
        self.c.post("/compliance/benchmarks", data={"csrf": csrf(self.c, "/compliance/benchmarks")},
                    files={"file": ("r.zip", role_zip(top="RHEL9-CIS-1.0.0"), "application/zip")})
        self.seen = []
        from securitas import scan_compliance as scm

        def fake(targets, say):
            self.seen = targets
            by, _ = scm.parse_goss(GOSS_OUT)
            out = {}
            for t in targets:
                if t["host"] == "rocky2":
                    out[t["host"]] = RuntimeError("sudo refused: no rule")
                else:
                    rules, n = scm.evaluate(t["rules"], by)
                    out[t["host"]] = {"os": "Rocky Linux 9.9", "rules": rules, "counts": n}
            return out
        self.jobs.compliance_scanners = {"linux": fake}

    def run_scan(self):
        r = self.c.post("/compliance/scans", data={"csrf": csrf(self.c, "/compliance/scans"), "platform": "linux"},
                        follow_redirects=False)
        self.assertEqual(r.headers["location"], "/compliance/scans/1?ok=queued")
        cid = self.jobs._claim_compliance()
        self.jobs.run_compliance(cid)
        return cid

    def test_scan_results_pages(self):
        cid = self.run_scan()
        self.assertEqual([(t["host"], t["key"], [r["id"] for r in t["rules"]]) for t in self.seen],
                         [("rocky1", "RHEL9-CIS-1.0.0", ["1.1.1", "2.10.1"]), ("rocky2", "RHEL9-CIS-1.0.0", ["1.1.1", "2.10.1"])])
        from securitas.db import ComplianceResult, ComplianceScan
        with self.db.Session() as s:
            self.assertEqual(s.get(ComplianceScan, cid).status, "partial")
            res = {r.host: r for r in s.scalars(select(ComplianceResult)).all()}
        self.assertEqual((res["rocky1"].status, res["rocky1"].counts["score"]), ("done", 50.0))
        self.assertEqual(res["rocky2"].status, "failed")
        self.assertEqual((res["ubu1"].status, res["ubu1"].error), ("skipped", "no active benchmark for Ubuntu 22.04.4 LTS"))
        page = self.c.get("/compliance/scans/%d" % cid).text
        self.assertIn("sudo refused", page)
        self.assertIn("50.0%", page)
        host = self.c.get("/compliance/scans/%d/hosts/%d" % (cid, res["rocky1"].id)).text
        self.assertIn("patterns not found", host)                     # the failed test's message
        self.assertLess(host.index("1.1.1"), host.index("2.10.1"))      # failed first
        self.assertNotIn("2.10.1", self.c.get("/compliance/scans/%d/hosts/%d?status=fail" % (cid, res["rocky1"].id)).text)
        summary = self.c.get("/compliance").text
        self.assertIn("50.0%", summary)
        self.assertIn("Checked", summary)
        report = self.c.get("/compliance/report").text
        self.assertIn("/compliance/scans/%d/hosts/%d" % (cid, res["rocky1"].id), report)
        self.assertNotIn("Active benchmarks", report)
        self.assertNotIn("Active benchmarks", summary)
        from securitas.db import Target
        with self.db.Session() as s:
            tid = s.scalar(select(Target.id).where(Target.host == "rocky1"))
        self.assertIn('href="/compliance/targets/%d">rocky1</a>' % tid, report)          # targets link to their page
        tp = self.c.get("/compliance/targets/%d" % tid).text
        self.assertIn("Checks", tp)
        self.assertIn("patterns not found", tp)                                          # the newest check's rules
        self.assertIn('name="back" value="/compliance/targets/%d"' % tid, tp)
        r = self.c.post("/compliance/scans/%d/hosts/%d/exception" % (cid, res["rocky1"].id),
                        data={"csrf": csrf(self.c, "/compliance"), "rule": "1.1.1", "scope": "server", "reason": "x",
                              "back": "/compliance/targets/%d" % tid}, follow_redirects=False)
        self.assertTrue(r.headers["location"].startswith("/compliance/targets/%d?" % tid))
        r = self.c.post("/compliance/scans/%d/hosts/%d/exception" % (cid, res["rocky1"].id),
                        data={"csrf": csrf(self.c, "/compliance"), "rule": "1.1.1", "scope": "", "back": "https://evil"},
                        follow_redirects=False)
        self.assertTrue(r.headers["location"].startswith("/compliance/scans/"))           # other targets ignored
        self.assertEqual(self.c.get("/compliance/targets/9999").status_code, 404)
        bench = self.c.get("/compliance/benchmarks").text
        self.assertIn("Trivy k8s-cis", bench)                                         # Kubernetes listed with the others
        self.assertEqual(bench.count("<th>Rules checked</th>"), 2)                    # Linux and Kubernetes tables
        hist = self.c.get("/compliance/scans").text
        self.assertIn("1 of 3", hist)

    def test_selected_hosts_only(self):
        page = self.c.get("/compliance/scans").text
        self.assertIn('name="host" value="rocky1"', page)
        self.assertNotIn('name="host" value="ubu1"', page)            # not matched to a benchmark: not offered
        r = self.c.post("/compliance/scans", data={"csrf": csrf(self.c, "/compliance/scans"), "host": ["rocky1", "nope"]},
                        follow_redirects=False)                       # no platform ticked: the hosts decide
        self.assertEqual(r.headers["location"], "/compliance/scans/1?ok=queued")
        self.jobs.run_compliance(self.jobs._claim_compliance())
        self.assertEqual([t["host"] for t in self.seen], ["rocky1"])
        from securitas.db import ComplianceResult, ComplianceScan
        with self.db.Session() as s:
            self.assertEqual(s.get(ComplianceScan, 1).hosts, ["rocky1"])
            self.assertEqual(s.get(ComplianceScan, 1).status, "done")
            self.assertEqual(s.scalars(select(ComplianceResult.host)).all(), ["rocky1"])   # ubu1 not even skipped
        self.assertIn("only rocky1", self.c.get("/compliance/scans").text)
        self.assertIn("noplat", self.c.post("/compliance/scans", data={"csrf": csrf(self.c, "/compliance/scans"), "host": "ubu1"},
                                            follow_redirects=False).headers["location"])

    def test_home_and_about(self):
        self.run_scan()
        vhome = self.c.get("/").text                                                  # Vulnerabilities tab by default
        self.assertIn('class="on" aria-current="page">Vulnerabilities</a>', vhome)
        self.assertNotIn("Compliance over time", vhome)
        self.assertIn('href="/?range=day&tab=vulnerabilities#history"', vhome)
        home = self.c.get("/?tab=compliance").text
        self.assertIn('class="on" aria-current="page">Compliance</a>', home)
        self.assertNotIn("CVEs over time", home)
        self.assertIn("<title>Home", home)
        self.assertNotIn("Compliance score per host", home)                        # moved to Compliance -> Summary
        self.assertIn("Compliance score per host", self.c.get("/compliance").text)
        self.assertIn("Compliance over time", home)
        self.assertIn('href="/?crange=day&tab=compliance#chistory"', home)                          # daily by default
        self.assertIn("Compliance over time", self.c.get("/compliance").text)
        self.assertIn('id="pie-cr-linux"', home)
        self.assertIn("50.0%", home)
        about = self.c.get("/about").text
        self.assertIn("About Securitas", about)
        self.assertIn('<a href="/about" class="on">About</a>', about)
        self.assertIn("Apache License 2.0", about)

    def test_result_survives_benchmark_removal(self):
        cid = self.run_scan()
        from securitas.db import Benchmark, ComplianceResult
        with self.db.Session() as s:
            bid = s.scalar(select(Benchmark.id))
            rid = s.scalar(select(ComplianceResult.id).where(ComplianceResult.host == "rocky1"))
        self.c.post("/compliance/benchmarks/%d" % bid, data={"csrf": csrf(self.c, "/compliance/benchmarks/%d" % bid),
                                                             "action": "delete", "confirm": "on"})
        page = self.c.get("/compliance/scans/%d/hosts/%d" % (cid, rid)).text
        self.assertIn("since removed", page)
        self.assertIn("Ensure cramfs is not available", page)          # rule titles kept with the result

    def test_exceptions(self):
        cid = self.run_scan()
        from securitas.db import ComplianceException, ComplianceResult
        with self.db.Session() as s:
            rid = s.scalar(select(ComplianceResult.id).where(ComplianceResult.host == "rocky1"))
        url = "/compliance/scans/%d/hosts/%d" % (cid, rid)
        page = self.c.get(url).text
        self.assertIn('<option value="baseline">BASELINE EXCEPTION</option>', page)
        self.assertIn('<option value="server">SERVER EXCEPTION</option>', page)
        post = lambda **d: self.c.post(url + "/exception", data={"csrf": csrf(self.c, url), **d}, follow_redirects=False)
        self.assertIn("err=reason", post(rule="1.1.1", scope="server", reason=" ").headers["location"])
        self.assertEqual(post(rule="2.10.1", scope="server", reason="x").status_code, 400)     # it passed
        self.assertIn("ok=exception", post(rule="1.1.1", scope="server", reason="Needed by the backup agent").headers["location"])
        self.assertIn("Exception saved", self.c.get(url).text)
        # the next scan reports it as Accepted, with the reason, and counts it towards the score
        cid2 = self.run_scan_again()
        with self.db.Session() as s:
            r = s.scalar(select(ComplianceResult).where(ComplianceResult.scan_id == cid2, ComplianceResult.host == "rocky1"))
        self.assertEqual((r.counts["fail"], r.counts["accepted"], r.counts["score"]), (0, 1, 100.0))
        rule = next(x for x in r.rules if x["id"] == "1.1.1")
        self.assertEqual((rule["status"], rule["exception"]["scope"], rule["exception"]["reason"]),
                         ("accepted", "server", "Needed by the backup agent"))
        host = self.c.get("/compliance/scans/%d/hosts/%d" % (cid2, r.id)).text
        self.assertIn('class="badge b-accepted">Accepted</span>', host)
        self.assertIn("SERVER EXCEPTION: Needed by the backup agent", host)
        self.assertIn("var(--cr-accepted)", self.c.get("/?tab=compliance").text)                          # charts have the colour
        self.assertIn("Needed by the backup agent", self.c.get("/compliance/exceptions").text)
        # a baseline exception replaces this host's server exception and covers every host of the benchmark
        self.assertIn("ok=exception", post(rule="1.1.1", scope="baseline", reason="Not used here").headers["location"])
        with self.db.Session() as s:
            rows = [(x.benchmark, x.rule_id, x.scope, x.host) for x in s.scalars(select(ComplianceException)).all()]
        self.assertEqual(rows, [("RHEL9-CIS", "1.1.1", "baseline", "")])
        with self.db.Session() as s:
            exc = self.jobs.exceptions_for(s, "RHEL9-CIS-9.9.9")                                 # another version: same name
        from securitas import scan_compliance as scm
        rules, n = [{"id": "1.1.1", "status": "fail"}, {"id": "2.10.1", "status": "pass"}], {"pass": 1, "fail": 1}
        scm.apply_exceptions(rules, n, "any-host", exc)
        self.assertEqual((rules[0]["status"], n["score"]), ("accepted", 100.0))
        # viewers can read exceptions but not change them; removing one is audited
        self.c.post("/settings/users", data={"csrf": csrf(self.c), "username": "vic", "password": "a-long-password-1", "role": "viewer"})
        v = client(self.app)
        login(v, "vic", "a-long-password-1")
        self.assertNotIn('name="scope"', v.get(url).text)
        self.assertEqual(v.post(url + "/exception", data={"csrf": csrf(v, url), "rule": "1.1.1", "scope": "server",
                                                          "reason": "x"}, follow_redirects=False).status_code, 403)
        self.assertIn("Not used here", v.get("/compliance/exceptions").text)
        with self.db.Session() as s:
            xid = s.scalar(select(ComplianceException.id))
        self.c.post("/compliance/exceptions/%d/delete" % xid, data={"csrf": csrf(self.c, "/compliance/exceptions")})
        with self.db.Session() as s:
            self.assertIsNone(s.scalar(select(ComplianceException.id)))
        self.assertIn("compliance_exception.remove", self.c.get("/audit").text)

    def run_scan_again(self):
        self.c.post("/compliance/scans", data={"csrf": csrf(self.c, "/compliance/scans"), "platform": "linux"})
        cid = self.jobs._claim_compliance()
        self.jobs.run_compliance(cid)
        return cid

    def test_viewer_cannot_run_and_schedule_runs(self):
        from securitas.db import ComplianceSchedule, ComplianceScan
        import datetime as dt
        with self.db.Session() as s, s.begin():
            s.add(ComplianceSchedule(platform="linux", cron="0 6 * * 0", enabled=True,
                                     next_run=dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)))
            s.add(ComplianceSchedule(platform="windows", cron="0 6 * * 0", enabled=True,
                                     next_run=dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)))
        self.jobs.run_due()
        with self.db.Session() as s:
            self.assertEqual([x.platforms for x in s.scalars(select(ComplianceScan)).all()], [["linux"]])   # windows: no checker
        self.c.post("/settings/users", data={"csrf": csrf(self.c), "username": "vic", "password": "a-long-password-1", "role": "viewer"})
        v = client(self.app)
        login(v, "vic", "a-long-password-1")
        r = v.post("/compliance/scans", data={"csrf": csrf(v, "/compliance/scans"), "platform": "linux"}, follow_redirects=False)
        self.assertEqual(r.status_code, 403)


WIN_ZIPS = {k: os.environ.get("SECURITAS_TEST_" + k.replace("-", "_").upper(), "/mnt/c/Users/huhl/Downloads/%s.zip" % k)
            for k in ("Windows-2022-CIS-4.2.0", "Windows-2025-CIS-1.2.2")}


def win_zip(top="Windows-2022-CIS-9.0.0"):
    """A Windows-shaped role: member server / domain controller level tags."""
    tasks = """---
- name: "1.1.1 | PATCH | Ensure 'Enforce password history' is set to '24 or more password(s)'"
  when: win22cis_rule_1_1_1
  tags: [level1-domaincontroller, level1-memberserver, rule_1.1.1, NIST800-53R5_IA-5]
  ansible.windows.win_security_policy: {section: System Access, key: PasswordHistorySize, value: 24}
- name: "2.3.5.4 | PATCH | Ensure 'Domain controller: LDAP server signing requirements' is set to 'Require signing' (DC only)"
  when: win22cis_rule_2_3_5_4
  tags: [level1-domaincontroller, rule_2.3.5.4]
  ansible.windows.win_regedit: {path: HKLM:\\x, name: y, data: 2}
- name: "2.3.10.1 | PATCH | Ensure network access is restricted (MS only)"
  when: win22cis_rule_2_3_10_1
  tags: [level1-memberserver, rule_2.3.10.1]
  ansible.windows.win_regedit: {path: HKLM:\\x, name: z, data: 1}
- name: "18.1.1 | PATCH | Ensure a level 2 setting"
  when: win22cis_rule_18_1_1
  tags: [level2-domaincontroller, level2-memberserver, rule_18.1.1]
  ansible.windows.win_regedit: {path: HKLM:\\x, name: w, data: 1}
"""
    return role_zip(top=top, platform="Windows", extra={"tasks/section_1/cis_1.1.x.yml": tasks},   # replaces the Linux sample
                    defaults="benchmark_version: 'v4.0.0'\nwin22cis_rule_1_1_1: true\nwin22cis_rule_2_3_5_4: true\n"
                             "win22cis_rule_2_3_10_1: true\nwin22cis_rule_18_1_1: true\n")


class WindowsCompliance(unittest.TestCase):
    def test_profiles_by_role(self):
        from securitas import compliance
        b = compliance.parse_zip(win_zip())
        r = {x["rule_id"]: x for x in b["rules"]}
        self.assertEqual(r["2.3.5.4"]["levels"], ["level1-domaincontroller"])
        self.assertEqual(compliance.default_profile("windows"), "level1-auto")
        ms = [x for x in b["rules"] if compliance.in_profile(x["levels"], "level1-auto", "memberserver")]
        dc = [x for x in b["rules"] if compliance.in_profile(x["levels"], "level1-auto", "domaincontroller")]
        self.assertEqual(sorted(x["rule_id"] for x in ms), ["1.1.1", "2.3.10.1"])
        self.assertEqual(sorted(x["rule_id"] for x in dc), ["1.1.1", "2.3.5.4"])
        self.assertEqual(len([x for x in b["rules"] if compliance.in_profile(x["levels"], "level2-auto", "domaincontroller")]), 3)

    @unittest.skipUnless(all(os.path.exists(p) for p in WIN_ZIPS.values()), "real Windows CIS zips not available")
    def test_real_windows_zips(self):
        import yaml
        import zipfile
        from securitas import compliance
        for key, path in WIN_ZIPS.items():
            b = compliance.parse_zip(open(path, "rb").read())
            self.assertEqual((b["key"], b["platform"]), (key, "windows"))
            self.assertTrue(all(r["levels"] for r in b["rules"]), key)          # every rule has a level tag
            z = zipfile.ZipFile(path)
            d = yaml.safe_load(z.read(key + "/defaults/main/main.yml"))
            toggles = {k for k in d if re.fullmatch(r"win\d\dcis_rule_\d+(_\d+)+", k)}
            self.assertEqual({r["toggle"] for r in b["rules"]}, toggles, key)

    def test_parse_windows_output(self):
        from securitas import scan_compliance as sc
        role, osn, payload = sc.parse_windows("##ROLE 5\n##OS Microsoft Windows Server 2022 Standard\n##RESULT 0\n##JSON\n" + GOSS_OUT)
        self.assertEqual((role, sc.host_kind(role), osn), (5, "domaincontroller", "Microsoft Windows Server 2022 Standard"))
        self.assertEqual(sc.host_kind(3), "memberserver")
        with self.assertRaisesRegex(RuntimeError, "may not start"):
            sc.parse_windows("##ROLE 3\n##ERROR this account may not start the scheduled task: Access is denied\n")
        self.assertIn("'Windows-2022-CIS-4.2.0'", sc.windows_script("Windows-2022-CIS-4.2.0"))
        with self.assertRaises(ValueError):
            sc.windows_script("x' ; Remove-Item C:\\")

    def test_scan_uses_rules_for_each_role(self):
        app, db, jobs, cfg = make_app()
        c = client(app)
        login(c, "admin", ADMIN_PW)
        from securitas.db import ComplianceResult, PlatformResult, Scan, Target
        with db.Session() as s, s.begin():
            s.add_all([Target(platform="windows", host="dc1"), Target(platform="windows", host="ms1")])
            sc_ = Scan(trigger="manual", platforms=["windows"], status="done")
            s.add(sc_)
            s.flush()
            s.add(PlatformResult(scan_id=sc_.id, platform="windows", status="done", raw={
                "id": "windows", "title": "Windows", "totals": {}, "findings": [], "system_columns": [], "warnings": [], "failed": 0,
                "systems": [{"name": "dc1", "os": "Windows Server 2022 Standard"}, {"name": "ms1", "os": "Windows Server 2022 Datacenter"}]}))
        r = c.post("/compliance/benchmarks", data={"csrf": csrf(c, "/compliance/benchmarks")},
                   files={"file": ("w.zip", win_zip(top="Windows-2022-CIS-9.0.0"), "application/zip")}, follow_redirects=False)
        self.assertEqual(r.status_code, 303)
        from securitas import scan_compliance as scm
        seen = {}

        def fake(targets, say):
            out = {}
            for t in targets:
                kind = "domaincontroller" if t["host"] == "dc1" else "memberserver"
                rules, n = scm.evaluate(t["rules_by_kind"][kind], {})
                seen[t["host"]] = [x["id"] for x in rules]
                out[t["host"]] = {"os": "Windows Server 2022", "rules": rules, "counts": n, "host_kind": kind}
            return out
        jobs.compliance_scanners["windows"] = fake
        page = c.get("/compliance/scans").text
        self.assertIn('name="platform" value="windows" checked', page)
        c.post("/compliance/scans", data={"csrf": csrf(c, "/compliance/scans"), "platform": "windows"})
        jobs.run_compliance(jobs._claim_compliance())
        self.assertEqual(seen, {"dc1": ["1.1.1", "2.3.5.4"], "ms1": ["1.1.1", "2.3.10.1"]})
        with db.Session() as s:
            prof = {r.host: r.profile for r in s.scalars(select(ComplianceResult)).all()}
        self.assertEqual(prof, {"dc1": "level1-auto (domaincontroller)", "ms1": "level1-auto (memberserver)"})
        detail = c.get("/compliance/benchmarks/1").text
        self.assertIn("2 of 4 on member servers, 2 of 4 on domain controllers", detail)
        self.assertIn("by each host&#39;s role", detail)


def make_cert(names=("securitas.example.com",), days=365, ca=None, eku=True):
    """(cert, key) for tests; signed by ca=(cert, key) when given, else self-signed."""
    import datetime as dt
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0] if names else "CA")])
    b = (x509.CertificateBuilder().subject_name(subj).issuer_name(ca[0].subject if ca else subj)
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - dt.timedelta(days=max(1, 5 - days))).not_valid_after(now + dt.timedelta(days=days)))
    if names:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), False)
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
    return b.sign(ca[1] if ca else key, hashes.SHA256()), key


class Certificates(unittest.TestCase):
    def setUp(self):
        self.app, self.db, self.jobs, self.cfg = make_app(tls_secrets=["securitas-tls"], tls_hosts=["securitas.example.com"],
                                                          namespace="securitas")
        self.c = client(self.app)
        login(self.c, "admin", ADMIN_PW)
        from cryptography.hazmat.primitives import serialization as ser
        self.ser = ser
        self.ca = make_cert((), 3650, eku=False)
        old, _ = make_cert(days=10, ca=self.ca)
        self.store = {"crt": old.public_bytes(ser.Encoding.PEM), "key": None}
        from securitas import k8s
        self._get, self._put = k8s.get_tls_secret, k8s.put_tls_secret
        k8s.get_tls_secret = lambda cfg, name: (self.store["crt"], True)
        k8s.put_tls_secret = lambda cfg, name, crt, key: self.store.update(crt=crt, key=key, name=name)

    def tearDown(self):
        from securitas import k8s
        k8s.get_tls_secret, k8s.put_tls_secret = self._get, self._put

    def pem(self, c, k=None):
        ser = self.ser
        return c.public_bytes(ser.Encoding.PEM), (k.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()) if k else b"")

    def post(self, files, **data):
        url = "/settings/certificates"
        return self.c.post(url, data={"csrf": csrf(self.c, url), **data}, files=files, follow_redirects=False)

    def test_page_and_replace(self):
        page = self.c.get("/settings/certificates").text
        self.assertIn("securitas-tls", page)
        self.assertIn("days left", page)
        self.assertIn('href="/settings/certificates"', self.c.get("/settings").text)
        new, key = make_cert(ca=self.ca)
        crt, kp = self.pem(new, key)
        chain, _ = self.pem(self.ca[0])
        files = {"cert": ("c.pem", crt), "key": ("k.pem", kp), "chain": ("ca.pem", chain)}
        r = self.post(files, action="check")
        self.assertEqual(r.status_code, 200)
        self.assertIn("This certificate can be used", r.text)
        self.assertIsNone(self.store["key"])                                         # check only: nothing written
        self.assertEqual(self.post(files, action="replace").status_code, 400)        # Confirm not ticked
        r = self.post(files, action="replace", confirm="on")
        self.assertIn("ok=cert", r.headers["location"])
        self.assertEqual(self.store["crt"], crt)                                     # the root CA is not put in tls.crt
        self.assertIn(b"PRIVATE KEY", self.store["key"])
        self.assertIn("tls.replaced", self.c.get("/audit").text)

    def test_pfx_and_problems(self):
        from cryptography.hazmat.primitives.serialization import pkcs12, BestAvailableEncryption
        new, key = make_cert(ca=self.ca)
        pfx = pkcs12.serialize_key_and_certificates(b"x", key, new, [self.ca[0]], BestAvailableEncryption(b"pw"))
        self.assertIn("wrong password", self.post({"pfx": ("s.pfx", pfx)}, action="check", password="nope").text)
        r = self.post({"pfx": ("s.pfx", pfx)}, action="replace", confirm="on", password="pw")
        self.assertIn("ok=cert", r.headers["location"])
        other, okey = make_cert(("other.example.com",), ca=self.ca)
        crt, kp = self.pem(other, okey)
        r = self.post({"cert": ("c.pem", crt), "key": ("k.pem", kp)}, action="replace", confirm="on")
        self.assertEqual(r.status_code, 400)
        self.assertIn("does not cover securitas.example.com", r.text)
        _, wrong = make_cert()
        r = self.post({"cert": ("c.pem", self.pem(new)[0]), "key": ("k.pem", self.pem(new, wrong)[1])}, action="check")
        self.assertIn("does not belong to the certificate", r.text)
        old, oldkey = make_cert(days=-2, ca=self.ca)
        r = self.post({"cert": ("c.pem", self.pem(old)[0]), "key": ("k.pem", self.pem(old, oldkey)[1])}, action="check")
        self.assertIn("The certificate expired", r.text)

    def test_admins_only(self):
        self.c.post("/settings/users", data={"csrf": csrf(self.c), "username": "otto", "password": "a-long-password-1", "role": "operator"})
        o = client(self.app)
        login(o, "otto", "a-long-password-1")
        self.assertEqual(o.get("/settings/certificates").status_code, 403)
        self.assertNotIn("/settings/certificates", o.get("/settings").text)
        self.assertEqual(o.post("/settings/certificates", data={"csrf": csrf(o)}).status_code, 403)


def audit_zip(top="RHEL9-CIS-Audit-d9c0f2ce3be6", cis="rhel9cis_nfs_server: true\nrhel9cis_rpc_server: true\n"
              "rhel9cis_rule_2_1_9: true\nrhel9cis_level_1: true\nbenchmark_version: v1.0.0\nrhel9cis_motd: 'hello'\n",
              extra=None):
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(top + "/goss.yml", "gossfile:\n  section_1/*.yml: {}\n")
        z.writestr(top + "/vars/CIS.yml", cis)
        z.writestr(top + "/section_1/cis_1.1.1.yml", "file: {}\n")
        z.writestr(top + "/.github/workflows/x.yml", "x: 1\n")
        for k, v in (extra or {}).items():
            z.writestr(top + "/" + k, v)
    return buf.getvalue()


class AuditBundle(unittest.TestCase):
    def test_settings_and_bundle(self):
        import io
        import tarfile
        import yaml
        from securitas import audit_bundle as ab
        data = audit_zip()
        audit = ab.audit_defaults(data)
        role = {"rhel9cis_rpc_server": False, "rhel9cis_rule_2_1_9": False, "rhel9cis_level_1": False, "rhel9cis_motd": "role"}
        s = {k: (v, src) for k, v, src, _ in ab.settings(audit, role, {"rhel9cis_nfs_server": False})}
        self.assertEqual(s, {"rhel9cis_nfs_server": (False, "here"), "rhel9cis_rpc_server": (False, "role")})  # no rule/level
        v = ab.effective_vars(audit, role, {"rhel9cis_nfs_server": False, "nope": True})
        self.assertEqual((v["rhel9cis_nfs_server"], v["rhel9cis_rpc_server"], v["rhel9cis_rule_2_1_9"], v["rhel9cis_level_1"],
                          v["rhel9cis_motd"]), (False, False, True, True, "hello"))     # rule/level switches and text never from the role
        self.assertNotIn("nope", v)
        b1, h1 = ab.build(data, v)
        b2, h2 = ab.build(data, v)
        self.assertEqual((b1, h1), (b2, h2))                                             # deterministic
        self.assertNotEqual(h1, ab.build(data, audit)[1])
        with tarfile.open(fileobj=io.BytesIO(b1)) as t:
            members = t.getmembers()
            names = sorted(m.name for m in members)
            self.assertTrue(all(m.isfile() or m.isdir() for m in members))
            self.assertTrue(all(n.startswith("./") and ".." not in n for n in names))
            self.assertIn("./goss.yml", names)
            self.assertFalse(any(".github" in n for n in names))
            self.assertFalse(yaml.safe_load(t.extractfile("./vars/CIS.yml").read())["rhel9cis_nfs_server"])

    def test_bad_audit_zips(self):
        from securitas import audit_bundle as ab
        from securitas.compliance import BenchmarkError

        class B:
            name = "RHEL9-CIS"
        self.assertEqual(ab.parse_audit_zip(audit_zip(), B)["commit"], "d9c0f2ce3be6")
        import io
        import zipfile
        for bad in (b"not a zip", audit_zip(cis="other_setting: 1\n")):
            self.assertRaises(BenchmarkError, ab.parse_audit_zip, bad, B)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("A/goss.yml", "x")
            z.writestr("A/vars/CIS.yml", "rhel9cis_x: true")
            i = zipfile.ZipInfo("A/evil")
            i.external_attr = (0o120777 << 16)
            z.writestr(i, "/etc/shadow")
        self.assertRaises(BenchmarkError, ab.parse_audit_zip, buf.getvalue(), B)       # symlink refused

    def test_run_host_copies_and_runs(self):
        from securitas import scan_compliance as scm

        class Chan:
            def __init__(self, log):
                self.log, self.data = log, b""
            def settimeout(self, t): pass
            def exec_command(self, c): self.log.append(("exec", c))
            def sendall(self, d): self.data += d
            def shutdown_write(self): self.log.append(("sent", self.data))
            def recv_exit_status(self): return 0
            def recv_stderr_ready(self): return False
            def close(self): pass

        class Out:
            def __init__(self, text): self.text, self.channel = text, self
            def read(self): return self.text.encode()
            def recv_exit_status(self): return 0

        class Client:
            def __init__(self, reply):
                self.log, self.reply = [], reply
            def get_transport(self):
                c = self
                class T:
                    def open_session(self, timeout=None): return Chan(c.log)
                return T()
            def exec_command(self, cmd, timeout=None):
                self.log.append(("run", cmd))
                return None, Out(self.reply if "securitas-cis-audit" in cmd else ""), None
            def close(self): pass

        orig = scm.scan_linux.connect
        try:
            cl = Client("##OS Rocky Linux 9.6\n" + GOSS_OUT)
            scm.scan_linux.connect = lambda cfg, t, rk: cl
            cfg = type("C", (), {"host_timeout": 60})()
            t = {"host": "h", "key": "RHEL9-CIS-1.0.0", "system_type": "server", "bundle": (b"BUNDLE", "ab" * 32),
                 "rules": [{"id": "1.1.1", "title": "x", "kind": "PATCH"}]}
            r = scm.run_host(cfg, t, None)
            self.assertEqual(r["content"], "bundle:" + "ab" * 32)
            up = [c for k, c in cl.log if k == "exec"][0]
            path = re.search(r"cat > (\S+)", up).group(1)
            self.assertRegex(path, r"^/tmp/\.securitas-[A-Za-z0-9]{24}\.tar\.gz$")
            self.assertIn("noclobber", up)
            self.assertIn(("sent", b"BUNDLE"), cl.log)
            run = [c for k, c in cl.log if k == "run" and "securitas-cis-audit" in c][0]
            self.assertIn("RHEL9-CIS-1.0.0 server " + path, run)
            self.assertTrue(any(k == "run" and c == "rm -f " + path for k, c in cl.log))   # cleanup
            cl = Client('##OS Rocky\n{"error":"benchmark RHEL9-CIS-1.0.0: no audit content (goss.yml, vars/CIS.yml)"}\n')
            with self.assertRaisesRegex(RuntimeError, "update the agent"):
                scm.run_host(cfg, t, None)
            with self.assertRaisesRegex(RuntimeError, "could not be built"):
                scm.run_host(cfg, {**t, "bundle": ValueError("bad zip")}, None)
            self.assertRaises(ValueError, scm.remote_command, "K", "server", "/etc/passwd")
        finally:
            scm.scan_linux.connect = orig


class AuditUploadAndAgent(unittest.TestCase):
    def setUp(self):
        T = ComplianceScans("run_scan")
        T.setUp()
        self.t = T
        from securitas.db import Benchmark
        with T.db.Session() as s:
            self.bid = s.scalar(select(Benchmark.id))
        self.url = "/compliance/benchmarks/%d" % self.bid

    def test_upload_settings_and_scan_uses_bundle(self):
        c = self.t.c
        page = c.get(self.url).text
        self.assertIn("Not uploaded", page)
        r = c.post(self.url + "/audit", data={"csrf": csrf(c, self.url)}, files={"file": ("x.zip", b"junk")},
                   follow_redirects=False)
        self.assertIn("err=audit", r.headers["location"])
        r = c.post(self.url + "/audit", data={"csrf": csrf(c, self.url)}, files={"file": ("a.zip", audit_zip())},
                   follow_redirects=False)
        self.assertIn("ok=audit", r.headers["location"])
        page = c.get(self.url).text
        self.assertIn("RHEL9-CIS-Audit-d9c0f2ce3be6", page)
        self.assertIn("rhel9cis_nfs_server", page)
        self.assertNotIn("rhel9cis_rule_2_1_9<", page)
        c.post(self.url, data={"csrf": csrf(c, self.url), "action": "audit_settings", "shown": ["rhel9cis_nfs_server"],
                               "set_rhel9cis_nfs_server": "off"})
        from securitas.db import Benchmark, ComplianceResult
        with self.t.db.Session() as s:
            self.assertEqual(s.get(Benchmark, self.bid).meta["audit_settings"], {"rhel9cis_nfs_server": False})
        cid = self.t.run_scan()
        self.assertTrue(all(isinstance(x["bundle"], tuple) for x in self.t.seen))       # the scanner got the bundle
        with self.t.db.Session() as s:
            from securitas import compliance
            b = s.get(Benchmark, self.bid)
            want = compliance.audit_bundle(s, b)[1]
        self.assertEqual(self.t.seen[0]["bundle"][1], want)
        self.assertIn("benchmark.audit_uploaded", c.get("/audit").text)
        self.assertIn("benchmark.audit_settings", c.get("/audit").text)

    def test_agent_page_and_script(self):
        c = self.t.c
        anon = client(self.t.app)
        s = anon.get("/agent/install.sh")                                              # public: no secrets in it
        self.assertEqual(s.status_code, 200)
        self.assertIn("securitas-agent-setup --user", s.text)
        self.assertIn("SCAN_USER=svc-securitas", s.text)
        self.assertIn("BASE=http://testserver", s.text)
        self.assertNotIn("PRIVATE", s.text)
        self.assertIn(anon.get("/agent/securitas-agent.rpm").status_code, (200, 404))
        self.assertIn(anon.get("/settings/agent", follow_redirects=False).status_code, (303, 401, 403))
        page = c.get("/settings/agent").text
        self.assertIn("curl -fsS http://testserver/agent/install.sh | sudo bash", page)
        r = c.post("/settings/agent", data={"csrf": csrf(c, "/settings/agent"), "allowed": "192.168.11.42, 192.168.11.43"},
                   follow_redirects=False)
        self.assertIn("ok=saved", r.headers["location"])
        self.assertIn("SCAN_FROM=192.168.11.42,192.168.11.43", anon.get("/agent/install.sh").text)
        self.assertIn("err=agentfrom", c.post("/settings/agent", data={"csrf": csrf(c, "/settings/agent"),
                                                                      "allowed": "x; rm -rf /"}, follow_redirects=False).headers["location"])
