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
        self.assertEqual([r["cve"] for r in sec["cves"]], ["CVE-2099-0002", "CVE-2099-0001", "CVE-2099-0004"])
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
        self.assertIn("CVE-2099-0003", [r["cve"] for r in report.build_platform(raw, later)["cves"]])
        self.assertNotIn("CVE-2099-0003", [r["cve"] for r in report.build_platform(raw, ranker())["cves"]])

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
        self.assertEqual([r["cve"] for r in sec["cves"]], ["CVE-2099-0002"])

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
        self.assertEqual([r["cve"] for r in sec["cves"]], ["CVE-2099-0002"])
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
    def __init__(self, cfg):
        self.cfg, self.at = cfg, 1

    def get(self, force=False):
        return KEV, EPSS, {"kev": "test KEV", "epss": "test EPSS"}, []

    def ranker(self, force=False):
        return report.Ranker(KEV, EPSS, 0.10), {"kev": "test KEV", "epss": "test EPSS"}, []


def make_app(**over):
    from securitas.server import build
    cfg = Config(database_url="sqlite://", data_dir=tempfile.mkdtemp(), secure_cookies=False, admin_password=ADMIN_PW,
                 role_map=["Securitas-Admins=admin", "Securitas-Operators=operator", "Securitas-Viewers=viewer"],
                 base_url="http://testserver",
                 schedules={"kubernetes": "5 * * * *", "linux": "0 5 * * *", "windows": "30 5 * * *"}, **over)
    app, db, jobs = build(cfg, start_threads=False, scanners={"kubernetes": fake_kubernetes})
    jobs.feeds = FakeFeeds(cfg)
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
        for p in ("/", "/scans", "/report.pdf", "/data.json", "/admin/users"):
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
            self.c.post("/admin/users", data={"csrf": tok, "username": name, "password": "a-long-password-1", "role": role})
        v = client(self.app)
        self.assertEqual(login(v, "vera", "a-long-password-1").headers["location"], "/")
        self.assertEqual(v.get("/").status_code, 200)
        self.assertEqual(v.get("/scans").status_code, 200)
        self.assertNotIn("Run scan", v.get("/scans").text)
        self.assertEqual(v.post("/scans", data={"csrf": csrf(v), "platform": "kubernetes"}).status_code, 403)
        for p in ("/schedules", "/admin/targets", "/admin/users", "/admin/auth", "/admin/audit"):
            self.assertEqual(v.get(p).status_code, 403, p)
        o = client(self.app)
        login(o, "otto", "a-long-password-1")
        self.assertEqual(o.post("/scans", data={"csrf": csrf(o), "platform": "kubernetes"}, follow_redirects=False).status_code, 303)
        self.assertEqual(o.get("/schedules").status_code, 200)
        r = o.post("/schedules/linux", data={"csrf": csrf(o), "cron": "15 3 * * 1", "enabled": "on"}, follow_redirects=False)
        self.assertIn("ok=saved", r.headers["location"])
        self.assertIn("err=cron", o.post("/schedules/linux", data={"csrf": csrf(o), "cron": "bad"}, follow_redirects=False).headers["location"])
        for p in ("/admin/targets", "/admin/users", "/admin/auth", "/admin/audit"):
            self.assertEqual(o.get(p).status_code, 403, p)
        audit = self.c.get("/admin/audit").text
        self.assertIn("scan.run", audit)
        self.assertIn("schedule.saved", audit)

    def test_targets(self):
        login(self.c, "admin", ADMIN_PW)
        tok = csrf(self.c)
        self.c.post("/admin/targets", data={"csrf": tok, "platform": "linux", "host": "web1.example.com", "label": "Web"})
        self.assertIn("err=host", self.c.post("/admin/targets", data={"csrf": tok, "platform": "linux", "host": "bad host;rm"},
                                              follow_redirects=False).headers["location"])
        self.assertIn("web1.example.com", self.c.get("/admin/targets").text)
        self.assertIn("1 target)", self.c.get("/scans").text)

    def test_last_admin_and_self(self):
        login(self.c, "admin", ADMIN_PW)
        r = self.c.post("/admin/users/1", data={"csrf": csrf(self.c), "action": "role", "role": "viewer"}, follow_redirects=False)
        self.assertIn("err=self", r.headers["location"])

    def test_password_change_and_disable(self):
        login(self.c, "admin", ADMIN_PW)
        tok = csrf(self.c)
        self.c.post("/admin/users", data={"csrf": tok, "username": "pat", "password": "first-password-1", "role": "viewer"})
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
        self.c.post("/admin/users/%d" % uid, data={"csrf": tok, "action": "disable"})
        self.assertEqual(p.get("/", follow_redirects=False).status_code, 303)
        self.assertIn("e=", login(client(self.app), "pat", "second-password-2").headers["location"])

    def test_local_login_off(self):
        login(self.c, "admin", ADMIN_PW)
        tok = csrf(self.c)
        self.c.post("/admin/users", data={"csrf": tok, "username": "loc", "password": "local-password-1", "role": "viewer"})
        self.c.post("/admin/auth/local", data={"csrf": tok})
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
        self.assertIn("No scan has finished yet", self.c.get("/").text)
        self._scan(["kubernetes"])
        page = self.c.get("/").text
        self.assertIn("<title>Summary", page)
        self.assertIn('href="/report#kubernetes"', page)
        m = self.jobs.current_model()
        row = report.summary(m)[0]
        self.assertEqual(row["priority"], len(m["platforms"][0]["cves"]))
        self.assertEqual(row["kev"], sum(1 for r in m["platforms"][0]["cves"] if r["kev"]))
        self.assertIn('<section id="kubernetes">', self.c.get("/report").text)
        self.assertNotIn("CVE-2099-0002", page)          # the summary lists counts, not CVEs

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
        self.assertIn("Users", c.get("/").text)
        self.assertIn("e=norole", login(client(self.app), "nobody", "nobody-password").headers["location"])


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


if __name__ == "__main__":
    unittest.main()
