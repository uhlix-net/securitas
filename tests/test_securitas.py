"""Unit tests on synthetic data. Run: python -m unittest discover -s tests"""
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from securitas import render, report  # noqa: E402
from securitas.config import Config  # noqa: E402
from securitas.server import State, make_handler  # noqa: E402


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


def model(extras=(), warnings=None):
    cfg = Config(cluster_name="test")
    return report.build(cfg, REPORTS, KEV, "kev src", EPSS, "epss src", list(extras), warnings or [])


class ReportTests(unittest.TestCase):
    def test_priority_and_order(self):
        k = model()["platforms"][0]
        self.assertEqual([r["cve"] for r in k["cves"]], ["CVE-2099-0002", "CVE-2099-0001", "CVE-2099-0004"])
        top = k["cves"][0]
        self.assertEqual((top["kev"], top["ransomware"], top["severity"]), ("2099-01-02", True, "High"))
        self.assertEqual(top["fix"], "No fix published")
        self.assertIn("1.2", k["cves"][1]["fix"])

    def test_totals_and_systems(self):
        k = model()["platforms"][0]
        self.assertEqual(k["totals"]["Images scanned"], 3)
        self.assertEqual(k["totals"]["Distinct vulnerabilities"], 4)
        self.assertEqual(k["totals"]["Critical findings"], 1)
        self.assertEqual(k["totals"]["In CISA KEV"], 1)
        names = [s["name"] for s in k["systems"]]
        self.assertEqual(names[0], "library/app:1.0")
        self.assertIn("ghcr.io/team/tool:2.3", names)
        self.assertNotIn("library/quiet:1", names)
        self.assertEqual(k["systems"][0]["namespaces"], "db, web")

    def test_html_escapes_scanner_text(self):
        page = render.render_html(model())
        self.assertNotIn("<b>y</b>", page)
        self.assertNotIn("<script>", page)
        self.assertIn("x &lt;b&gt;y&lt;/b&gt;", page)
        self.assertIn('href="report.pdf"', page)

    def test_extra_platform(self):
        with tempfile.TemporaryDirectory() as d:
            json.dump({"id": "linux", "title": "Linux", "system_columns": [{"key": "name", "label": "Server"}],
                       "systems": [{"name": "host1"}],
                       "cves": [{"cve": "CVE-2099-0002", "systems": ["host1"]}, {"cve": "CVE-2099-0003"}]},
                      open(os.path.join(d, "linux.json"), "w"))
            open(os.path.join(d, "broken.json"), "w").write("{")
            warnings = []
            extras = report.load_extra(d, warnings)
            m = model(extras, warnings)
        self.assertEqual(len(extras), 1)
        self.assertTrue(any("broken.json" in w for w in m["warnings"]))
        linux = m["platforms"][1]
        self.assertEqual([r["cve"] for r in linux["cves"]], ["CVE-2099-0002"])
        self.assertEqual(linux["cves"][0]["title"], "Bar flaw")

    @unittest.skipUnless(__import__("importlib").util.find_spec("weasyprint"), "weasyprint not installed")
    def test_pdf(self):
        pdf = render.render_pdf(render.render_html(model()))
        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertGreater(len(pdf), 5000)


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from http.server import ThreadingHTTPServer
        cls.state = State()
        cls.state.html, cls.state.pdf, cls.state.json = b"<html>ok</html>", b"%PDF-1.7 test", b"{}"
        cls.state.pdf_name = "securitas-report-2099-01-01.pdf"
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(cls.state))
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.base = "http://127.0.0.1:%d" % cls.httpd.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def get(self, path, method="GET"):
        try:
            r = urllib.request.urlopen(urllib.request.Request(self.base + path, method=method, data=b"x" if method == "POST" else None))
            return r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read()

    def test_routes(self):
        code, h, body = self.get("/")
        self.assertEqual((code, body), (200, b"<html>ok</html>"))
        self.assertIn("default-src 'none'", h["Content-Security-Policy"])
        code, h, body = self.get("/report.pdf")
        self.assertEqual(code, 200)
        self.assertIn("securitas-report-2099-01-01.pdf", h["Content-Disposition"])
        self.assertEqual(self.get("/nope")[0], 404)
        self.assertEqual(self.get("/", "POST")[0], 405)
        self.assertEqual(self.get("/healthz")[0], 200)


if __name__ == "__main__":
    unittest.main()
