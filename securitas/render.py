"""Render the report model to HTML, and the same HTML to PDF with WeasyPrint (no browser)."""
import html
import re

e = lambda s: html.escape(str(s), quote=True)


def pdf_name(model):
    return "securitas-report-%s.pdf" % model["date"]


def _sev(s):
    cls = "".join(ch for ch in s.lower() if ch.isalpha()) or "unknown"
    return '<span class="sev sev-%s">%s</span>' % (cls, e(s))


def _kev(r):
    if not r["kev"]:
        return '<span class="muted">No</span>'
    out = '<span class="kev">KEV</span> <span class="date">%s</span>' % e(r["kev"])
    if r["ransomware"]:
        out += '<br><span class="ransom">ransomware use</span>'
    return out


def _epss(v):
    cls = "hi" if v >= 0.5 else "mid" if v >= 0.1 else "lo"
    return '<span class="epss-%s">%.2f</span>' % (cls, v)


def _link(cve):
    if cve.startswith("CVE-"):
        return '<a href="https://nvd.nist.gov/vuln/detail/%s">%s</a>' % (e(cve), e(cve))
    return '<a href="https://osv.dev/vulnerability/%s">%s</a>' % (e(cve), e(cve))


def _cell(value, typ):
    if typ in ("num", "hot"):
        try:
            n = int(value)
            return '<td class="n%s">%s</td>' % (" hot" if typ == "hot" and n else "", format(n, ","))
        except (TypeError, ValueError):
            return '<td class="n">%s</td>' % e(value)
    cls = {"mono": "mono", "date": "date"}.get(typ, "")
    return '<td%s>%s</td>' % (' class="%s"' % cls if cls else "", e(value if value is not None else ""))


def _systems(p):
    cols = p["system_columns"]
    if not cols or not p["systems"]:
        return ""
    head = "".join("<th>%s</th>" % e(c.get("label", c["key"])) for c in cols)
    rows = "\n".join("<tr>%s</tr>" % "".join(_cell(s.get(c["key"], ""), c.get("type", "text")) for c in cols) for s in p["systems"])
    return '<h3>%s</h3><div class="scroll"><table><thead><tr>%s</tr></thead><tbody>%s</tbody></table></div>' % (
        e(p["systems_caption"]), head, rows)


def _cves(p):
    nkev = sum(1 for r in p["cves"] if r["kev"])
    title = '<h3>Priority CVEs <span class="count">%d listed, %d known exploited</span></h3>' % (len(p["cves"]), nkev)
    if not p["cves"]:
        return title + '<p class="muted">No CVE on this platform is in the CISA KEV catalog or above the EPSS threshold.</p>'
    head = "".join("<th>%s</th>" % e(h) for h in
                   ["CVE", "Description", "Severity", "Known exploited", "EPSS", p["affected_label"], "Component", "Fix", "Status"])
    rows = []
    for r in p["cves"]:
        rows.append('<tr%s><td class="mono nowrap">%s</td><td>%s</td><td>%s</td><td class="nowrap">%s</td><td class="n">%s</td>'
                    '<td class="mono small aff">%s</td><td class="small">%s</td><td class="small">%s</td><td class="small">%s</td></tr>' % (
                        ' class="iskev"' if r["kev"] else "", _link(r["cve"]),
                        e(r["title"]) or '<span class="muted">No description</span>', _sev(r["severity"]), _kev(r),
                        _epss(r["epss"]), "<br>".join(e(s) for s in r["systems"]), e(r["component"]), e(r["fix"]), e(r["status"])))
    return title + '<div class="scroll"><table class="cves"><thead><tr>%s</tr></thead><tbody>%s</tbody></table></div>' % (
        head, "\n".join(rows))


def _section(p):
    totals = "".join('<div class="stat"><div class="v">%s</div><div class="k">%s</div></div>' % (
        format(v, ",") if isinstance(v, int) else e(v), e(k)) for k, v in p["totals"].items())
    return '<section id="%s"><h2>%s</h2><p class="sub">%s</p><div class="stats">%s</div>%s%s</section>' % (
        e(p["id"]), e(p["title"]), e(p["subtitle"]), totals, _systems(p), _cves(p))


CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1a2230;--muted:#5d6878;--line:#dfe3ea;--head:#eef1f5;--accent:#1f4e79;--accent-ink:#fff;
--crit:#a4161a;--crit-bg:#fde8e8;--imp:#9a4a00;--imp-bg:#fdebd3;--mod:#6b5900;--mod-bg:#fbf3c4;--low:#3d5a80;--low-bg:#e3ecf7;--kevrow:#fff6f5;
--warn-bg:#fff4d6;--warn-line:#e7c66b}
@media screen and (prefers-color-scheme:dark){:root{--bg:#12161c;--card:#1a2029;--ink:#e6e9ee;--muted:#9aa5b4;--line:#2c3542;--head:#222a35;
--accent:#8ab8e6;--accent-ink:#10202f;--crit:#ff9a9a;--crit-bg:#4a1c1f;--imp:#ffc27a;--imp-bg:#47300f;--mod:#ead77a;--mod-bg:#3d3611;
--low:#a9c4e6;--low-bg:#1f2f44;--kevrow:#2a1d20;--warn-bg:#3a3010;--warn-line:#7a6420}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,"DejaVu Sans",Arial,sans-serif}
a{color:var(--accent)}
.top{position:sticky;top:0;z-index:5;background:var(--card);border-bottom:1px solid var(--line);display:flex;align-items:center;gap:16px;padding:10px 20px;flex-wrap:wrap}
.brand{font-size:18px;font-weight:700}.brand small{font-weight:400;color:var(--muted);font-size:13px;margin-left:8px}
.nav{display:flex;gap:4px;flex-wrap:wrap}.nav a{text-decoration:none;color:var(--ink);padding:5px 10px;border-radius:6px;font-weight:600}
.nav a:hover{background:var(--head)}.nav a span{font-weight:400;color:var(--muted)}
.export{margin-left:auto;background:var(--accent);color:var(--accent-ink);text-decoration:none;font-weight:600;padding:8px 16px;border-radius:6px;white-space:nowrap}
main{max-width:1500px;margin:0 auto;padding:20px 16px}
.meta,section{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px 18px;margin-bottom:20px}
.meta h1{font-size:20px;margin:0 0 6px}.meta p{margin:4px 0;color:var(--muted)}.meta strong{color:var(--ink)}
.warn{background:var(--warn-bg);border:1px solid var(--warn-line);border-radius:8px;padding:10px 16px;margin-bottom:20px}
.warn p{margin:3px 0}
section{scroll-margin-top:64px}
h2{font-size:20px;margin:0}.sub{color:var(--muted);margin:2px 0 14px}
h3{font-size:13px;margin:20px 0 8px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
h3 .count{text-transform:none;letter-spacing:0;font-weight:400;margin-left:8px}
.stats{display:flex;gap:10px;flex-wrap:wrap}.stat{border:1px solid var(--line);border-radius:6px;padding:8px 14px;min-width:150px}
.stat .v{font-size:22px;font-weight:700}.stat .k{color:var(--muted);font-size:12px}
.scroll{overflow-x:auto;border:1px solid var(--line);border-radius:6px}
table{border-collapse:collapse;width:100%%}
th,td{padding:7px 10px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line)}
th{background:var(--head);font-size:12px;white-space:nowrap}
tbody tr:last-child td{border-bottom:0}
td.n{text-align:right;white-space:nowrap}td.hot{color:var(--crit);font-weight:700}
.mono{font-family:ui-monospace,SFMono-Regular,Consolas,"DejaVu Sans Mono",monospace;font-size:12.5px;overflow-wrap:anywhere}
td.aff{min-width:170px}
.small{font-size:12.5px}.nowrap{white-space:nowrap}.muted{color:var(--muted)}.date{white-space:nowrap}
tr.iskev td{background:var(--kevrow)}
.sev{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:600;white-space:nowrap}
.sev-critical{color:var(--crit);background:var(--crit-bg)}.sev-important,.sev-high{color:var(--imp);background:var(--imp-bg)}
.sev-moderate,.sev-medium{color:var(--mod);background:var(--mod-bg)}.sev-low,.sev-unknown,.sev-none{color:var(--low);background:var(--low-bg)}
.kev{display:inline-block;background:var(--crit);color:#fff;font-weight:700;font-size:11px;padding:1px 6px;border-radius:3px}
.ransom{color:var(--crit);font-size:11.5px;font-weight:600}
.epss-hi{color:var(--crit);font-weight:700}.epss-mid{color:var(--imp);font-weight:600}.epss-lo{color:var(--muted)}
.notes{color:var(--muted);font-size:13px;margin:0;padding-left:20px}.notes li{margin:4px 0}
@media print{
@page{size:%(paper)s landscape;margin:10mm;@bottom-right{content:"Page " counter(page) " of " counter(pages);font-size:8px;color:#555}
@bottom-left{content:"%(footer)s";font-size:8px;color:#555}}
:root{--bg:#fff;--card:#fff;--ink:#000;--muted:#444;--line:#bbb;--head:#eee;--accent:#000}
body{font-size:9.5px}.top{position:static;border:0;padding:0 0 6px}.export,.nav{display:none}
main{padding:0;max-width:none}.meta,section{border:0;padding:0;margin-bottom:14px}
section{page-break-before:always}.scroll{overflow:visible;border:0}table{border:1px solid var(--line)}
th,td{padding:3px 5px}th{font-size:8.5px}.mono,.small{font-size:8.5px}.sev,.kev,.ransom{font-size:8px}
tr{page-break-inside:avoid}thead{display:table-header-group}h3{page-break-after:avoid}
a{color:inherit;text-decoration:none}.stat{padding:4px 10px;min-width:110px}.stat .v{font-size:15px}
}
"""

ICON = ("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E%3Cpath fill='%231f4e79' "
        "d='M8 1l6 2v4c0 4-2.6 6.9-6 8-3.4-1.1-6-4-6-8V3z'/%3E%3C/svg%3E")


def render_html(model, paper="letter"):
    title = model["title"]
    sub = "CVE report" + (", " + model["cluster_name"] if model["cluster_name"] else "")
    nav = "".join('<a href="#%s">%s <span>%d</span></a>' % (e(p["id"]), e(p["title"]), len(p["cves"])) for p in model["platforms"])
    warn = ""
    if model["warnings"]:
        warn = '<div class="warn">%s</div>' % "".join("<p>%s</p>" % e(w) for w in model["warnings"])
    hours = model["refresh_seconds"] / 3600
    every = ("%g hour%s" % (hours, "" if hours == 1 else "s")) if hours >= 1 else "%d minutes" % (model["refresh_seconds"] // 60)
    footer = re.sub(r"[^\w .,:()/-]", "", title + " CVE report, " + model["generated"])
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>%(title)s: CVE report</title><link rel="icon" href="%(icon)s">
<style>%(css)s</style></head><body>
<div class="top"><div class="brand">%(title)s<small>%(sub)s</small></div><nav class="nav">%(nav)s</nav>
<a class="export" href="report.pdf" download="%(pdf)s">Export to PDF</a></div>
<main>%(warn)s
<div class="meta"><h1>Vulnerability report</h1>
<p><strong>Generated:</strong> %(generated)s &nbsp;·&nbsp; <strong>Refreshed:</strong> every %(every)s</p>
<p><strong>Sources:</strong> Trivy Operator, %(kev)s, %(epss)s</p>
<p><strong>What is listed:</strong> each platform has a table of its systems and a table of priority CVEs. A CVE is a priority when it is in the CISA Known Exploited Vulnerabilities (KEV) catalog, or its EPSS score (probability of exploitation in the next 30 days) is %(min).2f or higher. Known-exploited CVEs are listed first.</p></div>
%(sections)s
<div class="meta"><h1>How to read this report</h1><ul class="notes">
<li>Counts are what the scanners report for the installed packages. Whether a CVE can actually be exploited on a given system was not analysed.</li>
<li>KEV marks CVEs that CISA has seen exploited in the wild. EPSS is a probability, not proof: rank by KEV first.</li>
<li>Generated by Securitas, https://github.com/uhlix-net/securitas</li>
</ul></div>
</main></body></html>
""" % dict(title=e(title), icon=ICON, css=CSS % dict(paper="A4" if paper.lower() == "a4" else "letter", footer=footer),
           sub=e(sub), nav=nav, pdf=e(pdf_name(model)), warn=warn, generated=e(model["generated"]), every=e(every),
           kev=e(model["sources"]["kev"]), epss=e(model["sources"]["epss"]), min=model["epss_min"],
           sections="\n".join(_section(p) for p in model["platforms"]))


def render_pdf(html_text):
    from weasyprint import HTML  # imported here so the HTML path and tests work without it
    return HTML(string=html_text, base_url=None).write_pdf()
