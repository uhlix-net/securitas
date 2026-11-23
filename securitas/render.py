"""Render the report model to HTML (inside the web app, or standalone for the PDF) and the PDF with WeasyPrint."""
import html
import re
import urllib.parse

from .report import LEVEL_KEYS, LEVELS, is_priority, sev_level

e = lambda s: html.escape(str(s), quote=True)


def pdf_name(model):
    tag = ("-scan-%s" % re.sub(r"\D", "", model["label"])) if model.get("label") else ""
    return "securitas-report-%s%s.pdf" % (model["date"], tag)


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
        return '<a href="https://nvd.nist.gov/vuln/detail/%s" rel="noreferrer">%s</a>' % (e(cve), e(cve))
    return '<a href="https://osv.dev/vulnerability/%s" rel="noreferrer">%s</a>' % (e(cve), e(cve))


def _cell(value, typ):
    if typ in ("num", "hot"):
        try:
            n = int(value)
            return '<td class="n%s">%s</td>' % (" hot" if typ == "hot" and n else "", format(n, ","))
        except (TypeError, ValueError):
            return '<td class="n">%s</td>' % e(value if value is not None else "")
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


# ---------------------------------------------------------------- report view: severity filter and paging

PAGE_SIZE = 200
PDF_MAX_ROWS = 500      # per platform: WeasyPrint needs ~250 MB per 1,000 rows and the chart's memory limit is 1 GiB


def parse_view(params):
    """The report filter from the query string. `params` is a mapping with getlist (Starlette QueryParams) or a dict.
    sev=critical&sev=high (no sev, or none valid: every level); priority=1: priority CVEs only; p_<platform>=n: page."""
    get = params.getlist if hasattr(params, "getlist") else (lambda k: params.get(k, []) if isinstance(params.get(k), list)
                                                             else [params[k]] if k in params else [])
    levels = [k for k in LEVEL_KEYS if k in set(get("sev"))] or list(LEVEL_KEYS)
    pages = {}
    for k in (params.keys() if hasattr(params, "keys") else []):
        if k.startswith("p_"):
            try:
                pages[k[2:]] = max(1, int(get(k)[0]))
            except (ValueError, IndexError):
                pass
    return {"levels": levels, "priority_only": (get("priority") or [""])[0] == "1", "pages": pages}


def default_view():
    return {"levels": list(LEVEL_KEYS), "priority_only": False, "pages": {}}


def view_query(view, pages=None):
    """Query string that reproduces the filter (and the given pages), '' for the default view."""
    q = []
    if set(view["levels"]) != set(LEVEL_KEYS):
        q += [("sev", k) for k in view["levels"]]
    if view["priority_only"]:
        q.append(("priority", "1"))
    q += [("p_" + k, str(v)) for k, v in sorted((pages or {}).items()) if v > 1]
    return urllib.parse.urlencode(q)


def view_label(view):
    names = dict(LEVELS)
    lv = "all severity levels" if set(view["levels"]) == set(LEVEL_KEYS) else ", ".join(names[k] for k in view["levels"])
    return lv + (", priority CVEs only" if view["priority_only"] else "")


def filtered(p, view):
    lv = set(view["levels"])
    return [r for r in p["cves"] if (r.get("level") or sev_level(r.get("severity", ""))) in lv
            and (not view["priority_only"] or is_priority(r))]


def filter_form(view, action):
    """Severity checkboxes and the priority switch, submitted with GET so the page needs no script."""
    boxes = "".join('<label class="inline"><input type="checkbox" name="sev" value="%s"%s> <span class="sev sev-%s">%s</span></label>' % (
        k, " checked" if k in view["levels"] else "", k if k != "unknown" else "unknown", e(name)) for k, name in LEVELS)
    pri = '<label class="inline"><input type="checkbox" name="priority" value="1"%s> Priority CVEs only (CISA KEV or EPSS threshold)</label>' % (
        " checked" if view["priority_only"] else "")
    return ('<form class="filters noprint" method="get" action="%s"><fieldset><legend>Show severity</legend>%s</fieldset>'
            '<fieldset><legend>Ranking</legend>%s</fieldset><div class="fbtn"><button class="btn primary" type="submit">Apply</button> '
            '<a class="btn" href="%s">Reset</a></div></form>' % (e(action), boxes, pri, e(action)))


def _pager(p, view, page, pages):
    if pages <= 1:
        return ""
    def link(n, text):
        q = view_query(view, {**view["pages"], p["id"]: n})
        return '<a class="btn small" href="?%s#%s">%s</a>' % (e(q), e(p["id"]), text)
    out = [link(page - 1, "&larr; Previous") if page > 1 else ""]
    out.append('<span class="muted">Page %d of %d</span>' % (page, pages))
    out.append(link(page + 1, "Next &rarr;") if page < pages else "")
    return '<div class="pager noprint">%s</div>' % "".join(out)


def _cves(p, view=None, paged=False):
    view = view or default_view()
    rows_all = filtered(p, view)
    npri = sum(1 for r in p["cves"] if is_priority(r))
    nkev = sum(1 for r in rows_all if r["kev"])
    shown = "%s shown of %s" % (format(len(rows_all), ","), format(len(p["cves"]), ","))
    title = '<h3>CVEs <span class="count">%s &middot; %s priority &middot; %s known exploited</span></h3>' % (
        shown, format(npri, ","), format(nkev, ","))
    if not rows_all:
        if not p["cves"]:
            return title + '<p class="muted">No CVEs were found on this platform.</p>'
        return title + '<p class="muted">No CVE on this platform matches the filter (%s).</p>' % e(view_label(view))
    page, pages = 1, 1
    rows_page = rows_all
    cut = ""
    if not paged and len(rows_all) > PDF_MAX_ROWS:
        rows_page = rows_all[:PDF_MAX_ROWS]
        cut = ('<p class="cut">The first %s of %s matching CVEs are listed, in ranking order. Narrow the severity filter '
               'for a complete list.</p>' % (format(PDF_MAX_ROWS, ","), format(len(rows_all), ",")))
    if paged:
        pages = (len(rows_all) + PAGE_SIZE - 1) // PAGE_SIZE
        page = min(view["pages"].get(p["id"], 1), pages)
        rows_page = rows_all[(page - 1) * PAGE_SIZE:page * PAGE_SIZE]
    head = "".join("<th>%s</th>" % e(h) for h in
                   ["CVE", "Description", "Severity", "Known exploited", "EPSS", p["affected_label"], "Component", "Fix", "Status"])
    rows = []
    for r in rows_page:
        pri = ' <span class="pri" title="Priority: in CISA KEV or at or above the EPSS threshold">priority</span>' if (
            is_priority(r) and not r["kev"]) else ""
        rows.append('<tr%s><td class="mono nowrap">%s%s</td><td>%s</td><td>%s</td><td class="nowrap">%s</td><td class="n">%s</td>'
                    '<td class="mono small aff">%s</td><td class="small">%s</td><td class="small">%s</td><td class="small">%s</td></tr>' % (
                        ' class="iskev"' if r["kev"] else "", _link(r["cve"]), pri,
                        e(r["title"]) or '<span class="muted">No description</span>', _sev(r["severity"]), _kev(r),
                        _epss(r["epss"]), "<br>".join(e(s) for s in r["systems"]), e(r["component"]), e(r["fix"]), e(r["status"])))
    pager = _pager(p, view, page, pages)
    return title + cut + pager + '<div class="scroll"><table class="cves"><thead><tr>%s</tr></thead><tbody>%s</tbody></table></div>' % (
        head, "\n".join(rows)) + pager


def _section(p, view=None, paged=False):
    totals = "".join('<div class="stat"><div class="v">%s</div><div class="k">%s</div></div>' % (
        format(v, ",") if isinstance(v, int) else e(v), e(k)) for k, v in p["totals"].items())
    scanned = (' <span class="scanned">Scanned %s</span>' % e(p["scanned"])) if p.get("scanned") else ""
    st = p.get("status", "")
    badge = (' <span class="badge b-%s">%s</span>' % (st, STATUS_BADGE[st]) if st in ("failed", "partial", "off") else "")
    fail = '<div class="fail"><p>%s</p></div>' % e(p["failure"]) if p.get("failure") else ""
    warn = ""
    if p.get("warnings"):
        warn = '<div class="warn">%s</div>' % "".join("<p>%s</p>" % e(w) for w in p["warnings"])
    if p.get("no_results"):
        return '<section id="%s"><h2>%s%s%s</h2>%s%s<p class="muted">No results: nothing from this platform is included in the report.</p></section>' % (
            e(p["id"]), e(p["title"]), badge, scanned, fail, warn)
    return '<section id="%s"><h2>%s%s%s</h2><p class="sub">%s</p>%s%s<div class="stats">%s</div>%s%s</section>' % (
        e(p["id"]), e(p["title"]), badge, scanned, e(p["subtitle"]), fail, warn, totals, _systems(p), _cves(p, view, paged))


STATUS_BADGE = {"done": "OK", "failed": "Scan failed", "partial": "Partial scan", "off": "Turned off"}


def platform_nav(model, view=None):
    view = view or default_view()
    return "".join('<a href="#%s">%s <span>%s</span></a>' % (
        e(p["id"]), e(p["title"]), ("off" if p.get("turned_off") else "failed") if p.get("no_results")
        else "%s%s" % (format(len(filtered(p, view)), ","), " !" if p.get("failure") else "")) for p in model["platforms"])


def summary_table(model):
    """Per-platform status and counts (the Summary page's table), shown first in the report and the PDF."""
    from .report import summary
    rows = summary(model)
    if not rows:
        return ""
    n = lambda v: format(v, ",")
    body = []
    for r in rows:
        st = r["status"] if r["status"] in STATUS_BADGE else "done"
        when = e(r["scanned"]) + ((" (#%d)" % r["scan_id"]) if r.get("scan_id") else "")
        cells = ('<td class="muted" colspan="5">No results</td>' if r["no_results"] else
                 '<td class="n">%s</td><td class="n">%s</td><td class="n%s">%s</td><td class="n%s">%s</td><td class="n">%s</td>' % (
                     n(r["systems"]), n(r["priority"]), " hot" if r["kev"] else "", n(r["kev"]),
                     " hot" if r["critical"] else "", n(r["critical"]), n(r["high"])))
        body.append('<tr><td><a href="#%s"><strong>%s</strong></a></td><td><span class="badge b-%s">%s</span></td>'
                    '<td class="date">%s</td>%s</tr>' % (e(r["id"]), e(r["title"]), st, STATUS_BADGE[st], when, cells))
        if r["failure"]:
            body.append('<tr class="failrow"><td colspan="8">%s</td></tr>' % e(r["failure"]))
    foot = ""
    if len(rows) > 1:
        t = lambda k: n(sum(r[k] for r in rows))
        foot = ('<tfoot><tr><th colspan="3">Total</th><th class="n">%s</th><th class="n">%s</th><th class="n">%s</th>'
                '<th class="n">%s</th><th class="n">%s</th></tr></tfoot>' % (t("systems"), t("priority"), t("kev"), t("critical"), t("high")))
    return ('<section class="summary"><h2>Summary</h2><div class="scroll"><table class="summary"><thead><tr><th>Platform</th>'
            '<th>Status</th><th>Last scanned</th><th class="n">Systems</th><th class="n">Priority CVEs</th>'
            '<th class="n">Known exploited</th><th class="n">Critical</th><th class="n">High</th></tr></thead><tbody>%s</tbody>%s'
            '</table></div></section>' % ("\n".join(body), foot))


def report_body(model, view=None, paged=False):
    """Metadata box, one section per platform and the reading notes. `view`: the severity filter (default: every
    CVE); `paged`: split long CVE tables into pages (the web page; the PDF lists every matching row)."""
    view = view or default_view()
    warn = ""
    if model["warnings"]:
        warn = '<div class="warn">%s</div>' % "".join("<p>%s</p>" % e(w) for w in model["warnings"])
    src = model["sources"]
    sources = ", ".join(x for x in (src.get("kev", ""), src.get("epss", "")) if x)
    heading = "Vulnerability report" + (" &middot; %s" % e(model["label"]) if model.get("label") else "")
    if not model["platforms"]:
        sections = ('<section><h2>No results yet</h2><p class="sub">No scan has finished yet. '
                    'Operators and admins can start one on the Scans page; scheduled scans run on their own.</p></section>')
    else:
        sections = summary_table(model) + "\n" + "\n".join(_section(p, view, paged) for p in model["platforms"])
    kev_on, epss_on = model.get("kev_on", True), model.get("epss_on", True)
    if kev_on and epss_on:
        rule = ("A CVE is a priority when it is in the CISA Known Exploited Vulnerabilities (KEV) catalog, or its EPSS score "
                "(probability of exploitation in the next 30 days) is %.2f or higher. Priority CVEs are listed first, known-exploited ones at the top." % model["epss_min"])
    elif kev_on:
        rule = "A CVE is a priority when it is in the CISA Known Exploited Vulnerabilities (KEV) catalog. EPSS is turned off."
    elif epss_on:
        rule = ("A CVE is a priority when its EPSS score (probability of exploitation in the next 30 days) is %.2f or higher. "
                "The CISA KEV catalog is turned off." % model["epss_min"])
    else:
        rule = "CISA KEV and EPSS are both turned off, so every CVE is listed, unranked."
    return """%(warn)s
<div class="meta"><h1>%(heading)s</h1>
<p><strong>Generated:</strong> %(generated)s</p>
<p><strong>Sources:</strong> %(sources)s</p>
<p><strong>What is listed:</strong> each platform has a table of its systems and a table of its CVEs. %(rule)s</p>
<p><strong>Showing:</strong> %(showing)s.</p></div>
%(sections)s
<div class="meta"><h1>How to read this report</h1><ul class="notes">
<li>Counts are what the scanners report for the installed packages. Whether a CVE can actually be exploited on a given system was not analysed.</li>
<li>KEV marks CVEs that CISA has seen exploited in the wild. EPSS is a probability, not proof: rank by KEV first.</li>
<li>Generated by Securitas, https://github.com/uhlix-net/securitas</li>
</ul></div>""" % dict(warn=warn, heading=heading, generated=e(model["generated"]), sources=e(sources) or "none",
                     rule=e(rule), sections=sections, showing=e(view_label(view)))


# Colour tokens. Light is the default; dark follows the system setting unless the viewer picked a theme
# (data-theme on <html>). The PDF always uses the light tokens.
TOKENS_LIGHT = """--bg:#f6f7f9;--card:#fff;--ink:#1a2230;--muted:#5d6878;--line:#dfe3ea;--head:#eef1f5;--accent:#1f4e79;--accent-ink:#fff;
--crit:#a4161a;--crit-bg:#fde8e8;--imp:#9a4a00;--imp-bg:#fdebd3;--mod:#6b5900;--mod-bg:#fbf3c4;--low:#3d5a80;--low-bg:#e3ecf7;--kevrow:#fff6f5;
--warn-bg:#fff4d6;--warn-line:#e7c66b;--acc-ink:#6b4f00;--acc-bg:#fff3c4;--ok:#1d6b3a;--ok-bg:#e1f3e7;--input:#fff"""
TOKENS_DARK = """--bg:#12161c;--card:#1a2029;--ink:#e6e9ee;--muted:#9aa5b4;--line:#2c3542;--head:#222a35;
--accent:#8ab8e6;--accent-ink:#10202f;--crit:#ff9a9a;--crit-bg:#4a1c1f;--imp:#ffc27a;--imp-bg:#47300f;--mod:#ead77a;--mod-bg:#3d3611;
--low:#a9c4e6;--low-bg:#1f2f44;--kevrow:#2a1d20;--warn-bg:#3a3010;--warn-line:#7a6420;--acc-ink:#f2d466;--acc-bg:#3a3010;--ok:#8fd8a8;--ok-bg:#16301f;--input:#141920"""

CSS_REPORT = """
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,"DejaVu Sans",Arial,sans-serif}
a{color:var(--accent)}
.brand{font-size:18px;font-weight:700}.brand small{font-weight:400;color:var(--muted);font-size:13px;margin-left:8px}
main{max-width:1500px;margin:0 auto;padding:20px 16px}
.meta,section{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px 18px;margin-bottom:20px}
.meta h1{font-size:20px;margin:0 0 6px}.meta p{margin:4px 0;color:var(--muted)}.meta strong{color:var(--ink)}
.warn{background:var(--warn-bg);border:1px solid var(--warn-line);border-radius:8px;padding:10px 16px;margin-bottom:20px}
.warn p{margin:3px 0}
.fail{background:var(--crit-bg);border:1px solid var(--crit);color:var(--crit);border-radius:8px;padding:10px 16px;margin-bottom:16px;font-weight:600}
.fail p{margin:3px 0}
h2 .badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:600;white-space:nowrap;vertical-align:middle}
h2 .b-failed{color:var(--crit);background:var(--crit-bg)}h2 .b-partial{color:var(--imp);background:var(--imp-bg)}
h2 .b-off,table.summary .b-off{color:var(--muted);background:var(--head)}
table.summary .badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:600;white-space:nowrap}
table.summary .b-done{color:var(--ok);background:var(--ok-bg)}table.summary .b-partial{color:var(--imp);background:var(--imp-bg)}
table.summary .b-failed{color:var(--crit);background:var(--crit-bg)}th.n{text-align:right}
tr.failrow td{color:var(--crit);background:var(--crit-bg);font-size:12.5px;border-top:0}
h2{font-size:20px;margin:0}.sub{color:var(--muted);margin:2px 0 14px}
h2 .scanned{font-size:13px;font-weight:400;color:var(--muted);margin-left:10px}
h3{font-size:13px;margin:20px 0 8px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
h3 .count{text-transform:none;letter-spacing:0;font-weight:400;margin-left:8px}
.stats{display:flex;flex-wrap:wrap}.stat{border:1px solid var(--line);border-radius:6px;padding:8px 14px;min-width:150px;margin:0 10px 10px 0}
.stat .v{font-size:22px;font-weight:700}.stat .k{color:var(--muted);font-size:12px}
.scroll{border:1px solid var(--line);border-radius:6px}
table{border-collapse:collapse;width:100%}
th,td{padding:7px 10px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line)}
th{background:var(--head);font-size:12px;white-space:nowrap}
tbody tr:last-child td{border-bottom:0}
td.n{text-align:right;white-space:nowrap}td.hot{color:var(--crit);font-weight:700}
.mono{font-family:ui-monospace,SFMono-Regular,Consolas,"DejaVu Sans Mono",monospace;font-size:12.5px}
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
.cut{background:var(--warn-bg);border:1px solid var(--warn-line);border-radius:6px;padding:6px 10px;margin:0 0 8px}
.pri{display:inline-block;margin-left:6px;font-family:system-ui,sans-serif;font-size:10.5px;font-weight:700;padding:0 5px;border-radius:3px;color:var(--accent);border:1px solid var(--accent)}
"""

CSS_PRINT = """
@page{size:%(paper)s landscape;margin:10mm;@bottom-right{content:"Page " counter(page) " of " counter(pages);font-size:8px;color:#555}
@bottom-left{content:"%(footer)s";font-size:8px;color:#555}}
:root{--bg:#fff;--card:#fff;--ink:#000;--muted:#444;--line:#bbb;--head:#eee;--accent:#000}
body{font-size:9.5px}.top{border:0;padding:0 0 6px}
main{padding:0;max-width:none}.meta,section{border:0;padding:0;margin-bottom:14px}
section{page-break-before:always}section.summary{page-break-before:avoid}.scroll{border:0}table{border:1px solid var(--line)}
th,td{padding:3px 5px}th{font-size:8.5px}.mono,.small{font-size:8.5px}.sev,.kev,.ransom{font-size:8px}
tr{page-break-inside:avoid}thead{display:table-header-group}h3{page-break-after:avoid}
a{color:inherit;text-decoration:none}.stat{padding:4px 10px;min-width:110px}.stat .v{font-size:15px}
"""

CSS_APP = """
.top{position:sticky;top:0;z-index:5;background:var(--card);border-bottom:1px solid var(--line);display:flex;align-items:center;gap:16px;padding:10px 20px;flex-wrap:wrap}
.nav{display:flex;gap:4px;flex-wrap:wrap}.nav a{text-decoration:none;color:var(--ink);padding:5px 10px;border-radius:6px;font-weight:600}
.nav a:hover{background:var(--head)}.nav a span{font-weight:400;color:var(--muted)}.nav a.on{background:var(--head)}
.right{margin-left:auto;display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.who{color:var(--muted);font-size:13px;text-decoration:none}.who:hover strong{text-decoration:underline}.who strong{color:var(--ink)}
.subbar{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:16px}
.export{margin-left:auto;background:var(--accent);color:var(--accent-ink);text-decoration:none;font-weight:600;padding:8px 16px;border-radius:6px;white-space:nowrap}
section{scroll-margin-top:64px}
main{max-width:none;width:85%}@media (max-width:1000px){main{width:auto}}
table.targets{table-layout:fixed}table.targets td{vertical-align:middle}table.targets input[type=text]{width:100%}
table.targets col.c-host{width:24%}table.targets col.c-role{width:26%}table.targets col.c-on{width:8%}
table.targets col.c-key{width:16%}table.targets col.c-save{width:12%}table.targets col.c-del{width:14%}
.scroll{overflow-x:auto}.mono{overflow-wrap:anywhere}.stats{gap:10px}.stat{margin:0}
form{margin:0}
.seg{display:inline-flex;border:1px solid var(--line);border-radius:6px;overflow:hidden}
.seg button{border:0;border-right:1px solid var(--line);background:var(--card);color:var(--ink);padding:5px 10px;font:inherit;font-size:12.5px;cursor:pointer}
.seg button:last-child{border-right:0}.seg button.on{background:var(--accent);color:var(--accent-ink);font-weight:600}
.btn{display:inline-block;border:1px solid var(--line);background:var(--card);color:var(--ink);padding:6px 14px;border-radius:6px;font:inherit;font-weight:600;cursor:pointer;text-decoration:none;white-space:nowrap}
.btn:hover{background:var(--head)}.btn.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-ink)}
.btn.danger{color:var(--crit);border-color:var(--crit)}.btn.small{padding:3px 9px;font-size:12.5px}
input[type=text],input[type=password],input[type=email],select,textarea{font:inherit;color:var(--ink);background:var(--input);border:1px solid var(--line);border-radius:6px;padding:6px 9px;max-width:100%}
input:focus,select:focus,textarea:focus,button:focus-visible,a:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
label{display:block;font-weight:600;margin:10px 0 4px}label.inline{display:inline-flex;align-items:center;gap:6px;font-weight:400;margin:4px 14px 4px 0}
.hint{color:var(--muted);font-size:12.5px;margin:3px 0 0}
.row{display:flex;gap:14px;flex-wrap:wrap;align-items:flex-end}.row>div{min-width:160px}
.flash{border-radius:8px;padding:10px 16px;margin-bottom:16px;border:1px solid var(--line)}
.flash.ok{background:var(--ok-bg);border-color:var(--ok);color:var(--ok)}.flash.err{background:var(--crit-bg);border-color:var(--crit);color:var(--crit)}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:600;white-space:nowrap}
.b-done{color:var(--ok);background:var(--ok-bg)}.b-partial{color:var(--imp);background:var(--imp-bg)}
.b-failed{color:var(--crit);background:var(--crit-bg)}.b-queued,.b-running{color:var(--low);background:var(--low-bg)}
.b-role{color:var(--low);background:var(--low-bg)}.b-off{color:var(--muted);background:var(--head)}
.b-accepted{color:var(--acc-ink);background:var(--acc-bg);border:1px solid var(--cr-accepted)}
td.acc{color:var(--acc-ink);font-weight:700}.excform{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-top:6px}
.excform select,.excform input[type=text]{font-size:12.5px;padding:3px 6px}.excform input[type=text]{flex:1;min-width:180px}
.excform .btn{font-size:12.5px;padding:3px 10px}.excnote{font-size:12.5px;margin-top:4px}
td form{display:inline}td .row{gap:6px;align-items:center}
pre.log{background:var(--head);border:1px solid var(--line);border-radius:6px;padding:10px 12px;font-size:12px;overflow-x:auto;white-space:pre-wrap;max-height:480px;overflow-y:auto}
.login{max-width:400px;margin:60px auto}.login .brand{text-align:center;margin-bottom:18px;font-size:24px}
.login input[type=text],.login input[type=password]{width:100%}.login .btn{width:100%;text-align:center;margin-top:14px;padding:9px}
.or{display:flex;align-items:center;gap:10px;color:var(--muted);margin:18px 0 4px;font-size:12.5px}.or:before,.or:after{content:"";flex:1;border-top:1px solid var(--line)}
.pager{display:flex;gap:8px;margin:10px 0;align-items:center}
form.filters{display:flex;gap:10px 24px;flex-wrap:wrap;align-items:flex-end;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 16px;margin-bottom:16px}
form.filters fieldset{border:0;margin:0;padding:0}form.filters legend{font-weight:600;font-size:12.5px;color:var(--muted);padding:0;margin-bottom:2px}
form.filters .fbtn{margin-left:auto;display:flex;gap:8px}
.subnav{display:flex;gap:4px;flex-wrap:wrap;margin-bottom:16px;border-bottom:1px solid var(--line);padding-bottom:8px}
.subnav a{text-decoration:none;color:var(--ink);padding:5px 10px;border-radius:6px;font-weight:600;font-size:13.5px}
.subnav a:hover{background:var(--head)}.subnav a.on{background:var(--accent);color:var(--accent-ink)}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px}
.card{display:block;border:1px solid var(--line);border-radius:8px;padding:14px 16px;text-decoration:none;color:var(--ink);background:var(--card)}
.card:hover{border-color:var(--accent)}.card h3{margin:0 0 6px;font-size:15px;text-transform:none;letter-spacing:0;color:var(--ink)}.card p{margin:0;color:var(--muted);font-size:13px}
.src{font-size:11.5px;font-weight:600;padding:1px 7px;border-radius:9px;background:var(--head);color:var(--muted);white-space:nowrap}.src.ui{background:var(--low-bg);color:var(--low)}
.form-grid{display:grid;grid-template-columns:minmax(180px,260px) 1fr;gap:8px 16px;align-items:center}.form-grid input[type=text],.form-grid input[type=password],.form-grid select,.form-grid textarea{width:100%}
.form-grid .lbl{font-weight:600}.form-grid .meta2{grid-column:2;margin-top:-4px}@media (max-width:700px){.form-grid{grid-template-columns:1fr}.form-grid .meta2{grid-column:1}}
textarea{font:inherit;font-family:ui-monospace,Consolas,monospace;font-size:12px;color:var(--ink);background:var(--input);border:1px solid var(--line);border-radius:6px;padding:6px 9px}
details.script pre{background:var(--head);border:1px solid var(--line);border-radius:6px;padding:10px 12px;font-size:12px;overflow-x:auto;white-space:pre-wrap}
table.summary td a strong{font-size:15px}
@media print{.top,.subbar,.noprint{display:none}}
"""


def app_css():
    from .charts import CSS as CHART_CSS, TOKENS_DARK as CD, TOKENS_LIGHT as CL
    light, dark = TOKENS_LIGHT + ";" + CL, TOKENS_DARK + ";" + CD
    return (":root{%s}\n@media (prefers-color-scheme:dark){:root:not([data-theme=light]){%s}}\n:root[data-theme=dark]{%s}\n"
            ":root{color-scheme:light}:root[data-theme=dark]{color-scheme:dark}"
            "@media (prefers-color-scheme:dark){:root:not([data-theme=light]){color-scheme:dark}}\n"
            % (light, dark, dark)) + CSS_REPORT + CSS_APP + CHART_CSS


ICON = ("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E%3Cpath fill='%231f4e79' "
        "d='M8 1l6 2v4c0 4-2.6 6.9-6 8-3.4-1.1-6-4-6-8V3z'/%3E%3C/svg%3E")


def pdf_html(model, paper="letter", view=None):
    """Standalone page for WeasyPrint: light colours, no navigation, print layout."""
    title = model["title"]
    sub = "CVE report" + (", " + model["cluster_name"] if model["cluster_name"] else "")
    footer = re.sub(r"[^\w .,:()#/-]", "", title + " CVE report, " + (model.get("label") + ", " if model.get("label") else "")
                    + model["generated"])
    css = ":root{%s}" % TOKENS_LIGHT + CSS_REPORT + CSS_PRINT % dict(paper="A4" if paper.lower() == "a4" else "letter", footer=footer)
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>%(title)s: CVE report</title><style>%(css)s</style></head><body>
<div class="top"><div class="brand">%(title)s<small>%(sub)s</small></div></div>
<main>%(body)s</main></body></html>
""" % dict(title=e(title), css=css, sub=e(sub), body=report_body(model, view))


def render_pdf(html_text):
    from weasyprint import HTML  # imported here so the HTML path and tests work without it
    return HTML(string=html_text, base_url=None).write_pdf()
