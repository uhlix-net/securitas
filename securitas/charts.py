"""Inline SVG charts for the Summary page: the CVE history (one shaded line per platform) and a severity pie per
platform. Rendered on the server: the pages carry no script (see the Content-Security-Policy in web.py), so hover
details are native SVG <title> tooltips and every chart has a table view.

Colours are CSS custom properties defined in render.py (light and dark): --pl-<platform> for platforms
(categorical slots 1-3, validated all-pairs in both modes) and --lv-<level> for severity (one warm ordinal ramp,
most severe = most contrast with the surface; Unknown is neutral grey).
"""
import html
import math

from .report import LEVELS, RANGES

e = lambda s: html.escape(str(s), quote=True)
n = lambda v: format(v, ",")


def _nice_axis(v):
    """(top, step): the smallest top above v made of 3 to 5 steps of 1, 2, 2.5 or 5 x 10^k."""
    if v <= 0:
        return 4, 1
    best = None
    mag = 10 ** math.floor(math.log10(v / 5))
    for m in (1, 2, 2.5, 5, 10, 20):
        step = m * mag
        if step < 1 or step != int(step):
            continue
        step = int(step)
        k = math.ceil(v / step)
        if 3 <= k <= 5 and (best is None or k * step < best[0]):
            best = (k * step, step)
    return best or (max(4, math.ceil(v)), 1)


def range_switch(current, base="/vulnerabilities"):
    links = []
    for key, (name, span, _) in RANGES.items():
        cls = ' class="on" aria-current="true"' if key == current else ""
        links.append('<a%s href="%s?range=%s#history">%s <span>(%s)</span></a>' % (cls, base, key, name, span))
    return '<nav class="seg seglinks" aria-label="Interval">%s</nav>' % "".join(links)


def history_svg(h):
    """h: report.history() result. A shaded line per platform, direct-labelled at its last point."""
    labels, series = h["labels"], h["series"]
    if not series:
        return '<p class="muted">No history yet: the graph fills in as scans finish.</p>'
    W, H, L, R, T, B = 920, 300, 58, 150, 14, 34
    pw, ph = W - L - R, H - T - B
    top, step = _nice_axis(max(v for s in series for v in s["values"] if v is not None))
    npts = len(labels)
    x = lambda i: L + (pw * i / (npts - 1) if npts > 1 else pw / 2)
    y = lambda v: T + ph - ph * v / top
    out = ['<svg class="chart" viewBox="0 0 %d %d" role="img" aria-labelledby="hist-t">' % (W, H),
           '<title id="hist-t">Distinct CVEs per platform, %s</title>' % e(RANGES[h["range"]][0].lower())]
    for k in range(int(round(top / step)) + 1):   # recessive grid and y labels
        v = step * k
        out.append('<line class="grid" x1="%d" x2="%d" y1="%.1f" y2="%.1f"/>' % (L, L + pw, y(v), y(v)))
        out.append('<text class="ax" x="%d" y="%.1f" text-anchor="end" dy=".32em">%s</text>' % (L - 8, y(v), n(int(v))))
    every = max(1, math.ceil(npts / 8))        # x labels: at most ~8, always the last
    for i, lab in enumerate(labels):
        if i % every == 0 or i == npts - 1:
            if i != npts - 1 and npts - 1 - i < every:
                continue
            out.append('<text class="ax" x="%.1f" y="%d" text-anchor="middle">%s</text>' % (x(i), T + ph + 20, e(lab)))
    ends = []
    for s in series:
        pts = [(x(i), y(v), v, labels[i]) for i, v in enumerate(s["values"]) if v is not None]
        var = "var(--pl-%s, var(--pl-other))" % e(s["id"])
        if len(pts) > 1:
            line = " ".join(("M" if j == 0 else "L") + "%.1f %.1f" % (px, py) for j, (px, py, _, _) in enumerate(pts))
            area = line + " L%.1f %.1f L%.1f %.1f Z" % (pts[-1][0], T + ph, pts[0][0], T + ph)
            out.append('<path class="area" d="%s" style="fill:%s"/>' % (area, var))
            out.append('<path class="line" d="%s" style="stroke:%s"/>' % (line, var))
        for px, py, v, lab in pts:
            out.append('<g class="pt"><circle class="hit" cx="%.1f" cy="%.1f" r="10"/>'
                       '<circle class="dot" cx="%.1f" cy="%.1f" r="4" style="fill:%s"/>'
                       '<title>%s, %s: %s CVEs</title></g>' % (px, py, px, py, var, e(s["title"]), e(lab), n(v)))
        ends.append([pts[-1][1], s, pts[-1]])
    ends.sort(key=lambda t: t[0])              # end labels: keep at least 15px apart
    for j in range(1, len(ends)):
        ends[j][0] = max(ends[j][0], ends[j - 1][0] + 15)
    for ly, s, (px, py, v, _) in ends:
        out.append('<text class="end" x="%.1f" y="%.1f" dy=".32em"><tspan class="nm">%s</tspan> %s</text>' % (
            L + pw + 12, ly, e(s["title"]), n(v)))
    out.append("</svg>")
    legend = '<ul class="legend">%s</ul>' % "".join(
        '<li><span class="sw" style="background:var(--pl-%s, var(--pl-other))"></span>%s</li>' % (e(s["id"]), e(s["title"]))
        for s in series)
    head = "".join("<th class=\"n\">%s</th>" % e(s["title"]) for s in series)
    body = "".join("<tr><td class=\"date\">%s</td>%s</tr>" % (e(lab), "".join(
        '<td class="n">%s</td>' % (n(s["values"][i]) if s["values"][i] is not None else "&ndash;") for s in series))
        for i, lab in enumerate(labels))
    table = ('<details class="tview"><summary>Show as a table</summary><div class="scroll"><table><thead><tr><th>%s</th>%s</tr>'
             '</thead><tbody>%s</tbody></table></div></details>' % ({"day": "Day", "week": "Week ending", "month": "Month"}[h["range"]],
                                                                     head, body))
    return legend + out[0] + "".join(out[1:]) + table


def _arc(cx, cy, r, a0, a1):
    x0, y0 = cx + r * math.sin(a0), cy - r * math.cos(a0)
    x1, y1 = cx + r * math.sin(a1), cy - r * math.cos(a1)
    return "M%.2f %.2f L%.2f %.2f A%.2f %.2f 0 %d 1 %.2f %.2f Z" % (cx, cy, x0, y0, r, r, 1 if a1 - a0 > math.pi else 0, x1, y1)


def pie_svg(p, keys=None, var="lv", href="/report#", unit="CVEs"):
    """p: {"id", "title", "total", "levels": {level: count}}. Slices in `keys` order (most severe first by default),
    clockwise from 12 o'clock, coloured var(--<var>-<key>)."""
    LEVELS = keys or globals()["LEVELS"]
    total = p["total"]
    cx = cy = 90
    r = 84
    out = ['<svg class="pie" viewBox="0 0 180 180" role="img" aria-label="%s: %s %s">' % (e(p["title"]), n(total), e(unit))]
    if total == 0:
        out.append('<circle cx="90" cy="90" r="84" class="empty"/>')
    else:
        a = 0.0
        for key, name in LEVELS:
            c = p["levels"].get(key, 0)
            if not c:
                continue
            frac = c / total
            tip = "<title>%s: %s of %s (%.1f%%)</title>" % (e(name), n(c), n(total), 100 * frac)
            if frac >= 0.9999:
                out.append('<circle class="slice" cx="90" cy="90" r="%d" style="fill:var(--%s-%s)">%s</circle>' % (r, var, key, tip))
            else:
                out.append('<path class="slice" d="%s" style="fill:var(--%s-%s)">%s</path>' % (
                    _arc(cx, cy, r, a, a + 2 * math.pi * frac), var, key, tip))
            a += 2 * math.pi * frac
    out.append("</svg>")
    rows = "".join('<tr><td><span class="sw" style="background:var(--%s-%s)"></span>%s</td><td class="n">%s</td><td class="n">%s</td></tr>' % (
        var, key, e(name), n(p["levels"].get(key, 0)),
        ("%.1f%%" % (100 * p["levels"].get(key, 0) / total)) if total else "&ndash;") for key, name in LEVELS)
    return ('<figure class="piecard" id="pie-%s-%s"><figcaption><a href="%s%s">%s</a> <span class="muted">%s %s</span></figcaption>'
            '<div class="piewrap">%s<table class="pielegend"><tbody>%s</tbody></table></div></figure>' % (
                e(var), e(p["id"]), e(href), e(p["id"]), e(p["title"]), n(total), e(unit), "".join(out), rows))


def pies(platforms):
    if not platforms:
        return ""
    return '<div class="pies">%s</div>' % "".join(pie_svg(p) for p in platforms)


# Compliance rule results, in slice order.
RESULTS = [("fail", "Failed"), ("accepted", "Accepted"), ("pass", "Passed"), ("skip", "Not applicable"), ("notest", "No automated check")]


def result_pies(platforms):
    """platforms: [{"id", "title", "total", "levels": {result: count}}] -> rule results per platform."""
    if not platforms:
        return ""
    return '<div class="pies">%s</div>' % "".join(
        pie_svg(p, RESULTS, "cr", "/compliance/report#", "rule results") for p in platforms)


def score_bars(hosts):
    """hosts: [{"host", "pass", "fail", "accepted", "score", "href"}]: a stacked bar of passed, accepted (failed with
    an exception) and failed rules per host,
    labelled with the score. Sorted lowest score first so the hosts needing work are on top."""
    if not hosts:
        return '<p class="muted">No host has been checked yet.</p>'
    hosts = sorted(hosts, key=lambda h: (h["score"] if h["score"] is not None else 101, h["host"]))
    w, lab, row, bar = 1100, 250, 20, 12        # drawn at the page width: a wide viewBox keeps bars and text modest
    width = w - lab - 70
    out = ['<svg class="chart bars" viewBox="0 0 %d %d" role="img" aria-label="Compliance score per host">' % (w, row * len(hosts) + 6)]
    for i, h in enumerate(hosts):
        y = 3 + i * row
        acc = h.get("accepted", 0)
        tot = h["pass"] + acc + h["fail"]
        pw = width * h["pass"] / tot if tot else 0
        aw = width * acc / tot if tot else 0
        out.append('<g class="pt"><title>%s: %s passed, %s accepted, %s failed, score %s</title>' % (
            e(h["host"]), n(h["pass"]), n(acc), n(h["fail"]), "%s%%" % h["score"] if h["score"] is not None else "-"))
        out.append('<a href="%s"><text class="ax" x="%d" y="%d" text-anchor="end">%s</text></a>' % (
            e(h["href"]), lab - 8, y + bar - 2, e(h["host"] if len(h["host"]) <= 36 else h["host"][:35] + "…")))
        out.append('<rect x="%d" y="%d" width="%.1f" height="%d" rx="2" style="fill:var(--cr-pass)"/>' % (lab, y, pw, bar))
        if aw:
            out.append('<rect x="%.1f" y="%d" width="%.1f" height="%d" rx="2" style="fill:var(--cr-accepted)"/>' % (lab + pw, y, aw, bar))
        out.append('<rect x="%.1f" y="%d" width="%.1f" height="%d" rx="2" style="fill:var(--cr-fail)"/>' % (
            lab + pw + aw, y, width - pw - aw if tot else 0, bar))
        if not tot:
            out.append('<rect x="%d" y="%d" width="%d" height="%d" rx="2" class="empty"/>' % (lab, y, width, bar))
        out.append('<text class="end" x="%d" y="%d">%s</text></g>' % (lab + width + 8, y + bar - 2,
                                                                       "%s%%" % h["score"] if h["score"] is not None else "–"))
    out.append("</svg>")
    legend = ('<ul class="legend"><li><span class="sw" style="background:var(--cr-pass)"></span>Passed</li>'
              '<li><span class="sw" style="background:var(--cr-accepted)"></span>Accepted (exception)</li>'
              '<li><span class="sw" style="background:var(--cr-fail)"></span>Failed</li></ul>')
    rows = "".join('<tr><td class="mono"><a href="%s">%s</a></td><td class="n">%s</td><td class="n">%s</td><td class="n">%s</td><td class="n">%s</td></tr>' % (
        e(h["href"]), e(h["host"]), n(h["pass"]), n(h.get("accepted", 0)), n(h["fail"]),
        "%s%%" % h["score"] if h["score"] is not None else "–") for h in hosts)
    table = ('<details class="tview"><summary>Show as a table</summary><div class="scroll"><table><thead><tr><th>Host</th>'
             '<th class="n">Passed</th><th class="n">Accepted</th><th class="n">Failed</th><th class="n">Score</th></tr></thead><tbody>%s</tbody></table></div></details>' % rows)
    return legend + "".join(out) + table


# Light and dark colour tokens for the charts (added to render.TOKENS_*). Validated with the data-viz palette
# checks: platforms are categorical slots 1-3; severity is an ordinal ramp (Critical .. Low) plus neutral Unknown.
TOKENS_LIGHT = ("--cr-pass:#2e8b57;--cr-fail:#b3261e;--cr-accepted:#d9a400;--cr-skip:#9aa3ae;--cr-notest:#c9d3df;"
                "--pl-kubernetes:#2a78d6;--pl-linux:#eb6834;--pl-windows:#1baf7a;--pl-other:#6250d6;"
                "--lv-critical:#7a0d16;--lv-high:#b3261e;--lv-medium:#e0561b;--lv-low:#f29a5c;--lv-unknown:#9aa3ae")
TOKENS_DARK = ("--cr-pass:#4fb67c;--cr-fail:#ec7a45;--cr-accepted:#e6c440;--cr-skip:#6b7584;--cr-notest:#465163;"
               "--pl-kubernetes:#3987e5;--pl-linux:#d95926;--pl-windows:#199e70;--pl-other:#9085e9;"
               "--lv-critical:#f7b38a;--lv-high:#ec7a45;--lv-medium:#d4442a;--lv-low:#9e2a22;--lv-unknown:#6b7584")

CSS = """
.chartcard h2{display:flex;align-items:center;gap:12px;flex-wrap:wrap}.chartcard h2 .seg{margin-left:auto}
.seglinks a{display:inline-block;border-right:1px solid var(--line);background:var(--card);color:var(--ink);padding:5px 10px;font-size:12.5px;text-decoration:none}
.seglinks a:last-child{border-right:0}.seglinks a span{color:var(--muted)}.seglinks a.on{background:var(--accent);color:var(--accent-ink);font-weight:600}
.seglinks a.on span{color:inherit;opacity:.8}
svg.chart{width:100%;height:auto;display:block;font:10.5px system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif}
svg.chart.bars{font-size:11px}
svg.chart .grid{stroke:var(--line);stroke-width:1}svg.chart .ax{fill:var(--muted)}
svg.chart .area{fill-opacity:.14;stroke:none}svg.chart .line{fill:none;stroke-width:2;stroke-linejoin:round;stroke-linecap:round}
svg.chart .dot{stroke:var(--card);stroke-width:2}svg.chart .hit{fill:transparent}svg.chart .pt:hover .dot{r:6}
svg.chart .end{fill:var(--ink);font-weight:600}svg.chart .end .nm{fill:var(--muted);font-weight:400}
.legend{display:flex;gap:16px;flex-wrap:wrap;list-style:none;margin:0 0 8px;padding:0;font-size:13px}
.legend li{display:flex;align-items:center;gap:6px}
.sw{display:inline-block;width:12px;height:12px;border-radius:3px;vertical-align:-1px;margin-right:6px}
.legend .sw{margin-right:0}
details.tview{margin-top:8px}details.tview summary{cursor:pointer;color:var(--accent);font-size:13px}details.tview .scroll{margin-top:8px}
.pies{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:16px}
.piecard{margin:0;border:1px solid var(--line);border-radius:8px;padding:12px 14px}
.piecard figcaption{font-weight:700;font-size:15px;margin-bottom:8px}.piecard figcaption .muted{font-weight:400;font-size:13px;margin-left:6px}
.piewrap{display:flex;gap:14px;align-items:center;flex-wrap:wrap}
svg.pie{width:150px;height:150px;flex:none}svg.pie .slice{stroke:var(--card);stroke-width:2;stroke-linejoin:round}
svg.pie .slice:hover{opacity:.85}svg.pie .empty{fill:none;stroke:var(--line);stroke-width:2}
svg.bars .empty{fill:none;stroke:var(--line)}svg.bars a text{fill:var(--accent)}svg.bars .pt:hover rect{opacity:.85}
table.pielegend{width:auto;flex:1;min-width:170px;border:0}table.pielegend td{padding:3px 6px;border:0;font-size:13px}
"""
