"""The HTML report: `art14 <sbom> --report out.html`.

One file, and everything it needs is inside it. The CSS is inline, the one
figure is inline SVG, and there is no script at all -- so it opens from a USB
stick on a machine with no network, and it renders the same way in three
years. Three years later is exactly when somebody asks what this run knew.

It is built for paper. A compliance officer prints it to PDF and attaches it
to a thread, so the page is A4, the background is white, and nothing in it
depends on colour: every bucket carries its name as text beside its rule.

It reads the public JSON document and nothing else -- the same dict `--json`
writes -- which makes it a consumer of the documented schema rather than a
second rendering path into the core, and a worked example of that schema for
anyone building their own. The cost is visible and deliberate: the brief's
dispositions and its upstream sentence are not fields in that document, so
they are reproduced here from the fields that are. Everything else, `what`,
`signal` and `question` included, is taken already rendered.

What it is not is a dashboard. No severity donut, no top-N table, no health
grade, no fix versions, no remediation advice. Severity appears once, inside
a brief, as context. Every one of those exclusions is a recorded decision
rather than an omission.
"""

from __future__ import annotations

import html
from typing import Any, Mapping, Sequence

# Bucket colour is the second signal and never the only one, the same rule the
# terminal table follows. Print drops backgrounds, and a compliance officer may
# print in monochrome, so these are borders and a word, never a fill a reader
# has to decode.
BUCKET_CLASS = {"REPORT": "b-report", "ASSESS": "b-assess", "NO": "b-no"}

# The figure's geometry, in user units and scaled by the viewBox, so the same
# numbers hold on a phone and on A4.
FIGURE_WIDTH = 740
LABEL_WIDTH = 168
TRACK_X = 180
TRACK_WIDTH = 288
ROW_HEIGHT = 48
UNIT_GAP = 30

STYLE = """\
:root { color-scheme: light; }
* { box-sizing: border-box; }
body {
  margin: 0 auto; padding: 26px 24px 44px; max-width: 940px;
  background: #ffffff; color: #1a1a1a;
  font: 15px/1.5 "Segoe UI", "Helvetica Neue", Helvetica, Arial, sans-serif;
}
h1 { font-size: 21px; line-height: 1.25; margin: 0 0 2px; }
h2 {
  font-size: 13px; text-transform: uppercase; letter-spacing: .09em;
  color: #333333; margin: 28px 0 10px; padding-bottom: 4px;
  border-bottom: 1px solid #d4d4d4;
}
h3 { font-size: 15px; margin: 0 0 8px; }
p { margin: 8px 0; }
.sub { color: #5a5a5a; margin: 0 0 4px; }
.note { color: #5a5a5a; font-size: 13px; }
code, .mono { font-family: Consolas, "DejaVu Sans Mono", Menlo, monospace; }
/* PURLs and bom-refs are one long unbreakable word; without this the
   table they sit in decides the width of the page. */
.mono, td { overflow-wrap: anywhere; }
table { border-collapse: collapse; width: 100%; margin: 6px 0 4px; }
th, td { text-align: left; padding: 4px 10px 4px 0; vertical-align: top; }
th { font-weight: 600; color: #333333; border-bottom: 1px solid #d4d4d4; }
tbody tr + tr td { border-top: 1px solid #ececec; }
td.num { text-align: right; width: 5em; font-variant-numeric: tabular-nums; }
.kv th { width: 15em; font-weight: 600; border: 0; color: #5a5a5a; }
.kv td { border: 0; }
.kv tbody tr + tr td, .kv tbody tr + tr th { border-top: 1px solid #f0f0f0; }
.gate {
  border: 1px solid #b8b8b8; border-left: 5px solid #9b1c1c;
  padding: 10px 14px; margin: 16px 0;
}
.gate h3 { color: #9b1c1c; }
.gate ul { margin: 6px 0 0; padding-left: 20px; }
.counts td.label { font-weight: 600; width: 12em; }
.counts td.label span { border-left: 5px solid #999999; padding-left: 8px; }
.counts td.b-report span { border-left-color: #9b1c1c; color: #9b1c1c; }
.counts td.b-assess span { border-left-color: #8a5a00; color: #8a5a00; }
.counts td.b-no span { border-left-color: #6b6b6b; }
.brief {
  border: 1px solid #d4d4d4; border-left: 5px solid #6b6b6b;
  padding: 12px 14px; margin: 14px 0;
}
.brief.b-report { border-left-color: #9b1c1c; }
.brief.b-assess { border-left-color: #8a5a00; }
.brief .tag {
  font-size: 12px; letter-spacing: .08em; font-weight: 700; margin-right: 8px;
}
.brief.b-report .tag { color: #9b1c1c; }
.brief.b-assess .tag { color: #8a5a00; }
.brief .ids { color: #5a5a5a; font-size: 13px; margin: 0 0 8px; }
.field { display: flex; gap: 12px; margin: 6px 0; }
.field > .name {
  flex: 0 0 5.5em; color: #5a5a5a; font-size: 13px; padding-top: 2px;
}
.field > .body { flex: 1 1 auto; }
.field .body p { margin: 0 0 6px; }
.dispositions {
  margin: 10px 0 0; padding: 8px 0 0; border-top: 1px solid #ececec;
}
.disposition { display: flex; gap: 10px; margin: 6px 0; }
.disposition > .arrow { flex: 0 0 5.5em; font-weight: 600; }
.disposition.to-report > .arrow { color: #9b1c1c; }
.context { margin-top: 8px; color: #5a5a5a; font-size: 13px; }
.figure { margin: 10px 0 4px; }
.figure svg { width: 100%; max-width: 740px; height: auto; }
.figure text { font-family: "Segoe UI", Helvetica, Arial, sans-serif; }
.f-label { font-size: 13px; fill: #1a1a1a; }
.f-value { font-size: 14px; font-weight: 700; fill: #1a1a1a; }
.f-note { font-size: 11px; fill: #5a5a5a; }
.f-unit { font-size: 11px; fill: #5a5a5a; letter-spacing: .04em; }
footer {
  margin-top: 30px; padding-top: 10px; border-top: 1px solid #d4d4d4;
  color: #5a5a5a; font-size: 12px;
}
@page { size: A4; margin: 16mm 14mm; }
@media print {
  body {
    max-width: none; padding: 0;
    font: 10pt/1.45 Georgia, "Times New Roman", serif;
    orphans: 3; widows: 3;
  }
  h1 { font-size: 16pt; }
  h2 { font-size: 10pt; margin-top: 16pt; }
  /* The figure is the one place a second typeface could get in: SVG text
     does not inherit the print font, so it would print sans on a serif
     page. Sized up as well, because 13 user units against a 740-unit
     viewBox lands under the body size once the figure is scaled to the
     text column. */
  .figure text { font-family: Georgia, "Times New Roman", serif; }
  .f-label { font-size: 15px; }
  .f-value { font-size: 16px; }
  .f-note, .f-unit { font-size: 13px; }
  /* Keep a heading with what it introduces, and never leave a disposition
     or a field label on its own side of a break. */
  h1, h2, h3 { break-after: avoid; page-break-after: avoid; }
  .gate, .figure, table, .field, .disposition, .ids, .context {
    break-inside: avoid; page-break-inside: avoid;
  }
  /* The verdict as a whole, not just the table inside it: a heading and its
     one-line result left at the foot of a page put an unlabelled table in
     front of whoever turns it. It is short enough to always keep together;
     the sections that are not are the ones that are meant to break. */
  #verdict { break-inside: avoid; page-break-inside: avoid; }
  /* A brief is kept whole where it fits. The ruled-out rationales are the
     ones that do not: a rationale can run longer than a page, and every
     engine ignores break-inside on a block taller than the page anyway.
     Orphans and widows above are what actually carry those. */
  .brief { break-inside: avoid; page-break-inside: avoid; }
}
"""


def render(payload: Mapping[str, Any]) -> str:
    """The whole document, from the public JSON dict and nothing else.

    The order is the argument. Provenance first, because what this report is
    worth is that it says what was known and when. Then the one picture, then
    the verdict, then coverage -- which sits above the findings rather than
    under them. A report that files its own blind spots at the bottom is one
    whose reader has already stopped.
    """
    product = _text(payload.get("product")) or "unknown product"
    sections = [_header(payload, product), _gate(payload)]
    if _block(payload, "input").get("gated"):
        # The same call the terminal makes, and for the same reason: on an
        # input this poor every count below would describe the well formed
        # minority and read as a result for the whole product. Coverage is
        # then the document.
        sections.append(_withheld(payload))
        sections.append(_coverage(payload))
    else:
        sections.extend(
            [
                _funnel(payload),
                _verdict(payload),
                _coverage(payload),
                _briefs(payload),
                _closing(payload),
            ]
        )
    sections.append(_footer(payload))
    body = "\n".join(section for section in sections if section)
    return (
        "<!doctype html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>Article 14 triage - {_e(product)}</title>\n"
        f"<style>\n{STYLE}</style>\n</head>\n<body>\n{body}\n</body>\n</html>\n"
    )


# --- header and provenance ------------------------------------------------


def _header(payload: Mapping[str, Any], product: str) -> str:
    provenance = _block(payload, "provenance")
    rows = [
        ("Product", _e(product)),
        ("SBOM source", _source(payload)),
        ("Format", _format(payload)),
        ("Run", _mono(provenance.get("generatedAt"))),
        ("Tool", _e(f"art14 {_text(payload.get('art14')) or 'unknown'}")),
        ("Run mode", _e(_text(provenance.get("mode")) or "unknown")),
        ("Vulnerability data", _stamp(_block(provenance, "osv"), stale=False)),
        (
            "Exploitation catalogue",
            _stamp(_block(provenance, "kev"), stale=bool(provenance.get("kevStale"))),
        ),
        (
            "Upstream VEX claims",
            "adopted (<code>--adopt-upstream-vex</code>)"
            if provenance.get("adoptUpstreamVex")
            else "not adopted; shown and attributed only",
        ),
    ]
    note = _text(provenance.get("note"))
    return (
        "<header>\n"
        f"<h1>{_e(product)}</h1>\n"
        '<p class="sub">Article 14 triage record'
        " - which vulnerabilities in this SBOM are known to be exploited.</p>\n"
        "</header>\n"
        "<h2>Provenance</h2>\n"
        '<p class="note">What this run consulted, and when. The sources below are'
        " point-in-time snapshots: the same SBOM run tomorrow can land"
        " differently, and this block is what says which day this was.</p>\n"
        + _kv(rows)
        + (f'<p class="note">{_e(note)}</p>\n' if note else "")
    )


def _source(payload: Mapping[str, Any]) -> str:
    """Which file this was, as the command line named it."""
    source = _text(payload.get("source"))
    if not source:
        return '<span class="note">not recorded</span>'
    if source == "-":
        return "standard input (piped)"
    return _mono(source)


def _format(payload: Mapping[str, Any]) -> str:
    spec = _text(payload.get("specVersion")) or "unknown"
    caveat = _text(payload.get("specVersionCaveat"))
    out = _e(f"CycloneDX {spec}")
    if caveat:
        out += f'<br><span class="note">{_e(caveat)}</span>'
    return out


def _stamp(stamp: Mapping[str, Any], *, stale: bool) -> str:
    """One source's two timestamps, in the shape a reader can act on.

    A cache hit with no fetch time is not a blank field: it says the answer
    came off the disk and how old it was. Printing the empty fetch time and
    stopping is the one thing this block must not do.
    """
    name = _text(stamp.get("source"))
    if not name:
        return '<span class="note">not consulted on this run</span>'
    fetched = _text(stamp.get("fetchedAt"))
    if fetched:
        detail = f"fetched {fetched}"
    else:
        age = _age(stamp.get("cacheAgeSeconds"))
        detail = f"served from cache, {age} old" if age else "served from cache"
    out = f'{_e(name)} <span class="note">- {_e(detail)}</span>'
    if stale:
        out += (
            '<br><span class="note">Past the freshness window. A CVE added to the'
            " catalogue since then is not in this result.</span>"
        )
    return out


def _age(seconds: Any) -> str:
    """A cache age a person reads, not a float of seconds."""
    try:
        total = int(float(seconds))
    except (TypeError, ValueError):
        return ""
    if total < 90:
        return f"{total} s"
    minutes = total // 60
    if minutes < 90:
        return f"{minutes} min"
    hours = minutes // 60
    if hours < 48:
        return f"{hours} h {minutes % 60} min"
    return f"{hours // 24} days"


# --- the gate notice ------------------------------------------------------


def _gate(payload: Mapping[str, Any]) -> str:
    """The blind spots, above everything they undermine.

    Nothing here is new: every line of it is somewhere further down as well.
    It is repeated at the top because the failure it guards against is a
    reader taking the verdict and stopping, on a run whose verdict rests on a
    minority of the product.
    """
    inp = _block(payload, "input")
    triage = _block(payload, "triage")
    points: list[str] = []
    level = _text(inp.get("quality"))
    if level and level != "ok":
        points.append(
            f"SBOM quality is {level}: {_int(inp.get('unmatchable'))} of"
            f" {_int(inp.get('components'))} graded components could not be"
            f" matched ({_int(inp.get('unmatchablePercent'))}%)."
        )
    coverage = _text(inp.get("sourceCoverage"))
    if coverage == "none":
        points.append(
            "Nothing came back from the vulnerability source for any package"
            " type. This run found no vulnerabilities because nothing was"
            " returned, not because there are none."
        )
    elif coverage == "partial":
        points.append(
            "Nothing came back at all for some package types. The silent ones"
            " are named under Coverage below."
        )
    if not triage.get("available", True):
        points.append(
            "The exploitation catalogue could not be consulted, so nothing in"
            " this inventory has been judged against it."
        )
    if not inp.get("canRuleOut", True):
        points.append(
            "This run cannot support a negative claim. Absence from the sections"
            " below is not evidence of absence from the product."
        )
    if inp.get("gated"):
        points.append(
            "No verdict is shown below. A count covering only the well formed"
            " minority of this SBOM would read as a result for the whole"
            " product; what the run can say is under Coverage."
        )
    if not points:
        return ""
    items = "\n".join(f"<li>{_e(point)}</li>" for point in points)
    return (
        '<section class="gate" id="gate">\n'
        "<h3>Coverage limits what this report can say</h3>\n"
        f"<ul>\n{items}\n</ul>\n</section>\n"
    )


# --- the funnel -----------------------------------------------------------


class _Stage:
    """One row of the figure: a number, the unit it is in, and its base."""

    def __init__(
        self,
        label: str,
        value: int | None,
        base: int,
        unit: str,
        note: str,
        tone: str = "step",
    ) -> None:
        self.label = label
        self.value = value
        self.base = base
        self.unit = unit
        self.note = note
        self.tone = tone


def _stages(payload: Mapping[str, Any]) -> list[_Stage]:
    """The five stages, each carrying the unit it counts in.

    The unit is not the same all the way down and the figure must not pretend
    otherwise: components become CVE ids and CVE ids become component-CVE
    pairs, and in between the count goes up rather than down. So every bar is
    a share of its own stated base, that base is printed on the row, and the
    two places the unit changes are marked. One tapering shape drawn across
    all five would assert arithmetic that does not work.
    """
    counts = _block(payload, "counts")
    inp = _block(payload, "input")
    matching = _block(payload, "matching")
    kev = _block(payload, "kev")
    bucket = _block(_block(payload, "triage"), "counts")

    components = _int(counts.get("components"))
    document = _int(counts.get("documentComponents"))
    stages = [
        _Stage(
            "components",
            components,
            components,
            "components",
            f"graded, of {document} {_unit(document, 'entry', 'entries')} in the SBOM"
            if document and document != components
            else "read from the SBOM",
            tone="base",
        )
    ]
    if matching.get("source"):
        stages.append(
            _Stage(
                "with records",
                _int(matching.get("withRecords")),
                components,
                "components",
                _queried_note(
                    _int(matching.get("queried")),
                    _int(matching.get("withRecords")),
                    _int(inp.get("unmatchable")),
                ),
            )
        )
    else:
        stages.append(
            _Stage(
                "with records",
                None,
                components,
                "components",
                "not measured here: the SBOM arrived with its own vulnerabilities",
            )
        )

    records = _int(counts.get("vulnerabilities"))
    if kev.get("available"):
        checked = _int(kev.get("checked"))
        uncheckable = _int(kev.get("uncheckable"))
        note = (
            f"distinct ids, from {records} vulnerability"
            f" {_unit(records, 'record', 'records')}"
        )
        if uncheckable:
            note += (
                f"; {uncheckable} record carries no CVE id"
                if uncheckable == 1
                else f"; {uncheckable} records carry no CVE id"
            )
        pairs = _int(kev.get("listedPairs"))
        stages.append(
            _Stage("CVE ids found", checked, checked, "CVE ids", note, "base")
        )
        stages.append(
            _Stage(
                "known exploited",
                _int(kev.get("listed")),
                checked,
                "CVE ids",
                "listed in the EUVD KEV catalogue, across"
                f" {pairs} {_pairs(pairs)}",
            )
        )
    else:
        pairs = 0
        stages.append(
            _Stage(
                "vulnerabilities",
                records,
                records,
                "records",
                "no catalogue on this run, so none of them was judged",
                "base",
            )
        )
    stages.append(
        _Stage(
            "REPORT",
            _int(bucket.get("report")),
            pairs,
            "component-CVE pairs",
            "of the pairs in the catalogue;"
            f" {_int(bucket.get('assess'))} still to assess",
            "report",
        )
    )
    return stages


def _queried_note(queried: int, with_records: int, unmatchable: int) -> str:
    """How much of the inventory was sendable, and what came back.

    The gap between the two numbers is not silence. Every one of these
    components was looked up and answered for; the rest came back carrying
    nothing, which is the source saying it holds no record rather than the
    source saying nothing. Naming that here is the difference between a
    reader reading the row as coverage and reading it as a shortfall.
    """
    rest = queried - with_records
    if not unmatchable:
        sendable = (
            "the one component could be queried"
            if queried == 1
            else f"all {queried} could be queried"
        )
    else:
        sendable = (
            f"{queried} could be queried; {unmatchable}"
            f" {_unit(unmatchable, 'carries', 'carry')} no usable"
            " identifier"
        )
    if rest > 0:
        others = _unit(rest, "one", str(rest))
        return (
            f"{sendable}; the other {others} came back carrying no record"
            if not unmatchable
            else f"{sendable}; {others} of those came back carrying no"
            " record"
        )
    return sendable


def _funnel(payload: Mapping[str, Any]) -> str:
    body: list[str] = []
    y = 6
    previous_unit = ""
    for stage in _stages(payload):
        if previous_unit and stage.unit != previous_unit:
            body.append(
                f'<line x1="{TRACK_X}" y1="{y + 8}" x2="{TRACK_X + TRACK_WIDTH}"'
                f' y2="{y + 8}" stroke="#cfcfcf" stroke-dasharray="3 3"/>'
            )
            body.append(
                f'<text class="f-unit" x="{TRACK_X}" y="{y + 24}">'
                f"unit changes to {_e(stage.unit)}</text>"
            )
            y += UNIT_GAP
        body.extend(_stage_svg(stage, y))
        y += ROW_HEIGHT
        previous_unit = stage.unit
    height = y + 2
    return (
        "<h2>From SBOM to obligation</h2>\n"
        '<div class="figure" id="funnel">\n'
        f'<svg viewBox="0 0 {FIGURE_WIDTH} {height}" width="{FIGURE_WIDTH}"'
        f' height="{height}" role="img" aria-label="From components in the SBOM'
        ' to the pairs that must be reported">\n'
        + "\n".join(body)
        + "\n</svg>\n</div>\n"
        '<p class="note">Each bar is a share of the base printed beside it, and'
        " the base changes twice on the way down. The asymmetry is the point of"
        " the tool: a few hundred findings collapse to the handful a person has"
        " to decide about.</p>\n"
    )


def _stage_svg(stage: _Stage, y: int) -> list[str]:
    fill = {"base": "#c6cfd6", "step": "#5b6b7a", "report": "#9b1c1c"}[stage.tone]
    if stage.tone == "report" and not stage.value:
        fill = "#8a8a8a"
    parts = [
        f'<text class="f-label" x="{LABEL_WIDTH}" y="{y + 18}"'
        f' text-anchor="end">{_e(stage.label)}</text>',
        f'<rect x="{TRACK_X}" y="{y + 6}" width="{TRACK_WIDTH}" height="16"'
        ' fill="#f0f0ee" stroke="#d4d4d4"/>',
    ]
    if stage.value is None:
        parts.append(
            f'<text class="f-note" x="{TRACK_X + 8}" y="{y + 18}">not'
            " measured</text>"
        )
        value = "-"
    else:
        width = _bar(stage.value, stage.base)
        if width:
            parts.append(
                f'<rect x="{TRACK_X}" y="{y + 6}" width="{width}" height="16"'
                f' fill="{fill}"/>'
            )
        value = f"{stage.value} of {stage.base} {stage.unit}"
    parts.append(
        f'<text class="f-value" x="{TRACK_X + TRACK_WIDTH + 12}" y="{y + 19}">'
        f"{_e(value)}</text>"
    )
    parts.append(
        f'<text class="f-note" x="{TRACK_X}" y="{y + 38}">{_e(stage.note)}</text>'
    )
    return parts


def _bar(value: int, base: int) -> int:
    """Bar width in user units. A non-zero count never draws as nothing."""
    if value <= 0 or base <= 0:
        return 0
    return max(3, min(TRACK_WIDTH, round(TRACK_WIDTH * value / base)))


# --- verdict --------------------------------------------------------------


def _withheld(payload: Mapping[str, Any]) -> str:
    """What stands in for the result when the input cannot support one.

    Not an empty results section and not a zero: either would be read as a
    clean run, which is the exact failure the gate exists to prevent.
    """
    inp = _block(payload, "input")
    return (
        '<h2>Result</h2>\n<section id="verdict">\n'
        f"<p><strong>Withheld.</strong> {_int(inp.get('unmatchable'))} of"
        f" {_int(inp.get('components'))} components in this SBOM"
        f" ({_int(inp.get('unmatchablePercent'))}%) could not be matched. Any"
        " count here would describe the minority that happens to be well"
        " formed, and it would read as a result for the whole product.</p>\n"
        "<p>This is an input that could not be assessed, not a clean one. What"
        " the run can say about it is under Coverage below.</p>\n"
        "</section>\n"
    )


def _verdict(payload: Mapping[str, Any]) -> str:
    triage = _block(payload, "triage")
    counts = _block(triage, "counts")
    if not triage.get("available"):
        return (
            '<h2>Verdict</h2>\n<section id="verdict">\n'
            "<p>None. The exploitation catalogue could not be consulted on this"
            " run, so no vulnerability in this inventory has been checked"
            " against it. What follows says what was found, not what it"
            " means.</p>\n</section>\n"
        )
    report = _int(counts.get("report"))
    assess = _int(counts.get("assess"))
    no = _int(counts.get("no"))
    label = _no_label(counts)
    body = [
        f"<p><strong>{report} to report - {assess} to assess -"
        f" {no} {_e(label)}</strong></p>",
        '<table class="counts"><tbody>',
    ]
    rows = [
        ("REPORT", report, f"{_pairs(report)}; the 24h clock is running"),
        (
            "ASSESS",
            assess,
            f"{_unit(assess, 'pair', 'pairs')} in the KEV catalogue;"
            " needs a decision now",
        ),
        ("NO", no, f"{_unit(no, 'pair', 'pairs')} {label}"),
    ]
    for name, value, gloss in rows:
        body.append(
            f'<tr><td class="label {BUCKET_CLASS[name]}"><span>{name}</span></td>'
            f'<td class="num">{value}</td><td>{_e(gloss)}</td></tr>'
        )
    ruled_out = _int(counts.get("ruledOut"))
    suppressed = _int(counts.get("suppressed"))
    of_which = []
    if ruled_out:
        of_which.append(
            (
                ruled_out,
                "ruled out in configuration; the"
                f" {_unit(ruled_out, 'reason is', 'reasons are')} below",
            )
        )
    if suppressed:
        of_which.append(
            (
                suppressed,
                "suppressed by --adopt-upstream-vex (the SBOM's own claim)",
            )
        )
    for value, gloss in of_which:
        body.append(
            '<tr><td class="label"><span>of which</span></td>'
            f'<td class="num">{value}</td>'
            f"<td>{_e(gloss)}</td></tr>"
        )
    unassessed = _int(counts.get("unassessed"))
    if unassessed:
        body.append(
            '<tr><td class="label"><span>unchecked</span></td>'
            f'<td class="num">{unassessed}</td>'
            f"<td>{_unit(unassessed, 'pair', 'pairs')} whose record"
            " carries no CVE id</td></tr>"
        )
    body.append("</tbody></table>")
    return (
        '<h2>Verdict</h2>\n<section id="verdict">\n'
        + "\n".join(body)
        + "\n</section>\n"
    )


def _unit(count: int, singular: str, plural: str) -> str:
    """The noun, agreeing with the number printed in front of it.

    The glosses in this document are sentences a reader meets beside the
    number they describe, so "1 pairs" is a defect in the same class as
    "1 pair(s)". The terminal keeps its fixed column, which reads as a
    legend rather than as a sentence.
    """
    return singular if count == 1 else plural


def _pairs(count: int) -> str:
    """The unit, agreeing with its number.

    A printed record reads as unfinished when it says "1 pair(s)", and this
    one is meant to be forwarded to somebody who did not run the tool. The
    terminal keeps the shorter form; this is the only place the difference
    is worth the branch.
    """
    return _unit(count, "component-CVE pair", "component-CVE pairs")


def _no_label(counts: Mapping[str, Any]) -> str:
    """What the NO count may be called, given what is in it."""
    if _int(counts.get("ruledOut")) or _int(counts.get("suppressed")):
        return "not to report"
    return "not in the KEV catalogue"


# --- coverage -------------------------------------------------------------


# What each level of the coverage axis means, in the words the axis is about:
# which package types came back with records, never whether a component has
# vulnerabilities. The gloss reads the gate's own verdict rather than working
# it out again from the per-type table, so the two cannot disagree.
COVERAGE_GLOSS = {
    "full": "every package type came back with records",
    "partial": "at least one package type came back with nothing at all",
    "none": "nothing came back for any package type",
}


def _coverage_gloss(level: Any) -> str:
    """The coverage level, with the sentence that stops it reading as a score."""
    word = _text(level) or "unknown"
    gloss = COVERAGE_GLOSS.get(word)
    return f"{_e(word)} - {_e(gloss)}" if gloss else _e(word)


def _graded(inp: Mapping[str, Any]) -> str:
    """How much of the document was gradeable, in agreeing numbers."""
    entries = _int(inp.get("documentComponents"))
    other = _int(inp.get("nonPackageComponents"))
    aside = (
        "1 is not a package" if other == 1 else f"{other} are not packages"
    )
    return (
        f"{_int(inp.get('components'))} of {entries}"
        f" {_unit(entries, 'entry', 'entries')} ({aside})"
    )


def _coverage(payload: Mapping[str, Any]) -> str:
    """The quality gate, stated plainly and above the findings.

    Unmatched components are named rather than counted, the same way the
    terminal output names them: a number is a thing a reader skips, and a name
    is a thing they recognise as part of their own product.
    """
    inp = _block(payload, "input")
    matching = _block(payload, "matching")
    kev = _block(payload, "kev")
    rows = [
        ("Verdict on the input", _e(_text(inp.get("verdict")) or "unknown")),
        ("SBOM quality", _e(_text(inp.get("quality")) or "unknown")),
        ("Source coverage", _coverage_gloss(inp.get("sourceCoverage"))),
        ("Components graded", _e(_graded(inp))),
        (
            "Without a PURL",
            _e(
                f"{_int(inp.get('withoutPurl'))}"
                f" ({_int(inp.get('withoutPurlPercent'))}%)"
            ),
        ),
        ("Without a version", _e(str(_int(inp.get("withoutVersion"))))),
        ("Lookups that failed", _e(str(_int(inp.get("queryFailures"))))),
        (
            "Not assessed",
            _e(
                f"{_int(inp.get('unmatchable'))}"
                f" ({_int(inp.get('unmatchablePercent'))}%)"
            ),
        ),
    ]
    out = ['<h2>Coverage</h2>\n<section id="coverage">', _kv(rows)]

    ecosystems = _block(_block(matching, "coverage"), "ecosystems", [])
    if ecosystems:
        out.append(
            "<p>What came back from the vulnerability source, by package type."
            " Every component listed here was looked up; the second column"
            " counts the ones that came back carrying a record, which is a"
            " different question from whether the source responded. A group"
            " where nothing came back at all is a blind spot over part of the"
            " product, and it is invisible in the total.</p>"
        )
        out.append(
            _table(
                ("Package type", "Queried", "With records"),
                [
                    (
                        _mono(row.get("purlType")),
                        str(_int(row.get("queried"))),
                        str(_int(row.get("withRecords"))),
                    )
                    for row in ecosystems
                ],
                numeric=(1, 2),
            )
        )

    unmatchable = _block(inp, "unmatchableComponents", [])
    if unmatchable:
        out.append(
            f"<p>{len(unmatchable)} component was not assessed. It is named"
            " here rather than counted: nothing below says anything about"
            " it.</p>"
            if len(unmatchable) == 1
            else f"<p>{len(unmatchable)} components were not assessed. They are"
            " named here rather than counted: nothing below says anything"
            " about them.</p>"
        )
        out.append(
            _table(
                ("Component", "Version", "Identifier", "Why not assessed"),
                [
                    (
                        _e(_text(row.get("name")) or "-"),
                        _e(_text(row.get("version")) or "-"),
                        _mono(row.get("purl") or row.get("bomRef")),
                        _e(_text(row.get("reason")) or "-"),
                    )
                    for row in unmatchable
                ],
            )
        )

    uncheckable = _block(kev, "uncheckableVulnerabilities", [])
    if uncheckable:
        out.append(
            "<p>1 vulnerability record carries no CVE id, so it could not be"
            " looked up in the catalogue. It is not in the NO bucket: it was"
            " never checked.</p>"
            if len(uncheckable) == 1
            else f"<p>{len(uncheckable)} vulnerability records carry no CVE id,"
            " so they could not be looked up in the catalogue. They are not in"
            " the NO bucket: they were never checked.</p>"
        )
        out.append(
            _table(
                ("Record", "Components"),
                [
                    (
                        _mono(row.get("id")),
                        _mono(", ".join(str(ref) for ref in row.get("bomRefs") or ())),
                    )
                    for row in uncheckable
                ],
            )
        )
    out.append("</section>")
    return "\n".join(out) + "\n"


# --- the briefs -----------------------------------------------------------


def _briefs(payload: Mapping[str, Any]) -> str:
    """The full decision brief for every REPORT and ASSESS item.

    This is the substance of the document and everything above it is the
    frame. Both dispositions are stated on every open item, because a brief
    that only says "look at this" has handed the work back.
    """
    items = _block(payload, "triage").get("items") or ()
    if not items:
        return (
            '<h2>Decision briefs</h2>\n<section id="briefs">\n'
            "<p>Nothing in this SBOM is in the exploitation catalogue, so there"
            " is no item to decide about.</p>\n</section>\n"
        )
    briefs = "\n".join(_brief(item) for item in items)
    return (
        '<h2>Decision briefs</h2>\n<section id="briefs">\n'
        + (
            "<p>1 item needs a decision. It says where it sits, what it is, who"
            " says it is exploited, and the one question to answer about this"
            " product.</p>\n"
            if len(items) == 1
            else f"<p>{len(items)} items need a decision. Each one says where"
            " it sits, what it is, who says it is exploited, and the one"
            " question to answer about this product.</p>\n"
        )
        + f"{briefs}\n</section>\n"
    )


def _brief(item: Mapping[str, Any]) -> str:
    bucket = _text(item.get("bucket")) or "ASSESS"
    css = BUCKET_CLASS.get(bucket, "b-no")
    identifiers = ", ".join(
        part
        for part in [_text(item.get("euvd"))]
        + [_text(osv) for osv in item.get("osvIds") or ()]
        if part
    )
    parts = [
        f'<article class="brief {css}">',
        f'<h3><span class="tag">{_e(bucket)}</span>'
        f'{_e(_text(item.get("cve")) or "-")} -'
        f' {_e(_text(item.get("component")) or "-")}</h3>',
    ]
    if identifiers:
        parts.append(f'<p class="ids mono">{_e(identifiers)}</p>')
    parts.append(_field("Where", _e(_text(item.get("where")) or "-")))
    parts.append(_field("What", _e(_text(item.get("what")) or "-")))
    parts.append(_field("Signal", _e(_text(item.get("signal")) or "-")))
    claim = item.get("upstreamClaim")
    if isinstance(claim, Mapping):
        parts.append(_field("Upstream", _e(_upstream(claim, bucket))))
    if bucket == "REPORT":
        parts.append(_field("Confirmed", _paragraphs(item.get("rationale"))))
        confirmed_by = _text(item.get("confirmedBy"))
        if confirmed_by:
            parts.append(
                '<p class="note">stated in <span class="mono">'
                f"{_e(confirmed_by)}</span></p>"
            )
        # The basis is already in the Signal field above, which is where the
        # question of whose word it is gets answered. This is the other half
        # the file now records: the day, in a field rather than in prose.
        aware = _text(item.get("aware"))
        if aware:
            parts.append(_field("Aware", _e(aware)))
    else:
        parts.append(_field("Question", _e(_text(item.get("question")) or "-")))
    parts.append(_dispositions(item, bucket, claim))
    context = _context(item)
    if context:
        parts.append(f'<p class="context">context: {_e(context)}</p>')
    parts.append("</article>")
    return "\n".join(parts)


def _dispositions(item: Mapping[str, Any], bucket: str, claim: Any) -> str:
    """Both ways an open item can end, stated on the item.

    Reproduced here rather than read out of the document: the JSON carries
    every field of the brief but not these sentences, and the alternative was
    to grow the schema so that one renderer could avoid retyping them.
    """
    component = _text(item.get("component")) or "this component"
    rows: list[tuple[str, str, str]] = []
    if bucket == "REPORT":
        # Whether a catalogue entry stands behind this item. Read off the
        # three fields a catalogue entry fills rather than asserted as a
        # fourth: the JSON says what the entry held, and "there was one" is
        # that and nothing more.
        listed = bool(
            item.get("sources") or item.get("euvd") or item.get("dateAdded")
        )
        rows.append(
            (
                "->",
                "to-report",
                # Two sentences, because there are two ways to be in REPORT
                # and the difference is the point. On a CVE no catalogue
                # lists there is no catalogue date to point away from, and
                # the Signal field above is carrying the basis instead.
                "The obligation is on the record. The 24h clock runs from when"
                " you became aware, not from the catalogue date above."
                if listed
                else "The obligation is on the record, and it does not rest on"
                " the catalogue: no catalogue this run read lists this CVE, and"
                " the Signal field above names what the entry rests on instead."
                " The 24h clock runs from when you became aware.",
            )
        )
    else:
        rows.append(
            (
                "-> REPORT",
                "to-report",
                "if yes, or if it cannot be ruled out. Record it as a [[report]]"
                f" entry for {component}, with the reason it is reachable.",
            )
        )
        rows.append(
            (
                "-> NO",
                "",
                "if the component is present but the vulnerable path is never"
                f" reached. Record it as a [[no]] entry for {component}, with"
                " the reason it is not: that is your VEX entry and your audit"
                " trail.",
            )
        )
        if isinstance(claim, Mapping) and claim.get("adoptable"):
            asserter = _text(claim.get("assertedBy")) or "whoever produced the SBOM"
            rows.append(
                (
                    "-> adopt",
                    "",
                    f"if you are prepared to stand behind {asserter} having made"
                    " that determination for your product. Re-running with"
                    " --adopt-upstream-vex moves this item to NO, records the"
                    " claim and its author in the output, and can change the"
                    " exit code. It does not move the obligation.",
                )
            )
    body = "\n".join(
        f'<div class="disposition {css}"><div class="arrow mono">{_e(arrow)}</div>'
        f"<div>{_e(text)}</div></div>"
        for arrow, css, text in rows
    )
    return f'<div class="dispositions">\n{body}\n</div>'


def _upstream(claim: Mapping[str, Any], bucket: str) -> str:
    """The SBOM's own claim, never printed as a bare assertion."""
    asserter = _text(claim.get("assertedBy")) or "the SBOM"
    stated = _text(claim.get("state")) or "a claim"
    justification = _text(claim.get("justification"))
    if justification:
        stated += f" ({justification})"
    text = f"{asserter} asserts {stated} for this product."
    detail = _one_line(claim.get("detail"))
    if detail:
        text += f' "{detail}"'
    if bucket == "REPORT":
        return (
            text
            + " Your confirmation below says otherwise and wins: a statement"
            " about your own product outranks one made about somebody's."
        )
    if claim.get("adopted"):
        return text + " Adopted on this run; the item is in NO on that authority."
    if not claim.get("adoptable"):
        return (
            text
            + " Unverified, and not adoptable: only not_affected can be adopted,"
            " and this is a statement about the scan rather than about whether"
            " the path is live in your product."
        )
    return (
        text
        + " Unverified - art14 did not check it and this run did not act on it."
        " The item is still yours to decide."
    )


def _context(item: Mapping[str, Any]) -> str:
    """Severity context for ordering work inside a bucket. Never a trigger."""
    score = item.get("cvss")
    word = _text(item.get("severity"))
    vector = _text(item.get("cvssVector"))
    if score is not None:
        return f"CVSS {score} - {word}" if word else f"CVSS {score}"
    if vector:
        return f"{word} - {vector}" if word else vector
    return word


# --- the NO bucket, and what somebody decided -----------------------------


def _closing(payload: Mapping[str, Any]) -> str:
    """NO in one line, and the two kinds of row that earn more than that.

    The bucket is never enumerated: a few hundred rows that need nothing from
    anybody would destroy the asymmetry the whole report is about. The
    exceptions are the items somebody decided -- a ruling in configuration, or
    an adopted upstream claim -- because those are in the catalogue and are in
    NO on a person's word, which a reader has to be able to check.
    """
    triage = _block(payload, "triage")
    counts = _block(triage, "counts")
    no = _int(counts.get("no"))
    out = ['<h2>Not reportable</h2>\n<section id="no">']
    if no:
        out.append(
            f"<p>{no} {_pairs(no)} {_e(_no_label(counts))}. They are"
            " counted, not listed: they need nothing from anybody, and a few"
            " hundred rows here would bury the ones that do.</p>"
        )
    else:
        out.append("<p>No pair landed in the NO bucket on this run.</p>")

    ruled_out = _block(triage, "ruledOutInConfig", [])
    if ruled_out:
        out.append(
            "<h3>Ruled out in configuration</h3>"
            "<p>In the catalogue, and in NO because a person decided so and"
            " wrote down why. This is the audit trail for those decisions.</p>"
        )
        out.extend(_decided(item) for item in ruled_out)

    suppressed = _block(triage, "suppressedByUpstreamVex", [])
    if suppressed:
        out.append(
            "<h3>Suppressed by an upstream claim</h3>"
            "<p>In the catalogue, and in NO on the authority of whoever produced"
            " the SBOM, adopted by running with --adopt-upstream-vex.</p>"
        )
        out.extend(_suppressed(item) for item in suppressed)

    unused = _block(triage, "unusedConfirmations", [])
    if unused:
        entries = "".join(
            f'<li><span class="mono">{_e(_text(row.get("component")) or "-")}'
            f' {_e(_text(row.get("cve")) or "-")}</span> -'
            f' {_e(_text(row.get("reason")) or "did not match")}</li>'
            for row in unused
        )
        out.append(
            '<div class="gate"><h3>Confirmations that matched nothing</h3>'
            "<p>Each of these was written down as a decision about this product"
            " and landed on no item in this run. Whoever wrote it believes"
            f" something is in REPORT that is not.</p><ul>{entries}</ul></div>"
        )
    out.append("</section>")
    return "\n".join(out) + "\n"


def _decided(item: Mapping[str, Any]) -> str:
    aware = _text(item.get("aware"))
    dated = f'<p class="note">aware {_e(aware)}</p>' if aware else ""
    confirmed_by = _text(item.get("confirmedBy"))
    stated = (
        f'<p class="note">stated in <span class="mono">{_e(confirmed_by)}</span>'
        "</p>"
        if confirmed_by
        else ""
    )
    return (
        '<div class="brief b-no">'
        f'<h3>{_e(_text(item.get("cve")) or "-")} -'
        f' {_e(_text(item.get("component")) or "-")}</h3>'
        f'<p class="ids">{_e(_text(item.get("where")))}</p>'
        f"{dated}{_paragraphs(item.get('rationale'))}{stated}</div>"
    )


def _suppressed(item: Mapping[str, Any]) -> str:
    stated = _text(item.get("state")) or "not_affected"
    justification = _text(item.get("justification"))
    if justification:
        stated += f" ({justification})"
    reason = f"{_text(item.get('assertedBy')) or 'the SBOM'} asserts {stated}."
    detail = _one_line(item.get("detail"))
    if detail:
        reason += f' "{detail}"'
    return (
        '<div class="brief b-no">'
        f'<h3>{_e(_text(item.get("cve")) or "-")} -'
        f' {_e(_text(item.get("component")) or "-")}</h3>'
        f"<p>{_e(reason)}</p></div>"
    )


def _footer(payload: Mapping[str, Any]) -> str:
    tool = _text(payload.get("art14")) or "unknown"
    return (
        "<footer>\n"
        f"<p>Generated by art14 {_e(tool)} from the SBOM named above. art14"
        " never scans images, containers or filesystems, stores no vulnerability"
        " data of its own, and claims no exhaustiveness: it reports what the"
        " sources named under Provenance answered on this run, and says what"
        " they did not answer.</p>\n"
        "<p>This does not replace a legal assessment of scope.</p>\n"
        "</footer>\n"
    )


# --- small helpers --------------------------------------------------------


def _e(value: Any) -> str:
    """Escape, always.

    Component names, descriptions and written rationales all arrive from an
    SBOM or a configuration file this tool did not write, and this document is
    meant to be emailed to somebody.
    """
    return html.escape("" if value is None else str(value), quote=True)


def _mono(value: Any) -> str:
    text = _text(value)
    return f'<span class="mono">{_e(text)}</span>' if text else "-"


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _one_line(value: Any) -> str:
    return " ".join(_text(value).split())


def _paragraphs(value: Any) -> str:
    """A written rationale, hard-wrapped by whoever typed it, as paragraphs.

    Single newlines are the width of somebody's editor and mean nothing here;
    blank lines are the paragraph breaks they meant.
    """
    text = _text(value).strip()
    if not text:
        return ""
    blocks = [" ".join(part.split()) for part in text.split("\n\n")]
    return "".join(f"<p>{_e(block)}</p>" for block in blocks if block)


def _field(name: str, body: str) -> str:
    if not body:
        body = "-"
    if not body.startswith("<p"):
        body = f"<p>{body}</p>"
    return (
        f'<div class="field"><div class="name">{_e(name)}</div>'
        f'<div class="body">{body}</div></div>'
    )


def _kv(rows: Sequence[tuple[str, str]]) -> str:
    body = "\n".join(
        f"<tr><th>{_e(name)}</th><td>{value}</td></tr>" for name, value in rows
    )
    return f'<table class="kv"><tbody>\n{body}\n</tbody></table>\n'


def _table(
    headings: Sequence[str],
    rows: Sequence[Sequence[str]],
    *,
    numeric: Sequence[int] = (),
) -> str:
    head = "".join(f"<th>{_e(name)}</th>" for name in headings)
    body = []
    for row in rows:
        cells = "".join(
            f'<td class="num">{cell}</td>' if index in numeric else f"<td>{cell}</td>"
            for index, cell in enumerate(row)
        )
        body.append(f"<tr>{cells}</tr>")
    return (
        f"<table><thead><tr>{head}</tr></thead><tbody>\n"
        + "\n".join(body)
        + "\n</tbody></table>"
    )


def _block(payload: Mapping[str, Any], key: str, default: Any = None) -> Any:
    """One sub-document, defaulting to an empty one.

    Every caller reads keys off whatever comes back, so a payload written by a
    different build is a missing field rather than a traceback in the middle
    of writing a file somebody asked for.
    """
    value = payload.get(key)
    if default is None:
        return value if isinstance(value, Mapping) else {}
    return value if isinstance(value, list) else default
