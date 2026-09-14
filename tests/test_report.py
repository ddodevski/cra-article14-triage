"""The HTML report.

Two rules carry most of the weight here. The document must be standalone --
no fetch of any kind at render time or view time, because it is meant to open
from a memory stick on a machine with no network. And it must escape
everything, because every name, description and rationale in it came out of
an SBOM or a config file this tool did not write, and the document is meant to
be emailed to somebody.

The third is the one the rest of the output already lives by: the NO bucket is
counted, never enumerated.
"""

from __future__ import annotations

import io
import json
import re
import sys
from pathlib import Path

from art14 import report
from art14.cli import EXIT_ERROR, EXIT_OK, main
from tests.conftest import IRRELEVANT_KEV_DUMP

FIXTURE = Path(__file__).parent / "fixtures" / "graph.cdx.json"

# Anything that would make the browser go and get something. A bare "http" is
# not on the list: it appears in prose and in the CVSS vector, and neither is
# a fetch.
FETCHES = (
    re.compile(r"\bsrc\s*=", re.I),
    re.compile(r"<link\b", re.I),
    re.compile(r"<script\b", re.I),
    re.compile(r"@import\b", re.I),
    re.compile(r"url\(\s*['\"]?(?:https?:)?//", re.I),
    re.compile(r"<iframe\b", re.I),
    re.compile(r"<img\b", re.I),
)


def _payload(argv, capsys):
    """One run's public JSON document, the report's only input."""
    main(["--json", *argv])
    return json.loads(capsys.readouterr().out)


def test_the_report_fetches_nothing(capsys, kev_state):
    """Self-contained is the whole point: a CDN reference is a document that
    renders differently in three years, and three years later is when somebody
    asks what this run knew."""
    html = report.render(_payload([str(FIXTURE)], capsys))
    for pattern in FETCHES:
        assert not pattern.search(html), pattern.pattern


def test_everything_interpolated_is_escaped(tmp_path, capsys, kev_state):
    """A component name is attacker-adjacent input: it comes from whoever built
    the SBOM. This document gets emailed and opened."""
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    document["components"][0]["name"] = "<script>alert(1)</script>evil"
    payload = _payload([_written(tmp_path, document)], capsys)
    html = report.render(payload)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;evil" in html


def test_the_no_bucket_is_counted_and_never_enumerated(capsys, kev_state):
    """The same rule the terminal output lives by. A few hundred rows that need
    nothing from anybody would bury the two or three that do."""
    payload = _payload([str(FIXTURE)], capsys)
    triage = payload["triage"]
    assert triage["counts"]["no"]
    html = report.render(payload)
    expected = (
        len(triage["items"])
        + len(triage["ruledOutInConfig"])
        + len(triage["suppressedByUpstreamVex"])
    )
    assert html.count('class="brief') == expected
    assert f"{triage['counts']['no']} component-CVE pairs" in html


def test_coverage_comes_before_the_findings(capsys, kev_state):
    """A report that files its own blind spots at the bottom is one whose
    reader has already stopped."""
    html = report.render(_payload([str(FIXTURE)], capsys))
    assert html.index('id="coverage"') < html.index('id="briefs"')
    assert html.index('id="funnel"') < html.index('id="coverage"')


def test_every_open_item_gets_a_brief_with_both_dispositions(capsys, kev_state):
    """A brief that only says "look at this" has handed the work back."""
    payload = _payload([str(FIXTURE)], capsys)
    items = payload["triage"]["items"]
    assert items
    html = report.render(payload)
    for item in items:
        assert item["cve"] in html
        assert item["question"] is None or item["question"] in html
    assert "-&gt; REPORT" in html
    assert "-&gt; NO" in html


def test_the_funnel_names_the_unit_on_every_stage(capsys, kev_state):
    """Components become CVE ids become component-CVE pairs, and in between the
    count goes up rather than down. The figure says so on the row rather than
    drawing one taper across three different units."""
    html = report.render(_payload([str(FIXTURE)], capsys))
    figure = html[html.index('id="funnel"') : html.index("</svg>")]
    values = re.findall(r'class="f-value"[^>]*>([^<]+)<', figure)
    assert len(values) == 5
    # This fixture arrived with its own vulnerability list, so no matching of
    # ours ran. The row says that rather than quoting a share of a stage that
    # never happened.
    assert values[1] == "-"
    assert "not measured" in figure
    for value in values[:1] + values[2:]:
        assert re.fullmatch(r"\d+ of \d+ [a-zA-Z -]+", value), value
    assert "unit changes to CVE ids" in figure
    assert "unit changes to component-CVE pairs" in figure


def test_the_funnel_does_not_taper_where_the_numbers_do_not():
    """The Log4j walkthrough's own shape: 36 components, 28 of them answered,
    and then 136 CVE ids. The middle of the funnel goes up. Every bar is a
    share of the base on its own row, so nothing here has to pretend
    otherwise."""
    html = report.render(
        {
            "counts": {
                "components": 36,
                "documentComponents": 36,
                "vulnerabilities": 138,
            },
            "input": {"unmatchable": 0},
            "matching": {"source": "osv", "queried": 36, "withRecords": 28},
            "kev": {
                "available": True,
                "checked": 136,
                "listed": 5,
                "listedPairs": 7,
                "uncheckable": 1,
            },
            "triage": {
                "available": True,
                "counts": {"report": 1, "assess": 1, "no": 136},
            },
        }
    )
    figure = html[html.index('id="funnel"') : html.index("</svg>")]
    assert "36 of 36 components" in figure
    assert "28 of 36 components" in figure
    assert "136 of 136 CVE ids" in figure
    assert "5 of 136 CVE ids" in figure
    assert "1 of 7 component-CVE pairs" in figure


def test_severity_appears_only_as_context(capsys, kev_state):
    """Severity is not an axis anywhere in this tool, and a report is exactly
    where it would quietly become one."""
    html = report.render(_payload([str(FIXTURE)], capsys))
    for word in ("donut", "top 10", "health score", "health grade"):
        assert word.lower() not in html.lower()
    for match in re.finditer(r"CVSS", html):
        line_start = html.rfind("\n", 0, match.start())
        assert 'class="context"' in html[line_start : match.start()]


def test_a_run_with_no_catalogue_says_so_instead_of_a_verdict(capsys, kev_state):
    """`triage.available` false is not "nothing was reportable"."""
    payload = _payload([str(FIXTURE)], capsys)
    payload["triage"] = dict(payload["triage"], available=False, items=[])
    payload["input"] = dict(payload["input"], canRuleOut=False)
    html = report.render(payload)
    assert "could not be consulted" in html
    assert 'class="gate"' in html


def test_a_degraded_run_states_its_blind_spots_above_everything(capsys, kev_state):
    payload = _payload([str(FIXTURE)], capsys)
    payload["input"] = dict(
        payload["input"], quality="unusable", unmatchable=9, unmatchablePercent=90
    )
    html = report.render(payload)
    assert html.index('id="gate"') < html.index('id="funnel"')
    assert "SBOM quality is unusable" in html


def test_a_gated_run_withholds_the_result_rather_than_printing_a_zero(
    capsys, kev_state
):
    """The same call the terminal makes. On an input this poor every count
    would describe the well formed minority and read as a clean run, which is
    the failure the gate exists to prevent."""
    payload = _payload([str(FIXTURE)], capsys)
    payload["input"] = dict(
        payload["input"],
        gated=True,
        quality="unusable",
        unmatchable=9,
        unmatchablePercent=90,
    )
    html = report.render(payload)
    assert "Withheld." in html
    assert 'id="coverage"' in html
    for absent in ('id="funnel"', 'id="briefs"', 'id="no"', "component-CVE pair"):
        assert absent not in html


def test_a_payload_missing_a_block_renders_rather_than_crashes():
    """The renderer reads a document, and a document written by a different
    build is a missing field rather than a traceback in the middle of writing
    a file somebody asked for."""
    html = report.render({"product": "thing@1.0"})
    assert "thing@1.0" in html
    assert html.startswith("<!doctype html>")


def test_the_coverage_table_counts_records_not_responses(capsys, kev_state):
    """Eight of these components came back carrying nothing, and every one of
    them was answered for. A column headed "Answered" would print the exact
    conflation this tool exists to prevent, in the tool's own report."""
    payload = _payload([str(FIXTURE)], capsys)
    payload["input"] = dict(payload["input"], sourceCoverage="full")
    payload["matching"] = {
        "source": "osv",
        "queried": 36,
        "withRecords": 28,
        "coverage": {
            "level": "full",
            "ecosystems": [
                {"purlType": "pkg:maven", "queried": 36, "withRecords": 28}
            ],
        },
    }
    html = report.render(payload)
    assert ">With records<" in html
    assert ">Answered<" not in html
    # And the gate's own word for the axis, so that "full" above a table
    # reading 36 and 28 does not read as a contradiction.
    assert "full - every package type came back with records" in html
    assert "the other 8 came back carrying no record" in html


def test_the_document_never_prints_a_parenthesised_plural(capsys, kev_state):
    """This one gets printed and forwarded to somebody who did not run it.
    "1 item(s)" reads as unfinished on paper in a way it does not in a
    terminal, which keeps the shorter form."""
    payload = _payload([str(FIXTURE)], capsys)
    assert "(s)" not in report.render(payload)

    one = dict(payload)
    one["triage"] = dict(
        payload["triage"],
        counts=dict(payload["triage"]["counts"], no=1),
        items=payload["triage"]["items"][:1],
    )
    one["kev"] = dict(
        payload["kev"],
        uncheckable=1,
        uncheckableVulnerabilities=[{"id": "GHSA-x", "bomRefs": ["pkg:maven/a@1"]}],
    )
    html = report.render(one)
    assert "1 component-CVE pair " in html
    assert "1 item needs a decision. It says where it sits" in html
    assert "1 vulnerability record carries no CVE id, so it could not" in html
    assert "1 record carries no CVE id" in html


def test_the_printed_page_carries_one_typeface(capsys, kev_state):
    """SVG text does not inherit the print font, so a figure left alone
    prints sans on a serif page."""
    html = report.render(_payload([str(FIXTURE)], capsys))
    printed = html[html.index("@media print") : html.index("</style>")]
    assert ".figure text" in printed
    assert "Georgia" in printed
    # A heading at the foot of a page whose content starts on the next one
    # hands the reader an unlabelled table.
    assert "break-after: avoid" in printed
    assert "#verdict" in printed


# --- the flag -------------------------------------------------------------


def test_the_report_flag_writes_a_file_and_leaves_the_exit_code_alone(
    tmp_path, capsys, kev_state
):
    """Writing a second rendering of the same run must not be able to change
    what the run concluded."""
    kev_state["dump"] = list(IRRELEVANT_KEV_DUMP)
    out = tmp_path / "report.html"
    assert main([str(FIXTURE), "--report", str(out)]) == EXIT_OK
    captured = capsys.readouterr()
    assert out.read_text(encoding="utf-8").startswith("<!doctype html>")
    # The confirmation goes to stderr, so `--json --report` still writes one
    # parseable document to stdout and nothing else.
    assert str(out) in captured.err
    assert "<!doctype" not in captured.out


def test_the_report_flag_is_additional_output_not_a_replacement(
    tmp_path, capsys, kev_state
):
    out = tmp_path / "report.html"
    assert main(["--json", str(FIXTURE), "--report", str(out)]) == EXIT_ERROR
    payload = json.loads(capsys.readouterr().out)
    assert payload["source"] == str(FIXTURE)
    assert out.exists()


def test_an_unwritable_report_path_fails_before_the_run(tmp_path, capsys, kev_state):
    """A typo found after the run would leave the exit code deciding between a
    REPORT item and a failed write, and those are not the same statement."""
    assert main([str(FIXTURE), "--report", str(tmp_path / "absent" / "r.html")]) == (
        EXIT_ERROR
    )
    captured = capsys.readouterr()
    assert "cannot write the report" in captured.err
    # Nothing ran: no banner, no verdict, no half-written report.
    assert captured.out == ""
    assert not (tmp_path / "absent").exists()


def test_a_failed_run_leaves_no_empty_report_behind(tmp_path, capsys, kev_state):
    """The writability probe must not be mistakable for a report."""
    out = tmp_path / "report.html"
    assert main([str(tmp_path / "absent.cdx.json"), "--report", str(out)]) == EXIT_ERROR
    assert not out.exists()


def test_the_json_records_which_file_this_was(capsys, kev_state):
    """A run is evidence about a particular file, so the document names it."""
    payload = _payload([str(FIXTURE)], capsys)
    assert payload["source"] == str(FIXTURE)


def test_a_piped_sbom_says_so_rather_than_showing_a_dash(monkeypatch, capsys):
    """`-` is the command line's word for it, not a filename, and the header of
    a record somebody files should not leave that to be worked out."""
    monkeypatch.setattr(
        sys, "stdin", io.StringIO(FIXTURE.read_text(encoding="utf-8"))
    )
    payload = _payload(["-"], capsys)
    assert payload["source"] == "-"
    assert "standard input (piped)" in report.render(payload)


def _written(tmp_path, document, name="input.cdx.json"):
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return str(path)


def test_every_gloss_agrees_with_the_number_beside_it():
    """A gloss sits directly beside the count it describes, so "1 pairs" is
    the same defect as "1 pair(s)" -- and the static gloss strings are the
    ones a pluralisation sweep walks past. Every count here is one."""
    html = report.render(
        {
            "counts": {
                "components": 36,
                "documentComponents": 37,
                "vulnerabilities": 1,
            },
            "input": {
                "components": 36,
                "documentComponents": 37,
                "nonPackageComponents": 1,
                "unmatchable": 1,
            },
            "matching": {"source": "osv", "queried": 36, "withRecords": 35},
            "kev": {
                "available": True,
                "checked": 10,
                "listed": 1,
                "listedPairs": 3,
                "uncheckable": 1,
            },
            "triage": {
                "available": True,
                "counts": {
                    "report": 1,
                    "assess": 1,
                    "no": 1,
                    "ruledOut": 1,
                    "unassessed": 1,
                },
            },
        }
    )
    one = '<td class="num">1</td><td>'
    assert f"{one}component-CVE pair; the 24h clock is running" in html
    assert "pair in the KEV catalogue; needs a decision now" in html
    assert "pair not to report" in html
    assert "the reason is below" in html
    assert "pair whose record carries no CVE id" in html
    assert "36 of 37 entries (1 is not a package)" in html
    assert "from 1 vulnerability record" in html
    assert "1 carries no usable identifier" in html
    assert "one of those came back carrying no record" in html
    for wrong in (
        "1 pairs",
        "1 entries",
        "1 vulnerability records",
        "1 are not packages",
        "reasons are below",
        "1 carry no usable",
    ):
        assert wrong not in html


# --- own evidence in the document -----------------------------------------


def _flat(html):
    return " ".join(re.sub(r"<[^>]+>", " ", html).split())


def _own_evidence_payload(tmp_path, capsys, kev_state, *, listed):
    """One REPORT item, with and without a catalogue entry behind it.

    The same config either way: what changes is whether the catalogue names
    the CVE, which is the difference the document has to keep visible.
    """
    if not listed:
        kev_state["dump"] = list(IRRELEVANT_KEV_DUMP)
    config = tmp_path / "dispositions.toml"
    config.write_text(
        '[[report]]\ncomponent = "pkg:maven/example/bravo@2.0.0"\n'
        'cve = "CVE-2021-44228"\nbasis = "vendor advisory"\n'
        "aware = 2026-09-12\n"
        'rationale = "Named as exploited in the vendor advisory of 2026-09-11."\n',
        encoding="utf-8",
    )
    return _payload(["--config", str(config), str(FIXTURE)], capsys)


def test_an_unlisted_report_does_not_read_as_a_catalogue_hit(
    tmp_path, capsys, kev_state
):
    payload = _own_evidence_payload(tmp_path, capsys, kev_state, listed=False)
    text = _flat(report.render(payload))
    assert "not in the KEV catalogue - reported on a vendor advisory" in text
    # The disposition points at the basis rather than at a catalogue date
    # there is none of.
    assert "does not rest on the catalogue" in text
    assert "not from the catalogue date above" not in text


def test_a_listed_report_still_points_at_the_catalogue_date(
    tmp_path, capsys, kev_state
):
    payload = _own_evidence_payload(tmp_path, capsys, kev_state, listed=True)
    text = _flat(report.render(payload))
    assert "not from the catalogue date above" in text
    assert "does not rest on the catalogue" not in text


def test_the_awareness_date_is_a_field_rather_than_prose(
    tmp_path, capsys, kev_state
):
    """The whole point of recording it: until now the date existed only inside
    the rationale, where nothing could read it."""
    payload = _own_evidence_payload(tmp_path, capsys, kev_state, listed=True)
    assert payload["triage"]["items"][0]["aware"] == "2026-09-12"
    assert "Aware 2026-09-12" in _flat(report.render(payload))
