"""The compact table.

Presentation, so the tests are about what a reader can take away from it: the
row order, what the two loud lines say, and the two crops this output is
actually read in. The screenshot in the README is one of them and a paste into
an email is the other, so nothing here may depend on colour surviving.

Glyphs are never asserted on. Rich substitutes box characters by itself on a
legacy Windows console, and the same run through a pipe and through pytest's
capture does not draw the same rule.
"""

from __future__ import annotations

from dataclasses import replace

from rich import box
from rich.console import Console

from art14.kev import Catalogue, KevEntry, review as kev_review
from art14.models import (
    DIRECT,
    ROOT,
    TRANSITIVE,
    Component,
    Finding,
    Location,
    Rating,
    Sbom,
    Vulnerability,
)
from art14.table import (
    MAX_WIDTH,
    MIN_WIDTH,
    TARGET_WIDTH,
    _box_for,
    _listed_by,
    dependency_key,
    print_table,
    render_width,
    result_line,
    rows,
    summary_row,
)
from art14.triage import ASSESS, Confirmation, REPORT, triage

ROOT_COMPONENT = Component(
    bom_ref="app", name="gateway", version="3.2.0", purl="pkg:maven/acme/gateway@3.2.0"
)
LOG4J = Component(
    bom_ref="log4j-core",
    name="log4j-core",
    version="2.14.1",
    purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
)
SPRING = Component(
    bom_ref="spring-beans",
    name="spring-beans",
    version="5.3.12",
    purl="pkg:maven/org.springframework/spring-beans@5.3.12",
)
ENTRY = KevEntry(
    cve_id="CVE-2021-44228",
    euvd_id="EUVD-2021-0001",
    date_added="2021-12-10",
    sources=("cisa_kev", "eu_kev"),
)
LOCATIONS = {
    "log4j-core": Location(kind=DIRECT, depth=1, chain=("app", "log4j-core")),
    "spring-beans": Location(
        kind=TRANSITIVE, depth=2, chain=("app", "boot", "spring-beans")
    ),
}


def _vuln(vuln_id, cve, ref, *, score=None):
    ratings = (Rating(method="CVSSv31", score=score),) if score is not None else ()
    return Vulnerability(
        id=vuln_id,
        aliases=(cve,),
        affects=(ref,),
        ratings=ratings,
        description="",
        source_name="OSV",
    )


def _sbom(vulns, components=(LOG4J, SPRING), locations=None):
    locations = LOCATIONS if locations is None else locations
    by_ref = {c.bom_ref: c for c in components}
    return Sbom(
        spec_version="1.6",
        root=ROOT_COMPONENT,
        components=(ROOT_COMPONENT,) + tuple(components),
        vulnerabilities=tuple(vulns),
        locations=locations,
        findings=tuple(
            Finding(
                vulnerability=v,
                component=by_ref[v.affects[0]],
                location=locations[v.affects[0]],
            )
            for v in vulns
        ),
    )


def _run(vulns, *, listed=(), confirmations=(), sbom=None):
    document = sbom if sbom is not None else _sbom(vulns)
    catalogue = Catalogue(
        {
            cve: (ENTRY if cve == "CVE-2021-44228" else KevEntry(cve_id=cve))
            for cve in listed
        }
    )
    return triage(
        document, kev_review(document.vulnerabilities, catalogue), confirmations
    )


def _confirmed():
    return (
        Confirmation(
            component=LOG4J.purl,
            cve_id="CVE-2021-44228",
            rationale="The gateway logs untrusted headers at INFO.",
            source="dispositions.toml",
        ),
    )


def _mixed():
    """One of each bucket: REPORT, ASSESS, and something the catalogue misses."""
    vulns = [
        _vuln("GHSA-jfh8", "CVE-2021-44228", "log4j-core", score=10.0),
        _vuln("GHSA-36p3", "CVE-2022-22965", "spring-beans", score=9.8),
        _vuln("GHSA-quiet", "CVE-2020-0001", "spring-beans"),
    ]
    return _run(
        vulns,
        listed=("CVE-2021-44228", "CVE-2022-22965"),
        confirmations=_confirmed(),
    )


# --- what the table contains ----------------------------------------------


def test_report_rows_come_before_assess_rows():
    """The same precedence as the exit code. A reader who takes the first row
    of a screenshot has to take the worst one."""
    result = _mixed()
    assert [row.bucket for row in rows(result)] == [REPORT, ASSESS]
    assert rows(result)[0].cve == "CVE-2021-44228"


def test_a_row_carries_where_the_component_sits():
    result = _mixed()
    assert rows(result)[0].component == "log4j-core@2.14.1"
    assert rows(result)[0].dependency == "D"
    assert rows(result)[1].dependency == "T"


def test_nothing_from_the_no_bucket_is_ever_a_row():
    """One summary line, never row by row. The asymmetry is the product, and a
    few hundred rows destroy it."""
    result = _mixed()
    assert len(result.no) == 1
    assert all(row.bucket != "NO" for row in rows(result))
    assert summary_row(result) == "+ 1 item(s) not in the KEV catalogue"


def test_an_empty_no_bucket_gets_no_summary_line():
    result = _run(
        [_vuln("GHSA-jfh8", "CVE-2021-44228", "log4j-core")],
        listed=("CVE-2021-44228",),
    )
    assert summary_row(result) is None


def test_the_catalogue_is_named_rather_than_art14():
    """Never the tool's own word for it. The authority is the point."""
    result = _mixed()
    assert _listed_by(result.report[0]) == "CISA, EU"
    assert _listed_by(result.no[0]) == "-"


def test_both_spellings_of_the_eu_tag_read_as_eu():
    """The dump writes `eukev_kev`; the API documentation writes `eu_kev`.

    Every fixture in this suite once used the documented spelling, so the
    suite agreed with the documentation while the live catalogue tagged all
    of its EU-listed records the other way and they printed as the raw field
    name in the column that exists to name the authority.
    """
    result = _mixed()
    item = result.report[0]
    for sources, expected in (
        (("eu_kev",), "EU"),
        (("eukev_kev",), "EU"),
        (("cisa_kev", "eukev_kev"), "CISA, EU"),
        # Both spellings on one record still name the authority once.
        (("eu_kev", "eukev_kev"), "EU"),
    ):
        entry = replace(item.entry, sources=sources)
        assert _listed_by(replace(item, entry=entry)) == expected


def test_an_unknown_catalogue_tag_reaches_the_reader():
    """A spelling we have not met prints as sent rather than disappearing.

    The column would otherwise be silent about a source the catalogue named,
    which is the failure mode this tool exists to refuse.
    """
    item = _mixed().report[0]
    entry = replace(item.entry, sources=("cisa_kev", "some_new_list"))
    assert _listed_by(replace(item, entry=entry)) == "CISA, some_new_list"


def test_the_table_never_carries_a_severity_column(capsys):
    """The bucket is the verdict.

    A severity word beside it invites the reader to treat the two as views of
    the same thing, which is the reflex this tool exists to break -- and the
    column cost the component its width, which truncated the one direct
    dependency in the ASSESS block. Severity is in --brief and --json, where
    a reader has already stopped skimming.
    """
    result = _mixed()
    for width in (MIN_WIDTH, 80, TARGET_WIDTH, MAX_WIDTH):
        print_table(result, width=width)
        out = capsys.readouterr().out
        assert "severity" not in out
        assert "critical" not in out
        assert "10.0" not in out
        assert "CVE-2021-44228" in out


def test_no_row_ends_in_padding(capsys):
    """The last column is right-justified so that it does not.

    A caption was rejected for this: rich pads a left-justified cell out to
    the column width, and once severity was gone "CISA" under a nine-
    character heading left five trailing spaces on every row. They survive a
    copy-paste into an email and a README code block.
    """
    result = _mixed()
    for width in (MIN_WIDTH, 80, TARGET_WIDTH):
        print_table(result, width=width)
        out = capsys.readouterr().out
        assert out.strip()
        for line in out.splitlines():
            assert line == line.rstrip(), repr(line)


# --- the headline ---------------------------------------------------------


def test_the_result_line_says_all_three_numbers_in_plain_text():
    """Colour does not survive a screenshot on a light README or a paste into
    an email, and those are the two places this output is actually read."""
    assert result_line(_mixed()) == "result: 1 to report - 1 to assess - 1 not in the KEV catalogue"


def test_the_result_line_is_nothing_without_a_result():
    assert result_line(None) is None


# --- the D/T key ----------------------------------------------------------


def test_the_key_glosses_only_the_letters_in_the_table():
    key = dependency_key(_mixed())
    assert key == "D = direct dependency, T = transitive (pulled in by another component)"
    assert "R =" not in key and "? =" not in key


def test_the_key_fits_on_one_line_at_eighty_columns():
    """The constraint it exists under: it explains the table, so it may not
    wrap into the prose under the table."""
    assert len(dependency_key(_mixed(), 80)) <= 80


def test_a_table_with_every_kind_shortens_rather_than_wraps():
    components = (LOG4J, SPRING, ROOT_COMPONENT, Component(bom_ref="orphan", name="orphan", version="1.0"))
    locations = dict(LOCATIONS)
    locations["app"] = Location(kind=ROOT, depth=0, chain=("app",))
    locations["orphan"] = Location(kind="unknown", depth=0, chain=())
    vulns = [
        _vuln("GHSA-1", "CVE-2021-44228", "log4j-core"),
        _vuln("GHSA-2", "CVE-2022-22965", "spring-beans"),
        _vuln("GHSA-3", "CVE-2023-0001", "app"),
        _vuln("GHSA-4", "CVE-2023-0002", "orphan"),
    ]
    result = _run(
        vulns,
        listed=("CVE-2021-44228", "CVE-2022-22965", "CVE-2023-0001", "CVE-2023-0002"),
        sbom=_sbom(vulns, components=components, locations=locations),
    )
    key = dependency_key(result, 80)
    assert len(key) <= 80
    assert key.startswith("R = the product,")
    assert "T = transitive" in key


def test_there_is_no_key_when_there_is_no_table():
    result = _run(
        [_vuln("GHSA-quiet", "CVE-2020-0001", "spring-beans")],
        listed=(),
    )
    assert dependency_key(result) is None


# --- what the crop of the table alone carries -----------------------------


def test_the_key_and_the_summary_travel_with_the_table():
    """The whole reason both lines sit under the table rather than in the
    closing prose: someone screenshots the table without the header."""
    console = Console(file=_Sink(), width=100, record=True, highlight=False)
    print_table(_mixed(), console=console, width=100)
    printed = console.export_text()
    lines = [line for line in printed.splitlines() if line.strip()]
    assert lines[-1].rstrip() == "+ 1 item(s) not in the KEV catalogue"
    assert lines[-2].startswith("D = direct dependency")
    assert "CVE-2021-44228" in printed and "REPORT" in printed


def test_nothing_is_printed_when_nothing_needs_a_decision():
    """A table whose only row is the NO summary is a table about the absence
    of work, and the counts above already said that in a line."""
    result = _run([_vuln("GHSA-quiet", "CVE-2020-0001", "spring-beans")])
    console = Console(file=_Sink(), width=100, record=True, highlight=False)
    print_table(result, console=console, width=100)
    assert console.export_text().strip() == ""


class _Sink:
    """A file rich can write to and encode against, holding nothing."""

    encoding = "utf-8"

    def write(self, text):  # pragma: no cover - rich calls it, nothing reads it
        return len(text)

    def flush(self):  # pragma: no cover - same
        pass


# --- width and encoding ---------------------------------------------------


def test_a_narrow_terminal_is_never_required_to_be_wider():
    assert render_width(40) == MIN_WIDTH
    assert render_width(80) == 80
    assert render_width(TARGET_WIDTH) == TARGET_WIDTH


def test_a_very_wide_terminal_is_not_filled():
    """A table spanning 200 columns puts the CVE and its bucket at opposite
    ends of the screen, and the screenshot it becomes is read on a phone."""
    assert render_width(200) == MAX_WIDTH


def test_a_stream_that_cannot_encode_the_rule_gets_ascii():
    """`art14 sbom.json > report.txt` on a Windows console writes cp1252, and
    a box character there is an exception rather than a smudge."""
    assert _box_for("cp1252") is box.ASCII
    assert _box_for("utf-8") is box.SIMPLE
    assert _box_for(None) is box.SIMPLE
