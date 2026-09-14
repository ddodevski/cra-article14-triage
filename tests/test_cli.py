"""CLI scaffold tests: argument surface and exit codes.

Exit codes are part of the output contract, so they are pinned from the start
rather than retrofitted once triage lands. The rule under test throughout:
exit 0 asserts "nothing in REPORT", so it is only ever emitted by a run that
can stand behind that sentence.
"""

from __future__ import annotations

import io
import json
import re
import sys
from pathlib import Path

import httpx
import pytest

from art14.cli import EXIT_ERROR, EXIT_OK, EXIT_REPORT, _exit_code, main
from art14.kev import CatalogueUnavailable

from art14.quality import DEGRADED, UNUSABLE, as_json, warnings
from tests.conftest import IRRELEVANT_KEV_DUMP, osv_handler, record

FIXTURE = Path(__file__).parent / "fixtures" / "graph.cdx.json"


def _flat(text):
    """Output is wrapped to 76 columns, so a phrase can straddle a newline."""
    return " ".join(text.split())


def _write(tmp_path, document, name="input.cdx.json"):
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return str(path)


@pytest.fixture
def document():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_reads_an_sbom_and_names_the_product(capsys, kev_state):
    # Nothing listed, so nothing is open and the run may certify. The same
    # fixture against the default catalogue exits 1 -- see the ASSESS tests.
    kev_state["dump"] = list(IRRELEVANT_KEV_DUMP)
    assert main([str(FIXTURE)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "demo-app@1.0.0" in out
    assert "CycloneDX 1.6" in out


def test_unreadable_sbom_exits_one(tmp_path, capsys):
    assert main([str(tmp_path / "absent.cdx.json")]) == EXIT_ERROR
    captured = capsys.readouterr()
    assert "art14:" in captured.err
    # Nothing parseable on stdout: this is what tells a CI consumer a crash
    # apart from a gated run, which exits 1 *and* emits JSON.
    assert captured.out == ""


def test_json_output_is_machine_readable(capsys, kev_state):
    kev_state["dump"] = list(IRRELEVANT_KEV_DUMP)
    assert main(["--json", str(FIXTURE)]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["specVersion"] == "1.6"
    assert payload["counts"]["findings"] == 5
    assert payload["unresolvedAffects"] == [{"id": "CVE-2026-0003", "ref": "ghost"}]
    assert payload["excludedAffects"] == [{"id": "CVE-2026-0005", "ref": "d"}]
    assert payload["input"]["informed"] is True
    assert payload["input"]["informedBy"] == "pre-enriched"


def test_reads_stdin_with_a_dash(capsys, monkeypatch, kev_state):
    kev_state["dump"] = list(IRRELEVANT_KEV_DUMP)
    monkeypatch.setattr(
        sys, "stdin", io.StringIO(FIXTURE.read_text(encoding="utf-8"))
    )
    assert main(["-"]) == EXIT_OK
    assert "demo-app@1.0.0" in capsys.readouterr().out


def test_brief_flag_is_accepted(capsys, kev_state):
    kev_state["dump"] = list(IRRELEVANT_KEV_DUMP)
    assert main(["--brief", str(FIXTURE)]) == EXIT_OK


def test_missing_argument_is_a_usage_error():
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2


def test_output_carries_no_emoji(capsys):
    """Box-drawing characters are the one exception, and they are furniture
    rather than decoration: the table rule is drawn with them, and `table`
    falls back to ASCII on a stream that cannot carry them."""
    main([str(FIXTURE)])
    out = capsys.readouterr().out
    assert all(ord(char) < 0x2190 or 0x2500 <= ord(char) <= 0x257F for char in out)


# --- the banner -----------------------------------------------------------


def test_banner_precedes_any_result(capsys):
    main([str(FIXTURE)])
    out = capsys.readouterr().out
    assert "input: 6 components - 0 without PURL (0%) - 0 without version" in out
    assert "SBOM quality: ok" in out
    assert out.index("input: 6 components") < out.index("vulnerabilities")


def test_banner_counts_appear_in_json_too(capsys):
    main(["--json", str(FIXTURE)])
    block = json.loads(capsys.readouterr().out)["input"]
    assert block["components"] == 6
    assert block["withoutPurl"] == 0
    assert block["withoutVersion"] == 0
    assert block["quality"] == "ok"


def _answered(document, *, cve="CVE-2019-7000"):
    """OSV with one real answer in it, on the first component's PURL.

    A run whose every lookup came back empty no longer certifies -- silence
    from the source is not a negative answer -- so a test about anything else
    has to give the source something to say. The CVE is deliberately not in
    the catalogue fixture, so the finding lands in NO and the run can exit 0.
    """
    purl = document["components"][0]["purl"]
    vuln_id = "OSV-ANSWERED-1"
    return osv_handler(
        {purl: [{"id": vuln_id, "modified": "2026-01-01T00:00:00Z"}]},
        {
            vuln_id: record(
                vuln_id, aliases=[cve], affected=[{"package": {"purl": purl}}]
            )
        },
    )


# --- the three axes -------------------------------------------------------
#
# informed  did we look at all
# quality   could we have found anything if we did
# coverage  did the source answer on what we asked


def test_a_matched_sbom_with_answers_and_no_hits_exits_zero(
    capsys, tmp_path, document, osv_responses
):
    """We looked, coverage was good, the source answered, nothing was listed.
    That certifies."""
    osv_responses(_answered(document))
    document.pop("vulnerabilities")
    assert main([_write(tmp_path, document)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "matched against OSV.dev" in out
    assert "source coverage" not in out


def test_a_run_the_source_answered_nothing_on_cannot_certify(
    capsys, tmp_path, document, osv_responses
):
    """The false clean bill of health this rule exists for.

    Measured on `syft alpine:3.10 -o cyclonedx-json | art14 -`: fourteen well
    formed apk PURLs, every lookup completed, no records returned, an empty
    result and exit 0 on an image another scanner finds 125 vulnerabilities
    in. Identifier coverage was fine, so the quality grade said nothing. A
    source that holds nothing for an ecosystem and an ecosystem with nothing
    to report are indistinguishable from here, and only one of them certifies.
    """
    osv_responses(osv_handler({}, {}))
    document.pop("vulnerabilities")
    assert main([_write(tmp_path, document)]) == EXIT_ERROR
    out = _flat(capsys.readouterr().out)
    assert "source coverage: none" in out
    assert "not a defect in the SBOM" in out
    assert "will not certify" in out
    # Not blamed on the SBOM: every identifier in it is usable.
    assert "not fit for Article 14 purposes" not in out


def test_one_silent_ecosystem_is_named_even_when_others_answered(
    capsys, tmp_path, document, osv_responses
):
    """The blind spot a total would hide. Zero for one PURL type while another
    answered is the same failure over a smaller part of the product, and the
    run still exits 0 -- the fact reaches the reader either way."""
    document["components"][1]["purl"] = "pkg:apk/alpine/busybox@1.30.1-r5"
    document["components"][1]["version"] = "1.30.1-r5"
    osv_responses(_answered(document))
    document.pop("vulnerabilities")
    assert main([_write(tmp_path, document)]) == EXIT_OK
    out = _flat(capsys.readouterr().out)
    assert "source coverage: partial - nothing came back for pkg:apk/alpine" in out
    assert "pkg:apk/alpine 1 queried, 0 answered" in out
    assert "Treat that part of the product as unassessed" in out


def test_the_coverage_axis_is_in_the_json_with_its_rates(
    capsys, tmp_path, document, osv_responses
):
    osv_responses(osv_handler({}, {}))
    document.pop("vulnerabilities")
    main(["--json", _write(tmp_path, document)])
    payload = json.loads(capsys.readouterr().out)
    assert payload["input"]["sourceCoverage"] == "none"
    assert payload["input"]["canRuleOut"] is False
    # The identifier axis is untouched: nothing was wrong with the SBOM.
    assert payload["input"]["quality"] == "ok"
    matching = payload["matching"]
    assert matching["withRecords"] == 0
    assert matching["coverage"]["level"] == "none"
    assert matching["coverage"]["ecosystems"] == [
        {"purlType": "pkg:maven/example", "queried": 6, "withRecords": 0}
    ]


def test_an_untested_spec_version_cannot_certify(
    capsys, tmp_path, document, osv_responses
):
    """The same run that exits 0 on 1.7 exits 1 on 1.9. Reading a version this
    build has never been checked against is the one place the tool guesses;
    exit 0 is the one code that makes a claim. It does not get to do both."""
    osv_responses(osv_handler({}, {}))
    document.pop("vulnerabilities")
    document["specVersion"] = "1.9"
    assert main([_write(tmp_path, document)]) == EXIT_ERROR
    assert "newer than anything this build" in capsys.readouterr().out


def test_a_tested_spec_version_still_certifies(
    capsys, tmp_path, document, osv_responses
):
    osv_responses(_answered(document))
    document.pop("vulnerabilities")
    document["specVersion"] = "1.7"
    assert main([_write(tmp_path, document)]) == EXIT_OK


def test_matching_is_visible_in_json(capsys, tmp_path, document, osv_responses):
    osv_responses(osv_handler({}, {}))
    document.pop("vulnerabilities")
    main(["--json", _write(tmp_path, document)])
    payload = json.loads(capsys.readouterr().out)
    assert payload["input"]["informed"] is True
    assert payload["input"]["informedBy"] == "osv"
    assert payload["matching"]["source"] == "osv"
    assert payload["matching"]["queried"] == 6
    assert payload["matching"]["failed"] == 0


def test_a_pre_enriched_sbom_is_not_re_queried(capsys, document, osv_responses):
    """Section 3: the SBOM brought its own answers, so layer 1 is skipped."""
    calls = []
    osv_responses(osv_handler({}, {}, calls=calls))
    main(["--json", str(FIXTURE)])
    payload = json.loads(capsys.readouterr().out)
    assert payload["input"]["informedBy"] == "pre-enriched"
    assert payload["matching"]["source"] is None
    assert calls == []


def test_nothing_sendable_prints_no_result_table(capsys, tmp_path, document, osv_responses):
    """Matching ran and had nothing it could ask about."""
    osv_responses(osv_handler({}, {}))
    document.pop("vulnerabilities")
    for entry in document["components"]:
        entry.pop("purl", None)
        entry.pop("version", None)
    assert main([_write(tmp_path, document)]) == EXIT_ERROR
    out = _flat(capsys.readouterr().out)
    assert "no result table is printed" in out.lower()
    assert "not fit for Article 14 purposes" in out
    # The exact inverse of what the informed+unusable test asserts is
    # present: the table header, not a phrase that also occurs in prose.
    assert "component-CVE pairs" not in out


def test_a_gated_run_still_emits_json_on_stdout(capsys, tmp_path, document, osv_responses):
    """Exit 1 plus valid JSON is a bad SBOM; exit 1 plus silence is a crash."""
    osv_responses(osv_handler({}, {}))
    document.pop("vulnerabilities")
    for entry in document["components"]:
        entry.pop("purl", None)
        entry.pop("version", None)
    assert main(["--json", _write(tmp_path, document)]) == EXIT_ERROR

    payload = json.loads(capsys.readouterr().out)
    block = payload["input"]
    assert block["quality"] == "unusable"
    assert block["gated"] is True
    # Same shape as any other run, so a consumer never branches before
    # it can read input.quality.
    assert payload["counts"]["components"] == 6
    assert payload["findings"] == []
    # Identically shaped on every run, like `kev` and `provenance`. `available`
    # false is not "nothing was reportable": nothing was asked.
    assert payload["triage"]["available"] is True
    assert payload["triage"]["counts"] == {
        "report": 0,
        "assess": 0,
        "no": 0,
        "unassessed": 0,
        "ruledOut": 0,
        "suppressed": 0,
    }


def test_json_lists_the_unmatchable_components(capsys, tmp_path, document):
    document["components"][0].pop("purl")
    # A bare PURL and no version field: nothing gives OSV a version to query.
    document["components"][1].pop("version")
    document["components"][1]["purl"] = "pkg:maven/demo/bravo"
    main(["--json", _write(tmp_path, document)])
    listed = json.loads(capsys.readouterr().out)["input"]["unmatchableComponents"]
    assert {entry["reason"] for entry in listed} == {"no PURL", "no version"}
    assert {entry["name"] for entry in listed} == {"alpha", "bravo"}


def test_a_document_of_nothing_but_files_cannot_exit_zero(
    capsys, tmp_path, document
):
    """`syft` lists the files it walked beside the packages. A document that
    is nothing but those is an input we cannot assess -- not a product with
    nothing to report -- so it may not produce the one exit code that makes a
    negative claim."""
    document["components"] = [
        {"bom-ref": f"f{i}", "name": f"/usr/bin/f{i}", "type": "file"}
        for i in range(6)
    ]
    document["dependencies"] = []
    document.pop("vulnerabilities")
    assert main([_write(tmp_path, document)]) == EXIT_ERROR
    out = capsys.readouterr().out
    assert "input: no package components in 6 entries" in out
    assert "All 6 entries" in out
    assert "cannot be assessed, not a clean one" in out
    # The empty-document wording would be false here: the file had six.
    assert "lists no components at all" not in out


def test_the_funnel_says_what_the_type_rule_set_aside(capsys, tmp_path, document):
    """Point 2 of the report: the denominator is wrong everywhere if it is
    wrong anywhere. The funnel counts the graded inventory and names the
    difference rather than quietly counting one and printing the other."""
    document["components"] = document["components"] + [
        {"bom-ref": f"f{i}", "name": f"/usr/bin/f{i}", "type": "file"}
        for i in range(4)
    ]
    main([_write(tmp_path, document)])
    out = capsys.readouterr().out
    graded = int(re.search(r"input: (\d+) package components", out).group(1))
    listed, aside = re.search(
        r"\(of (\d+) in the SBOM; (\d+) are not packages\)", out
    ).groups()
    assert int(listed) - int(aside) == graded
    assert int(aside) == 4
    assert f"{graded} entries in the document" not in out


def test_the_json_carries_both_numbers(capsys, tmp_path, document):
    document["components"] = document["components"] + [
        {"bom-ref": "f1", "name": "/bin/sh", "type": "file"}
    ]
    main(["--json", _write(tmp_path, document)])
    block = json.loads(capsys.readouterr().out)
    payload = block["input"]
    assert payload["documentComponents"] == payload["components"] + 1
    assert payload["nonPackageComponents"] == 1
    assert payload["nonPackageTypes"] == ["file"]
    assert block["counts"]["components"] == payload["components"]
    assert block["counts"]["documentComponents"] == payload["documentComponents"]


def test_an_sbom_with_no_components_reads_as_empty_not_as_a_majority(
    capsys, tmp_path, document
):
    """0 of 0 unmatchable is not a ratio, and must not be phrased as one."""
    document["components"] = []
    document["dependencies"] = []
    document.pop("vulnerabilities")
    assert main([_write(tmp_path, document)]) == EXIT_ERROR
    out = capsys.readouterr().out
    assert "input: no components" in out
    assert "lists no components at all" in out
    assert "not fit for Article 14 purposes" in out
    assert "0 of 0" not in out
    assert "(0%)" not in out
    assert "More than half" not in out


def test_the_exit_basis_is_readable_without_re_deriving_it(capsys, tmp_path, document):
    """A consumer explains a non-zero exit from the block, not from the rule.

    Pre-enriched and unusable: the table is not withheld -- the findings came
    from a tool that had more context than we do -- but the coverage behind
    them cannot support "nothing else to report".
    """
    for entry in document["components"]:
        entry.pop("purl", None)
        entry.pop("version", None)
    assert main(["--json", _write(tmp_path, document)]) == EXIT_ERROR
    block = json.loads(capsys.readouterr().out)["input"]
    assert block["gated"] is False
    assert block["canRuleOut"] is False
    assert block["quality"] == "unusable"


def test_a_clean_informed_run_certifies(capsys, kev_state):
    kev_state["dump"] = list(IRRELEVANT_KEV_DUMP)
    assert main(["--json", str(FIXTURE)]) == EXIT_OK
    assert json.loads(capsys.readouterr().out)["input"]["canRuleOut"] is True


# --- exit code precedence --------------------------------------------------
#
# A REPORT item wins over every input complaint. Poor coverage undermines
# negative claims, not positive ones -- and exit 1 would be read by a gating
# pipeline as infrastructure flake, retried or ignored, missing the trigger.
#
# These exercise `_exit_code` and the gate predicates directly, on hand-built
# quality states the fixtures cannot produce. The end-to-end counterparts --
# a real REPORT item out of a real config, and a real ASSESS item out of the
# catalogue -- are at the bottom of this file.


def _quality(document, **kwargs):
    from art14.cyclonedx import parse_document
    from art14.quality import assess

    return assess(parse_document(document), **kwargs)


def _strip_matching_data(document, count=None):
    for entry in document["components"][:count]:
        entry.pop("purl", None)
        entry.pop("version", None)
    return document


def test_report_beats_unusable(document):
    quality = _quality(_strip_matching_data(document), matching_performed=True)
    assert quality.level == UNUSABLE
    assert quality.can_certify_nothing_to_report is False
    assert _exit_code(quality, report_items=1, assess_items=0) == EXIT_REPORT


def test_report_beats_not_informed(document):
    document.pop("vulnerabilities")
    quality = _quality(document)
    assert quality.informed is False
    assert _exit_code(quality, report_items=1, assess_items=0) == EXIT_REPORT


def test_report_beats_degraded(document):
    quality = _quality(_strip_matching_data(document, 2), matching_performed=True)
    assert quality.level == DEGRADED
    # Degraded certifies on its own; the point is that the REPORT item is what
    # decides, so this must not come back 0 either.
    assert _exit_code(quality, report_items=1, assess_items=0) == EXIT_REPORT


def test_without_a_report_item_the_gate_still_decides(document):
    quality = _quality(_strip_matching_data(document), matching_performed=True)
    assert _exit_code(quality, report_items=0, assess_items=0) == EXIT_ERROR


def test_a_report_item_is_never_withheld_by_the_gate(document):
    """The same precedence, applied to the table rather than the exit code."""
    document.pop("vulnerabilities")
    quality = _quality(_strip_matching_data(document), matching_performed=True)
    assert quality.blocks is True
    assert quality.withholds_table(report_items=0, assess_items=0) is True
    assert quality.withholds_table(report_items=1, assess_items=0) is False


def test_the_loud_warning_survives_a_report_item(document):
    """Both halves get said: reportable finding, and separately, poor coverage."""
    document.pop("vulnerabilities")
    quality = _quality(_strip_matching_data(document), matching_performed=True)
    paragraphs = " ".join(warnings(quality, report_items=1, assess_items=0))
    assert "WARNING" in paragraphs
    assert "not fit for Article 14 purposes" in paragraphs
    assert "stand on their own" in paragraphs
    assert "does not rule out" in paragraphs or "rules out" in paragraphs
    # The gate no longer suppresses the table, so it must not claim it did.
    assert "no result table is printed" not in paragraphs.lower()


def test_a_withheld_table_is_not_described_as_printed(document):
    """informed + unusable + nothing positive: the table really is withheld."""
    document.pop("vulnerabilities")
    quality = _quality(_strip_matching_data(document), matching_performed=True)
    paragraphs = " ".join(warnings(quality, report_items=0, assess_items=0))
    assert "no result table is printed" in paragraphs.lower()
    # Nothing is shown, so nothing may be referred to as being below.
    assert "below" not in paragraphs


def test_json_says_the_table_was_not_withheld_when_a_report_item_forced_it(document):
    document.pop("vulnerabilities")
    quality = _quality(_strip_matching_data(document), matching_performed=True)
    assert as_json(quality, report_items=0, assess_items=0)["gated"] is True
    block = as_json(quality, report_items=1, assess_items=0)
    assert block["gated"] is False
    # Still not a clean bill of health: the negative claim remains ungranted.
    assert block["canRuleOut"] is False
    assert block["quality"] == "unusable"


# --- matching failures reach the banner -----------------------------------


def test_offline_with_a_cold_cache_is_unusable_not_clean(capsys, tmp_path, document):
    """The recurring CI state after step 4, and the most dangerous one.

    The SBOM is perfect. Nothing was assessed. An empty result here must not
    read as an empty result there, and it must not exit 0.
    """
    document.pop("vulnerabilities")
    assert main(["--offline", _write(tmp_path, document)]) == EXIT_ERROR
    out = _flat(capsys.readouterr().out)
    assert "matching quality: unusable" in out
    assert "0 without PURL (0%)" in out
    # The cause named is the real one.
    assert "lookup did not complete" in out
    assert "no PURL or no version" not in out


def test_offline_failures_are_counted_in_json(capsys, tmp_path, document):
    document.pop("vulnerabilities")
    main(["--json", "--offline", _write(tmp_path, document)])
    payload = json.loads(capsys.readouterr().out)
    assert payload["matching"]["failed"] == 6
    assert payload["matching"]["queried"] == 0
    assert payload["input"]["queryFailures"] == 6
    assert payload["input"]["canRuleOut"] is False
    reasons = {e["reason"] for e in payload["input"]["unmatchableComponents"]}
    assert reasons == {"lookup did not complete"}


def test_a_partial_network_failure_does_not_read_as_a_short_clean_result(
    capsys, tmp_path, document, osv_responses
):
    """Half the inventory answered, half errored. Degraded, not done."""
    answered = {"pkg:maven/demo/alpha@1.0.0": []}

    def handle(request):
        if request.url.path == "/v1/querybatch":
            queries = json.loads(request.content)["queries"]
            purls = [q.get("package", {}).get("purl", "") for q in queries]
            if any(p not in answered for p in purls):
                return httpx.Response(503, json={"message": "try later"})
            return httpx.Response(200, json={"results": [{"vulns": []}] * len(purls)})
        return httpx.Response(404, json={})

    osv_responses(handle)
    document.pop("vulnerabilities")
    assert main([_write(tmp_path, document)]) == EXIT_ERROR
    out = _flat(capsys.readouterr().out)
    assert "matching quality: unusable" in out
    assert "lookup did not complete" in out


# --- provenance -----------------------------------------------------------


def test_every_json_run_carries_a_provenance_block(capsys, tmp_path, document, osv_responses):
    osv_responses(osv_handler({}, {}))
    document.pop("vulnerabilities")
    main(["--json", _write(tmp_path, document)])
    block = json.loads(capsys.readouterr().out)["provenance"]
    assert block["mode"] == "online"
    assert block["osv"]["fetchedAt"] is not None
    # Both sources are stamped, never just the one. A catalogue consulted on
    # this run has to be able to say so, or a later run producing a different
    # verdict cannot be shown to be a change in the catalogue.
    assert block["osv"]["source"] == "osv"
    assert block["kev"]["source"] == "euvd-kev"
    assert block["kev"]["fetchedAt"] is not None
    assert block["kevStale"] is False
    assert block["generatedAt"].endswith("Z")



def test_a_pre_enriched_run_is_stamped_as_such(capsys, tmp_path, document):
    """The SBOM brought its own answers, so art14 reached no upstream at all.

    A consumer must be able to tell that apart from a run where we looked.
    """
    main(["--json", _write(tmp_path, document)])
    block = json.loads(capsys.readouterr().out)["provenance"]
    assert block["mode"] == "pre-enriched"
    assert block["osv"] is None


def test_a_cache_served_run_is_distinguishable_from_a_live_one(
    capsys, tmp_path, document, osv_responses
):
    """The requirement, end to end: two runs of the same SBOM, different stamps."""
    osv_responses(osv_handler({}, {}))
    document.pop("vulnerabilities")
    path = _write(tmp_path, document)

    main(["--json", path])
    live = json.loads(capsys.readouterr().out)["provenance"]
    main(["--json", path])
    cached = json.loads(capsys.readouterr().out)["provenance"]

    assert live["mode"] == "online"
    assert cached["mode"] == "cache-served"
    assert live["osv"]["fetchedAt"] is not None
    assert cached["osv"]["fetchedAt"] is None
    assert cached["osv"]["cacheHit"] is True


def test_a_gated_run_is_still_stamped(capsys, tmp_path, document, osv_responses):
    """No table, but the run still has to say when it looked and at what."""
    osv_responses(osv_handler({}, {}))
    document.pop("vulnerabilities")
    for component in document["components"]:
        component.pop("purl", None)
    main(["--json", _write(tmp_path, document)])
    payload = json.loads(capsys.readouterr().out)
    assert payload["provenance"]["mode"] in {"online", "cache-served"}
    assert payload["provenance"]["generatedAt"] is not None


def test_each_finding_keeps_upstreams_own_modified_stamp(
    capsys, tmp_path, document, osv_responses
):
    """The run-level block says when we asked; this says how current the
    particular record was when upstream last touched it."""
    purl = document["components"][0]["purl"]
    batch = {purl: [{"id": "GHSA-stamp", "modified": "2026-09-01T00:00:00Z"}]}
    records = {"GHSA-stamp": record("GHSA-stamp", modified="2026-09-01T00:00:00.123Z")}
    osv_responses(osv_handler(batch, records))
    document.pop("vulnerabilities")
    main(["--json", _write(tmp_path, document)])
    findings = json.loads(capsys.readouterr().out)["findings"]
    assert findings
    # The record's own value, not the truncated one querybatch reported.
    assert findings[0]["modified"] == "2026-09-01T00:00:00.123Z"


def test_brief_prints_the_provenance_block(capsys, tmp_path, document, osv_responses):
    osv_responses(_answered(document))
    document.pop("vulnerabilities")
    assert main(["--brief", _write(tmp_path, document)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "provenance" in out
    assert "OSV" in out
    assert "EUVD KEV" in out


def test_the_default_run_is_not_cluttered_with_provenance(
    capsys, tmp_path, document, osv_responses
):
    """It is evidence, not a headline. --brief and --json carry it."""
    osv_responses(osv_handler({}, {}))
    document.pop("vulnerabilities")
    main([_write(tmp_path, document)])
    assert "provenance" not in capsys.readouterr().out


# --- layer 2: the catalogue -----------------------------------------------
#
# Three failure modes, none of which raises on its own: a join on the wrong
# key, a vulnerability that was never checkable being counted as absent, and
# an unreachable catalogue being read as an empty one.

LOG4J_FIXTURE = Path(__file__).parent / "fixtures" / "log4j.cdx.json"
LOG4SHELL_GHSA = "GHSA-jfh8-c2jp-5v3q"
LOG4SHELL_CVE = "CVE-2021-44228"
LOG4J_PURL = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"


def _log4j_osv():
    """OSV's answer for log4j-core 2.14.1: a GHSA whose only CVE is an alias."""
    purl = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    batch = {purl: [{"id": LOG4SHELL_GHSA, "modified": "2026-01-01T00:00:00Z"}]}
    records = {
        LOG4SHELL_GHSA: record(
            LOG4SHELL_GHSA,
            aliases=[LOG4SHELL_CVE],
            affected=[{"package": {"purl": purl}}],
        )
    }
    return osv_handler(batch, records)


def test_the_log4j_demo_resolves_the_ghsa_to_a_cve_and_hits_the_catalogue(
    capsys, osv_responses
):
    """End to end, on the example the whole tool is built to demonstrate.

    OSV identifies Log4Shell as GHSA-jfh8-c2jp-5v3q; the catalogue keys on
    CVE-2021-44228. Joining on the OSV id matches nothing, raises nothing, and
    produces a run that looks perfectly plausible -- which is why this asserts
    the hit rather than the absence of an error.
    """
    osv_responses(_log4j_osv())
    main(["--json", str(LOG4J_FIXTURE)])
    payload = json.loads(capsys.readouterr().out)["kev"]

    assert payload["available"] is True
    assert payload["listed"] == 1
    exposure = payload["exposures"][0]
    assert exposure["cve"] == LOG4SHELL_CVE
    assert exposure["listed"] is True
    # The trail back: the user can follow the CVE to the record it came from.
    assert exposure["osvIds"] == [LOG4SHELL_GHSA]
    # bom-refs, under a key that says so. `component` elsewhere in this
    # document is a human-readable name@version, and the two must not collide.
    assert exposure["bomRefs"] == ["log4j-core"]
    assert "components" not in exposure
    assert exposure["kev"]["sources"] == ["cisa_kev", "eu_kev"]
    assert payload["uncheckable"] == 0


def test_a_vulnerability_with_no_cve_is_counted_not_buried(
    capsys, tmp_path, document
):
    """Never checkable is not the same as checked and absent."""
    document["vulnerabilities"] = [
        {"bom-ref": "v1", "id": "GHSA-nocve-1", "affects": [{"ref": "b"}]}
    ]
    assert main(["--json", _write(tmp_path, document)]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)["kev"]

    assert payload["uncheckable"] == 1
    assert payload["uncheckableVulnerabilities"][0]["id"] == "GHSA-nocve-1"
    # The distinction the count exists for.
    assert payload["absent"] == 0
    assert payload["checked"] == 0


def test_the_uncheckable_count_is_surfaced_in_the_banner(capsys, tmp_path, document):
    document["vulnerabilities"] = [
        {"bom-ref": "v1", "id": "GHSA-nocve-1", "affects": [{"ref": "b"}]}
    ]
    main([_write(tmp_path, document)])
    out = _flat(capsys.readouterr().out)

    assert "1 vulnerability with no CVE id" in out
    assert "not checkable against the KEV catalogue" in out
    # And said plainly, so it cannot be read as a clean result -- in the
    # number the run actually found, which here is one.
    assert "It is not absent from the catalogue" in out


def test_an_unavailable_catalogue_fails_closed(capsys, kev_state):
    """Absence of a signal is not absence of the thing.

    The catalogue is what decides whether anything is reportable. Without it
    the run has judged nothing, so it cannot say "nothing to report" -- and
    saying it anyway is the one failure this tool exists to prevent.
    """
    kev_state["error"] = CatalogueUnavailable("the catalogue could not be fetched")
    assert main(["--json", str(FIXTURE)]) == EXIT_ERROR

    captured = capsys.readouterr()
    # A gated run, not a crash: the full document is still on stdout, which is
    # what tells a CI consumer the two apart (section 6).
    payload = json.loads(captured.out)
    assert payload["input"]["informed"] is False
    assert payload["input"]["catalogueAvailable"] is False
    assert payload["input"]["canRuleOut"] is False
    assert payload["kev"] == {
        "available": False,
        "checked": 0,
        "listed": 0,
        "listedPairs": 0,
        "absent": 0,
        "uncheckable": 0,
        "exposures": [],
        "uncheckableVulnerabilities": [],
    }
    assert "could not be fetched" in captured.err


def test_an_unavailable_catalogue_does_not_blame_the_sbom(capsys, kev_state):
    """A perfectly formed SBOM and an unreachable catalogue is our problem.

    The generic not-informed wording says matching never ran, which would be
    false here and would send the user to fix the wrong thing.
    """
    kev_state["error"] = CatalogueUnavailable("no catalogue")
    main([str(FIXTURE)])
    out = _flat(capsys.readouterr().out)

    assert "EUVD KEV catalogue could not be consulted" in out
    assert "absence of the signal is not absence of the thing" in out
    assert "matching has not run" not in out
    # What layer 1 did find is still shown -- it is real, it is just unjudged.
    assert "vulnerabilities" in out


def test_an_unavailable_catalogue_is_stamped_as_absent_not_stale(capsys, kev_state):
    kev_state["error"] = CatalogueUnavailable("no catalogue")
    main(["--brief", str(FIXTURE)])
    out = _flat(capsys.readouterr().out)

    assert "EUVD KEV unavailable - exploitation was not checked" in out
    # Staleness is a different claim: it presumes a catalogue.
    assert "was not refreshed on this run" not in out


def test_a_stale_catalogue_says_so_out_loud(capsys, kev_state):
    """The warning that has never fired.

    Until the KEV stamp was wired, `kev` was always None and `kev_is_stale` was
    always False, so this path existed without ever being taken. It is the one
    that matters most for a NO: a catalogue from yesterday answers "not listed"
    for everything added since, with no outward sign that it is doing so.
    """
    from art14.kev import CatalogueLoad, parse_dump
    from art14.provenance import KEV_MAX_AGE
    from tests.conftest import KEV_DUMP

    kev_state["load"] = CatalogueLoad(
        catalogue=parse_dump([dict(e) for e in KEV_DUMP]),
        # Served from cache, so no fetch timestamp -- the pair of facts that
        # makes it stale rather than current.
        fetched_at=None,
        cache_age_seconds=KEV_MAX_AGE + 60,
    )
    main([str(FIXTURE)])
    out = _flat(capsys.readouterr().out)

    assert "was not refreshed on this run" in out
    assert "an entry added since then would not appear" in out.lower()


def test_a_stale_catalogue_is_flagged_in_json(capsys, kev_state):
    """A CI consumer reads the flag, not the paragraph."""
    from art14.kev import CatalogueLoad, parse_dump
    from art14.provenance import KEV_MAX_AGE
    from tests.conftest import KEV_DUMP

    kev_state["load"] = CatalogueLoad(
        catalogue=parse_dump([dict(e) for e in KEV_DUMP]),
        cache_age_seconds=KEV_MAX_AGE + 60,
    )
    main(["--json", str(FIXTURE)])
    provenance = json.loads(capsys.readouterr().out)["provenance"]

    assert provenance["kevStale"] is True
    # Stale is not absent: the catalogue was consulted, it was just old.
    assert provenance["kev"]["fetchedAt"] is None
    assert provenance["kev"]["cacheAgeSeconds"] > KEV_MAX_AGE


def test_offline_reaches_the_catalogue_client(kev_state):
    """Pins the wiring the stub would otherwise hide.

    `_StubClient` accepts any kwargs and opens no socket, so dropping
    `offline=offline` in `_load_catalogue` would leave every test passing while
    a real `--offline` run went to the network -- the one thing that flag
    promises it will not do.
    """
    main(["--offline", str(FIXTURE)])
    assert kev_state["kwargs"] == {"offline": True}

    kev_state["kwargs"] = None
    main([str(FIXTURE)])
    assert kev_state["kwargs"] == {"offline": False}


def test_a_catalogue_hit_opens_an_assess_item_and_exits_one(capsys):
    """The tripwire from step 5, deliberately flipped.

    Before triage a KEV hit changed nothing and the run exited 0. It now opens
    an ASSESS item, and exit 0 is the one code that asserts "nothing to
    report" -- which a run with a KEV-listed CVE sitting undecided in the
    product cannot say, however good its coverage is. Section 4 resolves
    uncertainty towards reporting; this is where that costs something.

    Not REPORT: that needs an explicit confirmation and there is no config
    here. The two are pinned together on purpose, because the failure this
    guards against is a later change quietly promoting one to the other.
    """
    assert main(["--json", str(FIXTURE)]) == EXIT_ERROR
    payload = json.loads(capsys.readouterr().out)
    assert payload["kev"]["listed"] >= 1
    assert payload["triage"]["counts"]["report"] == 0
    assert payload["triage"]["counts"]["assess"] >= 1
    # Coverage is fine. The exit code is about the open item, not the input,
    # and a consumer has to be able to tell those two kinds of 1 apart.
    assert payload["input"]["canRuleOut"] is True


# --- layer 3: triage ------------------------------------------------------
#
# The end-to-end half of the precedence tests above. What these pin that the
# unit tests cannot: that the buckets reach the exit code, that a config file
# reaches the buckets, and that a config the tool could not read stops the run
# instead of quietly becoming an empty one.


def _config(tmp_path, body, name="dispositions.toml"):
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return str(path)


def _log4j_confirmation(tmp_path, *, purl=LOG4J_PURL, cve=LOG4SHELL_CVE):
    return _config(
        tmp_path,
        f'[[report]]\ncomponent = "{purl}"\ncve = "{cve}"\n'
        'rationale = "The gateway logs untrusted headers at INFO."\n',
    )


def test_a_confirmed_kev_hit_exits_two(capsys, tmp_path, osv_responses):
    """The whole chain, on the demo the tool exists for: GHSA from OSV, CVE
    from its aliases, entry from the catalogue, REPORT from the config."""
    osv_responses(_log4j_osv())
    config = _log4j_confirmation(tmp_path)
    assert main(["--json", "--config", config, str(LOG4J_FIXTURE)]) == EXIT_REPORT
    payload = json.loads(capsys.readouterr().out)
    assert payload["triage"]["counts"] == {
        "report": 1,
        "assess": 0,
        "no": 0,
        "unassessed": 0,
        "ruledOut": 0,
        "suppressed": 0,
    }
    item = payload["triage"]["items"][0]
    assert item["bucket"] == "REPORT"
    assert item["cve"] == LOG4SHELL_CVE
    assert item["rationale"].startswith("The gateway logs")
    assert item["confirmedBy"] == config


def test_a_report_item_exits_two_through_an_unusable_gate(
    capsys, tmp_path, document, osv_responses
):
    """Ratified precedence: 2 beats 1 beats 0, and coverage never touches a 2.
    Exercised end to end, because the unit test above cannot see the wiring."""
    osv_responses(_log4j_osv())
    config = _log4j_confirmation(tmp_path)
    # Two components the matcher can do nothing with, alongside the one that
    # matters. Majority unmatchable, so the gate would otherwise block.
    sbom = json.loads(LOG4J_FIXTURE.read_text(encoding="utf-8"))
    for entry in sbom["components"]:
        if entry.get("bom-ref") != "log4j-core":
            entry.pop("purl", None)
            entry.pop("version", None)
    path = _write(tmp_path, sbom, name="degraded.cdx.json")
    assert main(["--json", "--config", config, path]) == EXIT_REPORT
    payload = json.loads(capsys.readouterr().out)
    assert payload["input"]["quality"] == UNUSABLE
    assert payload["input"]["canRuleOut"] is False
    assert payload["input"]["gated"] is False
    assert payload["triage"]["counts"]["report"] == 1


def test_an_open_assess_item_is_never_withheld_by_the_gate(
    capsys, tmp_path, osv_responses
):
    """A run that exits non-zero while printing only a coverage complaint is
    this gate pointed backwards: the Log4Shell it found goes unmentioned."""
    osv_responses(_log4j_osv())
    sbom = json.loads(LOG4J_FIXTURE.read_text(encoding="utf-8"))
    for entry in sbom["components"]:
        if entry.get("bom-ref") != "log4j-core":
            entry.pop("purl", None)
            entry.pop("version", None)
    assert main([_write(tmp_path, sbom, name="degraded.cdx.json")]) == EXIT_ERROR
    out = capsys.readouterr().out
    assert "WARNING" in out
    assert "ASSESS 1" in _flat(out)
    assert "no result table is printed" not in _flat(out).lower()


def test_a_confirmation_that_matched_nothing_is_loud_on_stdout(
    capsys, tmp_path, osv_responses
):
    """The under-reporting direction: the user believes it is in REPORT, it is
    in ASSESS, and the run exits 1. Silence here is the whole failure."""
    osv_responses(_log4j_osv())
    config = _log4j_confirmation(tmp_path, purl="pkg:maven/typo/typo@1.0")
    assert main(["--config", config, str(LOG4J_FIXTURE)]) == EXIT_ERROR
    out = _flat(capsys.readouterr().out)
    assert "matched no component in this SBOM" in out
    assert "pkg:maven/typo/typo@1.0" in out


def test_an_unreadable_config_stops_the_run_before_anything_else(capsys, tmp_path):
    """Nothing parseable on stdout, like any other crash. A run that continued
    with an empty confirmation list would under-report in silence."""
    config = _config(tmp_path, "[[report]\nbroken")
    assert main(["--json", "--config", config, str(LOG4J_FIXTURE)]) == EXIT_ERROR
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "not valid TOML" in captured.err


def test_there_is_no_config_auto_discovery(capsys, tmp_path, monkeypatch, osv_responses):
    """A REPORT verdict is a statement about the product. The command line has
    to record what it rested on, or a file appearing in the working directory
    silently changes the exit code of an unchanged pipeline."""
    osv_responses(_log4j_osv())
    _log4j_confirmation(tmp_path)
    monkeypatch.chdir(tmp_path)
    assert main(["--json", str(LOG4J_FIXTURE)]) == EXIT_ERROR
    payload = json.loads(capsys.readouterr().out)
    assert payload["triage"]["counts"]["report"] == 0
    assert payload["triage"]["counts"]["assess"] == 1


def test_the_headline_sits_above_every_warning(capsys, tmp_path, osv_responses):
    """The top-of-output crop has to carry the answer. The warnings below it
    are loud by design and they are about a different question; a reader who
    takes only the first lines must leave with the verdict rather than with a
    complaint about the input."""
    osv_responses(_log4j_osv())
    sbom = json.loads(LOG4J_FIXTURE.read_text(encoding="utf-8"))
    for entry in sbom["components"]:
        if entry.get("bom-ref") != "log4j-core":
            entry.pop("purl", None)
            entry.pop("version", None)
    main([_write(tmp_path, sbom, name="degraded.cdx.json")])
    out = capsys.readouterr().out
    assert "result: 0 to report - 1 to assess" in out
    assert out.index("result:") < out.index("WARNING")
    assert out.index("input:") < out.index("result:")


def test_the_headline_says_the_report_count_in_words(
    capsys, tmp_path, osv_responses
):
    """Red is the second signal and never the only one. A screenshot on a
    light README and a paste into an email both lose the colour."""
    osv_responses(_log4j_osv())
    config = _log4j_confirmation(tmp_path)
    assert main(["--config", config, str(LOG4J_FIXTURE)]) == EXIT_REPORT
    out = capsys.readouterr().out
    assert "result: 1 to report" in out


def test_the_counts_are_the_heading_of_the_table(capsys, osv_responses):
    """A crop of the table alone shows REPORT in a cell and nothing else. The
    counts are glued to it so that crop carries the verdict too."""
    osv_responses(_log4j_osv())
    main([str(LOG4J_FIXTURE)])
    lines = [line for line in capsys.readouterr().out.splitlines()]
    counts_at = next(i for i, line in enumerate(lines) if line.strip().startswith("NO "))
    header_at = next(i for i, line in enumerate(lines) if "CVE" in line and "bucket" in line)
    assert header_at == counts_at + 1


def test_the_table_explains_its_own_columns(capsys, osv_responses):
    """Two bare letters in a column heading were the one thing in the default
    output with no gloss, and the table is the part that gets screenshotted
    without the header above it."""
    osv_responses(_log4j_osv())
    main([str(LOG4J_FIXTURE)])
    out = capsys.readouterr().out
    lines = [line.rstrip() for line in out.splitlines() if line.strip()]
    key_at = next(i for i, line in enumerate(lines) if line.startswith("D = direct"))
    # Only the letters this table actually uses: the fixture's one finding is
    # a direct dependency, so a gloss for T would explain a column value that
    # is not on screen.
    assert lines[key_at] == "D = direct dependency"
    assert len(lines[key_at]) <= 80
    # Directly under the last row, so it travels with a crop of the table
    # rather than drifting into the prose below.
    assert "CVE-2021-44228" in lines[key_at - 1]


def test_the_default_run_points_at_brief_rather_than_printing_it(
    capsys, tmp_path, osv_responses
):
    osv_responses(_log4j_osv())
    main([str(LOG4J_FIXTURE)])
    out = capsys.readouterr().out
    assert "ASSESS 1" in _flat(out)
    assert "--brief" in _flat(out)
    assert "Question" not in out


def test_brief_prints_the_full_decision_brief(capsys, osv_responses):
    osv_responses(_log4j_osv())
    main(["--brief", str(LOG4J_FIXTURE)])
    out = capsys.readouterr().out
    assert "[ASSESS] CVE-2021-44228" in out
    assert "log4j-core@2.14.1" in out
    assert "Where" in out and "What" in out and "Signal" in out
    assert "Question" in out
    assert "-> REPORT" in out and "-> NO" in out


def test_the_funnel_says_which_unit_each_number_is_in(capsys, kev_state):
    """The arithmetic a reader does between two adjacent lines has to work.

    `known exploited` is distinct CVE ids and the buckets directly under it
    are component-CVE pairs, so the two differ whenever one CVE reaches more
    than one component -- which is the normal case, not the corner one. Each
    gloss names its own unit, and the listed line names both.
    """
    main([str(FIXTURE)])
    out = _flat(capsys.readouterr().out)

    assert "vulnerabilities 6 (records carried by the SBOM, not matched here)" in out
    assert "component-CVE pairs 5 (one record can affect several components)" in out
    assert "CVEs checked 6 (distinct CVE ids put to the EUVD KEV catalogue)" in out
    assert "distinct CVE ids listed in the catalogue," in out
    assert "REPORT 0 (component-CVE pairs; the 24h clock is running)" in out
    assert "pairs in the KEV catalogue; needs a decision now" in out
    assert "pairs not in the KEV catalogue" in out

    # The identity the reader is entitled to: the pairs quoted beside the
    # listed CVE ids are the pairs sitting in the buckets that the catalogue
    # put there. Asserted rather than hardcoded, so it keeps holding when the
    # fixture changes.
    listed_pairs = int(re.search(r"across (\d+) component-CVE pair", out).group(1))
    report = int(re.search(r"REPORT (\d+)", out).group(1))
    assess = int(re.search(r"ASSESS (\d+)", out).group(1))
    assert listed_pairs == report + assess


def test_the_funnel_owns_up_when_two_records_are_one_pair(
    capsys, document, tmp_path, kev_state
):
    """The line above the buckets is findings; the buckets are pairs.

    Two records aliasing one CVE on one component is the ordinary case -- a
    scanner's own feed and OSV both carry Log4shell -- and it makes the two
    differ by one. The reader is told on the line rather than left to add the
    buckets up and find a number that is not above them.
    """
    duplicate = dict(document["vulnerabilities"][0], **{"bom-ref": "vuln-1-again"})
    document["vulnerabilities"].append(duplicate)
    main([_write(tmp_path, document)])
    out = _flat(capsys.readouterr().out)

    findings = int(re.search(r"component-CVE pairs (\d+)", out).group(1))
    distinct = int(re.search(r"one CVE: (\d+) distinct pairs", out).group(1))
    assert distinct == findings - 1
    # `unchecked` prints only when something was unassessable, so it is
    # summed where it appears rather than required.
    found = [
        re.search(rf"{label} (\d+)", out)
        for label in ("REPORT", "ASSESS", "NO", "unchecked")
    ]
    buckets = sum(int(m.group(1)) for m in found if m)
    assert buckets == distinct


def test_a_funnel_that_collapses_nothing_says_nothing(capsys, kev_state):
    """The second line is a reconciliation, so it is there only when there is
    something to reconcile. On a run where every finding is its own pair it
    would be a clause a reader has to read and discard."""
    main([str(FIXTURE)])
    out = _flat(capsys.readouterr().out)
    assert "component-CVE pairs 5 (one record can affect several components)" in out
    assert "distinct pairs" not in out


def test_no_is_counted_and_never_listed_row_by_row(capsys, kev_state):
    """One summary line. Listing it buries the two buckets that decide
    anything, and it is most of the output on any real product."""
    kev_state["dump"] = list(IRRELEVANT_KEV_DUMP)
    main(["--brief", str(FIXTURE)])
    out = capsys.readouterr().out
    assert "NO 5 (pairs not in the KEV catalogue)" in _flat(out)
    assert "[NO]" not in out


# --- the SBOM's own VEX statement -----------------------------------------
#
# End to end, because the unit tests cannot see the two things that matter
# here: that the claim reaches the exit code only when the operator says so,
# and that the run records the flag was used.


def _vexed(document, state="not_affected"):
    """Every vulnerability in the document asserts it does not apply, with a
    tool named for it. This is what `grype ... | art14 -` looks like when the
    producer has already done its own analysis."""
    document["metadata"]["tools"] = {
        "components": [{"type": "application", "name": "grype", "version": "0.100.0"}]
    }
    for entry in document["vulnerabilities"]:
        entry["analysis"] = {
            "state": state,
            "justification": "code_not_reachable",
            "detail": "Bundled but never invoked.",
        }
    return document


def test_an_upstream_claim_is_shown_and_not_obeyed(capsys, tmp_path, document):
    """The default. If the claim were honoured silently the tool would be a
    laundering channel: an upstream scanner asserts not_affected, art14 prints
    a clean run, and the manufacturer has a verdict nobody reasoned about."""
    path = _write(tmp_path, _vexed(document))
    assert main(["--brief", path]) == EXIT_ERROR
    out = _flat(capsys.readouterr().out)
    assert "grype 0.100.0 asserts not_affected (code_not_reachable)" in out
    assert "grype 0.100.0" in out
    assert "Unverified" in out
    # And the way to adopt it is in the brief, not only in --help.
    assert "--adopt-upstream-vex" in out


def test_adopting_the_claim_can_certify_the_run(capsys, tmp_path, document):
    """What the flag is for, and the reason it has to be opt-in: it is the one
    thing in the tool that turns an open ASSESS item into a clean exit without
    a human having looked at the product."""
    path = _write(tmp_path, _vexed(document))
    assert main(["--adopt-upstream-vex", path]) == EXIT_OK
    out = _flat(capsys.readouterr().out)
    # Never only a number. The suppression is named, with its authority.
    assert "suppressed" in out
    assert "CVE-2021-44228" in out
    assert "asserted by grype 0.100.0" in out


def test_the_json_records_every_suppression_and_the_flag(capsys, tmp_path, document):
    path = _write(tmp_path, _vexed(document))
    assert main(["--json", "--adopt-upstream-vex", path]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["provenance"]["adoptUpstreamVex"] is True
    suppressed = payload["triage"]["suppressedByUpstreamVex"]
    assert suppressed, "a suppression that leaves no record is the failure mode"
    assert {row["cve"] for row in suppressed} >= {"CVE-2021-44228"}
    row = next(r for r in suppressed if r["cve"] == "CVE-2021-44228")
    assert row["assertedBy"] == "grype 0.100.0"
    assert row["justification"] == "code_not_reachable"
    assert row["state"] == "not_affected"
    assert payload["triage"]["counts"]["suppressed"] == len(suppressed)


def test_the_flag_is_false_in_the_json_of_a_run_that_did_not_use_it(
    capsys, tmp_path, document
):
    """Present on every run, true or false. A consumer deciding whether to
    trust a clean result must not have to know which build wrote the file."""
    path = _write(tmp_path, _vexed(document))
    assert main(["--json", path]) == EXIT_ERROR
    payload = json.loads(capsys.readouterr().out)
    assert payload["provenance"]["adoptUpstreamVex"] is False
    assert payload["triage"]["suppressedByUpstreamVex"] == []
    assert payload["triage"]["counts"]["suppressed"] == 0
    # The claim is still on the item, so nothing about it is hidden.
    assert payload["triage"]["items"][0]["upstreamClaim"]["adopted"] is False


def test_the_provenance_block_says_the_flag_was_used(capsys, tmp_path, document):
    path = _write(tmp_path, _vexed(document))
    assert main(["--brief", "--adopt-upstream-vex", path]) == EXIT_OK
    assert "upstream VEX" in _flat(capsys.readouterr().out)


def test_the_flag_on_an_sbom_with_no_claims_says_it_did_nothing(
    capsys, tmp_path, document
):
    """The common case, because the flag is in --help on every run: an SBOM
    matched against OSV here carries no claims for it to adopt."""
    path = _write(tmp_path, document)
    assert main(["--adopt-upstream-vex", path]) == EXIT_ERROR
    out = _flat(capsys.readouterr().out)
    assert "nothing was suppressed" in out


def test_a_run_without_the_flag_says_nothing_about_it(capsys, tmp_path, document):
    """The note belongs to the operator who typed the flag. Explaining an
    absent flag to everybody else is noise in the one place that has to stay
    readable."""
    path = _write(tmp_path, document)
    assert main([path]) == EXIT_ERROR
    assert "--adopt-upstream-vex" not in _flat(capsys.readouterr().out)


def test_a_state_other_than_not_affected_is_never_adopted(capsys, tmp_path, document):
    """`false_positive` is a statement about the scan rather than about the
    product, so the flag leaves the item open and the run still exits 1."""
    path = _write(tmp_path, _vexed(document, state="false_positive"))
    assert main(["--adopt-upstream-vex", path]) == EXIT_ERROR


# --- own evidence, end to end ---------------------------------------------
#
# The half the unit tests cannot see: that a [[report]] on a CVE no catalogue
# lists reaches the exit code. It did not. The item stayed in NO, the run
# exited 0, and the only trace was a line under the table saying the entry did
# not apply -- a tool whose product is the exit code certifying a product its
# manufacturer had direct evidence was being exploited.


def _own_evidence(tmp_path, *, basis=True):
    body = f'[[report]]\ncomponent = "{LOG4J_PURL}"\ncve = "{LOG4SHELL_CVE}"\n'
    if basis:
        body += 'basis = "operator evidence"\naware = 2026-09-12\n'
    body += 'rationale = "Exploitation attempts against customer deployments."\n'
    return _config(tmp_path, body)


def test_own_evidence_on_an_unlisted_cve_exits_two(
    capsys, tmp_path, osv_responses, kev_state
):
    osv_responses(_log4j_osv())
    # A catalogue that lists something else entirely: the situation the field
    # exists for, where the manufacturer knows and CISA does not yet.
    kev_state["dump"] = list(IRRELEVANT_KEV_DUMP)
    config = _own_evidence(tmp_path)
    assert main(["--json", "--config", config, str(LOG4J_FIXTURE)]) == EXIT_REPORT
    payload = json.loads(capsys.readouterr().out)
    item = payload["triage"]["items"][0]
    assert item["bucket"] == "REPORT"
    assert item["basis"] == "operator evidence"
    assert item["aware"] == "2026-09-12"
    # Nothing behind it in any catalogue, and the payload says so plainly
    # rather than leaving the REPORT to be read as a listing.
    assert item["sources"] == []
    assert item["dateAdded"] is None
    assert "reported on the manufacturer's own evidence" in item["signal"]
    assert payload["triage"]["unusedConfirmations"] == []


def test_own_evidence_without_a_basis_stops_the_run(
    capsys, tmp_path, osv_responses, kev_state
):
    """Refused rather than promoted quietly, on the same stance as a config
    that cannot be read: a verdict this tool cannot render faithfully is worse
    than no verdict. And refused cleanly -- a message, not a traceback."""
    osv_responses(_log4j_osv())
    kev_state["dump"] = list(IRRELEVANT_KEV_DUMP)
    config = _own_evidence(tmp_path, basis=False)
    assert main(["--config", config, str(LOG4J_FIXTURE)]) == EXIT_ERROR
    captured = capsys.readouterr()
    assert "Traceback" not in captured.err
    assert "needs a `basis`" in _flat(captured.err)
