"""The CycloneDX VEX export.

Two rules carry the weight. Nothing in the document may be a determination
art14 did not make -- no guessed justification, no remediation, no claim about
a pair nobody looked at. And what the document leaves out has to be said
inside the document, because the reader is a tool that will never see the
README and the default reading of silence in VEX is "fine".

The third is structural: the file is written for another program, so it is
checked against the CycloneDX vocabularies rather than against prose.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from art14 import vex
from art14.cli import EXIT_ERROR, EXIT_OK, EXIT_REPORT, main
from tests.conftest import IRRELEVANT_KEV_DUMP

FIXTURE = Path(__file__).parent / "fixtures" / "graph.cdx.json"

# CycloneDX 1.6, `impactAnalysisState` and `impactAnalysisJustification`.
# Copied here so the export is pinned against the spec's list rather than
# against the module's own constants, which would agree with themselves.
STATES = {
    "resolved",
    "resolved_with_pedigree",
    "exploitable",
    "in_triage",
    "false_positive",
    "not_affected",
}
JUSTIFICATIONS = {
    "code_not_present",
    "code_not_reachable",
    "requires_configuration",
    "requires_dependency",
    "requires_environment",
    "protected_by_compiler",
    "protected_at_runtime",
    "protected_at_perimeter",
    "protected_by_mitigating_control",
}


def _payload(argv, capsys):
    """One run's public JSON document, the export's only input."""
    main(["--json", *argv])
    return json.loads(capsys.readouterr().out)


def _config(tmp_path, body, name="dispositions.toml"):
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return str(path)


def _by_cve(document):
    return {entry["id"]: entry for entry in document["vulnerabilities"]}


# CVE-2021-44228 affects `bravo`, CVE-2026-0002 affects `alpha` and `charlie`;
# the first two are in the default catalogue and the run exits 1 on them.
RULED_OUT = """
[[no]]
component = "pkg:maven/example/bravo@2.0.0"
cve = "CVE-2021-44228"
justification = "code_not_reachable"
rationale = "The lookup path is never entered in this build."
"""

CONFIRMED = """
[[report]]
component = "pkg:maven/example/bravo@2.0.0"
cve = "CVE-2021-44228"
aware = 2026-09-12
rationale = "Reachable and confirmed by test."
"""


# --- the three states -----------------------------------------------------


def test_every_state_and_justification_is_one_the_spec_defines(
    tmp_path, capsys, kev_state
):
    """The whole point of the export is that another tool can read it. A value
    outside the vocabulary is a file that parses and means nothing."""
    payload = _payload(["--config", _config(tmp_path, RULED_OUT), str(FIXTURE)], capsys)
    document = vex.build(payload)
    assert document["vulnerabilities"], "an export with no statements tests nothing"
    for entry in document["vulnerabilities"]:
        analysis = entry["analysis"]
        assert analysis["state"] in STATES
        if "justification" in analysis:
            assert analysis["justification"] in JUSTIFICATIONS


def test_a_report_item_is_exploitable_and_its_version_affected(
    tmp_path, capsys, kev_state
):
    """`affected` is not a state in this format -- it is a status on the
    version -- so a REPORT needs both halves or it says less than it means."""
    payload = _payload(["--config", _config(tmp_path, CONFIRMED), str(FIXTURE)], capsys)
    entry = _by_cve(vex.build(payload))["CVE-2021-44228"]
    assert entry["analysis"]["state"] == "exploitable"
    assert entry["affects"][0]["versions"] == [
        {"version": "2.0.0", "status": "affected"}
    ]


def test_an_open_assess_item_is_in_triage_rather_than_absent(capsys, kev_state):
    """Omitting it would let a consumer read "not mentioned" as "clean", which
    is the one thing this tool never does. in_triage is the spec's own word
    for the position art14 is actually in."""
    payload = _payload([str(FIXTURE)], capsys)
    entry = _by_cve(vex.build(payload))["CVE-2021-44228"]
    assert entry["analysis"]["state"] == "in_triage"
    # And it says what is open, rather than claiming an answer.
    assert entry["analysis"]["detail"].startswith("Not yet decided.")


def test_a_ruling_out_is_not_affected_with_the_operators_words(
    tmp_path, capsys, kev_state
):
    payload = _payload(["--config", _config(tmp_path, RULED_OUT), str(FIXTURE)], capsys)
    entry = _by_cve(vex.build(payload))["CVE-2021-44228"]
    assert entry["analysis"]["state"] == "not_affected"
    assert entry["analysis"]["justification"] == "code_not_reachable"
    # Verbatim. The rationale is the product; the justification is an enum a
    # machine can sort on, and it is not a substitute for the sentence.
    assert (
        entry["analysis"]["detail"] == "The lookup path is never entered in this build."
    )


def test_a_ruling_out_without_a_justification_still_exports(
    tmp_path, capsys, kev_state
):
    """CycloneDX makes justification a SHOULD, not a MUST. Dropping the
    statement would hide a decision the operator made, and inventing a
    justification would publish a determination art14 never made -- so it
    exports as what it is: not_affected, on the words alone."""
    body = RULED_OUT.replace('justification = "code_not_reachable"\n', "")
    payload = _payload(["--config", _config(tmp_path, body), str(FIXTURE)], capsys)
    entry = _by_cve(vex.build(payload))["CVE-2021-44228"]
    assert entry["analysis"]["state"] == "not_affected"
    assert "justification" not in entry["analysis"]
    assert entry["analysis"]["detail"]


def test_a_justification_is_never_read_out_of_the_rationale(
    tmp_path, capsys, kev_state
):
    """A rationale that names the reason in so many words is still prose, and
    turning it into an enum would be art14 deciding what the operator meant
    and then publishing that decision under their name."""
    body = RULED_OUT.replace('justification = "code_not_reachable"\n', "").replace(
        '"The lookup path is never entered in this build."',
        '"The vulnerable code is not invoked at runtime."',
    )
    payload = _payload(["--config", _config(tmp_path, body), str(FIXTURE)], capsys)
    entry = _by_cve(vex.build(payload))["CVE-2021-44228"]
    assert "justification" not in entry["analysis"]


# --- what the document does not say ---------------------------------------


def test_a_pair_the_catalogue_did_not_list_is_not_a_statement(capsys, kev_state):
    """"Not currently known to be exploited" is not a determination about
    whether the product is affected, and art14 has no grounds to make one."""
    kev_state["dump"] = list(IRRELEVANT_KEV_DUMP)
    payload = _payload([str(FIXTURE)], capsys)
    assert payload["triage"]["counts"]["no"] > 0
    assert vex.build(payload)["vulnerabilities"] == []


def test_the_document_says_what_its_silence_means(capsys, kev_state):
    """An empty VEX and a VEX that covers nothing look identical to a consumer
    unless the document itself says which it is."""
    kev_state["dump"] = list(IRRELEVANT_KEV_DUMP)
    properties = {
        item["name"]: item["value"]
        for item in vex.build(_payload([str(FIXTURE)], capsys))["metadata"][
            "properties"
        ]
    }
    assert "not a statement that the product is unaffected" in (
        properties["art14:vex:scope"]
    )
    assert "omitted" in properties["art14:vex:omitted:not-in-catalogue"]


def test_an_adopted_upstream_claim_is_omitted_and_the_omission_declared(
    tmp_path, capsys, kev_state
):
    """Re-emitting it would publish somebody else's claim under this
    document's name, and the adoption lives in a flag rather than in the file
    the operator commits."""
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    document["metadata"]["tools"] = {
        "components": [{"type": "application", "name": "grype", "version": "0.100.0"}]
    }
    for entry in document["vulnerabilities"]:
        entry["analysis"] = {
            "state": "not_affected",
            "justification": "code_not_reachable",
            "detail": "Bundled but never invoked.",
        }
    path = tmp_path / "vexed.cdx.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    payload = _payload(["--adopt-upstream-vex", str(path)], capsys)
    assert payload["triage"]["counts"]["suppressed"] > 0
    built = vex.build(payload)
    assert built["vulnerabilities"] == []
    properties = {
        item["name"]: item["value"] for item in built["metadata"]["properties"]
    }
    assert "--adopt-upstream-vex" in properties["art14:vex:omitted:upstream-vex"]


def test_nothing_in_the_document_advises_a_remediation(tmp_path, capsys, kev_state):
    """`analysis.response` is can_not_fix / will_not_fix / update / rollback /
    workaround_available, every one of them a statement about what to do next.
    That exclusion is the reason this is CycloneDX and not CSAF, whose VEX
    profile requires one for every affected product."""
    payload = _payload(["--config", _config(tmp_path, CONFIRMED), str(FIXTURE)], capsys)
    text = vex.render(payload)
    assert "response" not in text
    assert "recommendation" not in text
    assert "workaround" not in text


def test_the_awareness_date_is_not_written_as_a_statement_date(
    tmp_path, capsys, kev_state
):
    """`firstIssued` is when the statement was issued; `aware` is when the
    manufacturer learned of the vulnerability. A consumer counting from the
    first would be counting from the wrong one."""
    payload = _payload(["--config", _config(tmp_path, CONFIRMED), str(FIXTURE)], capsys)
    entry = _by_cve(vex.build(payload))["CVE-2021-44228"]
    assert "firstIssued" not in entry["analysis"]
    assert "lastUpdated" not in entry["analysis"]
    properties = {item["name"]: item["value"] for item in entry["properties"]}
    assert properties["art14:aware"] == "2026-09-12"


# --- binding the statements to their subject ------------------------------


def test_a_serial_number_becomes_a_bom_link(tmp_path, capsys, kev_state):
    """The only identifier a consumer can resolve without being handed the
    source file."""
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    document["serialNumber"] = "urn:uuid:3E671687-395B-41F5-A30F-A58921A69B79"
    document["version"] = 3
    path = tmp_path / "serial.cdx.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    built = vex.build(_payload([str(path)], capsys))
    link = "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/3"
    # Lowercased: CycloneDX accepts either case in serialNumber and only
    # lowercase inside a BOM-Link.
    assert built["externalReferences"][0]["url"] == link
    assert built["vulnerabilities"][0]["affects"][0]["ref"].startswith(f"{link}#")


def test_a_malformed_serial_number_is_not_used(tmp_path, capsys, kev_state):
    """Putting a string that is not an RFC 4122 urn into a BOM-Link makes a
    link no consumer can resolve. Falling back says less and stays true."""
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    document["serialNumber"] = "sbom-2026-09-15"
    path = tmp_path / "loose.cdx.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    built = vex.build(_payload([str(path)], capsys))
    assert built["externalReferences"][0]["url"] == str(path)
    assert not built["vulnerabilities"][0]["affects"][0]["ref"].startswith("urn:cdx:")


def test_without_a_serial_number_the_path_is_named_instead(capsys, kev_state):
    built = vex.build(_payload([str(FIXTURE)], capsys))
    assert built["externalReferences"][0]["url"] == str(FIXTURE)
    assert "declares no serialNumber" in built["externalReferences"][0]["comment"]


def test_stdin_gets_no_external_reference(capsys, kev_state, monkeypatch):
    """`-` identifies no document; a link pointing at it has no referent."""
    import io
    import sys

    monkeypatch.setattr(
        sys, "stdin", io.StringIO(FIXTURE.read_text(encoding="utf-8"))
    )
    built = vex.build(_payload(["-"], capsys))
    assert "externalReferences" not in built


# --- the file on disk -----------------------------------------------------


def test_the_same_payload_writes_the_same_bytes(capsys, kev_state):
    """The operator commits this file. One that changes when nothing changed
    is a diff nobody can read, which is why no serial number is minted here
    and no clock is read."""
    payload = _payload([str(FIXTURE)], capsys)
    assert vex.render(payload) == vex.render(payload)
    assert "serialNumber" not in vex.build(payload)


def test_the_export_does_not_touch_the_exit_code(tmp_path, capsys, kev_state):
    """Same rule as --report. A failed write and a reportable vulnerability
    are not the same statement, so the typo is caught before the run."""
    out = tmp_path / "out.vex.json"
    assert main(["--config", _config(tmp_path, CONFIRMED), "--vex", str(out),
                 str(FIXTURE)]) == EXIT_REPORT
    assert json.loads(out.read_text(encoding="utf-8"))["bomFormat"] == "CycloneDX"

    kev_state["dump"] = list(IRRELEVANT_KEV_DUMP)
    assert main(["--vex", str(tmp_path / "clean.vex.json"), str(FIXTURE)]) == EXIT_OK


def test_an_unwritable_path_fails_before_the_run(tmp_path, capsys, kev_state):
    unwritable = tmp_path / "missing" / "out.vex.json"
    assert main(["--vex", str(unwritable), str(FIXTURE)]) == EXIT_ERROR
    # Nothing parseable on stdout: the run never happened.
    assert not capsys.readouterr().out.strip()


def test_json_and_vex_together_leave_stdout_parseable(tmp_path, capsys, kev_state):
    out = tmp_path / "out.vex.json"
    main(["--json", "--vex", str(out), str(FIXTURE)])
    captured = capsys.readouterr()
    json.loads(captured.out)
    assert str(out) in captured.err


# --- the configuration field ----------------------------------------------


def test_a_justification_outside_the_vocabulary_is_refused(
    tmp_path, capsys, kev_state
):
    """Extending the list would write a value into a VEX document that no
    consumer can read, which is worse than the field being absent."""
    body = RULED_OUT.replace("code_not_reachable", "not_our_problem")
    assert main(["--config", _config(tmp_path, body), str(FIXTURE)]) == EXIT_ERROR
    assert "not one of" in capsys.readouterr().err


def test_a_justification_on_a_report_entry_is_refused(tmp_path, capsys, kev_state):
    """The vocabulary qualifies "this does not affect us". A REPORT claims the
    opposite, and `basis` is the field that qualifies that one."""
    body = CONFIRMED.replace(
        'aware = 2026-09-12', 'justification = "code_not_reachable"'
    )
    assert main(["--config", _config(tmp_path, body), str(FIXTURE)]) == EXIT_ERROR
    assert "belongs on a [[no]]" in capsys.readouterr().err


@pytest.mark.parametrize(
    "written", ["code-not-reachable", "Code Not Reachable", "CODE_NOT_REACHABLE"]
)
def test_spelling_is_forgiven_and_normalised(written, tmp_path, capsys, kev_state):
    body = RULED_OUT.replace("code_not_reachable", written)
    payload = _payload(["--config", _config(tmp_path, body), str(FIXTURE)], capsys)
    entry = _by_cve(vex.build(payload))["CVE-2021-44228"]
    assert entry["analysis"]["justification"] == "code_not_reachable"


# --- the sample the README walks through ----------------------------------


def test_the_shipped_example_names_only_real_justifications():
    """The walkthrough is the demo. A justification in it that CycloneDX does
    not define would be a worked example of an unreadable document."""
    from art14.triage import NO, load_confirmations

    root = Path(__file__).resolve().parents[1]
    entries = load_confirmations(root / "examples" / "dispositions.toml")
    named = [entry for entry in entries if entry.justification]
    assert named, "the sample should show the field, or it documents nothing"
    for entry in named:
        assert entry.verdict == NO
        assert entry.justification in JUSTIFICATIONS
    # And one [[no]] deliberately without one, because the field is optional
    # and an entry resting on its rationale alone still exports.
    assert any(
        entry.verdict == NO and entry.justification is None for entry in entries
    )
