"""Parser tests.

`tests/fixtures/graph.cdx.json` is a hand-written SBOM that packs the shapes
real ones break on into six components: a two-hop chain, a cycle, a component
reachable by two paths of different length, a nested component, an orphan
outside the dependency graph, a CVE hitting two components, and a CVE pointing
at a component that is not in the document.
"""

from __future__ import annotations

import codecs
import copy
import io
import json
from pathlib import Path

import pytest

from art14.cyclonedx import parse_document, parse_file, parse_source, parse_stream
from art14.cyclonedx import version_caveat
from art14.errors import SbomError
from art14.models import DIRECT, ROOT, TRANSITIVE, UNKNOWN

FIXTURE = Path(__file__).parent / "fixtures" / "graph.cdx.json"


@pytest.fixture(scope="module")
def sbom():
    return parse_file(FIXTURE)


@pytest.fixture
def document():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


# --- document level -------------------------------------------------------


def test_reads_spec_version_and_root(sbom):
    assert sbom.spec_version == "1.6"
    assert sbom.root is not None
    assert sbom.root.label == "demo-app@1.0.0"


@pytest.mark.parametrize("version", ["1.5", "1.6", "1.7"])
def test_accepts_every_tested_spec_version(document, version):
    document["specVersion"] = version
    parsed = parse_document(document)
    assert parsed.spec_version == version
    assert version_caveat(version) is None


def test_rejects_a_version_older_than_the_floor(document):
    document["specVersion"] = "1.4"
    with pytest.raises(SbomError, match="1.4"):
        parse_document(document)


def test_reads_a_later_1_x_rather_than_refusing_it(document):
    """`grype ... | art14 -` is the documented composition path and the scanner
    upgrades on its own schedule. Refusing outright stops answering a question
    that can still be answered; CycloneDX is additive within a major version."""
    document["specVersion"] = "1.9"
    parsed = parse_document(document)
    assert parsed.spec_version == "1.9"
    assert len(parsed.components) == len(parse_document({**document,
                                                         "specVersion": "1.7"}).components)


def test_a_later_1_x_says_so_out_loud(document):
    """Parsed is not the same as verified. A consumer who is not told cannot
    account for it."""
    caveat = version_caveat("1.9")
    assert caveat is not None
    assert "1.9" in caveat
    assert "newer than anything this build" in caveat


def test_rejects_a_later_major_version(document):
    """A major version is exactly where a field this module reads is allowed
    to be renamed, so tolerance stops at the major boundary."""
    document["specVersion"] = "2.0"
    with pytest.raises(SbomError, match="2.0"):
        parse_document(document)


def test_rejects_a_spec_version_that_is_not_a_version(document):
    document["specVersion"] = "1.7-beta"
    with pytest.raises(SbomError, match="1.7-beta"):
        parse_document(document)


def test_rejects_other_sbom_formats(document):
    document["bomFormat"] = "SPDX"
    with pytest.raises(SbomError, match="CycloneDX"):
        parse_document(document)


def test_missing_file_is_a_user_error(tmp_path):
    with pytest.raises(SbomError, match="no such file"):
        parse_file(tmp_path / "absent.cdx.json")


def test_reads_a_bom_prefixed_file(tmp_path):
    # utf-8-sig at the read, not a strip afterwards: SBOMs generated on Windows
    # carry a byte order mark and json.loads rejects it.
    path = tmp_path / "bom.cdx.json"
    path.write_bytes(codecs.BOM_UTF8 + FIXTURE.read_bytes())
    assert parse_file(path).spec_version == "1.6"


def test_invalid_json_is_a_user_error(tmp_path):
    path = tmp_path / "broken.cdx.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(SbomError, match="not valid JSON"):
        parse_file(path)


# --- components -----------------------------------------------------------


def test_flattens_nested_components(sbom):
    names = {component.name for component in sbom.components}
    assert names == {"alpha", "bravo", "charlie", "delta", "nested", "orphan"}


def test_root_is_not_counted_among_components(sbom):
    assert all(component.name != "demo-app" for component in sbom.components)
    assert sbom.component_by_ref("app") is sbom.root


# --- dependency graph -----------------------------------------------------


def test_root_is_depth_zero(sbom):
    assert sbom.location_of("app").kind == ROOT
    assert sbom.location_of("app").depth == 0


def test_direct_dependencies(sbom):
    for ref in ("a", "c"):
        location = sbom.location_of(ref)
        assert location.kind == DIRECT
        assert location.depth == 1
        assert location.short == "D"


def test_shortest_path_wins(sbom):
    # bravo is reachable as app -> a -> b and as app -> c -> d -> b.
    location = sbom.location_of("b")
    assert location.kind == TRANSITIVE
    assert location.depth == 2
    assert location.chain == ("app", "a", "b")
    assert location.parent_ref == "a"
    assert location.describe() == "transitive, depth 2"


def test_cycle_does_not_hang_or_double_count(sbom):
    # d depends back on c, which is already direct.
    assert sbom.location_of("d").chain == ("app", "c", "d")
    assert sbom.location_of("c").depth == 1


def test_nested_component_gets_its_graph_depth(sbom):
    assert sbom.location_of("n").chain == ("app", "a", "b", "n")
    assert sbom.location_of("n").depth == 3


def test_orphan_is_unknown_not_direct(sbom):
    location = sbom.location_of("o")
    assert location.kind == UNKNOWN
    assert location.depth is None
    assert location.short == "?"
    assert location.describe() == "not in the dependency graph"


def test_root_falls_back_when_metadata_ref_is_absent_from_graph(document):
    document["metadata"]["component"].pop("bom-ref")
    document["dependencies"] = [
        {"ref": "a", "dependsOn": ["b"]},
        {"ref": "b", "dependsOn": []},
    ]
    parsed = parse_document(document)
    # Nothing depends on "a", so it is the only honest root.
    assert parsed.location_of("a").kind == ROOT
    assert parsed.location_of("b").kind == DIRECT


def test_no_dependency_section_leaves_everything_unknown(document):
    document.pop("dependencies")
    parsed = parse_document(document)
    assert all(
        parsed.location_of(component.bom_ref).kind == UNKNOWN
        for component in parsed.components
    )


# --- vulnerabilities and findings ----------------------------------------


def test_one_finding_per_vulnerability_component_pair(sbom):
    pairs = {(f.vulnerability.id, f.component.name) for f in sbom.findings}
    assert pairs == {
        ("CVE-2021-44228", "bravo"),
        ("CVE-2026-0002", "alpha"),
        ("CVE-2026-0002", "charlie"),
        ("CVE-2026-0004", "orphan"),
        ("CVE-2026-0006", "delta"),
    }
    assert len(sbom.findings) == 5
    assert len(sbom.vulnerabilities) == 6


def test_finding_carries_the_location(sbom):
    finding = next(f for f in sbom.findings if f.vulnerability.id == "CVE-2021-44228")
    assert finding.component.label == "bravo@2.0.0"
    assert finding.location.depth == 2


def test_unresolved_affects_are_reported_not_dropped(sbom):
    assert sbom.unresolved_affects == (("CVE-2026-0003", "ghost"),)


def test_explicitly_unaffected_components_are_not_triaged(sbom):
    # An ASSESS brief for a component the SBOM rules out is exactly the noise
    # this tool exists to discard -- but it is counted, not lost.
    assert sbom.excluded_affects == (("CVE-2026-0005", "d"),)
    assert all(f.vulnerability.id != "CVE-2026-0005" for f in sbom.findings)


def test_explicitly_affected_version_range_still_triages(sbom):
    assert any(f.vulnerability.id == "CVE-2026-0006" for f in sbom.findings)


def test_unknown_status_is_triaged(sbom):
    # affects[].versions[].status "unknown" resolves towards reporting.
    assert any(
        f.vulnerability.id == "CVE-2026-0002" and f.component.name == "alpha"
        for f in sbom.findings
    )


def test_affected_assertion_beats_unaffected_assertion(document):
    document["vulnerabilities"] = [
        {
            "id": "CVE-2026-0009",
            "affects": [
                {"ref": "a", "versions": [{"version": "1.0.0", "status": "unaffected"}]},
                {"ref": "a", "versions": [{"version": "1.0.0", "status": "affected"}]},
            ],
        }
    ]
    parsed = parse_document(document)
    assert len(parsed.findings) == 1
    assert parsed.excluded_affects == ()


def test_missing_versions_means_affected(document):
    document["vulnerabilities"] = [{"id": "CVE-2026-0010", "affects": [{"ref": "a"}]}]
    assert len(parse_document(document).findings) == 1


def test_brief_fields_survive_the_parse(sbom):
    vulnerability = next(v for v in sbom.vulnerabilities if v.id == "CVE-2021-44228")
    assert vulnerability.cwes == (917,)
    assert vulnerability.source_name == "NVD"
    assert "JNDI" in (vulnerability.description or "")


def test_cwe_strings_are_normalised(sbom):
    vulnerability = next(v for v in sbom.vulnerabilities if v.id == "CVE-2026-0002")
    assert vulnerability.cwes == (79,)


def test_best_cvss_rating_wins_over_older_methods(sbom):
    vulnerability = next(v for v in sbom.vulnerabilities if v.id == "CVE-2021-44228")
    assert vulnerability.cvss is not None
    assert vulnerability.cvss.score == 10.0
    assert vulnerability.cvss.method == "CVSSv31"


def test_no_rating_means_no_cvss(sbom):
    vulnerability = next(v for v in sbom.vulnerabilities if v.id == "CVE-2026-0004")
    assert vulnerability.cvss is None


def test_empty_sbom_parses():
    minimal = {"bomFormat": "CycloneDX", "specVersion": "1.6"}
    parsed = parse_document(minimal)
    assert parsed.components == ()
    assert parsed.findings == ()
    assert parsed.root is None


def test_parsing_does_not_mutate_the_document(document):
    before = copy.deepcopy(document)
    parse_document(document)
    assert document == before


# --- input sources --------------------------------------------------------


def test_dash_reads_stdin():
    stream = io.StringIO(FIXTURE.read_text(encoding="utf-8"))
    parsed = parse_source("-", stream=stream)
    assert parsed.spec_version == "1.6"
    assert len(parsed.components) == 6


def test_stdin_decodes_utf8_bytes_regardless_of_console_encoding():
    class BinaryStdin:
        buffer = io.BytesIO(FIXTURE.read_bytes())

    assert parse_stream(BinaryStdin()).spec_version == "1.6"


def test_empty_stdin_is_a_user_error():
    with pytest.raises(SbomError, match="no input on stdin"):
        parse_stream(io.StringIO("   "))


def test_stdin_errors_name_stdin_not_a_path():
    with pytest.raises(SbomError, match="stdin is not valid JSON"):
        parse_stream(io.StringIO("{not json"))


def test_a_path_is_still_read_from_disk():
    assert parse_source(FIXTURE).spec_version == "1.6"


def test_dash_with_no_pipe_errors_instead_of_hanging():
    class Tty(io.StringIO):
        def isatty(self):
            return True

    with pytest.raises(SbomError, match="nothing is piped in"):
        parse_source("-", stream=Tty(""))


# --- CycloneDX 1.7, as a scanner actually emits it ------------------------
#
# The fixture is the spec here, the same way the KEV dump fixtures are. What
# it pins is that 1.7's additions sit beside the fields this module reads
# rather than replacing them: `provides` on a dependency, `omniborId`, `swhid`,
# `tags` and `isExternal` on a component, a tool block shaped like 1.5's is
# not, and a vulnerability `analysis` object.

GRYPE_1_7 = Path(__file__).parent / "fixtures" / "grype-1.7.cdx.json"


@pytest.fixture
def grype17():
    return parse_source(GRYPE_1_7)


def test_a_1_7_document_parses_with_no_caveat(grype17):
    assert grype17.spec_version == "1.7"
    assert version_caveat(grype17.spec_version) is None
    assert grype17.root is not None
    assert grype17.root.label == "ghcr.io/acme/gateway@1.4"


def test_1_7_components_survive_intact(grype17):
    by_name = {c.name: c for c in grype17.components}
    assert set(by_name) == {"log4j-core", "log4j-api", "openssl"}
    core = by_name["log4j-core"]
    assert core.bom_ref == "log4j-core"
    assert core.version == "2.14.1"
    assert core.purl == "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    assert core.type == "library"
    # A PURL with qualifiers still arrives whole: the matcher sends it verbatim.
    assert by_name["openssl"].purl.endswith("?arch=amd64&distro=debian-11")


def test_1_7_dependency_graph_survives_provides(grype17):
    """1.7 adds `provides` beside `dependsOn`. Reading the wrong one would turn
    every transitive dependency into a direct one and quietly change the field
    a human looks at first."""
    assert grype17.location_of("log4j-core").short == "D"
    api = grype17.location_of("log4j-api")
    assert api.short == "T"
    assert api.depth == 2
    assert api.chain == ("app", "log4j-core", "log4j-api")


def test_1_7_vulnerabilities_survive_intact(grype17):
    assert len(grype17.vulnerabilities) == 2
    log4shell = next(v for v in grype17.vulnerabilities if v.id == "CVE-2021-44228")
    assert log4shell.cve_ids == ("CVE-2021-44228",)
    assert log4shell.cwes == (917,)
    assert log4shell.cvss is not None
    assert log4shell.cvss.score == 10.0
    assert log4shell.cvss.severity == "critical"
    assert log4shell.affects == ("log4j-core",)
    assert "JNDI" in (log4shell.description or "")


def test_1_7_findings_pair_up(grype17):
    pairs = {(f.vulnerability.id, f.component.name) for f in grype17.findings}
    assert pairs == {
        ("CVE-2021-44228", "log4j-core"),
        ("CVE-2022-0778", "openssl"),
    }


def test_a_vulnerability_level_analysis_block_is_carried_but_rules_nothing_out(
    grype17,
):
    """The split this parser keeps, pinned deliberately. `not_affected` read
    from `affects[].versions[].status` is per component and is acted on here.
    The vulnerability's own `analysis` object is a document-level VEX
    statement: it is parsed and attributed so that layer 3 can show it, and it
    removes nothing. Anyone changing that should have to change this test."""
    assert grype17.excluded_affects == ()
    finding = next(f for f in grype17.findings if f.vulnerability.id == "CVE-2022-0778")
    claim = finding.vulnerability.analysis
    assert claim is not None
    assert claim.state == "not_affected"
    assert claim.justification == "code_not_reachable"
    assert claim.detail.startswith("The product never parses")
    assert claim.is_not_affected is True


def test_the_claim_carries_who_made_it(grype17):
    """"Upstream says so" is not an attribution. The adoption decision is a
    decision about a specific producer, so the producer has to reach the
    output with the claim."""
    claim = next(
        v.analysis for v in grype17.vulnerabilities if v.analysis is not None
    )
    assert claim.asserted_by == "grype 0.100.0"
    assert "grype 0.100.0" in claim.summary()


def test_a_vulnerability_with_no_analysis_block_carries_no_claim(grype17):
    log4shell = next(v for v in grype17.vulnerabilities if v.id == "CVE-2021-44228")
    assert log4shell.analysis is None


def test_the_legacy_tools_array_is_read_too(document):
    """`metadata.tools` became an object in 1.5 and the flat array is still
    everywhere. An attribution that silently depends on which spelling the
    producer chose is not one."""
    document["metadata"]["tools"] = [{"vendor": "acme", "name": "cdxgen", "version": "10.0.0"}]
    document["vulnerabilities"] = [
        {"id": "CVE-2026-9999", "analysis": {"state": "not_affected"}}
    ]
    claim = parse_document(document).vulnerabilities[0].analysis
    assert claim.asserted_by == "cdxgen 10.0.0"


def test_authors_are_the_fallback_attribution(document):
    """A hand-written VEX statement has a person behind it, not a tool."""
    document["metadata"]["authors"] = [{"name": "A. Engineer"}]
    document["vulnerabilities"] = [
        {"id": "CVE-2026-9999", "analysis": {"state": "not_affected"}}
    ]
    claim = parse_document(document).vulnerabilities[0].analysis
    assert claim.asserted_by == "A. Engineer"


def test_an_unattributed_claim_still_says_so(document):
    """Never blank in the output: a claim nobody signed is a weaker claim, and
    the reader deciding whether to adopt it needs to see that."""
    document["metadata"].pop("tools", None)
    document["vulnerabilities"] = [
        {"id": "CVE-2026-9999", "analysis": {"state": "not_affected"}}
    ]
    claim = parse_document(document).vulnerabilities[0].analysis
    assert claim.asserted_by == ""
    assert "unnamed" in claim.asserter


def test_an_analysis_block_with_no_state_asserts_nothing(document):
    """CycloneDX has no default state, and inventing one here would be this
    tool making the claim rather than reporting it."""
    document["vulnerabilities"] = [
        {"id": "CVE-2026-9999", "analysis": {"justification": "code_not_reachable"}}
    ]
    assert parse_document(document).vulnerabilities[0].analysis is None


# --- the type rule --------------------------------------------------------


def test_non_package_components_are_parsed_and_kept_apart():
    sbom = parse_document(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {"bom-ref": "lib", "name": "zlib", "version": "1.2.11", "type": "library"},
                {"bom-ref": "f1", "name": "/bin/sh", "type": "file"},
            ],
        }
    )
    assert [c.bom_ref for c in sbom.components] == ["lib"]
    assert [c.bom_ref for c in sbom.non_packages] == ["f1"]
    assert sbom.document_components == 2


def test_a_vulnerability_against_a_non_package_still_resolves():
    """It must not land in `unresolved_affects`. That field means the affected
    component is not in the document, and saying so about a component the
    document plainly lists is a different and false claim."""
    sbom = parse_document(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [{"bom-ref": "f1", "name": "/bin/sh", "type": "file"}],
            "vulnerabilities": [
                {"id": "CVE-2021-44228", "affects": [{"ref": "f1"}]}
            ],
        }
    )
    assert sbom.unresolved_affects == ()
    assert len(sbom.findings) == 1
    assert sbom.findings[0].component.bom_ref == "f1"
    assert sbom.component_by_ref("f1") is not None
