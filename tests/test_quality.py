"""Input quality gate tests.

The numbers here drive an exit code, so the boundary cases get pinned: the
threshold is compared on the exact ratio rather than the rounded percentage the
banner prints, and "has a version" is decided without parsing a PURL.
"""

from __future__ import annotations

import pytest

from art14.cyclonedx import parse_document
from art14.models import Component, Finding
from art14.quality import (
    DEGRADED,
    OK,
    UNUSABLE,
    assess,
    banner,
    coverage,
    verdict_line,
    warnings,
)


def _sbom(components, *, with_vulnerabilities=False):
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": components,
    }
    if with_vulnerabilities:
        document["vulnerabilities"] = [{"id": "CVE-2021-44228"}]
    return parse_document(document)


def _component(index, *, purl=True, version=True):
    entry = {"bom-ref": f"c{index}", "name": f"c{index}", "type": "library"}
    if version:
        entry["version"] = "1.0.0"
    if purl:
        entry["purl"] = f"pkg:pypi/c{index}@1.0.0" if version else f"pkg:pypi/c{index}"
    return entry


def _file(index):
    """What a scanner lists beside the packages: a file it walked."""
    return {"bom-ref": f"f{index}", "name": f"/usr/bin/f{index}", "type": "file"}


# --- levels ---------------------------------------------------------------


def test_full_coverage_is_ok():
    quality = assess(_sbom([_component(i) for i in range(4)]))
    assert quality.level == OK
    assert quality.unmatchable == ()


def test_any_gap_is_degraded():
    components = [_component(i) for i in range(4)]
    components[0].pop("purl")
    quality = assess(_sbom(components))
    assert quality.level == DEGRADED
    assert len(quality.unmatchable) == 1


def test_exactly_half_unmatchable_is_still_degraded():
    # Section 9 says *more than* 50%. Half is bad, not disqualifying.
    components = [_component(i) for i in range(4)]
    for entry in components[:2]:
        entry.pop("purl")
    quality = assess(_sbom(components))
    assert quality.unmatchable_ratio == 0.5
    assert quality.level == DEGRADED


def test_just_over_half_is_unusable():
    components = [_component(i) for i in range(100)]
    for entry in components[:51]:
        entry.pop("purl")
    quality = assess(_sbom(components))
    assert quality.level == UNUSABLE


def test_threshold_uses_the_exact_ratio_not_the_printed_percentage():
    # 101 of 201 is 50.2%, which the banner rounds to 50%. It is still a
    # majority, so it is still unusable -- the rounded number must not be able
    # to read as the justification.
    components = [_component(i) for i in range(201)]
    for entry in components[:101]:
        entry.pop("purl")
    quality = assess(_sbom(components))
    assert quality.unmatchable_percent == 50
    assert quality.level == UNUSABLE


def test_an_empty_sbom_is_unusable_not_ok():
    # Zero of zero unmatchable is 0%, and calling that "ok" is exactly the
    # false clean bill of health the gate exists to prevent.
    quality = assess(_sbom([]))
    assert quality.level == UNUSABLE
    assert quality.components == 0
    assert quality.without_purl_percent == 0


# --- the type rule --------------------------------------------------------
#
# `syft alpine:3.10 -o cyclonedx-json` emits 76 components for a 14-package
# image: one `file` entry per file it walked. Grading those reported 82%
# unmatchable against an inventory that is in fact fully matchable, and an
# unusable grade withheld a correct result.


def test_non_package_entries_are_out_of_the_denominator():
    components = [_component(i) for i in range(3)]
    components += [_file(i) for i in range(9)]
    quality = assess(_sbom(components))
    assert quality.components == 3
    assert quality.document_components == 12
    assert len(quality.non_packages) == 9
    assert quality.level == OK


def test_the_narrowing_is_named_in_the_banner_with_its_rule():
    """Point of the whole change: a reader must see that the inventory was
    narrowed, by how much, and on what rule. Silently dropping two thirds of a
    document is the same class of error as silently calling it clean."""
    quality = assess(_sbom([_component(0)] + [_file(i) for i in range(9)]))
    lines = banner(quality)
    assert lines[0].startswith("input: 1 package components")
    assert "10 entries in the document" in lines[1]
    assert "9 are not packages (file)" in lines[1]
    assert "are not graded" in lines[1]


def test_a_document_with_no_non_packages_says_nothing_about_the_rule():
    """The line appears only where it applies. Every SBOM of plain packages --
    the walkthrough included -- reads exactly as it did before."""
    quality = assess(_sbom([_component(i) for i in range(3)]))
    lines = banner(quality)
    assert lines[0] == (
        "input: 3 components - 0 without PURL (0%) - 0 without version"
    )
    assert len(lines) == 2


def test_an_unknown_type_stays_in_the_inventory():
    """The rule is a denylist on purpose. Dropping a real package
    under-reports silently, which is the failure this fixes; keeping something
    package-shaped that is not costs an unmatchable entry and a worse grade,
    which is visible in the banner."""
    components = [
        {"bom-ref": "x", "name": "x", "version": "1", "type": "quantum-widget"}
    ]
    quality = assess(_sbom(components))
    assert quality.components == 1
    assert quality.non_packages == ()


def test_an_operating_system_entry_is_a_package_and_is_graded():
    """It is the Alpine case's only surprise: `os:alpine@3.10.9` has a version
    and no PURL, so the honest post-filter grade is degraded rather than ok."""
    components = [_component(i) for i in range(9)]
    components.append(
        {"bom-ref": "os", "name": "alpine", "version": "3.10.9", "type": "operating-system"}
    )
    quality = assess(_sbom(components))
    assert quality.components == 10
    assert quality.level == DEGRADED


def test_a_document_of_nothing_but_files_is_not_an_empty_one():
    """Nor an assessable one. Section 9's zero-component wording would say
    "this SBOM lists no components" about a file of 9 entries, which is
    false, and the reason it cannot be assessed is a different one."""
    quality = assess(_sbom([_file(i) for i in range(9)], with_vulnerabilities=True))
    assert quality.level == UNUSABLE
    assert quality.can_certify_nothing_to_report is False
    assert banner(quality)[0] == "input: no package components in 9 entries"
    assert verdict_line(quality) == "none of the 9 entries in this SBOM is a package"
    text = " ".join(warnings(quality, report_items=0, assess_items=0))
    assert "All 9 entries" in text
    assert "cannot be assessed, not a clean one" in text


def test_a_genuinely_empty_document_keeps_its_own_wording():
    quality = assess(_sbom([]))
    assert banner(quality)[0] == "input: no components"
    assert verdict_line(quality) == "this SBOM lists no components"


# --- source coverage: the third axis --------------------------------------
#
# Identifier coverage and source coverage fail differently. A missing PURL is
# a defect in the SBOM. A well formed PURL the source returns nothing for is a
# defect nowhere -- and it used to be invisible, because the grade only ever
# looked at identifiers.


class _Result:
    """The shape `coverage()` reads off a MatchResult."""

    def __init__(self, queried, answered_refs):
        self.queried = tuple(queried)
        self.findings = tuple(
            Finding(vulnerability=None, component=c)
            for c in queried
            if c.bom_ref in answered_refs
        )


def _c(ref, purl):
    return Component(bom_ref=ref, name=ref, version="1.0", purl=purl)


def test_a_run_where_nothing_came_back_cannot_certify():
    queried = [_c(f"a{i}", f"pkg:apk/alpine/a{i}@1.0") for i in range(14)]
    quality = assess(
        _sbom([_component(i) for i in range(14)]),
        matching_performed=True,
        source=coverage(_Result(queried, set()), inventory=14),
    )
    # Nothing wrong with the identifiers. Everything wrong with the silence.
    assert quality.level == OK
    assert quality.source.level == "none"
    assert quality.can_certify_nothing_to_report is False


def test_one_answer_is_enough_to_certify():
    queried = [_c(f"a{i}", f"pkg:apk/alpine/a{i}@1.0") for i in range(14)]
    quality = assess(
        _sbom([_component(i) for i in range(14)]),
        matching_performed=True,
        source=coverage(_Result(queried, {"a3"}), inventory=14),
    )
    assert quality.source.level == "full"
    assert quality.can_certify_nothing_to_report is True


def test_a_silent_ecosystem_beside_an_answering_one_is_partial():
    queried = [
        _c("m1", "pkg:maven/org.example/m1@1.0"),
        _c("m2", "pkg:maven/org.other/m2@1.0"),
        _c("a1", "pkg:apk/alpine/a1@1.0"),
    ]
    source = coverage(_Result(queried, {"m1"}), inventory=3)
    assert source.level == "partial"
    assert [e.label for e in source.silent_ecosystems] == ["pkg:apk/alpine"]
    # Two groupIds, so the namespace is dropped rather than fragmenting maven.
    assert [e.label for e in source.ecosystems] == ["pkg:apk/alpine", "pkg:maven"]
    # Partial does not block: something was established about this product.
    quality = assess(
        _sbom([_component(i) for i in range(3)]),
        matching_performed=True,
        source=source,
    )
    assert quality.can_certify_nothing_to_report is True


def test_the_namespace_is_shown_when_the_whole_group_shares_one():
    """`pkg:apk/alpine` is what a reader recognises; `pkg:apk` is not."""
    queried = [_c(f"a{i}", f"pkg:apk/alpine/a{i}@1.0?arch=x86_64") for i in range(3)]
    source = coverage(_Result(queried, set()), inventory=3)
    assert [e.label for e in source.ecosystems] == ["pkg:apk/alpine"]


def test_a_pre_enriched_run_has_no_coverage_of_its_own():
    """Nothing of ours was asked, so there is no answer rate of ours to
    report -- and no silence of ours to gate on."""
    quality = assess(
        _sbom([_component(i) for i in range(3)], with_vulnerabilities=True),
        source=coverage(None, inventory=3),
    )
    assert quality.source.nothing_answered is False
    assert quality.source.level == "full"
    assert quality.can_certify_nothing_to_report is True


def test_the_silence_is_named_in_the_banner_and_not_blamed_on_the_sbom():
    queried = [_c(f"a{i}", f"pkg:apk/alpine/a{i}@1.0") for i in range(14)]
    quality = assess(
        _sbom([_component(i) for i in range(14)]),
        matching_performed=True,
        source=coverage(_Result(queried, set()), inventory=14),
    )
    assert banner(quality)[-1] == (
        "       source coverage: none - nothing came back for any of the 14 queried"
    )
    text = " ".join(warnings(quality, report_items=0, assess_items=0))
    assert "not a defect in the SBOM" in text
    assert "not fit for Article 14 purposes" not in text


# --- what counts as matchable ---------------------------------------------


def test_a_versioned_purl_supplies_the_missing_version_field():
    components = [{"bom-ref": "x", "name": "x", "purl": "pkg:pypi/x@1.0.0"}]
    quality = assess(_sbom(components))
    assert quality.without_version == ()
    assert quality.level == OK


def test_a_bare_purl_with_no_version_field_is_unmatchable():
    components = [{"bom-ref": "x", "name": "x", "purl": "pkg:pypi/x"}]
    quality = assess(_sbom(components))
    assert len(quality.without_version) == 1
    assert len(quality.unmatchable) == 1


@pytest.mark.parametrize(
    "purl",
    [
        "pkg:deb/debian/openssl@1.1.1n?arch=amd64",
        "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
        "pkg:generic/openssl@1.1.1n#subpath",
        "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
    ],
)
def test_qualifiers_and_slashes_do_not_hide_the_version(purl):
    quality = assess(_sbom([{"bom-ref": "x", "name": "x", "purl": purl}]))
    assert quality.without_version == ()


@pytest.mark.parametrize(
    "purl",
    [
        "pkg:deb/debian/openssl?arch=amd64",
        "pkg:golang/github.com/gin-gonic/gin",
    ],
)
def test_a_qualifier_is_not_mistaken_for_a_version(purl):
    quality = assess(_sbom([{"bom-ref": "x", "name": "x", "purl": purl}]))
    assert len(quality.without_version) == 1


def test_no_purl_and_no_version_is_counted_once_not_twice():
    components = [_component(0, purl=False, version=False), _component(1)]
    quality = assess(_sbom(components))
    assert len(quality.without_purl) == 1
    assert len(quality.without_version) == 1
    assert len(quality.unmatchable) == 1


def test_the_root_component_is_not_counted():
    # The product itself is not something we query OSV about, and counting it
    # would skew the ratio on small SBOMs.
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"component": {"bom-ref": "app", "name": "app", "version": "1.0"}},
        "components": [_component(0)],
    }
    assert assess(parse_document(document)).components == 1


# --- the informed axis ----------------------------------------------------


def test_a_bare_sbom_is_not_informed():
    quality = assess(_sbom([_component(0)]))
    assert quality.informed is False
    assert quality.informed_by is None
    assert quality.can_certify_nothing_to_report is False


def test_a_pre_enriched_sbom_is_informed_by_the_sbom():
    quality = assess(_sbom([_component(0)], with_vulnerabilities=True))
    assert quality.informed is True
    assert quality.informed_by == "pre-enriched"
    assert quality.can_certify_nothing_to_report is True


def test_matching_performed_is_wired_for_the_osv_stage():
    quality = assess(_sbom([_component(0)]), matching_performed=True)
    assert quality.informed is True
    assert quality.informed_by == "osv"
    assert quality.can_certify_nothing_to_report is True


def test_unusable_never_certifies_nothing_to_report_even_when_informed():
    components = [_component(i, purl=False, version=False) for i in range(4)]
    quality = assess(_sbom(components, with_vulnerabilities=True))
    assert quality.informed is True
    assert quality.level == UNUSABLE
    assert quality.can_certify_nothing_to_report is False


def test_pre_enriched_input_is_measured_but_not_gated():
    # The gate counts components that are *unmatchable*, which is a property
    # relative to matching we are about to do. A pre-enriched SBOM has already
    # been matched by whatever produced it, so the coverage numbers are
    # reported and the result table is not withheld.
    components = [_component(i, purl=False, version=False) for i in range(4)]
    quality = assess(_sbom(components, with_vulnerabilities=True))
    assert quality.level == UNUSABLE
    assert quality.matching_was_ours is False
    assert quality.blocks is False


def test_a_pre_enriched_grade_is_not_called_matching_quality():
    """No matching of ours ran, so a grade named after it reports a coverage
    failure against a stage that never happened."""
    components = [_component(0, purl=False)] + [_component(i) for i in range(1, 4)]
    quality = assess(_sbom(components, with_vulnerabilities=True))
    line = banner(quality)[1]
    assert "SBOM quality: degraded" in line
    assert "no matching ran here" in line
    assert "matching quality" not in line


def test_a_matched_run_still_grades_its_own_matching():
    components = [_component(0, purl=False)] + [_component(i) for i in range(1, 4)]
    quality = assess(_sbom(components), matching_performed=True)
    assert "matching quality: degraded" in banner(quality)[1]


def test_an_identifiable_pre_enriched_sbom_carries_no_caveat():
    """The caveat exists to stop a bad grade being misread. There is no bad
    grade here and it would be the longest thing on the line."""
    quality = assess(_sbom([_component(i) for i in range(4)], with_vulnerabilities=True))
    assert banner(quality)[1].strip() == "SBOM quality: ok - see README"


def test_a_pre_enriched_gap_is_not_reported_as_a_failure_to_match():
    """The claim has a different shape when the matching was somebody else's.
    A scanner reading an image matches on package databases and file hashes
    that never reach the CycloneDX output, so a missing PURL here does not say
    the component went unassessed -- it says this run cannot tell."""
    components = [_component(0, purl=False)] + [_component(i) for i in range(1, 4)]
    quality = assess(_sbom(components, with_vulnerabilities=True))
    text = " ".join(warnings(quality, report_items=0, assess_items=0))
    assert "could not be matched" not in text
    assert "not a coverage figure for this run" in text
    assert "may not have identified those components either" in text
    assert "unverified rather than clean" in text


def test_a_matched_gap_keeps_the_stronger_wording():
    components = [_component(0, purl=False)] + [_component(i) for i in range(1, 4)]
    quality = assess(_sbom(components), matching_performed=True)
    text = " ".join(warnings(quality, report_items=0, assess_items=0))
    assert "could not be matched" in text


def test_an_unidentifiable_pre_enriched_sbom_still_refuses_to_certify():
    """The table is not withheld -- the findings are somebody else's and they
    stand -- but exit 0 is a negative claim, and "most of this inventory is
    unidentifiable and the file does not say what was checked" cannot support
    one."""
    components = [_component(i, purl=False, version=False) for i in range(4)]
    quality = assess(_sbom(components, with_vulnerabilities=True))
    assert quality.blocks is False
    assert quality.can_certify_nothing_to_report is False
    text = " ".join(warnings(quality, report_items=0, assess_items=0))
    assert "will not certify that there is nothing to report" in text


def test_the_verdict_sentence_does_not_claim_upstream_coverage():
    components = [_component(i, purl=False, version=False) for i in range(4)]
    quality = assess(_sbom(components, with_vulnerabilities=True))
    assert verdict_line(quality) == (
        "the SBOM arrived with vulnerabilities attached; how much of the"
        " product they cover is not knowable here"
    )


def test_a_bare_unusable_sbom_is_gated():
    components = [_component(i, purl=False, version=False) for i in range(4)]
    quality = assess(_sbom(components))
    assert quality.blocks is True


# --- the parts that get rendered ------------------------------------------


def test_every_unmatchable_component_carries_a_reason():
    components = [
        _component(0, purl=False),
        {"bom-ref": "c1", "name": "c1", "purl": "pkg:pypi/c1"},
    ]
    from art14.quality import as_json

    listed = as_json(assess(_sbom(components)), report_items=0, assess_items=0)["unmatchableComponents"]
    assert [entry["reason"] for entry in listed] == ["no PURL", "no version"]


# --- lookups that did not complete ----------------------------------------
#
# A failed OSV query and a missing PURL are different causes with the same
# consequence: we did not find out. Section 9 counts what could not be
# matched, so they share one ratio, one banner and one exit rule.


def test_a_failed_lookup_counts_as_unmatchable():
    sbom = _sbom([_component(i) for i in range(4)])
    quality = assess(
        sbom, matching_performed=True, query_failures=sbom.components[:1]
    )
    assert quality.level == DEGRADED
    assert len(quality.unmatchable) == 1
    assert len(quality.without_purl) == 0


def test_failed_lookups_can_push_a_clean_sbom_to_unusable():
    """Cold cache, no network: a perfect SBOM, and nothing was assessed."""
    sbom = _sbom([_component(i) for i in range(4)])
    quality = assess(
        sbom, matching_performed=True, query_failures=sbom.components
    )
    assert quality.without_purl == ()
    assert quality.level == UNUSABLE
    assert quality.informed is True
    assert quality.can_certify_nothing_to_report is False
    assert quality.blocks is True


def test_the_warning_does_not_blame_purls_for_a_network_failure():
    """Telling this user to fix their PURLs sends them to fix the wrong thing."""
    from art14.quality import shortfall, warnings

    sbom = _sbom([_component(i) for i in range(4)])
    quality = assess(
        sbom, matching_performed=True, query_failures=sbom.components
    )
    assert shortfall(quality) == "a lookup that did not complete"
    text = " ".join(warnings(quality, report_items=0, assess_items=0))
    assert "no PURL" not in text
    assert "lookup did not complete" in text


def test_a_mixed_cause_is_described_as_mixed():
    from art14.quality import shortfall

    components = [_component(0, purl=False), _component(1), _component(2)]
    sbom = _sbom(components)
    failed = [c for c in sbom.components if c.bom_ref == "c1"]
    quality = assess(sbom, matching_performed=True, query_failures=failed)
    assert len(quality.unmatchable) == 2
    assert shortfall(quality) == "no PURL, no version, or a lookup that did not complete"


def test_each_unmatchable_component_names_its_own_cause():
    from art14.quality import as_json

    components = [_component(0, purl=False), _component(1)]
    sbom = _sbom(components)
    failed = [c for c in sbom.components if c.bom_ref == "c1"]
    listed = as_json(
        assess(sbom, matching_performed=True, query_failures=failed),
        report_items=0,
        assess_items=0,
    )["unmatchableComponents"]
    assert {e["name"]: e["reason"] for e in listed} == {
        "c0": "no PURL",
        "c1": "lookup did not complete",
    }


def test_a_component_is_never_counted_twice():
    """A component with no PURL was never sendable, so it cannot also fail."""
    components = [_component(0, purl=False, version=False), _component(1)]
    sbom = _sbom(components)
    quality = assess(
        sbom, matching_performed=True, query_failures=sbom.components
    )
    assert len(quality.unmatchable) == 2
    assert len({c.bom_ref for c in quality.unmatchable}) == 2
