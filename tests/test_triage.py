"""Layer 3: buckets, confirmations and the decision brief.

The rule under test throughout is one asymmetry: ASSESS is the default for
every KEV match, and nothing in the tool may promote an item out of it on
its own -- not depth, not CVSS, not a name that looks
familiar. The only thing that does is an explicit confirmation with a
rationale, and a confirmation that matches nothing must be loud rather than
silent, because silence there under-reports.
"""

from __future__ import annotations

import pytest

from art14.errors import Art14Error
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
    VexClaim,
    Vulnerability,
)
from art14.triage import (
    ASSESS,
    NO,
    REPORT,
    Confirmation,
    as_json,
    brief_lines,
    counts,
    disposition_lines,
    load_confirmations,
    no_label,
    suppression_lines,
    triage,
    unused_warning,
)

LOG4J = Component(
    bom_ref="log4j-core",
    name="log4j-core",
    version="2.14.1",
    purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
)
ROOT_COMPONENT = Component(
    bom_ref="app", name="gateway", version="3.2.0", purl="pkg:maven/acme/gateway@3.2.0"
)
ENTRY = KevEntry(
    cve_id="CVE-2021-44228",
    euvd_id="EUVD-2021-0001",
    date_added="2021-12-10",
    sources=("cisa_kev", "eu_kev"),
)


def _vuln(vuln_id="GHSA-jfh8-c2jp-5v3q", *, aliases=("CVE-2021-44228",), **kwargs):
    kwargs.setdefault("description", "JNDI lookup in log messages enables RCE")
    kwargs.setdefault("cwes", (917,))
    kwargs.setdefault("source_name", "OSV")
    return Vulnerability(
        id=vuln_id, aliases=tuple(aliases), affects=(LOG4J.bom_ref,), **kwargs
    )


def _sbom(vulns, *, component=LOG4J, location=None):
    location = location or Location(kind=DIRECT, depth=1, chain=("app", "log4j-core"))
    return Sbom(
        spec_version="1.5",
        root=ROOT_COMPONENT,
        components=(ROOT_COMPONENT, component),
        vulnerabilities=tuple(vulns),
        locations={component.bom_ref: location},
        findings=tuple(
            Finding(vulnerability=v, component=component, location=location)
            for v in vulns
        ),
    )


def _run(
    vulns,
    *,
    listed=("CVE-2021-44228",),
    confirmations=(),
    sbom=None,
    adopt_upstream_vex=False,
):
    document = sbom if sbom is not None else _sbom(vulns)
    catalogue = Catalogue(
        {
            cve: (ENTRY if cve == "CVE-2021-44228" else KevEntry(cve_id=cve))
            for cve in listed
        }
    )
    return triage(
        document,
        kev_review(document.vulnerabilities, catalogue),
        confirmations,
        adopt_upstream_vex=adopt_upstream_vex,
    )


NOT_AFFECTED = VexClaim(
    state="not_affected",
    justification="code_not_reachable",
    detail="The product never calls the logger with user-controlled input.",
    asserted_by="grype 0.100.0",
)


# --- the default ----------------------------------------------------------


def test_a_kev_hit_with_no_configuration_is_assess():
    """Section 4's central rule. Nothing else in this file matters if it moves."""
    result = _run([_vuln()])
    assert [item.cve_id for item in result.assess] == ["CVE-2021-44228"]
    assert result.report == ()
    assert result.no == ()


def test_depth_never_promotes_anything():
    """Depth informs the human's decision; it does not make it."""
    for location in (
        Location(kind=ROOT, depth=0, chain=("log4j-core",)),
        Location(kind=DIRECT, depth=1, chain=("app", "log4j-core")),
        Location(kind=TRANSITIVE, depth=4, chain=("app", "a", "b", "log4j-core")),
    ):
        result = _run([_vuln()], sbom=_sbom([_vuln()], location=location))
        assert len(result.assess) == 1, location
        assert result.report == ()


def test_a_maximum_severity_score_never_promotes_anything():
    """Regardless of CVSS 10.0. Severity orders work; it does not trigger."""
    vuln = _vuln(ratings=(Rating(method="CVSSv31", score=10.0, severity="critical"),))
    result = _run([vuln])
    assert len(result.assess) == 1
    assert result.report == ()


def test_a_cve_absent_from_the_catalogue_is_no():
    result = _run([_vuln(aliases=("CVE-2019-0001",))], listed=())
    assert [item.cve_id for item in result.no] == ["CVE-2019-0001"]
    assert result.assess == ()


def test_a_record_with_no_cve_is_not_a_no():
    """Never checkable, so never checked. A coverage statement, not a bucket."""
    result = _run([_vuln("GHSA-only", aliases=())], listed=())
    assert result.no == ()
    assert result.assess == ()
    assert [f.vulnerability.id for f in result.unassessed] == ["GHSA-only"]


# --- the unit is (CVE, component) -----------------------------------------


def test_two_listed_aliases_on_one_record_are_two_obligations():
    """One brief per CVE: section 4's header carries a CVE, and each catalogue
    entry is its own entry, its own dateAdded and its own obligation."""
    vuln = _vuln(aliases=("CVE-2021-44228", "CVE-2021-45046"))
    result = _run([vuln], listed=("CVE-2021-44228", "CVE-2021-45046"))
    assert sorted(item.cve_id for item in result.assess) == [
        "CVE-2021-44228",
        "CVE-2021-45046",
    ]


def test_a_listed_alias_beside_an_absent_one_produces_no_no():
    """Printing a NO next to a live obligation for the same record reads as a
    contradiction, and the reassuring half is the one people remember."""
    vuln = _vuln(aliases=("CVE-2021-44228", "CVE-2021-99999"))
    result = _run([vuln], listed=("CVE-2021-44228",))
    assert [item.cve_id for item in result.assess] == ["CVE-2021-44228"]
    assert result.no == ()


def test_one_cve_across_two_components_is_two_items():
    other = Component(
        bom_ref="log4j-api",
        name="log4j-api",
        version="2.14.1",
        purl="pkg:maven/org.apache.logging.log4j/log4j-api@2.14.1",
    )
    vuln = Vulnerability(
        id="GHSA-x",
        aliases=("CVE-2021-44228",),
        affects=(LOG4J.bom_ref, other.bom_ref),
    )
    location = Location(kind=DIRECT, depth=1, chain=("app", "log4j-core"))
    document = Sbom(
        spec_version="1.5",
        root=ROOT_COMPONENT,
        components=(ROOT_COMPONENT, LOG4J, other),
        vulnerabilities=(vuln,),
        locations={LOG4J.bom_ref: location, other.bom_ref: location},
        findings=(
            Finding(vulnerability=vuln, component=LOG4J, location=location),
            Finding(vulnerability=vuln, component=other, location=location),
        ),
    )
    result = _run([vuln], sbom=document)
    assert sorted(item.component.bom_ref for item in result.assess) == [
        "log4j-api",
        "log4j-core",
    ]


def test_the_same_pair_twice_is_one_item():
    """Two OSV records aliasing one CVE against one component is one
    obligation. Counting it twice would inflate every number downstream."""
    vulns = [_vuln("GHSA-a"), _vuln("GHSA-b")]
    result = _run(vulns)
    assert len(result.assess) == 1


def test_the_pair_count_is_what_the_buckets_add_up_to():
    """Two records, one pair. The funnel prints the finding count above the
    buckets, so it also has to be able to print the number the buckets total
    -- otherwise a reader adds the bucket lines and lands one short."""
    sbom = _sbom([_vuln("GHSA-a"), _vuln("GHSA-b")])
    result = _run(sbom.vulnerabilities, sbom=sbom)
    assert len(sbom.findings) == 2
    assert result.pairs == 1
    assert result.pairs == (
        len(result.report) + len(result.assess) + len(result.no)
        + len(result.unassessed)
    )


# --- the ASSESS to REPORT transition --------------------------------------


def test_a_confirmation_promotes_exactly_its_own_cve():
    confirmation = Confirmation(
        component=LOG4J.purl, cve_id="CVE-2021-44228", rationale="Logs user input."
    )
    vuln = _vuln(aliases=("CVE-2021-44228", "CVE-2021-45046"))
    result = _run(
        [vuln],
        listed=("CVE-2021-44228", "CVE-2021-45046"),
        confirmations=[confirmation],
    )
    assert [item.cve_id for item in result.report] == ["CVE-2021-44228"]
    assert [item.cve_id for item in result.assess] == ["CVE-2021-45046"]


def test_a_report_item_carries_the_rationale_that_put_it_there():
    """The rationale is the audit trail. An item in REPORT without one is a
    claim with nothing behind it."""
    confirmation = Confirmation(
        component=LOG4J.purl,
        cve_id="CVE-2021-44228",
        rationale="The gateway logs the X-Forwarded-For header at INFO.",
        source="dispositions.toml",
    )
    result = _run([_vuln()], confirmations=[confirmation])
    item = result.report[0]
    assert item.rationale == confirmation.rationale
    assert item.confirmed_by == "dispositions.toml"


@pytest.mark.parametrize(
    "spec",
    [
        "log4j-core",
        "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar",
        "log4j-core@2.14.1",
    ],
)
def test_a_confirmation_may_name_the_component_any_of_four_ways(spec):
    """bom-ref, PURL, PURL with qualifiers, or name@version. A user copying an
    identifier out of grype or syft should not lose their confirmation to a
    `?type=jar` that means nothing to identity."""
    result = _run(
        [_vuln()],
        confirmations=[
            Confirmation(component=spec, cve_id="CVE-2021-44228", rationale="Reachable.")
        ],
    )
    assert len(result.report) == 1


def test_a_confirmation_for_another_version_does_not_carry_over():
    """The upgrade that fixes it must not inherit the confirmation that said it
    was live. Falling back to ASSESS is the safe direction, and the warning
    below says so out loud."""
    stale = Confirmation(
        component="pkg:maven/org.apache.logging.log4j/log4j-core@2.13.0",
        cve_id="CVE-2021-44228",
        rationale="Was reachable in 2.13.0.",
    )
    result = _run([_vuln()], confirmations=[stale])
    assert result.report == ()
    assert len(result.assess) == 1
    assert [use.matched_component for use in result.unused] == [False]


def test_a_version_free_bom_ref_does_carry_over():
    """The limit of the rule above, pinned deliberately. A bom-ref identifies
    whatever its author made it identify, and `log4j-core` carries no version,
    so this confirmation survives the upgrade that fixes the CVE. It errs
    towards reporting something already fixed, which is the visible kind of
    wrong -- and it is why the sample config says to prefer the PURL."""
    loose = Confirmation(
        component="log4j-core",
        cve_id="CVE-2021-44228",
        rationale="Reachable through the request logger.",
    )
    result = _run([_vuln()], confirmations=[loose])
    assert len(result.report) == 1
    assert result.unused == ()


def test_a_confirmation_that_matches_nothing_is_said_out_loud():
    """The silent false negative: the user believes it is in REPORT, the tool
    leaves it in ASSESS, and the run exits 1 with nothing saying why."""
    result = _run(
        [_vuln()],
        confirmations=[
            Confirmation(component="typo-core@1.0", cve_id="CVE-2021-44228", rationale="x")
        ],
    )
    text = " ".join(unused_warning(result))
    assert "WARNING" in text
    assert "matched no component" in text
    assert "typo-core@1.0" in text


def test_a_confirmation_standing_down_is_not_a_warning():
    """The component is here and the CVE is not in the catalogue. The config is
    correct and simply does not apply; calling that a problem trains the user
    to ignore the paragraph that matters."""
    result = _run(
        [_vuln(aliases=("CVE-2019-0001",))],
        listed=(),
        confirmations=[
            Confirmation(
                component=LOG4J.purl, cve_id="CVE-2019-0001", rationale="Reachable."
            )
        ],
    )
    text = " ".join(unused_warning(result))
    assert "WARNING" not in text
    assert "did not apply" in text
    assert "not in the KEV catalogue" in text


def test_a_confirmation_that_applied_raises_nothing():
    result = _run(
        [_vuln()],
        confirmations=[
            Confirmation(component=LOG4J.purl, cve_id="CVE-2021-44228", rationale="x")
        ],
    )
    assert result.unused == ()
    assert unused_warning(result) == []


# --- the configuration file -----------------------------------------------


def _config(tmp_path, text, name="dispositions.toml"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_a_config_round_trips(tmp_path):
    path = _config(
        tmp_path,
        """
[[report]]
component = "pkg:maven/acme/a@1.0"
cve = "cve-2021-44228"
rationale = "Reachable from the request path."

[[report]]
component = "b@2.0"
cve = "CVE-2026-0002"
rationale = "Enabled in the shipped profile."
""",
    )
    confirmations = load_confirmations(path)
    assert [c.component for c in confirmations] == ["pkg:maven/acme/a@1.0", "b@2.0"]
    # Normalised, because the catalogue is keyed on upper-case CVE ids and a
    # confirmation that matches on nothing but case is the worst kind of miss.
    assert confirmations[0].cve_id == "CVE-2021-44228"
    assert confirmations[0].source == str(path)


def test_an_absent_config_is_an_error_not_an_empty_list(tmp_path):
    with pytest.raises(Art14Error) as exc:
        load_confirmations(tmp_path / "nope.toml")
    assert "could not be read" in str(exc.value)


def test_unparseable_toml_is_an_error(tmp_path):
    """A config that cannot be read looks exactly like a config with nothing in
    it, and the difference is exit 2 against exit 1 on the one item the user
    cared enough about to write down."""
    with pytest.raises(Art14Error) as exc:
        load_confirmations(_config(tmp_path, "[[report]\ncomponent ="))
    assert "not valid TOML" in str(exc.value)


@pytest.mark.parametrize("key", ["component", "cve", "rationale"])
def test_every_field_is_required(tmp_path, key):
    entry = {
        "component": '"a@1.0"',
        "cve": '"CVE-2021-44228"',
        "rationale": '"Reachable."',
    }
    del entry[key]
    body = "[[report]]\n" + "".join(f"{k} = {v}\n" for k, v in entry.items())
    with pytest.raises(Art14Error) as exc:
        load_confirmations(_config(tmp_path, body))
    assert key in str(exc.value)


def test_an_empty_rationale_is_rejected(tmp_path):
    body = '[[report]]\ncomponent = "a@1.0"\ncve = "CVE-2021-44228"\nrationale = "  "\n'
    with pytest.raises(Art14Error) as exc:
        load_confirmations(_config(tmp_path, body))
    assert "rationale" in str(exc.value)


def test_a_non_cve_identifier_is_rejected(tmp_path):
    """The catalogue is keyed on CVEs. A GHSA here would match nothing and read
    to its author as a confirmation that was honoured."""
    body = (
        '[[report]]\ncomponent = "a@1.0"\ncve = "GHSA-jfh8-c2jp-5v3q"\n'
        'rationale = "Reachable."\n'
    )
    with pytest.raises(Art14Error) as exc:
        load_confirmations(_config(tmp_path, body))
    assert "not a CVE id" in str(exc.value)


def test_a_config_with_no_report_table_is_simply_empty(tmp_path):
    assert load_confirmations(_config(tmp_path, "# nothing here yet\n")) == ()


# --- [[no]]: the other half of the brief ----------------------------------
#
# Section 4 has always ended every brief with "-> NO ... record the rationale,
# that becomes your VEX entry and your audit trail". These are the tests that
# the tool can actually take the record.


def test_a_no_entry_is_read_with_the_same_fields_as_a_report_entry(tmp_path):
    body = (
        '[[no]]\ncomponent = "log4j-core@2.14.1"\ncve = "cve-2021-44228"\n'
        'rationale = "Lookups disabled at build time."\n'
    )
    (entry,) = load_confirmations(_config(tmp_path, body))
    assert entry.verdict == NO
    assert entry.rules_out is True
    assert entry.cve_id == "CVE-2021-44228"
    assert entry.rationale == "Lookups disabled at build time."


def test_a_no_entry_needs_a_rationale_like_every_other_entry(tmp_path):
    body = '[[no]]\ncomponent = "a@1.0"\ncve = "CVE-2021-44228"\n'
    with pytest.raises(Art14Error) as exc:
        load_confirmations(_config(tmp_path, body))
    assert "[[no]]" in str(exc.value)
    assert "rationale" in str(exc.value)


def test_both_tables_can_appear_in_one_file(tmp_path):
    body = (
        '[[report]]\ncomponent = "a@1.0"\ncve = "CVE-2021-44228"\n'
        'rationale = "Reachable."\n\n'
        '[[no]]\ncomponent = "b@2.0"\ncve = "CVE-2021-45046"\n'
        'rationale = "Not reachable."\n'
    )
    entries = load_confirmations(_config(tmp_path, body))
    assert [e.verdict for e in entries] == [REPORT, NO]


def test_a_ruled_out_item_lands_in_no_with_its_reason():
    """In the catalogue, and not reported, because a person decided so."""
    ruling = Confirmation(
        component="log4j-core@2.14.1",
        cve_id="CVE-2021-44228",
        rationale="The logger never sees attacker-controlled input.",
        source="dispositions.toml",
        verdict=NO,
    )
    result = _run([_vuln()], confirmations=(ruling,))
    assert result.report == ()
    assert result.assess == ()
    (item,) = result.no
    assert item.bucket == NO
    assert item.ruled_out is True
    assert item.rationale == ruling.rationale
    # The catalogue entry stays on it. It is in NO because somebody said so,
    # not because the catalogue was silent, and the entry is the difference.
    assert item.entry is not None
    assert result.ruled_out == (item,)


def test_a_ruled_out_item_is_listed_with_its_rationale_never_only_counted():
    ruling = Confirmation(
        component="log4j-core@2.14.1",
        cve_id="CVE-2021-44228",
        rationale="The logger never sees attacker-controlled input.",
        source="dispositions.toml",
        verdict=NO,
    )
    text = "\n".join(disposition_lines(_run([_vuln()], confirmations=(ruling,))))
    assert "CVE-2021-44228 log4j-core@2.14.1" in text
    assert "never sees attacker-controlled input" in text
    assert "dispositions.toml" in text


def test_nothing_ruled_out_prints_nothing():
    assert disposition_lines(_run([_vuln()])) == []


def test_the_no_count_stops_claiming_the_catalogue_was_silent():
    """The bucket holds an item that IS in the catalogue. The label says so by
    saying less: the reasons are listed underneath, one line each."""
    plain = _run([_vuln()])
    assert no_label(plain) == "not in the KEV catalogue"
    ruling = Confirmation(
        component="log4j-core@2.14.1",
        cve_id="CVE-2021-44228",
        rationale="Not reachable.",
        verdict=NO,
    )
    decided = _run([_vuln()], confirmations=(ruling,))
    assert no_label(decided) == "not to report"
    assert "not to report" in "\n".join(counts(decided))


def test_a_ruled_out_item_does_not_hold_the_exit_code_open():
    """Deciding is the point. An item a person ruled out with a reason is not
    an open item, and a run with nothing else open may certify."""
    ruling = Confirmation(
        component="log4j-core@2.14.1",
        cve_id="CVE-2021-44228",
        rationale="Not reachable.",
        verdict=NO,
    )
    result = _run([_vuln()], confirmations=(ruling,))
    assert result.actionable == ()


def test_a_no_entry_that_matches_nothing_is_said_out_loud():
    """The same failure as a REPORT entry that matches nothing, and the same
    treatment: the user believes a decision is recorded and it is not."""
    ruling = Confirmation(
        component="log4j-core@2.20.0",
        cve_id="CVE-2021-44228",
        rationale="Not reachable.",
        verdict=NO,
    )
    result = _run([_vuln()], confirmations=(ruling,))
    assert len(result.unused) == 1
    text = "\n".join(unused_warning(result))
    assert "WARNING" in text
    assert "[NO] log4j-core@2.20.0" in text


def test_a_ruled_out_item_carries_its_rationale_into_the_json():
    ruling = Confirmation(
        component="log4j-core@2.14.1",
        cve_id="CVE-2021-44228",
        rationale="The logger never sees attacker-controlled input.",
        source="dispositions.toml",
        verdict=NO,
    )
    result = _run([_vuln()], confirmations=(ruling,))
    block = as_json(result, _sbom([_vuln()]))
    assert block["counts"]["ruledOut"] == 1
    (row,) = block["ruledOutInConfig"]
    assert row["cve"] == "CVE-2021-44228"
    assert row["rationale"] == ruling.rationale
    assert row["confirmedBy"] == "dispositions.toml"
    # Still not in `items`: that list is what needs a decision, and this one
    # has had one.
    assert block["items"] == []


# --- the decision brief ---------------------------------------------------


def test_the_brief_carries_all_six_fields():
    """Section 4's format, in full. A brief that only says "check this" has
    failed, so both dispositions are part of the count."""
    document = _sbom([_vuln()])
    result = _run([_vuln()], sbom=document)
    text = "\n".join(brief_lines(result.assess[0], document))
    assert "[ASSESS] CVE-2021-44228 - EUVD-2021-0001 - log4j-core@2.14.1" in text
    assert "Where" in text
    assert "CWE-917" in text
    assert "cisa_kev, eu_kev - in catalogue since 2021-12-10" in text
    assert "Question" in text
    assert "-> REPORT" in text
    assert "-> NO" in text


def test_the_brief_shows_the_chain_a_transitive_dependency_arrives_through():
    """Section 4 calls this the first thing a human looks at and the single
    largest factor in the decision."""
    parent = Component(bom_ref="spring", name="spring-boot-starter-web", version="2.4.5")
    location = Location(kind=TRANSITIVE, depth=2, chain=("app", "spring", "log4j-core"))
    vuln = _vuln()
    document = Sbom(
        spec_version="1.5",
        root=ROOT_COMPONENT,
        components=(ROOT_COMPONENT, parent, LOG4J),
        vulnerabilities=(vuln,),
        locations={LOG4J.bom_ref: location},
        findings=(Finding(vulnerability=vuln, component=LOG4J, location=location),),
    )
    result = _run([vuln], sbom=document)
    text = "\n".join(brief_lines(result.assess[0], document))
    assert "transitive, depth 2  <-  spring-boot-starter-web@2.4.5" in text
    assert "arrives through spring-boot-starter-web@2.4.5" in text


def test_a_direct_dependency_does_not_arrive_through_the_root():
    """The header already names the product. "direct dependency <- the product"
    is noise in the field a human reads first."""
    document = _sbom([_vuln()])
    result = _run([_vuln()], sbom=document)
    text = "\n".join(brief_lines(result.assess[0], document))
    assert "Where      direct dependency" in text
    assert "<-" not in text


def test_the_question_names_the_component_and_is_answerable():
    document = _sbom([_vuln()])
    result = _run([_vuln()], sbom=document)
    text = "\n".join(brief_lines(result.assess[0], document))
    question = text.split("Question")[1].split("-> REPORT")[0]
    assert "log4j-core@2.14.1" in question
    assert question.strip().endswith("?")
    # CWE-917: the question turns on configuration, not only on input handling.
    assert "lookup evaluation" in " ".join(question.split())


def test_a_record_with_nothing_on_it_still_produces_a_usable_brief():
    """The degenerate case, and the one most likely in the wild: OSV fills
    neither summary nor cwe_ids. The brief must still name the component and
    ask something answerable rather than print a blank field."""
    vuln = Vulnerability(
        id="CVE-2026-0007",
        aliases=(),
        affects=(LOG4J.bom_ref,),
        description=None,
        cwes=(),
        source_name="OSV",
    )
    document = _sbom([vuln])
    catalogue = Catalogue({"CVE-2026-0007": KevEntry(cve_id="CVE-2026-0007")})
    result = triage(document, kev_review(document.vulnerabilities, catalogue))
    text = "\n".join(brief_lines(result.assess[0], document))
    assert "no description and no CWE on OSV" in text
    assert "CVE-2026-0007" in text
    assert "log4j-core@2.14.1" in text
    # Still a real question, not a placeholder.
    assert "affected functionality enabled in the shipped configuration" in text
    # No dateAdded on this entry, and the field says so rather than going blank.
    assert "date added not stated" in text


def test_a_report_brief_states_the_rationale_rather_than_asking():
    confirmation = Confirmation(
        component=LOG4J.purl,
        cve_id="CVE-2021-44228",
        rationale="The gateway logs untrusted headers at INFO.",
        source="dispositions.toml",
    )
    document = _sbom([_vuln()])
    result = _run([_vuln()], sbom=document, confirmations=[confirmation])
    text = "\n".join(brief_lines(result.report[0], document))
    assert "[REPORT]" in text
    assert "The gateway logs untrusted headers at INFO." in text
    assert "stated in dispositions.toml" in text
    assert "Question" not in text


def test_the_catalogue_date_is_never_presented_as_a_countdown():
    """The clock runs from when the manufacturer became aware. The first user
    who reads a 2021 date as a deadline thinks they are five years late."""
    document = _sbom([_vuln()])
    confirmation = Confirmation(
        component=LOG4J.purl, cve_id="CVE-2021-44228", rationale="Reachable."
    )
    result = _run([_vuln()], sbom=document, confirmations=[confirmation])
    text = " ".join("\n".join(brief_lines(result.report[0], document)).split())
    assert "in catalogue since 2021-12-10" in text
    assert "not from the catalogue date above" in text


def test_the_brief_never_mentions_epss():
    """Banned as a trigger, and absent from the tool entirely -- printing it
    beside a verdict is how it becomes one."""
    vuln = _vuln(ratings=(Rating(method="CVSSv31", score=10.0, severity="critical"),))
    document = _sbom([vuln])
    result = _run([vuln], sbom=document)
    text = "\n".join(brief_lines(result.assess[0], document)).lower()
    assert "epss" not in text
    assert "cvss 10.0" in text


def test_severity_survives_in_the_brief_and_the_json():
    """The table dropped the column; these two views are what is left.

    Section 6 took severity off the skim surface and said nothing was lost,
    which is only true for as long as the reader who stops skimming can
    still find it. Both shapes: the publisher's band, and a computed score
    where there is one.
    """
    vuln = _vuln(ratings=(Rating(method="CVSSv31", score=10.0, severity="critical"),))
    document = _sbom([vuln])
    result = _run([vuln], sbom=document)
    text = "\n".join(brief_lines(result.assess[0], document))
    assert "critical" in text
    assert "CVSS 10.0" in text
    item = as_json(result, document)["items"][0]
    assert item["severity"] == "critical"


def test_the_json_carries_the_vector_the_brief_shows():
    """The main path has no computed score, so the vector is the context.

    OSV publishes a vector and leaves the arithmetic to the reader. A
    consumer reading `cvss: null` where the brief printed a vector would be
    the one place the two views could be said to disagree, and the README
    tells a CI integrator they do not.
    """
    vuln = _vuln(
        ratings=(
            Rating(
                method="CVSSv31",
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                severity="critical",
            ),
        )
    )
    document = _sbom([vuln])
    result = _run([vuln], sbom=document)
    text = "\n".join(brief_lines(result.assess[0], document))
    assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" in text
    item = as_json(result, document)["items"][0]
    assert item["cvss"] is None
    assert item["cvssVector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert item["severity"] == "critical"


def test_the_brief_carries_no_emoji():
    document = _sbom([_vuln()])
    result = _run([_vuln()], sbom=document)
    text = "\n".join(brief_lines(result.assess[0], document))
    assert all(ord(char) < 0x2190 for char in text)


# --- counts and JSON ------------------------------------------------------


def test_the_no_bucket_is_one_line_never_rows():
    """Listing it row by row is noise and it buries the two buckets that
    decide anything."""
    absent = [_vuln(f"GHSA-{n}", aliases=(f"CVE-2019-000{n}",)) for n in range(1, 4)]
    result = _run(absent, listed=())
    lines = counts(result)
    assert sum(1 for line in lines if "NO " in line) == 1
    assert any(line.split()[:2] == ["NO", "3"] for line in lines)


def test_json_carries_every_brief_field():
    """Section 6: the JSON includes all brief fields, so a consumer never has
    to reproduce the wording and drift from it."""
    document = _sbom([_vuln()])
    result = _run([_vuln()], sbom=document)
    block = as_json(result, document)
    assert block["available"] is True
    assert block["counts"] == {
        "report": 0,
        "assess": 1,
        "no": 0,
        "unassessed": 0,
        "ruledOut": 0,
        "suppressed": 0,
    }
    item = block["items"][0]
    assert item["bucket"] == ASSESS
    assert item["cve"] == "CVE-2021-44228"
    assert item["euvd"] == "EUVD-2021-0001"
    assert item["bomRef"] == "log4j-core"
    assert item["component"] == "log4j-core@2.14.1"
    assert item["sources"] == ["cisa_kev", "eu_kev"]
    assert item["dateAdded"] == "2021-12-10"
    assert item["cwes"] == [917]
    assert "CWE-917" in item["what"]
    assert "in catalogue since" in item["signal"]
    assert item["question"].endswith("?")
    assert item["osvIds"] == ["GHSA-jfh8-c2jp-5v3q"]


def test_json_omits_the_no_bucket_from_items_but_not_from_counts():
    document = _sbom([_vuln(), _vuln("GHSA-z", aliases=("CVE-2019-0001",))])
    result = _run(document.vulnerabilities, sbom=document)
    block = as_json(result, document)
    assert block["counts"]["no"] == 1
    assert [item["bucket"] for item in block["items"]] == [ASSESS]


def test_json_lists_unused_confirmations_with_their_cause():
    document = _sbom([_vuln()])
    result = _run(
        [_vuln()],
        sbom=document,
        confirmations=[
            Confirmation(component="ghost@1.0", cve_id="CVE-2021-44228", rationale="x")
        ],
    )
    unused = as_json(result, document)["unusedConfirmations"]
    assert unused[0]["component"] == "ghost@1.0"
    assert unused[0]["matchedComponent"] is False
    assert "no component in this SBOM" in unused[0]["reason"]


def test_json_without_a_catalogue_is_shaped_like_every_other_run():
    """`available` false is not "nothing was reportable": nothing was asked."""
    block = as_json(None)
    assert block["available"] is False
    assert block["counts"] == {
        "report": 0,
        "assess": 0,
        "no": 0,
        "unassessed": 0,
        "ruledOut": 0,
        "suppressed": 0,
    }
    assert block["items"] == []
    assert counts(None) == []
    assert unused_warning(None) == []


def test_report_precedes_assess_everywhere():
    """Precedence is the same in every ordering the tool produces."""
    other = Component(
        bom_ref="log4j-api", name="log4j-api", version="2.14.1", purl="pkg:maven/a/b@1"
    )
    vuln = Vulnerability(
        id="GHSA-x", aliases=("CVE-2021-44228",), affects=("log4j-core", "log4j-api")
    )
    location = Location(kind=DIRECT, depth=1, chain=("app", "log4j-core"))
    document = Sbom(
        spec_version="1.5",
        root=ROOT_COMPONENT,
        components=(ROOT_COMPONENT, LOG4J, other),
        vulnerabilities=(vuln,),
        locations={LOG4J.bom_ref: location, other.bom_ref: location},
        findings=(
            Finding(vulnerability=vuln, component=other, location=location),
            Finding(vulnerability=vuln, component=LOG4J, location=location),
        ),
    )
    result = _run(
        [vuln],
        sbom=document,
        confirmations=[
            Confirmation(component=LOG4J.purl, cve_id="CVE-2021-44228", rationale="x")
        ],
    )
    assert [item.bucket for item in result.actionable] == [REPORT, ASSESS]
    assert [i["bucket"] for i in as_json(result, document)["items"]] == [REPORT, ASSESS]
    assert result.no == ()
    assert NO not in [item.bucket for item in result.actionable]

# --- the SBOM's own claim about itself ------------------------------------


def test_an_upstream_not_affected_claim_does_not_move_the_item():
    """The default, and the reason the flag exists. Honouring the claim
    silently would make art14 a laundering channel: an upstream tool asserts
    not_affected, the run prints NO, and nobody in the room ever reasoned
    about it. Same failure mode as an unmatched component reading as clean,
    one layer up."""
    result = _run([_vuln(analysis=NOT_AFFECTED)])
    assert [item.cve_id for item in result.assess] == ["CVE-2021-44228"]
    assert result.no == ()
    assert result.suppressed == ()


def test_the_claim_is_visible_in_the_brief_and_marked_unverified():
    """Not acted on is not the same as not shown. The reader has to be able to
    see that somebody made the claim, who, and that this run did not check
    it."""
    result = _run([_vuln(analysis=NOT_AFFECTED)])
    text = "\n".join(brief_lines(result.assess[0], _sbom([])))
    assert "Upstream" in text
    assert "not_affected (code_not_reachable)" in text
    assert "grype 0.100.0" in text
    assert "Unverified" in text
    # And the disposition says what adopting it would mean, rather than
    # leaving the reader to discover the flag in --help.
    assert "--adopt-upstream-vex" in text


def test_the_claim_reaches_json_on_an_item_that_was_not_adopted():
    result = _run([_vuln(analysis=NOT_AFFECTED)])
    claim = as_json(result, _sbom([]))["items"][0]["upstreamClaim"]
    assert claim["state"] == "not_affected"
    assert claim["justification"] == "code_not_reachable"
    assert claim["assertedBy"] == "grype 0.100.0"
    assert claim["adopted"] is False
    assert claim["adoptable"] is True


def test_an_sbom_with_no_claim_says_so_with_null_rather_than_a_missing_key():
    """Same discipline as the provenance block: absent is null, so a diff
    between two runs shows a claim appearing, not the schema changing."""
    result = _run([_vuln()])
    assert as_json(result, _sbom([]))["items"][0]["upstreamClaim"] is None


# --- adopting it, on the record -------------------------------------------


def test_adopting_the_claim_moves_the_item_to_no():
    result = _run([_vuln(analysis=NOT_AFFECTED)], adopt_upstream_vex=True)
    assert result.assess == ()
    assert [item.cve_id for item in result.no] == ["CVE-2021-44228"]
    assert result.no[0].suppressed_by is NOT_AFFECTED


def test_a_suppressed_item_keeps_its_catalogue_entry():
    """It is in NO because somebody said so, not because the catalogue was
    silent. Dropping the entry would erase the difference between the two, and
    the difference is the whole point of recording the suppression."""
    result = _run([_vuln(analysis=NOT_AFFECTED)], adopt_upstream_vex=True)
    assert result.no[0].entry is ENTRY


def test_a_suppression_is_never_only_a_number():
    """NO is summarised in one line everywhere else. A suppression folded into
    that line is invisible, which would make the flag worse than not having
    it."""
    result = _run([_vuln(analysis=NOT_AFFECTED)], adopt_upstream_vex=True)
    summary = "\n".join(counts(result))
    assert "suppressed" in summary
    lines = "\n".join(suppression_lines(result))
    assert "CVE-2021-44228" in lines
    assert "log4j-core@2.14.1" in lines
    assert "grype 0.100.0" in lines
    assert "code_not_reachable" in lines


def test_the_suppression_record_reaches_json_in_full():
    result = _run([_vuln(analysis=NOT_AFFECTED)], adopt_upstream_vex=True)
    block = as_json(result, _sbom([]))
    assert block["counts"]["suppressed"] == 1
    # A subset of NO, not an addition to it.
    assert block["counts"]["no"] == 1
    record = block["suppressedByUpstreamVex"][0]
    assert record["cve"] == "CVE-2021-44228"
    assert record["component"] == "log4j-core@2.14.1"
    assert record["justification"] == "code_not_reachable"
    assert record["assertedBy"] == "grype 0.100.0"
    assert record["detail"] == NOT_AFFECTED.detail


def test_only_not_affected_is_adoptable():
    """`false_positive` is a statement about the scan, and `resolved`
    contradicts the version the SBOM itself reports. Neither is a claim this
    tool converts into "nothing to report" on someone else's behalf, so the
    flag leaves them in ASSESS and the brief says why."""
    for state in ("false_positive", "resolved", "resolved_with_pedigree", "exploitable"):
        claim = VexClaim(state=state, asserted_by="grype 0.100.0")
        result = _run([_vuln(analysis=claim)], adopt_upstream_vex=True)
        assert [item.cve_id for item in result.assess] == ["CVE-2021-44228"], state
        assert result.suppressed == ()
        text = "\n".join(brief_lines(result.assess[0], _sbom([])))
        assert "not adoptable" in text


def test_a_confirmation_beats_an_upstream_claim():
    """The operator wrote a sentence about their own product; the scanner made
    a statement about somebody's. An item the user confirmed must never vanish
    into NO because a flag happened to be on."""
    confirmation = Confirmation(
        component=LOG4J.purl,
        cve_id="CVE-2021-44228",
        rationale="Reachable through the request logger.",
    )
    result = _run(
        [_vuln(analysis=NOT_AFFECTED)],
        confirmations=[confirmation],
        adopt_upstream_vex=True,
    )
    assert [item.cve_id for item in result.report] == ["CVE-2021-44228"]
    assert result.suppressed == ()
    text = "\n".join(brief_lines(result.report[0], _sbom([])))
    assert "wins" in text


def test_the_flag_changes_nothing_without_a_claim():
    result = _run([_vuln()], adopt_upstream_vex=True)
    assert [item.cve_id for item in result.assess] == ["CVE-2021-44228"]
    assert suppression_lines(result) == []


def test_a_flag_that_did_nothing_says_so():
    """The inverse of the failure the default guards against. On the ordinary
    path the vulnerabilities came from OSV and carry no claims at all, so the
    flag is a no-op -- and an operator who believes their VEX pipeline was
    honoured, on a run where it was not, is worse off than one who never
    passed the flag."""
    result = _run([_vuln()], adopt_upstream_vex=True)
    text = " ".join(suppression_lines(result, requested=True))
    assert "nothing was suppressed" in text
    assert "no vulnerability in this SBOM carries" in text


def test_a_claim_that_was_not_adoptable_says_that_instead():
    """Different cause, different sentence: there was something to act on and
    the tool declined, which is a decision the reader should be able to see
    rather than infer from silence."""
    claim = VexClaim(state="false_positive", asserted_by="grype 0.100.0")
    result = _run([_vuln(analysis=claim)], adopt_upstream_vex=True)
    text = " ".join(suppression_lines(result, requested=True))
    assert "this SBOM carries 1 claim(s)" in text
    assert "Only not_affected is adopted" in text


def test_a_claim_on_a_record_with_no_cve_is_still_unassessed():
    """An `analysis` block does not make a record checkable. Without a CVE the
    catalogue was never asked, so the item is a coverage statement and not a
    NO -- and the flag must not turn one into the other by the back door."""
    vuln = _vuln(aliases=(), analysis=NOT_AFFECTED)
    result = _run([vuln], adopt_upstream_vex=True)
    assert [f.vulnerability.id for f in result.unassessed] == [vuln.id]
    assert result.no == ()
    assert result.suppressed == ()
