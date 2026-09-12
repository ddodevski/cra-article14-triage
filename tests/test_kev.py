"""Layer 2 tests.

Almost everything here pins a failure that does not raise. The join between the
two layers is on a key neither layer shares with the other, an unreachable
catalogue looks exactly like an empty one, and a vulnerability with no CVE
looks exactly like a vulnerability the catalogue has never heard of. All three
produce a clean, plausible, completely wrong run -- so all three are tested for
the shape of the mistake, not just for the happy path.
"""

from __future__ import annotations

import json
import time


import httpx
import pytest

from art14.cache import Cache
from art14.kev import (
    CatalogueUnavailable,

    KevClient,
    Review,
    banner_line,
    parse_dump,
    review,
    summary_lines,
    uncheckable_warning,
)
from art14.models import Vulnerability
from art14.provenance import KEV_MAX_AGE
from tests.conftest import kev_handler

# The real ids. The whole demo turns on these two being the same vulnerability
# under two names, so the test uses the real pair rather than a made-up one.
LOG4SHELL_GHSA = "GHSA-jfh8-c2jp-5v3q"
LOG4SHELL_CVE = "CVE-2021-44228"

DUMP = [
    {
        "cveId": LOG4SHELL_CVE,
        "euvdId": "EUVD-2021-0001",
        "dateAdded": "2021-12-10",
        "sources": ["cisa_kev", "eu_kev"],
    }
]


def _catalogue(payload=None):
    return parse_dump(DUMP if payload is None else payload)


def _client(handler, cache=None, **kwargs):
    return KevClient(
        cache, transport=httpx.MockTransport(handler), **kwargs
    )


# --- parsing the dump -----------------------------------------------------
#
# The response shape is inferred from the field names in section 3, so these
# are the working specification. A real response that disagrees belongs here.


def test_a_bare_array_parses():
    catalogue = parse_dump(DUMP)
    assert len(catalogue) == 1
    assert catalogue.get(LOG4SHELL_CVE).euvd_id == "EUVD-2021-0001"


def test_an_array_wrapped_in_an_envelope_parses():
    catalogue = parse_dump({"total": 1, "items": DUMP})
    assert LOG4SHELL_CVE in catalogue


def test_the_only_list_in_an_envelope_is_the_dump_whatever_it_is_called():
    # The field name is not documented. Guessing wrong would empty the
    # catalogue, and an empty catalogue answers "not listed" to everything.
    catalogue = parse_dump({"count": 1, "vulnerabilitiesSomething": DUMP})
    assert LOG4SHELL_CVE in catalogue


def test_a_known_key_wins_when_an_envelope_holds_several_lists():
    catalogue = parse_dump({"warnings": [], "items": DUMP, "links": ["x"]})
    assert LOG4SHELL_CVE in catalogue


def test_sources_survive_as_a_delimited_string():
    # Section 3 shows an array. A single-source record serialised as a bare
    # string is the obvious way for this to vary, and `sources` is the part of
    # the output that says where the signal came from.
    catalogue = parse_dump([{"cveId": LOG4SHELL_CVE, "sources": "cisa_kev, eu_kev"}])
    assert catalogue.get(LOG4SHELL_CVE).sources == ("cisa_kev", "eu_kev")


def test_alternative_field_spellings_are_accepted():
    catalogue = parse_dump([{"cve_id": LOG4SHELL_CVE, "date_added": "2021-12-10"}])
    assert catalogue.get(LOG4SHELL_CVE).date_added == "2021-12-10"


def test_a_record_with_no_cve_is_skipped_rather_than_fatal():
    catalogue = parse_dump([{"euvdId": "EUVD-1"}, *DUMP])
    assert len(catalogue) == 1


def test_a_non_cve_identifier_is_not_treated_as_a_cve():
    catalogue = parse_dump([{"cveId": "GHSA-xxxx"}, *DUMP])
    assert len(catalogue) == 1


def test_the_same_cve_listed_twice_keeps_both_catalogues():
    catalogue = parse_dump(
        [
            {"cveId": LOG4SHELL_CVE, "dateAdded": "2021-12-10", "sources": ["cisa_kev"]},
            {"cveId": LOG4SHELL_CVE, "dateAdded": "2022-01-01", "sources": ["eu_kev"]},
        ]
    )
    entry = catalogue.get(LOG4SHELL_CVE)
    assert entry.sources == ("cisa_kev", "eu_kev")
    # `dateAdded` is upstream's earliest-across-sources field; re-deriving it
    # here would be second-guessing them on their own data.
    assert entry.date_added == "2021-12-10"


def test_lookup_is_case_insensitive():
    catalogue = parse_dump([{"cveId": "cve-2021-44228"}])
    assert catalogue.get(LOG4SHELL_CVE) is not None
    assert LOG4SHELL_CVE.lower() in catalogue


@pytest.mark.parametrize("payload", [[], {}, {"items": []}, [{"euvdId": "x"}], "nope"])
def test_a_dump_yielding_nothing_is_unavailable_not_empty(payload):
    """The single most likely way this ships broken.

    An empty catalogue and an unreachable one have identical effects: every CVE
    comes back not listed, and the run certifies the whole inventory as
    unexploited. So a dump that parses to nothing fails exactly as a failed
    fetch does.
    """
    with pytest.raises(CatalogueUnavailable):
        parse_dump(payload)


def test_a_dump_shorter_than_it_declares_is_a_page_not_a_catalogue():
    """The quieter cousin of the empty dump, and a worse one.

    If the endpoint ever paginates, one page unwraps into a catalogue that is
    the right shape, parses without complaint, and answers "not listed" for
    every CVE that did not fit on it. A short catalogue is not visibly wrong
    the way an empty one is, so the count it declares is the only thing that
    can catch it.
    """
    with pytest.raises(CatalogueUnavailable) as excinfo:
        parse_dump({"total": 5000, "items": [{"cveId": LOG4SHELL_CVE}]})
    message = str(excinfo.value)
    # Both numbers, because "the catalogue is incomplete" is not actionable
    # and "declared 5000, carried 1" is.
    assert "5000" in message and "1" in message


@pytest.mark.parametrize(
    "payload",
    [
        {"total": 1, "items": [{"cveId": LOG4SHELL_CVE}]},
        # Complete, and counted in a framing where the page size sits next to
        # the total. Nothing is missing, so nothing is raised.
        {"size": 1, "totalElements": 1, "content": [{"cveId": LOG4SHELL_CVE}]},
        # More records than declared. Odd, but nothing is missing, and failing
        # a run over a miscounted header we can see past would be its own bug.
        {"total": 0, "items": [{"cveId": LOG4SHELL_CVE}]},
        # No count at all: the documented shape, taken at face value.
        [{"cveId": LOG4SHELL_CVE}],
    ],
)
def test_a_complete_dump_passes_the_count_check(payload):
    assert LOG4SHELL_CVE in parse_dump(payload)


def test_a_page_size_alone_does_not_condemn_a_full_dump():
    """`size` next to a larger total must not be read as the total.

    The largest declared count is the one that has to be satisfied; reading the
    first key found would let a paginated response through whenever its page
    size happened to be listed first.
    """
    page = [{"cveId": f"CVE-2026-{n:04d}"} for n in range(20)]
    with pytest.raises(CatalogueUnavailable):
        parse_dump({"size": 20, "number": 0, "totalElements": 5000, "content": page})


def test_a_flag_is_not_a_count():
    """`bool` is an `int` in Python, and `{"total": True}` would otherwise
    declare one entry."""
    dump = [{"cveId": LOG4SHELL_CVE}, {"cveId": "CVE-2026-0002"}]
    assert len(parse_dump({"count": True, "items": dump})) == 2


# --- the join -------------------------------------------------------------


def test_the_log4j_record_resolves_its_ghsa_to_a_cve_and_hits_the_catalogue():
    """The pin. OSV calls it GHSA-jfh8-c2jp-5v3q, the catalogue calls it
    CVE-2021-44228, and the CVE is only in `aliases`."""
    vulnerability = Vulnerability(
        id=LOG4SHELL_GHSA, aliases=(LOG4SHELL_CVE,), affects=("log4j-core",)
    )
    result = review([vulnerability], _catalogue())

    assert [e.cve_id for e in result.listed] == [LOG4SHELL_CVE]
    entry = result.listed[0].entry
    assert entry.sources == ("cisa_kev", "eu_kev")
    # The trail back to where the CVE came from, kept for display.
    assert result.listed[0].osv_ids == (LOG4SHELL_GHSA,)
    assert result.listed[0].component_refs == ("log4j-core",)
    assert result.uncheckable == ()


def test_the_osv_id_itself_is_not_a_catalogue_key():
    """The bug this module is shaped around, asserted directly.

    Joining on the OSV id matches nothing and raises nothing. Without this
    test the Log4j demo runs clean and looks entirely plausible.
    """
    catalogue = _catalogue()
    assert catalogue.get(LOG4SHELL_GHSA) is None
    assert LOG4SHELL_GHSA not in catalogue


def test_one_cve_reached_through_two_osv_records_is_one_exposure():
    # One CVE is one obligation, however many records carry it. Bucketing on
    # anything but the CVE would double count it.
    records = [
        Vulnerability(id=LOG4SHELL_GHSA, aliases=(LOG4SHELL_CVE,), affects=("a",)),
        Vulnerability(id="OSV-2021-1", aliases=(LOG4SHELL_CVE,), affects=("b",)),
    ]
    result = review(records, _catalogue())

    assert result.checked == 1
    exposure = result.exposures[0]
    assert exposure.osv_ids == (LOG4SHELL_GHSA, "OSV-2021-1")
    assert exposure.component_refs == ("a", "b")


def test_one_osv_record_carrying_two_cves_is_two_exposures():
    catalogue = parse_dump(
        [*DUMP, {"cveId": "CVE-2021-45046", "sources": ["eu_kev"]}]
    )
    records = [
        Vulnerability(
            id=LOG4SHELL_GHSA, aliases=(LOG4SHELL_CVE, "CVE-2021-45046")
        )
    ]
    result = review(records, catalogue)

    assert [e.cve_id for e in result.exposures] == [LOG4SHELL_CVE, "CVE-2021-45046"]
    assert all(e.is_listed for e in result.exposures)


def test_a_record_with_no_cve_is_uncheckable_and_never_absent():
    """NO means checked against the catalogue and absent. This was not."""
    records = [
        Vulnerability(id="GHSA-only-1", affects=("a",)),
        Vulnerability(id=LOG4SHELL_GHSA, aliases=(LOG4SHELL_CVE,)),
    ]
    result = review(records, _catalogue())

    assert [u.vuln_id for u in result.uncheckable] == ["GHSA-only-1"]
    assert result.uncheckable[0].component_refs == ("a",)
    # The distinction the whole category exists for.
    assert [e.cve_id for e in result.absent] == []
    assert result.checked == 1


def test_the_uncheckable_paragraph_agrees_with_its_own_count():
    """One of them is `it`, two of them are `them`.

    The count already branched; the three pronouns after the first clause did
    not, so a single uncheckable record produced "1 vulnerability ... asked
    about them". This paragraph is the one that has to persuade a reader not
    to read a gap as a clean result, and a sentence that does not agree with
    itself reads as generated rather than meant.
    """
    one = review([Vulnerability(id="GHSA-only-1")], _catalogue())
    text = uncheckable_warning(one)
    assert text.startswith("1 vulnerability carries no CVE id")
    assert "asked about it." in text
    assert "It is not absent" in text
    assert "Treat it as unassessed" in text
    assert "them" not in text and "They" not in text
    assert banner_line(one).strip().startswith("1 vulnerability with no CVE id")

    two = review(
        [Vulnerability(id="GHSA-only-1"), Vulnerability(id="GHSA-only-2")],
        _catalogue(),
    )
    text = uncheckable_warning(two)
    assert text.startswith("2 vulnerabilities carry no CVE id")
    assert "asked about them." in text
    assert "They are not absent" in text
    assert "Treat them as unassessed" in text
    assert banner_line(two).strip().startswith("2 vulnerabilities with no CVE id")


def test_a_cve_the_catalogue_does_not_list_is_absent():
    result = review([Vulnerability(id="CVE-2026-9999")], _catalogue())
    assert [e.cve_id for e in result.absent] == ["CVE-2026-9999"]
    assert result.listed == ()
    assert result.uncheckable == ()


def test_a_cve_in_the_id_field_is_used_directly():
    result = review([Vulnerability(id=LOG4SHELL_CVE)], _catalogue())
    assert result.listed[0].osv_ids == (LOG4SHELL_CVE,)


# --- which unit the number is in ------------------------------------------
#
# The block changes unit on its way down: records, then component-CVE pairs,
# then distinct CVE ids here, then pairs again in the buckets. Every
# transition is correct and none is visible, so a reader does the arithmetic
# between two adjacent lines and it does not work.


def test_the_listed_line_names_both_units():
    """One CVE over two components is one id and two pairs. The buckets
    under this line count the pairs, so this line says both numbers."""
    records = [
        Vulnerability(
            id=LOG4SHELL_GHSA,
            aliases=(LOG4SHELL_CVE,),
            affects=("pkg:maven/a@1", "pkg:maven/b@1"),
        )
    ]
    result = review(records, _catalogue())
    assert len(result.listed) == 1
    assert result.listed_pairs == 2

    lines = summary_lines(result)
    assert "distinct CVE ids listed in the catalogue," in lines[1]
    assert lines[2].strip() == "across 2 component-CVE pairs)"
    # Aligned under the note column of the line it belongs to, not indented
    # arbitrarily: the two lines are one sentence.
    assert lines[2].index("across") == lines[1].index("(distinct")


def test_a_zero_needs_no_second_unit():
    """Nothing listed is nothing to reconcile, and "across 0 pairs" is a
    clause that makes a reader stop."""
    lines = summary_lines(review([Vulnerability(id="CVE-2026-9999")], _catalogue()))
    assert lines[1].endswith("(distinct CVE ids listed in the catalogue)")
    assert len(lines) == 2


def test_the_pair_count_reaches_the_json():
    """A consumer comparing kev.listed with triage.counts.assess is comparing
    CVE ids with pairs. Both are in the payload."""
    records = [
        Vulnerability(
            id=LOG4SHELL_GHSA,
            aliases=(LOG4SHELL_CVE,),
            affects=("pkg:maven/a@1", "pkg:maven/b@1"),
        )
    ]
    payload = review(records, _catalogue()).as_json()
    assert payload["listed"] == 1
    assert payload["listedPairs"] == 2


def test_the_json_shape_counts_all_three_categories():
    records = [
        Vulnerability(id=LOG4SHELL_GHSA, aliases=(LOG4SHELL_CVE,)),
        Vulnerability(id="CVE-2026-9999"),
        Vulnerability(id="GHSA-only-1"),
    ]
    payload = review(records, _catalogue()).as_json()

    assert payload["checked"] == 2
    assert payload["listed"] == 1
    assert payload["absent"] == 1
    assert payload["uncheckable"] == 1
    assert payload["uncheckableVulnerabilities"] == [
        {"id": "GHSA-only-1", "bomRefs": []}
    ]


def test_an_empty_review_is_shaped_like_a_full_one():
    # The CLI emits this when there was no catalogue, so a consumer reads
    # `kev.available` rather than testing for missing keys.
    assert set(Review().as_json()) == set(
        review([Vulnerability(id=LOG4SHELL_CVE)], _catalogue()).as_json()
    )


# --- fetching and caching -------------------------------------------------


def test_a_fresh_cache_is_used_without_touching_the_network(tmp_path):
    cache = Cache(tmp_path)
    calls = []
    with _client(kev_handler(DUMP, calls=calls), cache) as client:
        client.load()
    assert len(calls) == 1

    calls.clear()
    with _client(kev_handler(DUMP, calls=calls), cache) as client:
        load = client.load()
    assert calls == []
    assert load.fetched_at is None
    assert load.cache_age_seconds is not None
    assert LOG4SHELL_CVE in load.catalogue


def test_a_successful_fetch_is_stored(tmp_path):
    cache = Cache(tmp_path)
    with _client(kev_handler(DUMP), cache) as client:
        client.load()
    assert cache.get("euvd", "kev") is not None


def test_an_unusable_response_is_not_cached(tmp_path):
    # Caching a dump that parses to nothing would make every later run fail
    # closed for a day, on a payload we already know we cannot read.
    cache = Cache(tmp_path)
    with _client(kev_handler([]), cache) as client:
        with pytest.raises(CatalogueUnavailable):
            client.load()
    assert cache.get("euvd", "kev") is None


def test_a_stale_cache_is_refreshed(tmp_path):
    cache = Cache(tmp_path)
    cache.store("euvd", "kev", DUMP)
    _age(cache, KEV_MAX_AGE + 60)

    updated = [*DUMP, {"cveId": "CVE-2026-0001", "sources": ["eu_kev"]}]
    with _client(kev_handler(updated), cache) as client:
        load = client.load()

    assert load.fetched_at is not None
    assert "CVE-2026-0001" in load.catalogue


def test_a_stale_cache_is_served_when_the_refresh_fails(tmp_path):
    """Used, and audibly so. The staleness travels with it in the stamp."""
    cache = Cache(tmp_path)
    cache.store("euvd", "kev", DUMP)
    _age(cache, KEV_MAX_AGE + 60)

    with _client(_broken, cache) as client:
        load = client.load()

    assert load.fetched_at is None
    assert load.cache_age_seconds > KEV_MAX_AGE
    assert LOG4SHELL_CVE in load.catalogue


def test_a_stale_cache_outranks_a_response_we_cannot_read(tmp_path):
    """Yesterday's catalogue beats today's garbage.

    A 200 carrying an unreadable or truncated dump is not a better answer than
    no answer at all, so it is treated as the failed fetch it effectively is
    and the stale copy is served -- carrying its age, as always. Discarding a
    usable cache because the wire said 200 would invert the ordering the rest
    of this module keeps.
    """
    cache = Cache(tmp_path)
    cache.store("euvd", "kev", DUMP)
    _age(cache, KEV_MAX_AGE + 60)

    with _client(kev_handler({"total": 5000, "items": []}), cache) as client:
        load = client.load()

    assert load.fetched_at is None
    assert LOG4SHELL_CVE in load.catalogue
    # And the bad payload did not overwrite the good one.
    assert LOG4SHELL_CVE in parse_dump(cache.get("euvd", "kev").payload)


def test_a_failed_fetch_with_no_cache_fails_closed(tmp_path):
    """Absence of a catalogue is never absence of exploitation."""
    with _client(_broken, Cache(tmp_path)) as client:
        with pytest.raises(CatalogueUnavailable) as excinfo:
            client.load()
    assert "could not be fetched" in str(excinfo.value)


def test_an_error_status_fails_closed(tmp_path):
    with _client(kev_handler(DUMP, status=503), Cache(tmp_path)) as client:
        with pytest.raises(CatalogueUnavailable):
            client.load()


def test_offline_with_no_cache_fails_closed(tmp_path):
    with _client(_broken, Cache(tmp_path), offline=True) as client:
        with pytest.raises(CatalogueUnavailable) as excinfo:
            client.load()
    assert "--offline" in str(excinfo.value)


def test_offline_serves_a_stale_cache_without_opening_a_socket(tmp_path):
    cache = Cache(tmp_path)
    cache.store("euvd", "kev", DUMP)
    _age(cache, KEV_MAX_AGE + 60)

    calls = []
    with _client(kev_handler(DUMP, calls=calls), cache, offline=True) as client:
        load = client.load()

    assert calls == []
    assert load.fetched_at is None
    assert load.cache_age_seconds > KEV_MAX_AGE


def test_a_corrupt_cache_entry_is_a_miss_not_an_error(tmp_path):
    cache = Cache(tmp_path)
    cache.store("euvd", "kev", {"items": []})
    with _client(kev_handler(DUMP), cache) as client:
        load = client.load()
    assert load.fetched_at is not None
    assert LOG4SHELL_CVE in load.catalogue


def _broken(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("no route to host")


def _age(cache: Cache, seconds: float) -> None:
    """Backdate an entry in place.

    The cache reads its own `storedAt`, not the file's mtime, so that is what
    moves. Rewriting the record beats shifting the clock globally: these tests
    also assert on `fetched_at`, and a monkeypatched `time.time` would move
    both ends of the comparison at once.
    """
    path = cache.path_for("euvd", "kev")
    record = json.loads(path.read_text(encoding="utf-8"))
    record["storedAt"] = time.time() - seconds
    path.write_text(json.dumps(record), encoding="utf-8")
