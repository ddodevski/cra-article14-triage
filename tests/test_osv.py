"""Layer 1 tests.

Three of these pin things that would otherwise fail silently and look like a
clean result: index alignment, the version-or-versioned-purl rule, and the
treatment of a lookup that did not complete. A matching bug does not raise --
it returns fewer CVEs, which is indistinguishable from good news.
"""

from __future__ import annotations

import json

import httpx
import pytest

from art14.cache import Cache
from art14.models import Component
from art14.osv import BATCH_MAX_AGE, CHUNK, MatchResult, OsvClient, query_for
from tests.conftest import osv_handler, record


_DEFAULT = object()


def _component(index, *, purl=_DEFAULT, version="1.0.0"):
    # A sentinel, not None: `purl=None` is a component the SBOM gave no PURL
    # for, which is precisely what several of these tests are about.
    if purl is _DEFAULT:
        purl = f"pkg:pypi/c{index}@{version}"
    return Component(
        bom_ref=f"c{index}", name=f"c{index}", version=version, purl=purl
    )


def _client(handler, **kwargs):
    return OsvClient(transport=httpx.MockTransport(handler), **kwargs)


# --- query construction ---------------------------------------------------


def test_a_versioned_purl_is_sent_alone():
    # Section 3: a version and a versioned purl together return 400, which
    # would take down a whole chunk of 1000 over one component.
    query = query_for(_component(0, purl="pkg:pypi/x@1.0.0", version="1.0.0"))
    assert query == {"package": {"purl": "pkg:pypi/x@1.0.0"}}
    assert "version" not in query


def test_a_bare_purl_is_completed_by_the_version_field():
    query = query_for(_component(0, purl="pkg:pypi/x", version="1.0.0"))
    assert query == {"package": {"purl": "pkg:pypi/x"}, "version": "1.0.0"}


@pytest.mark.parametrize(
    "purl",
    [
        "pkg:deb/debian/openssl@1.1.1n?arch=amd64",
        "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
        "pkg:generic/openssl@1.1.1n#subpath",
    ],
)
def test_qualifiers_do_not_make_a_versioned_purl_look_bare(purl):
    assert query_for(_component(0, purl=purl, version="1.1.1n")) == {
        "package": {"purl": purl}
    }


def test_an_unsendable_component_produces_no_query():
    assert query_for(_component(0, purl=None)) is None
    assert query_for(_component(0, purl="pkg:pypi/x", version="")) is None


def test_unsendable_components_are_not_attempted():
    """They are the quality gate's business, not a lookup failure."""
    result = _client(osv_handler({}, {})).match(
        [_component(0), _component(1, purl=None)]
    )
    assert [c.bom_ref for c in result.queried] == ["c0"]
    assert result.failed == ()


# --- index alignment ------------------------------------------------------


def test_empty_results_do_not_shift_the_alignment():
    """The failure this pins: zipping only non-empty results onto the inventory.

    c1 has no vulns. If empty results are dropped, c2's CVE lands on c1 and
    every later component is wrong by one -- with no error anywhere.
    """
    components = [_component(i) for i in range(4)]
    batch = {
        "pkg:pypi/c0@1.0.0": [],
        "pkg:pypi/c1@1.0.0": [],
        "pkg:pypi/c2@1.0.0": [{"id": "GHSA-two", "modified": "m"}],
        "pkg:pypi/c3@1.0.0": [{"id": "GHSA-three", "modified": "m"}],
    }
    records = {
        "GHSA-two": record("GHSA-two", modified="m"),
        "GHSA-three": record("GHSA-three", modified="m"),
    }
    result = _client(osv_handler(batch, records)).match(components)

    landed = {
        finding.component.bom_ref: finding.vulnerability.id
        for finding in result.findings
    }
    assert landed == {"c2": "GHSA-two", "c3": "GHSA-three"}


def test_a_length_mismatch_fails_the_chunk_rather_than_guessing():
    """Short results array: we cannot say whose answer is whose, so nobody's is."""

    def handle(request):
        if request.url.path == "/v1/querybatch":
            # One result for three queries.
            return httpx.Response(200, json={"results": [{"vulns": []}]})
        return httpx.Response(404, json={})

    result = _client(handle).match([_component(i) for i in range(3)])
    assert result.queried == ()
    assert len(result.failed) == 3


def test_chunking_preserves_every_component():
    """Section 3: chunks of 1000. Boundaries are where alignment bugs hide."""
    components = [_component(i) for i in range(CHUNK + 5)]
    batch = {c.purl: [] for c in components}
    seen = []

    def handle(request):
        payload = json.loads(request.content)
        seen.append(len(payload["queries"]))
        return httpx.Response(
            200, json={"results": [{"vulns": []} for _ in payload["queries"]]}
        )

    result = _client(handle).match(components)
    assert seen == [CHUNK, 5]
    assert len(result.queried) == CHUNK + 5
    assert result.failed == ()


# --- failures are never silence -------------------------------------------


def test_a_failed_chunk_marks_its_components_unassessed():
    def handle(request):
        return httpx.Response(500, json={"message": "upstream is down"})

    result = _client(handle).match([_component(i) for i in range(3)])
    assert result.queried == ()
    assert [c.bom_ref for c in result.failed] == ["c0", "c1", "c2"]


def test_a_transport_error_is_a_failure_not_an_exception():
    """A CI run against a flaky network reports gaps; it does not traceback."""

    def handle(request):
        raise httpx.ConnectError("no route to host")

    result = _client(handle).match([_component(0)])
    assert len(result.failed) == 1


def test_a_vulnerability_that_will_not_hydrate_fails_its_component():
    """No record means no brief, and a CVE with no brief is not an assessment."""
    batch = {"pkg:pypi/c0@1.0.0": [{"id": "GHSA-gone", "modified": "m"}]}
    result = _client(osv_handler(batch, {})).match([_component(0)])
    assert result.queried == ()
    assert [c.bom_ref for c in result.failed] == ["c0"]
    assert result.findings == ()


def test_one_bad_record_does_not_condemn_an_unrelated_component():
    batch = {
        "pkg:pypi/c0@1.0.0": [{"id": "GHSA-gone", "modified": "m"}],
        "pkg:pypi/c1@1.0.0": [{"id": "GHSA-here", "modified": "m"}],
    }
    records = {"GHSA-here": record("GHSA-here", modified="m")}
    result = _client(osv_handler(batch, records)).match(
        [_component(0), _component(1)]
    )
    assert [c.bom_ref for c in result.failed] == ["c0"]
    assert [c.bom_ref for c in result.queried] == ["c1"]



def test_the_same_package_listed_twice_is_two_components():
    """One package at two places in the tree is two findings, not one.

    Normal in a multi-module build. The vulnerability is one record, but it is
    installed twice, and collapsing the second finding would understate where
    the fix has to land.
    """
    first = Component(bom_ref="a", name="dup", version="1.0.0", purl="pkg:pypi/d@1.0.0")
    second = Component(bom_ref="b", name="dup", version="1.0.0", purl="pkg:pypi/d@1.0.0")
    batch = {"pkg:pypi/d@1.0.0": [{"id": "GHSA-dup", "modified": "m"}]}
    records = {"GHSA-dup": record("GHSA-dup", modified="m")}

    result = _client(osv_handler(batch, records)).match([first, second])

    assert len(result.queried) == 2
    assert result.failed == ()
    # One vulnerability, but it affects both places it is installed. Losing the
    # second finding would understate the remediation surface.
    assert [v.id for v in result.vulnerabilities] == ["GHSA-dup"]
    assert sorted(f.component.bom_ref for f in result.findings) == ["a", "b"]


# --- caching and offline --------------------------------------------------


def test_a_second_run_reuses_the_cached_batch(tmp_path):
    calls = []
    batch = {"pkg:pypi/c0@1.0.0": [{"id": "GHSA-one", "modified": "m"}]}
    records = {"GHSA-one": record("GHSA-one", modified="m")}
    cache = Cache(tmp_path)

    first = _client(osv_handler(batch, records, calls=calls), cache=cache).match(
        [_component(0)]
    )
    assert first.fetched == 1
    before = len(calls)

    second = _client(osv_handler(batch, records, calls=calls), cache=cache).match(
        [_component(0)]
    )
    assert len(calls) == before
    assert second.from_cache == 1
    assert second.fetched == 0
    assert [v.id for v in second.vulnerabilities] == ["GHSA-one"]


def test_hydration_is_keyed_on_modified(tmp_path):
    """Section 3: same `modified` means the record cannot have changed."""
    cache = Cache(tmp_path)
    calls = []
    batch = {"pkg:pypi/c0@1.0.0": [{"id": "GHSA-one", "modified": "m1"}]}
    _client(
        osv_handler(batch, {"GHSA-one": record("GHSA-one", modified="m1")}, calls=calls),
        cache=cache,
    ).match([_component(0)])
    assert sum("/v1/vulns/" in str(c.url) for c in calls) == 1

    # Same id, same modified: no second download.
    calls.clear()
    again = _client(
        osv_handler(batch, {"GHSA-one": record("GHSA-one", modified="m1")}, calls=calls),
        cache=Cache(tmp_path),
    ).match([_component(0)])
    assert again.fetched == 0
    assert not any("/v1/vulns/" in str(c.url) for c in calls)


def test_a_changed_modified_forces_a_refetch(tmp_path):
    """The record moved under us. A cached copy at the old timestamp is stale."""
    cache = Cache(tmp_path)
    old = {"pkg:pypi/c0@1.0.0": [{"id": "GHSA-one", "modified": "m1"}]}
    _client(
        osv_handler(old, {"GHSA-one": record("GHSA-one", modified="m1")}), cache=cache
    ).match([_component(0)])

    # Drop only the batch entry, so the run re-queries and learns of m2 while
    # the hydrated record in the cache is still the m1 one.
    for path in (tmp_path / "osv" / "batch").glob("*.json"):
        path.unlink()

    calls = []
    new = {"pkg:pypi/c0@1.0.0": [{"id": "GHSA-one", "modified": "m2"}]}
    result = _client(
        osv_handler(
            new,
            {"GHSA-one": record("GHSA-one", modified="m2", summary="rewritten")},
            calls=calls,
        ),
        cache=Cache(tmp_path),
    ).match([_component(0)])

    assert sum("/v1/vulns/" in str(c.url) for c in calls) == 1
    assert result.vulnerabilities[0].description == "rewritten"


def test_offline_with_a_cold_cache_assesses_nothing(tmp_path):
    """The recurring CI state: no network, nothing warm. Honest, not empty."""
    client = OsvClient(cache=Cache(tmp_path), offline=True)
    result = client.match([_component(i) for i in range(3)])
    assert result.queried == ()
    assert len(result.failed) == 3
    assert result.vulnerabilities == ()


def test_offline_with_a_warm_cache_answers_without_a_connection(tmp_path):
    cache = Cache(tmp_path)
    batch = {"pkg:pypi/c0@1.0.0": [{"id": "GHSA-one", "modified": "m"}]}
    records = {"GHSA-one": record("GHSA-one", modified="m")}
    _client(osv_handler(batch, records), cache=cache).match([_component(0)])

    def refuse(request):  # pragma: no cover - reaching it is the failure
        raise AssertionError(f"--offline opened a connection: {request.url}")

    offline = OsvClient(
        cache=Cache(tmp_path), offline=True, transport=httpx.MockTransport(refuse)
    ).match([_component(0)])
    assert len(offline.queried) == 1
    assert [v.id for v in offline.vulnerabilities] == ["GHSA-one"]
    assert offline.stale == ()


def test_offline_reports_a_stale_answer_as_stale(tmp_path, monkeypatch):
    cache = Cache(tmp_path)
    batch = {"pkg:pypi/c0@1.0.0": [{"id": "GHSA-one", "modified": "m"}]}
    records = {"GHSA-one": record("GHSA-one", modified="m")}
    _client(osv_handler(batch, records), cache=cache).match([_component(0)])

    # Age every entry past the freshness window.
    import time as real_time

    import art14.cache as cache_module

    later = real_time.time() + BATCH_MAX_AGE * 2
    monkeypatch.setattr(cache_module.time, "time", lambda: later)
    offline = OsvClient(cache=Cache(tmp_path), offline=True).match([_component(0)])
    assert len(offline.queried) == 1
    assert len(offline.stale) == 1


# --- record conversion ----------------------------------------------------


def test_aliases_are_kept_so_layer_two_can_find_the_cve():
    """OSV answers with a GHSA; the KEV catalogue keys on CVE ids."""
    batch = {"pkg:pypi/c0@1.0.0": [{"id": "GHSA-x", "modified": "m"}]}
    records = {
        "GHSA-x": record("GHSA-x", modified="m", aliases=["CVE-2021-44228", "PYSEC-1"])
    }
    result = _client(osv_handler(batch, records)).match([_component(0)])
    vulnerability = result.vulnerabilities[0]
    assert vulnerability.id == "GHSA-x"
    assert vulnerability.cve_ids == ("CVE-2021-44228",)


def test_cwes_and_severity_survive_the_conversion():
    batch = {"pkg:pypi/c0@1.0.0": [{"id": "GHSA-x", "modified": "m"}]}
    records = {
        "GHSA-x": record(
            "GHSA-x",
            modified="m",
            database_specific={"cwe_ids": ["CWE-502", "CWE-20"]},
            severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
        )
    }
    vulnerability = _client(osv_handler(batch, records)).match(
        [_component(0)]
    ).vulnerabilities[0]
    assert vulnerability.cwes == (502, 20)
    assert vulnerability.ratings[0].method == "CVSSv3"
    assert vulnerability.ratings[0].vector.startswith("CVSS:3.1/")
    # OSV carries a vector, not a number, and art14 does not score vectors.
    assert vulnerability.ratings[0].score is None


def test_one_cve_across_two_components_is_two_findings():
    """Findings are the counted unit; one CVE can affect several components."""
    batch = {
        "pkg:pypi/c0@1.0.0": [{"id": "GHSA-x", "modified": "m"}],
        "pkg:pypi/c1@1.0.0": [{"id": "GHSA-x", "modified": "m"}],
    }
    records = {"GHSA-x": record("GHSA-x", modified="m")}
    result = _client(osv_handler(batch, records)).match(
        [_component(0), _component(1)]
    )
    assert len(result.vulnerabilities) == 1
    assert len(result.findings) == 2
    assert {f.component.bom_ref for f in result.findings} == {"c0", "c1"}


def test_an_empty_component_list_is_not_an_error():
    result = _client(osv_handler({}, {})).match([])
    assert result == MatchResult(
        vulnerabilities=(), findings=(), queried=(), failed=()
    )


def test_timestamp_precision_does_not_defeat_the_record_cache(tmp_path):
    """Regression: OSV truncates `modified` in a batch result, not in a record.

    querybatch says `...42.492278Z` and `/v1/vulns/{id}` says `...42.492278990Z`
    for the same record. Comparing the record's own field against the batch's
    misses on almost every entry, so every run re-downloads everything -- a
    cache that stores and never reuses, which looks like it is working.
    """
    cache = Cache(tmp_path)
    batch = {"pkg:pypi/c0@1.0.0": [{"id": "GHSA-one", "modified": "2026-01-01T00:00:00.123456Z"}]}
    records = {"GHSA-one": record("GHSA-one", modified="2026-01-01T00:00:00.123456789Z")}

    calls = []
    _client(osv_handler(batch, records, calls=calls), cache=cache).match([_component(0)])
    assert sum("/v1/vulns/" in str(c.url) for c in calls) == 1

    # Drop the batch entry so the second run re-queries and is told the same
    # truncated timestamp again. The record must still come from the cache.
    for path in (tmp_path / "osv" / "batch").glob("*.json"):
        path.unlink()
    calls.clear()
    result = _client(osv_handler(batch, records, calls=calls), cache=Cache(tmp_path)).match(
        [_component(0)]
    )
    assert not any("/v1/vulns/" in str(c.url) for c in calls)
    assert result.fetched == 0
    assert [v.id for v in result.vulnerabilities] == ["GHSA-one"]
