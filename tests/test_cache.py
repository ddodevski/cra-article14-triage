"""Cache tests.

The cache is the offline execution path, not an optimisation, so the
properties that matter are the ones that keep a broken cache from becoming a
broken result: a damaged entry is a miss, a write that cannot happen is not
an error, and an entry always knows how old it is.
"""

from __future__ import annotations

import json
import time

import pytest

from art14.cache import FORMAT, Cache, default_root


def test_a_stored_payload_comes_back(tmp_path):
    cache = Cache(tmp_path)
    cache.store("osv/vulns", "GHSA-x", {"id": "GHSA-x"})
    assert cache.get("osv/vulns", "GHSA-x").payload == {"id": "GHSA-x"}


def test_a_missing_entry_is_none(tmp_path):
    assert Cache(tmp_path).get("osv/vulns", "absent") is None


def test_a_truncated_entry_is_a_miss_not_a_crash(tmp_path):
    """A killed process mid-write must not be able to fail every later run."""
    cache = Cache(tmp_path)
    cache.store("osv/vulns", "GHSA-x", {"id": "GHSA-x"})
    path = cache.path_for("osv/vulns", "GHSA-x")
    path.write_text('{"format": 1, "payl', encoding="utf-8")
    assert cache.get("osv/vulns", "GHSA-x") is None


def test_an_entry_from_a_future_layout_is_ignored(tmp_path):
    cache = Cache(tmp_path)
    path = cache.path_for("osv/vulns", "GHSA-x")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"format": FORMAT + 1, "storedAt": time.time(), "payload": 1}),
        encoding="utf-8",
    )
    assert cache.get("osv/vulns", "GHSA-x") is None


def test_an_unwritable_cache_does_not_fail_the_run(tmp_path):
    """A cache is a convenience. It may not be able to break a triage run."""
    cache = Cache(tmp_path / "nested")
    cache.store("osv/vulns", "GHSA-x", {"id": "GHSA-x"})
    # Now make the directory a file, so every later write fails.
    (tmp_path / "blocked").write_text("not a directory", encoding="utf-8")
    blocked = Cache(tmp_path / "blocked")
    blocked.store("osv/vulns", "GHSA-x", {"id": "GHSA-x"})
    assert blocked.get("osv/vulns", "GHSA-x") is None


def test_freshness_is_measured_not_assumed(tmp_path):
    cache = Cache(tmp_path)
    cache.store("osv/batch", "k", [])
    entry = cache.get("osv/batch", "k")
    assert entry.is_fresh(60) is True
    assert entry.is_fresh(0) is True or entry.age_seconds > 0
    # None means the caller keys freshness on something else, not "expired".
    assert entry.is_fresh(None) is True


def test_a_stale_entry_is_returned_and_reported_as_old(tmp_path, monkeypatch):
    """Staleness is the caller's decision. The cache never silently discards."""
    cache = Cache(tmp_path)
    cache.store("osv/batch", "k", ["payload"])

    import art14.cache as cache_module

    later = time.time() + 10_000
    monkeypatch.setattr(cache_module.time, "time", lambda: later)
    entry = cache.get("osv/batch", "k")
    assert entry.payload == ["payload"]
    assert entry.is_fresh(60) is False


@pytest.mark.parametrize(
    "key",
    [
        "pkg:maven/org.apache/log4j@2.14.1",
        '{"package":{"purl":"pkg:pypi/x@1.0"}}',
        "../../etc/passwd",
        "",
    ],
)
def test_awkward_keys_stay_inside_the_cache_directory(tmp_path, key):
    cache = Cache(tmp_path)
    path = cache.path_for("osv/batch", key)
    assert tmp_path in path.parents
    cache.store("osv/batch", key, {"ok": True})
    assert cache.get("osv/batch", key).payload == {"ok": True}


def test_readable_ids_stay_readable(tmp_path):
    """Someone inspecting a CI cache should see what the run actually used."""
    assert Cache(tmp_path).path_for("osv/vulns", "CVE-2021-44228").name == (
        "CVE-2021-44228.json"
    )


def test_the_environment_variable_wins(monkeypatch, tmp_path):
    monkeypatch.setenv("ART14_CACHE_DIR", str(tmp_path / "ci-restored"))
    assert default_root() == tmp_path / "ci-restored"
