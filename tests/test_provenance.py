"""Provenance tests.

Every result is a point-in-time snapshot of upstream. These pin the two
properties that make the snapshot evidence rather than decoration: a
cache-served run does not look like a live one, and a catalogue too old to
support a NO verdict says so out loud.
"""

from __future__ import annotations

import time

import pytest

from art14 import provenance as prov
from art14.provenance import (
    CACHE_SERVED,
    KEV_MAX_AGE,
    ONLINE,
    PRE_ENRICHED,
    SourceStamp,
    build,
    kev_is_stale,
)


class _Matching:
    """The part of a MatchResult the provenance block reads.

    `answers` stands in for the component list: zero means the run assessed
    nothing, which is a different run from one that assessed everything live.
    """

    def __init__(self, *, fetched_at=None, oldest_cache_entry=None, answers=1):
        self.fetched_at = fetched_at
        self.oldest_cache_entry = oldest_cache_entry
        self.from_cache = 0 if oldest_cache_entry is None else 1
        self.queried = ["component"] * answers

    @property
    def went_online(self):
        return self.fetched_at is not None

    @property
    def served_from_cache(self):
        return self.from_cache > 0

    @property
    def has_answers(self):
        return bool(self.queried)


def _build(matching, **kwargs):
    # A live catalogue by default, because that is the ordinary run. `kev=None`
    # is the exceptional one -- no catalogue at all -- and the tests that mean
    # it say so, rather than getting it by inheriting a convenience default.
    kwargs.setdefault("kev", SourceStamp(name="euvd-kev", fetched_at=time.time()))
    return build(tool="0.1.0", matching=matching, **kwargs)


# --- mode -----------------------------------------------------------------


def test_a_pre_enriched_run_says_so():
    assert _build(None).mode == PRE_ENRICHED


def test_only_a_fully_live_run_is_online():
    """The user's word is *fully* online, and the mode is the one field a
    consumer is told it can read without branching."""
    assert _build(_Matching(fetched_at=time.time())).mode == ONLINE


def test_a_run_with_no_catalogue_is_not_online():
    """A verdict rests on both layers. Perfect matching and no catalogue is
    not a live result, and `online` is the field that would hide it."""
    live = _Matching(fetched_at=time.time())
    assert _build(live, kev=None).mode == CACHE_SERVED


def test_a_cached_catalogue_is_not_a_live_run_either():
    cached = SourceStamp(name="euvd-kev", cache_age_seconds=60)
    assert _build(_Matching(fetched_at=time.time()), kev=cached).mode == CACHE_SERVED


def test_a_partly_cached_run_is_not_a_live_run():
    """One chunk fetched and 999 components answered from a day-old cache is
    not a live run. Calling it one at `mode` would defeat the whole block."""
    mixed = _Matching(fetched_at=time.time(), oldest_cache_entry=time.time() - 86400)
    assert _build(mixed).mode == CACHE_SERVED


def test_the_terminal_block_does_not_contradict_itself():
    """`cache-served` now covers runs that did reach the network, so a gloss
    reading "no upstream query" would deny the fetch row printed below it."""
    mixed = _Matching(fetched_at=time.time(), oldest_cache_entry=time.time() - 86400)
    text = "\n".join(prov.lines(_build(mixed)))
    assert "fetched " in text
    assert "no upstream query" not in text

    # Nothing went over the wire at all: not the matching, not the catalogue.
    quiet = "\n".join(
        prov.lines(
            _build(
                _Matching(oldest_cache_entry=time.time()),
                kev=SourceStamp(name="euvd-kev", cache_age_seconds=60),
            )
        )
    )
    assert "no upstream query" in quiet


def test_a_refreshed_catalogue_contradicts_no_upstream_query():
    """Matching from cache, catalogue fetched. The gloss reads both stamps."""
    text = "\n".join(prov.lines(_build(_Matching(oldest_cache_entry=time.time()))))
    assert "fetched " in text
    assert "no upstream query" not in text


def test_a_run_that_assessed_nothing_is_not_online():
    """The network was reached and every chunk errored. `fetched_at` is
    stamped per attempt, so `went_online` alone would report a live run behind
    verdicts that do not exist."""
    assert _build(_Matching(fetched_at=time.time(), answers=0)).mode == CACHE_SERVED


def test_a_run_answered_entirely_from_cache_is_not_online():
    matching = _Matching(oldest_cache_entry=time.time() - 100)
    assert _build(matching).mode == CACHE_SERVED


def test_offline_is_an_input_not_an_outcome():
    """A cold --offline run served nothing, but it still served from cache.

    The mode reports what the run did. That it was *asked* to stay offline is
    not a fourth mode -- the quality gate already reports that nothing was
    assessed, and duplicating it here would be a second warning path.
    """
    assert _build(_Matching()).mode == CACHE_SERVED


# --- the requirement ------------------------------------------------------


def test_a_cache_served_run_does_not_look_like_a_live_one():
    """The sentence this module exists to enforce, as an assertion."""
    live = prov.as_json(_build(_Matching(fetched_at=time.time())))
    cached = prov.as_json(_build(_Matching(oldest_cache_entry=time.time() - 3600)))

    assert live["mode"] != cached["mode"]
    assert live["osv"]["fetchedAt"] is not None
    assert cached["osv"]["fetchedAt"] is None
    assert cached["osv"]["cacheHit"] is True
    assert cached["osv"]["cacheAgeSeconds"] >= 3600


def test_a_mixed_run_reports_both_halves():
    """One timestamp would either backdate the fetch or freshen the cache."""
    matching = _Matching(
        fetched_at=time.time(), oldest_cache_entry=time.time() - 7200
    )
    block = prov.as_json(_build(matching))
    assert block["osv"]["fetchedAt"] is not None
    assert block["osv"]["cacheAgeSeconds"] >= 7200
    # And the summary field does not round the half-stale half away.
    assert block["mode"] == CACHE_SERVED


def test_the_shape_is_the_same_on_every_kind_of_run():
    """A consumer reads `mode` without first branching on the run type."""
    runs = [
        _build(None),
        _build(_Matching(fetched_at=time.time())),
        _build(_Matching(oldest_cache_entry=time.time() - 10)),
        _build(_Matching(), kev=SourceStamp("kev", fetched_at=time.time())),
    ]
    shapes = {tuple(sorted(prov.as_json(run))) for run in runs}
    assert len(shapes) == 1


def test_the_block_never_presents_itself_as_authoritative():
    for run in (_build(None), _build(_Matching(fetched_at=time.time()))):
        assert "not a source of truth" in prov.as_json(run)["note"]


def test_a_pre_enriched_run_does_not_claim_a_snapshot_it_never_took():
    """No matching was done, so calling the result a snapshot of OSV would
    overstate the very evidence the block exists to provide.

    The catalogue is a different matter: layer 2 runs whatever layer 1 did,
    and the note says so rather than claiming no upstream was reached.
    """
    note = prov.as_json(_build(None))["note"]
    assert "matched nothing itself" in note
    assert "KEV catalogue was still consulted" in note
    assert "Point-in-time snapshot" not in note



def test_the_stub_reads_the_same_fields_the_real_result_offers():
    """These tests are only worth anything if MatchResult still answers them."""
    from art14.osv import MatchResult

    names = set(MatchResult.__dataclass_fields__) | set(vars(MatchResult))
    for field in ("fetched_at", "oldest_cache_entry", "went_online",
                  "served_from_cache", "has_answers"):
        assert field in names, field


# --- KEV staleness --------------------------------------------------------


def test_a_catalogue_older_than_the_threshold_is_stale():
    old = SourceStamp("kev", cache_age_seconds=KEV_MAX_AGE + 1)
    assert kev_is_stale(old) is True


def test_a_catalogue_inside_the_threshold_is_not_stale():
    assert kev_is_stale(SourceStamp("kev", cache_age_seconds=KEV_MAX_AGE - 1)) is False


def test_a_catalogue_fetched_this_run_is_current_whatever_the_cache_held():
    fresh = SourceStamp(
        "kev", fetched_at=time.time(), cache_age_seconds=KEV_MAX_AGE * 10
    )
    assert kev_is_stale(fresh) is False


def test_no_catalogue_is_absence_not_staleness():
    """Reporting a catalogue that was never consulted as `stale` would be a
    warning about the wrong thing; the caller says `not consulted` instead."""
    assert kev_is_stale(None) is False


def test_the_threshold_is_configurable():
    stamp = SourceStamp("kev", cache_age_seconds=3600)
    assert kev_is_stale(stamp, max_age=1800) is True
    assert kev_is_stale(stamp, max_age=7200) is False


def test_the_kev_threshold_is_not_the_osv_one():
    """Both are 24h today and they are different facts.

    "How fresh is this OSV answer" and "how current is this catalogue" happen
    to have the same default. Expressing one in terms of the other means that
    tuning either silently moves the other, so the coupling is pinned shut
    here rather than left to whoever next edits a constant.
    """
    import ast
    import pathlib

    from art14 import provenance

    tree = ast.parse(pathlib.Path(provenance.__file__).read_text(encoding="utf-8"))
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    } | {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    # Prose may mention the other constant; the module may not read it.
    assert not any("osv" in name for name in imported)
    assert isinstance(provenance.KEV_MAX_AGE, int)


def test_a_stale_catalogue_warns_loudly():
    stale = _build(
        _Matching(oldest_cache_entry=time.time()),
        kev=SourceStamp("kev", cache_age_seconds=KEV_MAX_AGE * 3),
    )
    warning = prov.staleness_warning(stale)
    assert warning is not None
    assert "WARNING" in warning
    assert "changes daily" in warning
    assert prov.as_json(stale)["kevStale"] is True


def test_a_current_catalogue_does_not_warn():
    current = _build(
        _Matching(fetched_at=time.time()),
        kev=SourceStamp("kev", fetched_at=time.time()),
    )
    assert prov.staleness_warning(current) is None


# --- wiring ---------------------------------------------------------------


def test_the_catalogue_stamp_cannot_be_forgotten():
    """Step 5 must wire KEV in here. A default would let it be skipped, and a
    provenance block quietly claiming no catalogue was consulted is exactly
    the kind of silent regression this block exists to prevent."""
    with pytest.raises(TypeError):
        build(tool="0.1.0", matching=None)


def test_the_terminal_block_labels_its_sources():
    lines = prov.lines(_build(_Matching(oldest_cache_entry=time.time() - 60)))
    text = "\n".join(lines)
    assert "OSV" in text
    assert "EUVD KEV" in text


def test_an_absent_catalogue_is_printed_as_absence():
    """`kev` is None only when the catalogue could not be had at all.

    An empty row, or anything that reads as "checked and found nothing", would
    turn the one state that cannot judge into the one that certifies.
    """
    text = "\n".join(prov.lines(_build(_Matching(fetched_at=time.time()), kev=None)))
    assert "unavailable" in text

    assert "exploitation was not checked" in text



def test_timestamps_are_utc_and_comparable_across_machines():
    stamp = prov.as_json(_build(_Matching(fetched_at=time.time())))
    assert stamp["generatedAt"].endswith("Z")
    assert stamp["osv"]["fetchedAt"].endswith("Z")
