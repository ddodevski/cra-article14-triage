"""When this answer was true, and on what basis.

art14 holds no vulnerability data of its own. OSV and the EUVD KEV catalogue
are the source of truth; the disk cache is a performance and offline-CI
mechanism and is never a datastore. Every result is therefore a point-in-time
snapshot, and the snapshot is only useful if it says which point in time.

That matters more here than in an ordinary tool. The KEV catalogue changes
daily, so a NO today can become a REPORT tomorrow with no change to the SBOM
at all -- and under Article 14 it is that transition that starts the clock. A
run therefore has to record when it looked and what it looked at, so that a
later run producing a different verdict is visibly a change in the catalogue
rather than a change in the tool.

The one rule this module exists to enforce: **a cache-served run must not look
identical to a live one.** Hence two timestamps rather than one. On a mixed run
-- some answers from cache, some fetched -- a single run-level stamp either
backdates what was fetched or freshens what was cached, and freshening stale
data is the direction that produces a confident, wrong, negative answer.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone

# How old the KEV catalogue may be before the run says so. Deliberately its own
# constant rather than a reference to `osv.BATCH_MAX_AGE`: both are 24 hours
# today, but "how fresh is this OSV answer" and "how current is this catalogue"
# are different facts, and coupling them means a future tuning of one silently
# moves the other.
KEV_MAX_AGE = 24 * 60 * 60

# What the run did, from the user's three values. `--offline` is an input to
# the run, not an outcome, so it does not appear here: a cold offline run is
# `cache-served` having served nothing, which the quality gate already reports.
ONLINE = "online"
CACHE_SERVED = "cache-served"
PRE_ENRICHED = "pre-enriched"


@dataclass(frozen=True)
class SourceStamp:
    """One upstream source: when we last reached it, and what the cache held."""

    name: str
    fetched_at: float | None = None
    cache_age_seconds: float | None = None

    @property
    def cache_hit(self) -> bool:
        return self.cache_age_seconds is not None

    def as_json(self) -> dict[str, object]:
        return {
            "source": self.name,
            # Null means nothing in this portion went over the wire.
            "fetchedAt": _iso(self.fetched_at),
            "cacheHit": self.cache_hit,
            "cacheAgeSeconds": (
                None
                if self.cache_age_seconds is None
                else round(self.cache_age_seconds, 1)
            ),
        }


@dataclass(frozen=True)
class Provenance:
    """Everything needed to say when this answer was true."""

    tool: str
    generated_at: float
    mode: str
    osv: SourceStamp | None
    kev: SourceStamp | None
    kev_max_age: float = KEV_MAX_AGE
    # Whether the run adopted the SBOM's own not_affected claims. Part of the
    # provenance and not of the triage block, because it is a fact about how
    # the answer was produced rather than about any one item: it changes what
    # the counts mean and it can change the exit code.
    adopt_upstream_vex: bool = False

    @property
    def kev_is_stale(self) -> bool:
        """A catalogue too old to support today's NO verdicts."""
        return kev_is_stale(self.kev, max_age=self.kev_max_age)


def kev_is_stale(kev: SourceStamp | None, *, max_age: float = KEV_MAX_AGE) -> bool:
    """Whether a KEV stamp is too old to be relied on.

    A silently stale catalogue producing NO verdicts is the quiet version of
    the same failure mode as an unmatchable SBOM: a negative claim resting on
    something that was never in a position to support it.

    A catalogue fetched during this run is current by definition. No catalogue
    at all is not staleness -- it is absence, and the caller reports it as
    such.
    """
    if kev is None:
        return False
    if kev.fetched_at is not None:
        return False
    if kev.cache_age_seconds is None:
        return False
    return kev.cache_age_seconds > max_age


def build(
    *,
    tool: str,
    matching,
    kev: SourceStamp | None,
    kev_max_age: float = KEV_MAX_AGE,
    adopt_upstream_vex: bool = False,
) -> Provenance:
    """Assemble the block for one run.

    `kev` is a required keyword rather than a defaulted one, so that omitting
    the catalogue stamp is a TypeError rather than a provenance block quietly
    claiming there was no catalogue. It is None only when there genuinely was
    none -- the fetch failed and no cached copy was available. Such a run
    cannot support a negative claim, and the quality gate fails it closed.
    """

    osv = None if matching is None else SourceStamp(
        name="osv",
        fetched_at=matching.fetched_at,
        cache_age_seconds=(
            None
            if matching.oldest_cache_entry is None
            else max(0.0, time.time() - matching.oldest_cache_entry)
        ),
    )
    return Provenance(
        tool=tool,
        generated_at=time.time(),
        mode=_mode(matching, kev),
        osv=osv,
        kev=kev,
        kev_max_age=kev_max_age,
        adopt_upstream_vex=adopt_upstream_vex,
    )


def _mode(matching, kev: SourceStamp | None) -> str:
    """Where the answers came from -- never what the run was asked to do.

    `online` means *fully* online. A run that fetched one chunk and served the
    other 999 components from a day-old cache is not a live run, and calling it
    one at the single field a consumer is told it can read without branching
    would defeat the whole block.

    The catalogue counts towards that too. A verdict rests on both layers, so a
    run that answered from a cached catalogue -- or could not get one at all --
    did not get every answer over the wire. Same rule as the errored-chunk case
    below, applied to layer 2: the one field read without branching must not be
    the field that hides a missing source.

    `mode` tracks where the *answers* came from, meaning the querybatch
    answers. Record hydration is deliberately not counted: a hydrated record
    is only served off disk when its `modified` matches what a live batch
    answer just named, so it cannot differ from what upstream holds now.

    A run with no answers is reported as `cache-served` even if it reached the
    network and every chunk errored. `online` would imply a live result behind
    a verdict, and there is no result at all; the quality gate reports the
    absence separately. `fetchedAt` still records that we tried, which is a
    different and useful question.
    """
    if matching is None:
        return PRE_ENRICHED
    fully_live = (
        matching.went_online
        and not matching.served_from_cache
        and matching.has_answers
        and kev is not None
        and kev.fetched_at is not None
    )
    return ONLINE if fully_live else CACHE_SERVED


def as_json(provenance: Provenance) -> dict[str, object]:
    """The block, identically shaped on every run.

    A consumer reads `provenance.mode` without first branching on which kind of
    run it got. Absent sources are null rather than missing keys, so a diff
    between two runs shows a source appearing, not the schema changing.
    """
    return {
        "tool": provenance.tool,
        "generatedAt": _iso(provenance.generated_at),
        "mode": provenance.mode,
        "osv": provenance.osv.as_json() if provenance.osv else None,
        "kev": provenance.kev.as_json() if provenance.kev else None,
        "kevStale": provenance.kev_is_stale,
        # Always present, true or false. A consumer deciding whether to trust
        # a clean run has to be able to read this without knowing which
        # version of art14 wrote the file.
        "adoptUpstreamVex": provenance.adopt_upstream_vex,
        # Said in the output rather than left to the README, because the whole
        # block is evidence and evidence that overstates itself is worse than
        # none. This is a snapshot of upstream, not a record art14 keeps.
        "note": _note(provenance.mode),
    }


def _note(mode: str) -> str:
    """Never overstate what this run rests on; the block is evidence."""
    if mode == PRE_ENRICHED:
        return (
            "The SBOM carried its own vulnerabilities, so art14 matched"
            " nothing itself; the KEV catalogue was still consulted, and the"
            " stamps say when. art14 stores no vulnerability data of its own"
            " and is not a source of truth."
        )

    return (
        "Point-in-time snapshot of OSV and the EUVD KEV catalogue."
        " art14 stores no vulnerability data of its own; the cache is a"
        " performance and offline mechanism, not a source of truth."
    )


def lines(provenance: Provenance) -> list[str]:
    """The same facts for a terminal, under `--brief`."""
    out = [
        "provenance",
        f"  tool                art14 {provenance.tool}",
        f"  run                 {_iso(provenance.generated_at)}",
        f"  mode                {provenance.mode}{_mode_gloss(provenance)}",
    ]
    if provenance.adopt_upstream_vex:
        out.append(
            "  upstream VEX        adopted - the SBOM's own not_affected"
            " claims were honoured"
        )
    out.extend(_source_lines("OSV", provenance.osv))
    if provenance.kev is None:
        # Absence, said as absence. An empty row here could be read as "the
        # catalogue was checked and held nothing", which is the one sentence
        # an unavailable catalogue must never be mistaken for.
        out.append(
            "  EUVD KEV            unavailable - exploitation was not checked"
        )
    else:
        out.extend(_source_lines("EUVD KEV", provenance.kev))
    return out


def _source_lines(label: str, stamp: SourceStamp | None) -> list[str]:
    """The label carries on the first row only, whichever row that turns out
    to be. A cache-only run has no fetch row, and an unlabelled `served from
    cache` line does not say which source it is talking about."""
    if stamp is None:
        return [f"  {label:<18}  not consulted"]
    details: list[str] = []
    if stamp.fetched_at is not None:
        details.append(f"fetched {_iso(stamp.fetched_at)}")
    if stamp.cache_hit:
        age = _age(stamp.cache_age_seconds or 0.0)
        served = "served from cache" if stamp.fetched_at is None else "also cached"
        details.append(f"{served}, oldest entry {age} old")
    if not details:
        details.append("no answer")
    return [
        f"  {label if i == 0 else '':<18}  {detail}"
        for i, detail in enumerate(details)
    ]


def staleness_warning(provenance: Provenance) -> str | None:
    """The loud line when the catalogue is too old to support a NO verdict."""
    if not provenance.kev_is_stale:
        return None
    age = _age(provenance.kev.cache_age_seconds or 0.0)
    return (
        f"WARNING: the EUVD KEV catalogue used here is {age} old and was not"
        " refreshed on this run. The catalogue changes daily, and an entry"
        " added since then would not appear above. Re-run with a network"
        " connection before treating this as a current statement about the"
        " product."
    )


def _mode_gloss(provenance: Provenance) -> str:
    """Read off the stamps, not the mode string.

    `cache-served` covers runs that did reach the network -- a partly cached
    one, and one whose chunks all errored. Glossing it as "no upstream query"
    would contradict the `fetched ...` row printed two lines below it, and
    evidence that contradicts itself is worse than none.
    """
    if provenance.mode == PRE_ENRICHED:
        return "   (the SBOM carried its own vulnerabilities)"
    if provenance.mode != CACHE_SERVED:
        return ""
    # Either source having gone over the wire is enough to make "no upstream
    # query" false. Reading only the OSV stamp would deny the EUVD fetch row
    # printed directly below on a run that served matching from cache and
    # refreshed the catalogue.
    sources = (provenance.osv, provenance.kev)
    if any(s is not None and s.fetched_at is not None for s in sources):
        return "   (not every answer came over the wire)"
    return "   (no upstream query on this run)"



def _age(seconds: float) -> str:
    if seconds < 90:
        return f"{int(seconds)}s"
    if seconds < 90 * 60:
        return f"{int(seconds // 60)}m"
    if seconds < 48 * 3600:
        return f"{int(seconds // 3600)}h"
    return f"{int(seconds // 86400)}d"


def _iso(stamp: float | None) -> str | None:
    """UTC, second precision. Two runs are compared across machines."""
    if stamp is None:
        return None
    return (
        datetime.fromtimestamp(stamp, tz=timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
