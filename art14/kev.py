"""Layer 2: CVE to reportable, via the EUVD KEV catalogue.

This is the exploitation layer and nothing else. It cannot discover a
vulnerability -- the dump carries no affected-version ranges, no PURL and no
CPE -- so it only ever answers one question about a CVE somebody else already
found: is it in the catalogue, and since when.

Four things here are not obvious, and three of them are silent-false-negative
territory:

**The two layers do not share a key.** OSV identifies records by its own ids,
which are frequently GHSAs; the dump is keyed on `cveId`. The CVE lives in the
OSV record's `aliases`. Joining on the OSV id matches nothing and raises
nothing -- the run completes, every verdict comes back negative, and it looks
entirely plausible. `review` therefore resolves aliases to CVE ids first and
the catalogue lookup accepts nothing else.

**A vulnerability with no CVE alias was never checkable.** It is not absent
from the catalogue; the catalogue was never in a position to be asked. That is
a different statement and it is counted separately, on the same principle as
components with no PURL: a negative claim that rests on something never asked
is the failure mode this tool exists to avoid.

**Absence of a catalogue is not absence of exploitation.** A failed fetch with
no usable cache raises `CatalogueUnavailable`, and so does a dump that parses
to nothing, and so does one that arrives short of the count it declares. An
empty catalogue, a broken one and one page of a long one are indistinguishable
in their effect -- the CVEs that are missing come back "not listed" -- so they
are treated alike and the run fails closed.

**The dump's exact shape is inferred, not observed.** The four fields are
documented; the envelope is not, so `parse_dump` accepts a bare array or an
object wrapping one, and `sources` as either a list or a delimited string.
The fixtures in `tests/fixtures/` are the working spec; a real response that
disagrees should be added there rather than special-cased here.

"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

import httpx

from .cache import Cache
from .errors import Art14Error
from .lines import count_line, note_line
from .models import Vulnerability
from .provenance import KEV_MAX_AGE

API = "https://euvdservices.enisa.europa.eu"
DUMP_PATH = "/api/kev/dump"

# One document, so one cache entry. The layout in cache.py reserves this.
_NS = "euvd"
_KEY = "kev"

# Keys the dump might wrap its array in. Tried in order, and only after a
# single list-valued key has failed to identify itself.
_ENVELOPE_KEYS = ("items", "kev", "data", "results", "result", "content")

# Field spellings accepted for each value. The EU API is not versioned in a way
# we can pin, and a renamed key would otherwise empty the catalogue silently.
_CVE_KEYS = ("cveId", "cve_id", "cve")
_EUVD_KEYS = ("euvdId", "euvd_id", "euvd")
_DATE_KEYS = ("dateAdded", "date_added", "dateadded")
_SOURCE_KEYS = ("sources", "source")

# Keys by which a response declares how many entries it holds. A paginated
# answer is the shape this module cannot otherwise detect: unwrap the array and
# one page of a large catalogue looks exactly like a small complete one, with
# every CVE outside the page coming back "not listed".
_COUNT_KEYS = ("total", "totalElements", "total_elements", "count", "size")


class CatalogueUnavailable(Art14Error):
    """The KEV catalogue could not be consulted on this run.

    Deliberately an error and not an empty catalogue. "We could not ask"
    and "we asked and the answer was no" are different claims, and only the
    second one can support an exit code 0.
    """


@dataclass(frozen=True)
class KevEntry:
    """One catalogue record: a CVE known to be exploited, and on whose word."""

    cve_id: str
    euvd_id: str | None = None
    date_added: str | None = None
    # Which catalogues contain it -- `cisa_kev`, and the EU list, which the
    # API documentation spells `eu_kev` and the live dump spells `eukev_kev`.
    # Kept exactly as the catalogue sent them: this is the record of what was
    # said, and `table.SOURCE_LABELS` does the reading-for-humans. Always
    # shown in output per section 3, so the user sees where the signal comes
    # from rather than taking art14's word for it.
    sources: tuple[str, ...] = ()

    def as_json(self) -> dict[str, object]:
        return {
            "cve": self.cve_id,
            "euvdId": self.euvd_id,
            # Severity context, never a countdown: the Article 14 clock runs
            # from when the manufacturer became aware, not from this date.
            "dateAdded": self.date_added,
            "sources": list(self.sources),
        }


class Catalogue:
    """The KEV dump, keyed on CVE id. Read only, and case insensitive."""

    def __init__(self, entries: Mapping[str, KevEntry]) -> None:
        self._entries = {key.upper(): value for key, value in entries.items()}

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, cve_id: object) -> bool:
        return isinstance(cve_id, str) and cve_id.upper() in self._entries

    def get(self, cve_id: str) -> KevEntry | None:
        """The entry for a CVE id, or None when the catalogue does not list it.

        Only CVE ids resolve. Passing an OSV id here is the join bug this
        module's docstring describes, and it returns None exactly as any other
        unlisted string would -- which is why `review` never passes one.
        """
        return self._entries.get(cve_id.upper())


@dataclass(frozen=True)
class Exposure:
    """One CVE the catalogue was asked about, and what it said.

    Keyed on the CVE rather than on the OSV record: a CVE can arrive through
    several OSV records and an OSV record can carry several CVE aliases, so
    bucketing on anything else double-counts. The OSV ids are kept alongside
    so the user can follow the trail back to where the CVE came from.
    """

    cve_id: str
    entry: KevEntry | None
    osv_ids: tuple[str, ...] = ()
    # bom-refs, not labels. Named for what they are: `component` elsewhere in
    # the output is a human-readable `name@version`, and one key meaning two
    # things is how a consumer ends up printing a bom-ref at a user.
    component_refs: tuple[str, ...] = ()

    @property
    def is_listed(self) -> bool:
        return self.entry is not None

    def as_json(self) -> dict[str, object]:
        return {
            "cve": self.cve_id,
            "listed": self.is_listed,
            # The trail back: which OSV records carried this CVE.
            "osvIds": list(self.osv_ids),
            "bomRefs": list(self.component_refs),
            "kev": self.entry.as_json() if self.entry else None,
        }


@dataclass(frozen=True)
class Uncheckable:
    """A vulnerability the catalogue could never have been asked about.

    No CVE alias, so there is no key to look up. This is not a NO: NO means
    checked against the catalogue and absent. These were never checkable, and
    folding them into NO would manufacture a negative answer out of a question
    that was never put.
    """

    vuln_id: str
    component_refs: tuple[str, ...] = ()

    def as_json(self) -> dict[str, object]:
        return {"id": self.vuln_id, "bomRefs": list(self.component_refs)}


@dataclass(frozen=True)
class Review:
    """What the catalogue said about one run's vulnerabilities."""

    exposures: tuple[Exposure, ...] = ()
    uncheckable: tuple[Uncheckable, ...] = ()

    @property
    def listed(self) -> tuple[Exposure, ...]:
        """CVEs the catalogue lists as exploited. The Article 14 candidates."""
        return tuple(e for e in self.exposures if e.is_listed)

    @property
    def absent(self) -> tuple[Exposure, ...]:
        """Checked against the catalogue and not in it. This is what NO means."""
        return tuple(e for e in self.exposures if not e.is_listed)

    @property
    def checked(self) -> int:
        """Distinct CVEs actually put to the catalogue."""
        return len(self.exposures)

    @property
    def listed_pairs(self) -> int:
        """The listed CVEs counted in component-CVE pairs.

        The buckets below are in pairs and this line is in CVE ids, so the
        two numbers differ whenever one CVE reaches more than one component.
        Both are printed rather than leaving the reader to reconcile them.
        """
        return sum(len(exposure.component_refs) for exposure in self.listed)

    def as_json(self) -> dict[str, object]:
        return {
            "checked": self.checked,
            "listed": len(self.listed),
            # Distinct CVE ids in `listed`, counted again in the unit the
            # triage buckets use. A consumer comparing `kev.listed` with
            # `triage.counts.assess` is comparing two different things.
            "listedPairs": self.listed_pairs,
            "absent": len(self.absent),
            # Counted and listed, never folded into `absent`.
            "uncheckable": len(self.uncheckable),
            "exposures": [e.as_json() for e in self.exposures],
            "uncheckableVulnerabilities": [u.as_json() for u in self.uncheckable],
        }


@dataclass(frozen=True)
class CatalogueLoad:
    """The catalogue, plus what the provenance block needs to stamp it.

    Two facts and never one, for the same reason layer 1 keeps two: a run-level
    timestamp on a cache-served catalogue would freshen it, and freshening is
    the direction that produces a confident, wrong, negative answer.
    """

    catalogue: Catalogue
    fetched_at: float | None = None
    cache_age_seconds: float | None = None


class KevClient:
    """Fetches the EUVD KEV dump, or reads it from the cache, or fails.

    What it never does is return an empty catalogue. Every path that cannot
    produce real entries raises `CatalogueUnavailable`, because the caller's
    only alternative reading of an empty catalogue is "nothing is exploited".
    """

    def __init__(
        self,
        cache: Cache | None = None,
        *,
        offline: bool = False,
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
        max_age: float = KEV_MAX_AGE,
    ) -> None:
        self.cache = cache if cache is not None else Cache()
        self.offline = offline
        self.timeout = timeout
        self.max_age = max_age
        self._transport = transport
        self._client: httpx.Client | None = None

    # -- public surface ---------------------------------------------------

    def load(self) -> CatalogueLoad:
        """The catalogue for this run. Raises when it cannot be had.

        A cached dump within the freshness window is used as is. Past it, a
        refresh is attempted and the stale copy is the fallback -- used, but
        carrying its age, so the provenance block can say so out loud.
        """
        entry = self.cache.get(_NS, _KEY)
        cached: Catalogue | None = None
        if entry is not None:
            try:
                cached = parse_dump(entry.payload)
            except CatalogueUnavailable:
                # A cached payload we can no longer make sense of. A miss, not
                # an error: the next fetch overwrites it.
                cached = None

        if cached is not None and entry is not None and entry.is_fresh(self.max_age):
            return CatalogueLoad(
                catalogue=cached, cache_age_seconds=entry.age_seconds
            )

        if self.offline:
            # Never opens a socket. A stale copy is still an answer, and the
            # staleness travels with it; no copy at all is not.
            if cached is not None and entry is not None:
                return CatalogueLoad(
                    catalogue=cached, cache_age_seconds=entry.age_seconds
                )
            raise CatalogueUnavailable(
                "the EUVD KEV catalogue is not in the cache and --offline was"
                " requested, so exploitation could not be checked"
            )

        try:
            payload = self._get(DUMP_PATH)
            # Parsed inside the same guard as the fetch, because a response
            # that arrives and makes no sense is no better an answer than one
            # that never arrives -- and a yesterday's catalogue beats both.
            catalogue = parse_dump(payload)
        except (httpx.HTTPError, ValueError, CatalogueUnavailable) as exc:
            if cached is not None and entry is not None:
                return CatalogueLoad(
                    catalogue=cached, cache_age_seconds=entry.age_seconds
                )
            raise CatalogueUnavailable(
                f"the EUVD KEV catalogue could not be fetched or read ({exc})"
                " and no cached copy is available, so exploitation could not be"
                " checked"
            ) from exc

        # Only a payload we have already parsed is worth keeping.
        self.cache.store(_NS, _KEY, payload)
        return CatalogueLoad(catalogue=catalogue, fetched_at=time.time())

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> KevClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- transport --------------------------------------------------------

    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            from . import __version__

            self._client = httpx.Client(
                base_url=API,
                timeout=self.timeout,
                transport=self._transport,
                headers={"user-agent": f"art14/{__version__} (+https://github.com/)"},
            )
        return self._client

    def _get(self, path: str) -> object:
        # No auth, no key, no custom headers -- section 3.
        response = self.client.get(path)
        response.raise_for_status()
        return response.json()


# --- parsing --------------------------------------------------------------


def parse_dump(payload: object) -> Catalogue:
    """The dump as a catalogue. Raises when it yields nothing usable.

    An empty result is never returned. A dump that parses to zero entries is
    indistinguishable in effect from a failed fetch -- every CVE comes back
    "not listed" -- so it fails the same way rather than quietly certifying
    the whole inventory as unexploited.
    """
    records = _records(payload)
    declared = _declared_count(payload)
    if declared is not None and declared[1] > len(records):
        key, count = declared
        raise CatalogueUnavailable(
            f"the EUVD KEV dump declared {count} entries ({key}) but carried"
            f" {len(records)}, so what arrived is part of the catalogue and not"
            " the catalogue; exploitation could not be checked"
        )
    entries: dict[str, KevEntry] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        cve_id = _first_string(record, _CVE_KEYS)
        if not cve_id or not cve_id.upper().startswith("CVE-"):
            continue
        key = cve_id.upper()
        sources = _sources(record)
        date_added = _first_string(record, _DATE_KEYS)
        existing = entries.get(key)
        if existing is not None:
            # The same CVE listed twice. Union the catalogues that named it and
            # keep the first date we saw: `dateAdded` is documented as the
            # earliest across sources, so re-deriving it here would second-guess
            # upstream on its own field.
            entries[key] = KevEntry(
                cve_id=existing.cve_id,
                euvd_id=existing.euvd_id or _first_string(record, _EUVD_KEYS),
                date_added=existing.date_added or date_added,
                sources=tuple(dict.fromkeys(existing.sources + sources)),
            )
            continue
        entries[key] = KevEntry(
            cve_id=key,
            euvd_id=_first_string(record, _EUVD_KEYS),
            date_added=date_added,
            sources=sources,
        )

    if not entries:
        raise CatalogueUnavailable(
            "the EUVD KEV catalogue returned no usable entries, so exploitation"
            " could not be checked"
        )
    return Catalogue(entries)


def _records(payload: object) -> Sequence[object]:
    """The array of records, whatever it was wrapped in."""
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return ()
    lists = [value for value in payload.values() if isinstance(value, list)]
    if len(lists) == 1:
        return lists[0]
    for key in _ENVELOPE_KEYS:
        value = payload.get(key)
        if isinstance(value, list):
            return value
    return ()


def _declared_count(payload: object) -> tuple[str, int] | None:
    """How many entries the dump says it holds, and under which key.

    The largest of the recognised counts wins, because they mean different
    things in different framings -- a page size and a total sit side by side in
    every paginated API -- and the largest is the only one that cannot be
    satisfied by a partial answer. A dump that declares nothing is taken at
    face value, which is the shape we expect and the one the fixtures use.
    """
    if not isinstance(payload, dict):
        return None
    counts: list[tuple[str, int]] = []
    for key in _COUNT_KEYS:
        value = payload.get(key)
        if isinstance(value, bool):  # bool is an int; a flag is not a count
            continue
        if isinstance(value, int):
            counts.append((key, value))
        elif isinstance(value, str) and value.strip().isdigit():
            counts.append((key, int(value.strip())))
    if not counts:
        return None
    return max(counts, key=lambda item: item[1])


def _first_string(record: Mapping[str, object], keys: Sequence[str]) -> str | None:
    for key in keys:
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _sources(record: Mapping[str, object]) -> tuple[str, ...]:
    """`sources` as a list, however it arrived.

    Seen as an array in the documented shape; accepted as a delimited string
    too, because a single-source record serialised as a bare string is the
    obvious way for this field to vary and losing it would drop the one part
    of the output that says where the signal came from.
    """
    for key in _SOURCE_KEYS:
        value = record.get(key)
        if isinstance(value, list):
            names = [str(v).strip() for v in value if str(v).strip()]
            if names:
                return tuple(dict.fromkeys(names))
        if isinstance(value, str) and value.strip():
            parts = [p.strip() for p in value.replace(";", ",").split(",")]
            names = [p for p in parts if p]
            if names:
                return tuple(dict.fromkeys(names))
    return ()


# --- the join -------------------------------------------------------------


def review(
    vulnerabilities: Iterable[Vulnerability], catalogue: Catalogue
) -> Review:
    """Ask the catalogue about every vulnerability, keyed on CVE.

    The whole point of this function is the key change. OSV hands us records
    identified by GHSA; the catalogue knows only CVEs, which live in the
    record's aliases. Looking up `vulnerability.id` would match nothing, raise
    nothing, and produce a clean-looking run -- so the lookup goes through
    `cve_ids` and nothing else reaches `Catalogue.get`.

    Deduplication is on the CVE for the same reason: one CVE reachable through
    two OSV records is one obligation, not two. The OSV ids travel with the
    exposure so the user can still follow it back.
    """
    order: list[str] = []
    osv_ids: dict[str, list[str]] = {}
    components: dict[str, list[str]] = {}
    uncheckable: list[Uncheckable] = []

    for vulnerability in vulnerabilities:
        cve_ids = vulnerability.cve_ids
        if not cve_ids:
            # No CVE anywhere in the record. Never checkable, and therefore
            # never a NO.
            uncheckable.append(
                Uncheckable(
                    vuln_id=vulnerability.id,
                    component_refs=tuple(vulnerability.affects),
                )
            )
            continue
        for cve_id in cve_ids:
            key = cve_id.upper()
            if key not in osv_ids:
                order.append(key)
                osv_ids[key] = []
                components[key] = []
            if vulnerability.id and vulnerability.id not in osv_ids[key]:
                osv_ids[key].append(vulnerability.id)
            for ref in vulnerability.affects:
                if ref not in components[key]:
                    components[key].append(ref)

    exposures = tuple(
        Exposure(
            cve_id=key,
            entry=catalogue.get(key),
            osv_ids=tuple(osv_ids[key]),
            component_refs=tuple(components[key]),
        )
        for key in order
    )
    return Review(exposures=exposures, uncheckable=tuple(uncheckable))


# --- rendering ------------------------------------------------------------
#
# Counts only. Buckets, the table and the decision brief are step 6 and 7;
# what belongs here is the part of the picture the catalogue layer owns --
# how many CVEs were put to it, how many came back listed, and how many
# vulnerabilities it was never in a position to be asked about.


def banner_line(review: Review) -> str | None:
    """The uncheckable count, for the input banner. None when there are none.

    Indented to line up under the quality gate's own second line: it is the
    same kind of statement -- this much of the product was not assessed -- and
    printing it anywhere else would read as a separate, weaker caveat.
    """
    if not review.uncheckable:
        return None
    count = len(review.uncheckable)
    noun = "vulnerability" if count == 1 else "vulnerabilities"
    return (
        f"       {count} {noun} with no CVE id"
        " - not checkable against the KEV catalogue"
    )


def uncheckable_warning(review: Review) -> str | None:
    """The paragraph explaining why those are not a NO.

    Both numbers are written out. The count governs three pronouns after the
    first clause, and a plural one behind a singular subject is the kind of
    seam that tells a reader the sentence was assembled rather than meant --
    in the one paragraph whose whole job is to be believed.
    """
    if not review.uncheckable:
        return None
    if len(review.uncheckable) == 1:
        subject, it, they, them = "1 vulnerability carries", "it", "It is", "it"
    else:
        subject = f"{len(review.uncheckable)} vulnerabilities carry"
        it, they, them = "them", "They are", "them"
    return (
        f"{subject} no CVE id, so the KEV catalogue could not be asked about"
        f" {it}. {they} not absent from the catalogue: the question was never"
        f" put. Treat {them} as unassessed for exploitation, exactly as you"
        " would an unmatched component -- not as clear."
    )


def summary_lines(review: Review) -> list[str]:
    """What the catalogue was asked and what it answered.

    The listed CVEs are counted, never enumerated here, and the absent ones get
    no row at all: section 6 allows one summary line for what is not in the
    catalogue, and this is it.
    """
    out = [
        count_line(
            "CVEs checked",
            review.checked,
            "(distinct CVE ids put to the EUVD KEV catalogue)",
        )
    ]
    if review.listed:
        # The unit changes here and the buckets below change it back, which
        # is exactly where a reader does the arithmetic and finds it does not
        # work. Five ids over seven pairs, said on screen.
        out.append(
            count_line(
                "known exploited",
                len(review.listed),
                "(distinct CVE ids listed in the catalogue,",
            )
        )
        pairs = review.listed_pairs
        noun = "pair" if pairs == 1 else "pairs"
        out.append(note_line(f"across {pairs} component-CVE {noun})"))
    else:
        out.append(
            count_line(
                "known exploited", 0, "(distinct CVE ids listed in the catalogue)"
            )
        )
    if review.uncheckable:
        out.append(
            count_line(
                "not checkable",
                len(review.uncheckable),
                "(records with no CVE id; no key to look up)",
            )
        )
    return out
