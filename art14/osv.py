"""Layer 1: component to CVE, via OSV.dev.

This stage is plumbing and is meant to be boring. It answers one question --
which vulnerabilities does OSV know about for these components -- and it is
deliberately incapable of deciding anything. No buckets, no severity
judgement, no KEV.

Three things here are not boring, and all three are places where a plausible
shortcut produces a silent false negative:

**Index alignment.** `querybatch` returns results positionally, including empty
ones. Zipping only the non-empty results back onto the inventory shifts every
subsequent component onto the wrong CVEs. The query list and the component list
are therefore built together and never filtered apart.

**Version or versioned purl, never both.** Sending both returns 400, which
would fail a whole chunk of 1000 because of one component.

**A failed query is not a clean component.** If a chunk errors, or the cache is
cold with no network, the components in it were not assessed. They are returned
as `failed` and the quality gate folds them into `unmatchable` alongside the
ones with no PURL, because for the purpose of "could we have found anything"
they are the same thing.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Iterable, Sequence

import httpx

from .cache import Cache
from .models import Component, Finding, Location, Rating, Vulnerability

API = "https://api.osv.dev"

# Section 3: batch in chunks of 1000.
CHUNK = 1000

# How long a querybatch result stays usable. OSV publishes continuously, so a
# day-old answer is a reasonable CI default -- and `--offline` accepts older
# entries rather than failing, because a stale answer that is reported as stale
# is more useful than no answer at all.
BATCH_MAX_AGE = 24 * 60 * 60

_NS_BATCH = "osv/batch"
_NS_VULNS = "osv/vulns"

# OSV severity `type` values mapped onto the method names the model ranks by.
_SEVERITY_METHODS = {
    "CVSS_V2": "CVSSv2",
    "CVSS_V3": "CVSSv3",
    "CVSS_V4": "CVSSv4",
}

# A single query can page when one component has an extreme number of vulns.
# Bounded so a malformed token cannot spin forever.
_MAX_PAGES = 20


@dataclass(frozen=True)
class MatchResult:
    """What layer 1 produced, and what it failed to produce.

    `queried` and `failed` together are every component that *could* have been
    sent. Components with no PURL or no version were never sendable and are
    already counted by the quality gate, so they appear in neither.
    """

    vulnerabilities: tuple[Vulnerability, ...]
    findings: tuple[Finding, ...]
    queried: tuple[Component, ...]
    failed: tuple[Component, ...]
    # Components answered from a cache entry older than BATCH_MAX_AGE. Used,
    # because offline is a supported mode, but never used silently.
    stale: tuple[Component, ...] = ()
    from_cache: int = 0
    fetched: int = 0
    # When this run last went over the wire, and how old the oldest answer it
    # served from the cache was. Two facts, never one: on a mixed run a single
    # run-level timestamp either backdates what was fetched or freshens what
    # was cached, and the second is the dangerous direction.
    fetched_at: float | None = None
    oldest_cache_entry: float | None = None

    @property
    def attempted(self) -> int:
        return len(self.queried) + len(self.failed)

    @property
    def went_online(self) -> bool:
        """Whether this run reached the network at all."""
        return self.fetched_at is not None

    @property
    def served_from_cache(self) -> bool:
        """Whether any answer here came off disk rather than the wire."""
        return self.from_cache > 0

    @property
    def has_answers(self) -> bool:
        """Whether anything at all was assessed."""
        return bool(self.queried)


class OsvClient:
    """Talks to OSV.dev, or to the cache, or to neither.

    `offline=True` never opens a socket: every answer comes from the cache and
    anything not cached is a failure. That is the mode CI has to run in, so it
    is a first-class path rather than an error handler.
    """

    def __init__(
        self,
        cache: Cache | None = None,
        *,
        offline: bool = False,
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.cache = cache if cache is not None else Cache()
        self.offline = offline
        self.timeout = timeout
        self._transport = transport
        self._client: httpx.Client | None = None

    # -- public surface ---------------------------------------------------

    def match(self, components: Sequence[Component]) -> MatchResult:
        """Query every sendable component and hydrate what comes back."""
        sendable = [c for c in components if query_for(c) is not None]

        queried: list[Component] = []
        failed: list[Component] = []
        stale: list[Component] = []
        # bom-ref -> the (id, modified) pairs OSV returned for it.
        hits: dict[str, list[dict[str, str]]] = {}
        from_cache = 0
        oldest_cache_entry: float | None = None

        pending: list[Component] = []
        for component in sendable:
            entry = self.cache.get(_NS_BATCH, _batch_key(component))
            if entry is None or not isinstance(entry.payload, list):
                pending.append(component)
                continue
            if not entry.is_fresh(BATCH_MAX_AGE):
                if not self.offline:
                    pending.append(component)
                    continue
                # Offline: an old answer, reported as old.
                stale.append(component)
            hits[component.bom_ref] = list(entry.payload)
            queried.append(component)
            from_cache += 1
            if oldest_cache_entry is None or entry.stored_at < oldest_cache_entry:
                oldest_cache_entry = entry.stored_at

        fetched_at: float | None = None
        for chunk in _chunks(pending, CHUNK):
            if not self.offline:
                # Stamped per attempt, not per success: a chunk that errored
                # still reached the network, and the provenance block says
                # when we last tried, not only when we last succeeded.
                fetched_at = time.time()
            resolved, chunk_failed = self._query_chunk(chunk)
            for component, vulns in resolved:
                hits[component.bom_ref] = vulns
                queried.append(component)
            failed.extend(chunk_failed)

        ids = {
            vuln["id"]: vuln.get("modified", "")
            for vulns in hits.values()
            for vuln in vulns
            if vuln.get("id")
        }
        records, fetched, unhydrated = self._hydrate(ids)
        if fetched and not self.offline:
            fetched_at = time.time()

        # A vulnerability we could not hydrate is a vulnerability we cannot put
        # a brief under. The component that carried it is not assessed.
        if unhydrated:
            still_ok, now_failed = [], []
            for component in queried:
                carried = {v.get("id") for v in hits.get(component.bom_ref, ())}
                (now_failed if carried & unhydrated else still_ok).append(component)
            queried, failed = still_ok, failed + now_failed

        kept = {c.bom_ref for c in queried}
        vulnerabilities, findings = _assemble(queried, hits, records)
        return MatchResult(
            vulnerabilities=vulnerabilities,
            findings=findings,
            queried=tuple(queried),
            failed=tuple(failed),
            stale=tuple(s for s in stale if s.bom_ref in kept),
            from_cache=from_cache,
            fetched=fetched,
            fetched_at=fetched_at,
            oldest_cache_entry=oldest_cache_entry,
        )

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> OsvClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- querying ---------------------------------------------------------

    def _query_chunk(
        self, chunk: Sequence[Component]
    ) -> tuple[list[tuple[Component, list[dict[str, str]]]], list[Component]]:
        """One querybatch call. Either the whole chunk resolves or it fails."""
        if self.offline:
            # Everything cacheable was already served above.
            return [], list(chunk)

        queries = [query_for(component) for component in chunk]
        try:
            payload = self._post("/v1/querybatch", {"queries": queries})
        except (httpx.HTTPError, ValueError):
            return [], list(chunk)

        results = payload.get("results")
        if not isinstance(results, list) or len(results) != len(chunk):
            # Section 3: results are index-aligned. A length mismatch means we
            # cannot say which answer belongs to which component, and guessing
            # is how a component silently acquires another one's CVEs.
            return [], list(chunk)

        # A list of pairs, not a dict: two components can be value-equal and
        # must not collapse into one entry.
        resolved: list[tuple[Component, list[dict[str, str]]]] = []
        failed: list[Component] = []
        for component, result, query in zip(chunk, results, queries):
            if not isinstance(result, dict):
                failed.append(component)
                continue
            vulns = [v for v in result.get("vulns") or [] if isinstance(v, dict)]
            token = result.get("next_page_token")
            if token:
                extra, complete = self._follow_pages(query, str(token))
                if not complete:
                    failed.append(component)
                    continue
                vulns.extend(extra)
            resolved.append((component, vulns))
            self.cache.store(_NS_BATCH, _batch_key(component), vulns)
        return resolved, failed

    def _follow_pages(
        self, query: dict[str, object], token: str
    ) -> tuple[list[dict[str, str]], bool]:
        """Drain one query's remaining pages. False means we gave up."""
        collected: list[dict[str, str]] = []
        for _ in range(_MAX_PAGES):
            paged = dict(query, page_token=token)
            try:
                payload = self._post("/v1/querybatch", {"queries": [paged]})
            except (httpx.HTTPError, ValueError):
                return collected, False
            results = payload.get("results")
            if not isinstance(results, list) or len(results) != 1:
                return collected, False
            result = results[0] if isinstance(results[0], dict) else {}
            collected.extend(
                v for v in result.get("vulns") or [] if isinstance(v, dict)
            )
            token = str(result.get("next_page_token") or "")
            if not token:
                return collected, True
        return collected, False

    # -- hydrating --------------------------------------------------------

    def _hydrate(
        self, ids: dict[str, str]
    ) -> tuple[dict[str, dict], int, set[str]]:
        """Full records for every id. Cached by (id, modified)."""
        records: dict[str, dict] = {}
        missing: set[str] = set()
        fetched = 0

        for vuln_id, modified in ids.items():
            entry = self.cache.get(_NS_VULNS, vuln_id)
            cached, seen_at = _unwrap(entry.payload if entry is not None else None)
            if cached is not None and (not modified or seen_at == modified):
                # Same modified timestamp: the record cannot have changed.
                records[vuln_id] = cached
                continue
            if self.offline:
                if cached is not None:
                    # Older than what querybatch just named, but it is a real
                    # record and offline is a supported mode.
                    records[vuln_id] = cached
                else:
                    missing.add(vuln_id)
                continue
            try:
                record = self._get(f"/v1/vulns/{vuln_id}")
            except (httpx.HTTPError, ValueError):
                if cached is not None:
                    records[vuln_id] = cached
                else:
                    missing.add(vuln_id)
                continue
            records[vuln_id] = record
            self.cache.store(_NS_VULNS, vuln_id, _wrap(record, modified))
            fetched += 1

        return records, fetched, missing

    # -- transport --------------------------------------------------------

    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                base_url=API,
                timeout=self.timeout,
                transport=self._transport,
                headers={"user-agent": _user_agent()},
            )
        return self._client

    def _post(self, path: str, body: dict[str, object]) -> dict:
        response = self.client.post(path, json=body)
        response.raise_for_status()
        return _decode(response)

    def _get(self, path: str) -> dict:
        response = self.client.get(path)
        response.raise_for_status()
        return _decode(response)


# --- query construction ---------------------------------------------------


def query_for(component: Component) -> dict[str, object] | None:
    """The OSV query for a component, or None when it is not sendable.

    Section 3: a version and a versioned purl together return 400, which would
    take down a whole chunk of 1000 over one component. So a versioned purl is
    sent alone, and the `version` field is only used to complete a bare one.
    """
    purl = component.purl
    if not purl:
        return None
    if _purl_has_version(purl):
        return {"package": {"purl": purl}}
    if component.version:
        return {"package": {"purl": purl}, "version": component.version}
    return None


def _purl_has_version(purl: str) -> bool:
    name = purl.split("#", 1)[0].split("?", 1)[0].rsplit("/", 1)[-1]
    return "@" in name


def _batch_key(component: Component) -> str:
    query = query_for(component)
    return json.dumps(query, sort_keys=True, separators=(",", ":"))


# --- record conversion ----------------------------------------------------


def _assemble(
    components: Iterable[Component],
    hits: dict[str, list[dict[str, str]]],
    records: dict[str, dict],
) -> tuple[tuple[Vulnerability, ...], tuple[Finding, ...]]:
    """Turn OSV records into the model the triage stage already understands.

    One Vulnerability per OSV id, carrying every component it affects, so the
    downstream shape is identical to a pre-enriched SBOM's.
    """
    affects: dict[str, list[str]] = {}
    order: list[str] = []
    for component in components:
        for hit in hits.get(component.bom_ref, ()):
            vuln_id = hit.get("id")
            if not vuln_id or vuln_id not in records:
                continue
            if vuln_id not in affects:
                affects[vuln_id] = []
                order.append(vuln_id)
            affects[vuln_id].append(component.bom_ref)

    by_ref = {c.bom_ref: c for c in components}
    vulnerabilities = tuple(
        to_vulnerability(records[vuln_id], tuple(affects[vuln_id]))
        for vuln_id in order
    )
    findings = tuple(
        Finding(vulnerability=vulnerability, component=by_ref[ref], location=Location())
        for vulnerability in vulnerabilities
        for ref in vulnerability.affects
        if ref in by_ref
    )
    return vulnerabilities, findings


def to_vulnerability(record: dict, affects: tuple[str, ...] = ()) -> Vulnerability:
    """One OSV record as a `Vulnerability`.

    OSV's own id is often a GHSA, while layer 2 keys on CVE ids, so aliases are
    kept rather than discarded -- the KEV lookup needs somewhere to find the
    CVE. Nothing here decides anything; it only carries what the brief needs.
    """
    aliases = tuple(str(a) for a in record.get("aliases") or [] if a)
    return Vulnerability(
        id=str(record.get("id") or ""),
        source_name="OSV",
        description=record.get("summary") or record.get("details") or None,
        cwes=_cwes(record),
        ratings=_ratings(record),
        affects=affects,
        aliases=aliases,
        # The record's own value, deliberately not the `seenAt` we cache under:
        # querybatch truncates to microseconds while the record keeps
        # nanoseconds, and `seenAt` is a cache-keying artefact, not provenance.
        modified=str(record.get("modified") or ""),
    )


def _cwes(record: dict) -> tuple[int, ...]:
    specific = record.get("database_specific")
    raw = specific.get("cwe_ids") if isinstance(specific, dict) else None
    numbers: list[int] = []
    for item in raw or []:
        text = str(item).upper().removeprefix("CWE-")
        if text.isdigit():
            numbers.append(int(text))
    return tuple(dict.fromkeys(numbers))


def _ratings(record: dict) -> tuple[Rating, ...]:
    word = _qualitative(record)
    ratings: list[Rating] = []
    for severity in record.get("severity") or []:
        if not isinstance(severity, dict):
            continue
        method = _SEVERITY_METHODS.get(str(severity.get("type") or ""))
        vector = severity.get("score")
        if method is None or not isinstance(vector, str):
            continue
        # OSV carries the vector string, not the number. Scoring a vector
        # ourselves would be a CVSS implementation, which this is not; the
        # vector is shown and the score stays absent unless the SBOM gave one.
        ratings.append(
            Rating(method=method, vector=vector, severity=word, source="OSV")
        )
    if not ratings and word:
        # A band with no vector behind it is still the only readable thing on
        # the record, and dropping it would leave the row blank.
        ratings.append(Rating(severity=word, source="OSV"))
    return tuple(ratings)


def _qualitative(record: dict) -> str | None:
    """The severity word, where the publishing database states one.

    OSV has no field of its own for it. GitHub, which is where most Maven,
    npm and PyPI records come from, puts `low` / `moderate` / `high` /
    `critical` in `database_specific`, and without it every row of a matched
    run carries a vector and no number -- nothing a reader can sort on at a
    glance. It is taken as it stands and never translated into the CVSS
    vocabulary: `moderate` is GitHub's word and `medium` would be ours, and
    the difference is whether the reader can go and check it.
    """
    specific = record.get("database_specific")
    if not isinstance(specific, dict):
        return None
    value = specific.get("severity")
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip().lower()


# --- helpers --------------------------------------------------------------


def _wrap(record: dict, modified: str) -> dict:
    """Store the record next to the timestamp querybatch reported for it.

    The two are not the same string. OSV truncates `modified` to microseconds
    in a querybatch result and serves nanoseconds in the record itself, so
    comparing the record's own field against the batch's would miss on almost
    every entry -- a cache that stores everything and reuses nothing.
    """
    return {"seenAt": modified, "record": record}


def _unwrap(payload: object) -> tuple[dict | None, str | None]:
    """The cached record and the timestamp it was stored against."""
    if not isinstance(payload, dict):
        return None, None
    record = payload.get("record")
    if isinstance(record, dict):
        seen_at = payload.get("seenAt")
        return record, seen_at if isinstance(seen_at, str) else None
    # An entry written before the wrapper existed: usable, but we cannot tell
    # what it was current as of, so it gets refreshed once.
    if "id" in payload:
        return payload, None
    return None, None


def _chunks(items: Sequence[Component], size: int) -> Iterable[Sequence[Component]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


def _decode(response: httpx.Response) -> dict:
    payload = response.json()
    if not isinstance(payload, dict):
        raise ValueError("OSV returned a non-object response")
    return payload


def _user_agent() -> str:
    from . import __version__

    return f"art14/{__version__} (+https://github.com/)"
