"""On-disk cache for everything fetched over the network.

Offline CI runs have to work against a warm cache, so the cache is not an
optimisation here -- it is the offline execution path. Two consequences
shape the design:

* Entries carry their own age and the caller decides what is too old. A
  matching run that silently used a year-old OSV record would be the same
  false-negative failure the input quality gate exists to prevent.
* A corrupt or unreadable entry is a miss, never an error. A cache is a
  convenience; it must not be able to break a run.

Layout, under one directory per source:

    <root>/osv/vulns/<id>.json        hydrated OSV records, keyed by id
    <root>/osv/batch/<sha256>.json    querybatch results, keyed by query
    <root>/euvd/kev.json              the KEV dump (step 5)

Nothing here knows what the payloads mean.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

# Written into every entry so a future version can recognise and discard
# layouts it does not understand instead of misreading them.
FORMAT = 1

_ENV_VAR = "ART14_CACHE_DIR"


def default_root() -> Path:
    """Where the cache lives when the caller does not say.

    `ART14_CACHE_DIR` wins, which is what CI uses to point the cache at a
    restored build artefact.
    """
    override = os.environ.get(_ENV_VAR)
    if override:
        return Path(override)
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return Path(base) / "art14" / "cache"
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(
        os.path.expanduser("~"), ".cache"
    )
    return Path(base) / "art14"


@dataclass(frozen=True)
class Entry:
    """One cached payload and how old it is."""

    payload: object
    stored_at: float

    @property
    def age_seconds(self) -> float:
        return max(0.0, time.time() - self.stored_at)

    def is_fresh(self, max_age_seconds: float | None) -> bool:
        """`None` means no expiry: the caller keys freshness on something else."""
        if max_age_seconds is None:
            return True
        return self.age_seconds <= max_age_seconds


class Cache:
    """A namespaced directory of JSON files. No index, no locking.

    Concurrency is handled by writing to a temporary file and renaming it, so a
    reader either sees the old entry or the new one and never a half-written
    one. Two runs racing on the same key write the same bytes anyway.
    """

    def __init__(self, root: Path | str | None = None) -> None:
        self.root = Path(root) if root is not None else default_root()

    # -- reading ----------------------------------------------------------

    def get(self, namespace: str, key: str) -> Entry | None:
        """The entry, or None if absent, unreadable or written by a newer art14."""
        path = self.path_for(namespace, key)
        try:
            raw = path.read_text(encoding="utf-8")
        except (OSError, ValueError):
            return None
        try:
            record = json.loads(raw)
        except json.JSONDecodeError:
            # A truncated write from a killed process. Treat as a miss; the
            # next store overwrites it.
            return None
        if not isinstance(record, dict) or record.get("format") != FORMAT:
            return None
        stored_at = record.get("storedAt")
        if not isinstance(stored_at, (int, float)):
            return None
        return Entry(payload=record.get("payload"), stored_at=float(stored_at))

    # -- writing ----------------------------------------------------------

    def store(self, namespace: str, key: str, payload: object) -> None:
        """Best effort. A cache that cannot be written must not fail the run."""
        path = self.path_for(namespace, key)
        record = {"format": FORMAT, "storedAt": time.time(), "payload": payload}
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.with_name(f"{path.name}.{os.getpid()}.tmp")
            temporary.write_text(json.dumps(record), encoding="utf-8")
            os.replace(temporary, path)
        except OSError:
            return

    # -- paths ------------------------------------------------------------

    def path_for(self, namespace: str, key: str) -> Path:
        return self.root / namespace / f"{_safe(key)}.json"


def _safe(key: str) -> str:
    """A filename for a key that may contain slashes, colons and @ signs.

    OSV ids are already filename-safe (`GHSA-...`, `CVE-...`) and stay
    readable, which matters when someone inspects a cache directory to see what
    a CI run actually used. Anything else is hashed.
    """
    if key and all(c.isalnum() or c in "-_." for c in key) and ".." not in key:
        return key
    return hashlib.sha256(key.encode("utf-8")).hexdigest()
