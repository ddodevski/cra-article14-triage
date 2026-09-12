"""Shared fixtures, and a hard guarantee that the suite never uses the network.

OSV and KEV fixtures are pinned so tests never touch the network. "We
remembered to mock it everywhere" is not that guarantee -- one un-mocked call
makes the suite flaky, slow and dependent on someone else's uptime, and it
usually appears in the test that matters most.

So the real transport is removed for every test. `httpx.MockTransport` is a
different class and is unaffected, which is exactly the line we want: fixtures
work, sockets do not.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import httpx
import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def no_network(monkeypatch, tmp_path):
    """Fail loudly on any real connection, and never touch the user's cache."""

    def forbidden(self, request):  # pragma: no cover - the point is to not run
        raise AssertionError(
            f"test attempted a real network request: {request.method} {request.url}"
        )

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", forbidden)
    # A test that wrote into the developer's real cache directory would leak
    # state between runs and could make a later run pass for the wrong reason.
    monkeypatch.setenv("ART14_CACHE_DIR", str(tmp_path / "cache"))


@pytest.fixture
def osv_responses(monkeypatch):
    """Serve OSV from a canned routing table, through the real client code.

    The client is exercised end to end -- chunking, index alignment, caching,
    hydration -- with only the socket replaced.
    """

    def install(handler):
        from art14 import cli
        from art14.osv import OsvClient

        transport = httpx.MockTransport(handler)

        def factory(*args, **kwargs):
            kwargs.setdefault("transport", transport)
            return OsvClient(*args, **kwargs)

        monkeypatch.setattr(cli, "OsvClient", factory)
        return transport

    return install


def osv_handler(batch, records, *, calls=None):
    """A MockTransport handler for querybatch plus hydration.

    `batch` maps a purl to the list of `{"id", "modified"}` OSV would return;
    `records` maps an id to the full record `/v1/vulns/{id}` serves.
    """

    def handle(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(request)
        if request.url.path == "/v1/querybatch":
            queries = json.loads(request.content)["queries"]
            results = []
            for query in queries:
                purl = query.get("package", {}).get("purl", "")
                results.append({"vulns": list(batch.get(purl, []))})
            return httpx.Response(200, json={"results": results})
        if request.url.path.startswith("/v1/vulns/"):
            vuln_id = request.url.path.rsplit("/", 1)[-1]
            if vuln_id in records:
                return httpx.Response(200, json=records[vuln_id])
            return httpx.Response(404, json={"message": "not found"})
        return httpx.Response(404, json={"message": "unexpected path"})

    return handle


def record(vuln_id, *, modified="2026-01-01T00:00:00Z", aliases=(), **extra):
    """A minimal OSV record, shaped like the real ones."""
    payload = {
        "id": vuln_id,
        "modified": modified,
        "summary": f"{vuln_id} summary",
        "aliases": list(aliases),
    }
    payload.update(extra)
    return payload


# The catalogue every CLI test runs against unless it says otherwise. Log4Shell
# is in it because that is the demo the whole tool is built around, and a test
# that needs it absent removes it rather than working around its presence.
KEV_DUMP = [
    {
        "cveId": "CVE-2021-44228",
        "euvdId": "EUVD-2021-0001",
        "dateAdded": "2021-12-10",
        "sources": ["cisa_kev", "eu_kev"],
    },
    {
        "cveId": "CVE-2026-0002",
        "euvdId": "EUVD-2026-0002",
        "dateAdded": "2026-02-01",
        "sources": ["eu_kev"],
    },
]


# A catalogue that exists and lists nothing this suite's fixtures contain. Not
# an empty list: a dump that parses to zero entries raises, by design, because
# an empty catalogue and an unavailable one answer every question identically.
IRRELEVANT_KEV_DUMP = [
    {
        "cveId": "CVE-1999-0001",
        "euvdId": "EUVD-1999-0001",
        "dateAdded": "1999-01-01",
        "sources": ["eu_kev"],
    },
]


@pytest.fixture
def kev_state():
    """What the stubbed catalogue serves. Mutate it to change the run.

    `dump` is the payload `parse_dump` sees; `error` is raised instead when set,
    which is how a test asks for the fail-closed path; `load` short-circuits
    both and hands back a ready-made `CatalogueLoad`, which is how a test asks
    for a stale cache-served catalogue without inventing a clock.

    `kwargs` is what the CLI actually constructed the client with. Asserting on
    it is the only way to catch `--offline` failing to reach the client: the
    stub would take a socket-opening run and make it pass.
    """
    return {
        "dump": [dict(entry) for entry in KEV_DUMP],
        "error": None,
        "load": None,
        "kwargs": None,
    }


@pytest.fixture(autouse=True)
def kev_catalogue(monkeypatch, kev_state):
    """Give every CLI run a catalogue, because every CLI run now needs one.

    Autouse deliberately. Without it the network guard would make each existing
    CLI test exercise the catalogue-unavailable path instead of the thing it
    was written to check, and a suite where every test fails the same way tells
    you nothing about any of them.

    Tests of the client itself build a real `KevClient` over a `MockTransport`
    and are untouched by this.
    """
    from art14 import cli, kev

    class _StubClient:
        def __init__(self, *args, **kwargs):
            kev_state["kwargs"] = dict(kwargs)

        def load(self):
            if kev_state["error"] is not None:
                raise kev_state["error"]
            if kev_state["load"] is not None:
                return kev_state["load"]
            return kev.CatalogueLoad(
                catalogue=kev.parse_dump(kev_state["dump"]),
                fetched_at=time.time(),
            )

        def close(self):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            pass

    monkeypatch.setattr(cli, "KevClient", _StubClient)


def kev_handler(payload, *, calls=None, status=200):
    """A MockTransport handler serving one KEV dump."""

    def handle(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(request)
        if request.url.path == "/api/kev/dump":
            return httpx.Response(status, json=payload)
        return httpx.Response(404, json={"message": "unexpected path"})

    return handle
