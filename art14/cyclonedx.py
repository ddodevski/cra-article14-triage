"""CycloneDX reader: JSON document in, `Sbom` out.

Supports CycloneDX 1.5, 1.6 and 1.7. The parts this tool reads -- `components`,
`dependencies`, `vulnerabilities` -- have the same shape in all three, so there
is no version abstraction layer here on purpose. 1.7 adds fields beside them
(`provides` on a dependency, `omniborId`, `swhid`, `tags`, `isExternal` on a
component) and renames nothing this module looks at.

A later 1.x is parsed rather than refused, and the run says so. CycloneDX is
additive within a major version, and the alternative is worse in a specific
way: `grype ... | art14 -` is the documented composition path, the scanner
upgrades on its own schedule, and a tool that exits 1 with "not supported" the
morning 1.8 ships has stopped answering a question it could still answer. A 2.x
is a different matter and is refused -- a major version is where things are
allowed to be renamed.

This module knows nothing about KEV, buckets, EPSS or rendering.
"""

from __future__ import annotations

import json
import sys
from collections import deque
from pathlib import Path
from typing import IO, Any, Iterable

from .errors import SbomError
from .models import (
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

# Versions this build has actually been read against, oldest first.
SUPPORTED_SPEC_VERSIONS = ("1.5", "1.6", "1.7")


def is_newer_than_tested(spec_version: str) -> bool:
    """Whether this is a 1.x past the last version this build was read against.

    Parsed on the strength of CycloneDX being additive within a major version,
    and never silently: `version_caveat` puts it in the output. Anything that
    is not a 1.x -- a 2.x, or something that is not two integers -- returns
    False and is refused, because a major version is exactly where a field
    this module reads is allowed to be renamed.
    """
    tested = _version_tuple(SUPPORTED_SPEC_VERSIONS[-1])
    found = _version_tuple(spec_version)
    if found is None or tested is None:
        return False
    return found[0] == tested[0] and found > tested


def version_caveat(spec_version: str) -> str | None:
    """What to say about an untested spec version, or None when there is
    nothing to say. Never suppressed: the run parsed something it has not been
    checked against, and a consumer who is not told cannot account for it."""
    if spec_version in SUPPORTED_SPEC_VERSIONS or not is_newer_than_tested(
        spec_version
    ):
        return None
    return (
        f"This SBOM declares CycloneDX {spec_version}, which is newer than"
        f" anything this build of art14 was tested against"
        f" ({SUPPORTED_SPEC_VERSIONS[-1]}). It was read on the assumption that"
        " the components, dependencies and vulnerabilities carry the same"
        " shape they always have. If the counts below look wrong, that"
        " assumption is where to look first. The run continues, but it will"
        " not certify: an assumption is not a check, and exit 0 is the one"
        " code that claims there is nothing to report."
    )


def _version_tuple(value: str) -> tuple[int, ...] | None:
    parts = value.split(".")
    if len(parts) != 2 or not all(part.isdigit() for part in parts):
        return None
    return tuple(int(part) for part in parts)


STDIN = "-"


def parse_source(source: str | Path, stream: IO[Any] | None = None) -> Sbom:
    """Read from a file path, or from stdin when `source` is `-`.

    Stdin is the composition path: the tool never scans anything itself, so
    `syft <image> -o cyclonedx-json | art14 -` is how image workflows are
    served.
    """
    if str(source) != STDIN:
        return parse_file(source)

    stream = stream if stream is not None else sys.stdin
    # Without this, `art14 -` typed at a prompt blocks on an empty terminal
    # with no output at all, which is the opposite of "a result in under ten
    # seconds".
    if getattr(stream, "isatty", lambda: False)():
        raise SbomError(
            "reading from stdin but nothing is piped in - "
            "use `syft <image> -o cyclonedx-json | art14 -`, "
            "or pass a path to an SBOM file"
        )
    return parse_stream(stream)


def parse_file(path: str | Path) -> Sbom:
    """Read a CycloneDX JSON file from disk."""
    path = Path(path)
    try:
        # utf-8-sig: SBOMs generated on Windows often carry a BOM, which
        # json.loads rejects.
        raw = path.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        raise SbomError(f"no such file: {path}") from None
    except UnicodeDecodeError:
        raise SbomError(f"{path} is not UTF-8 text") from None
    except OSError as exc:
        raise SbomError(f"cannot read {path}: {exc}") from None

    return parse_text(raw, origin=str(path))


def parse_stream(stream: IO[Any]) -> Sbom:
    """Read a CycloneDX document from an open stream, typically stdin.

    Reads the underlying binary buffer when there is one and decodes UTF-8
    explicitly: a piped SBOM is UTF-8 regardless of what the console code page
    happens to be, and on Windows the text layer would otherwise mangle it.
    """
    try:
        raw = stream.buffer.read() if hasattr(stream, "buffer") else stream.read()
    except OSError as exc:
        raise SbomError(f"cannot read stdin: {exc}") from None

    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            raise SbomError("stdin is not UTF-8 text") from None

    if not raw.strip():
        raise SbomError("no input on stdin")

    return parse_text(raw, origin="stdin")


def parse_text(raw: str, *, origin: str = "input") -> Sbom:
    """Parse CycloneDX JSON text.

    Both entry points above decode as utf-8-sig, so any byte order mark -- and
    SBOMs generated on Windows often carry one -- is already gone by here.
    `origin` only shapes the error message.
    """
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SbomError(f"{origin} is not valid JSON: {exc}") from None

    if not isinstance(document, dict):
        raise SbomError(f"{origin} does not contain a CycloneDX document")

    return parse_document(document)


def parse_document(document: dict[str, Any]) -> Sbom:
    """Parse an already-loaded CycloneDX document."""
    spec_version = _check_format(document)

    root = _parse_root(document)
    listed = _parse_components(document.get("components"), root)
    # The type rule, applied once here so that everything downstream -- the
    # matcher, the quality denominator, the funnel -- sees the same inventory.
    # `by_ref` keeps both halves: a vulnerability affecting a non-package
    # component has to resolve, or the run would report it as affecting
    # something absent from the document, which is a different and false claim.
    components = tuple(c for c in listed if c.is_package)
    non_packages = tuple(c for c in listed if not c.is_package)
    by_ref = {component.bom_ref: component for component in listed}
    if root is not None:
        by_ref.setdefault(root.bom_ref, root)

    edges, depended_on = _parse_dependencies(document.get("dependencies"))
    root_ref = _resolve_root_ref(root, edges, depended_on)
    locations = _walk(root_ref, edges)

    vulnerabilities = _parse_vulnerabilities(
        document.get("vulnerabilities"), asserter=_parse_asserter(document)
    )
    findings, unresolved, excluded = _pair(vulnerabilities, by_ref, locations)

    return Sbom(
        spec_version=spec_version,
        root=root,
        components=components,
        vulnerabilities=vulnerabilities,
        locations=locations,
        findings=findings,
        unresolved_affects=unresolved,
        excluded_affects=excluded,
        non_packages=non_packages,
    )


# --- document level -------------------------------------------------------


def _check_format(document: dict[str, Any]) -> str:
    bom_format = document.get("bomFormat")
    if bom_format is not None and bom_format != "CycloneDX":
        raise SbomError(
            f"unsupported SBOM format {bom_format!r} - art14 reads CycloneDX JSON"
        )

    spec_version = document.get("specVersion")
    if spec_version is None:
        raise SbomError("document has no specVersion - is this a CycloneDX SBOM?")

    spec_version = str(spec_version)
    if spec_version in SUPPORTED_SPEC_VERSIONS:
        return spec_version
    if is_newer_than_tested(spec_version):
        # Parsed, and said out loud by `version_caveat`. See the module
        # docstring for why this is not a refusal.
        return spec_version
    supported = ", ".join(SUPPORTED_SPEC_VERSIONS)
    raise SbomError(
        f"CycloneDX {spec_version} is not supported - art14 reads {supported}"
        " and later 1.x"
    )


def _parse_root(document: dict[str, Any]) -> Component | None:
    """The product itself. It lives under `metadata`, not in `components[]`."""
    metadata = document.get("metadata")
    if not isinstance(metadata, dict):
        return None
    component = metadata.get("component")
    if not isinstance(component, dict):
        return None
    return _component(component, fallback_ref="art14:root")


# --- components -----------------------------------------------------------


def _parse_components(raw: Any, root: Component | None) -> tuple[Component, ...]:
    components: list[Component] = []
    seen: set[str] = {root.bom_ref} if root is not None else set()
    for index, entry in enumerate(_flatten(raw)):
        component = _component(entry, fallback_ref=f"art14:component-{index}")
        if component is None or component.bom_ref in seen:
            continue
        seen.add(component.bom_ref)
        components.append(component)
    return tuple(components)


def _flatten(raw: Any) -> Iterable[dict[str, Any]]:
    """Yield components including nested `components[].components[]` trees."""
    if not isinstance(raw, list):
        return
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        yield entry
        yield from _flatten(entry.get("components"))


def _component(entry: Any, *, fallback_ref: str) -> Component | None:
    if not isinstance(entry, dict):
        return None
    name = _text(entry.get("name")) or ""
    version = _text(entry.get("version")) or ""
    purl = _text(entry.get("purl"))
    bom_ref = (
        _text(entry.get("bom-ref"))
        or purl
        or (f"{name}@{version}" if name else None)
        or fallback_ref
    )
    return Component(
        bom_ref=bom_ref,
        name=name or bom_ref,
        version=version,
        purl=purl,
        type=_text(entry.get("type")) or "library",
    )


# --- dependency graph -----------------------------------------------------


def _parse_dependencies(raw: Any) -> tuple[dict[str, tuple[str, ...]], set[str]]:
    """`dependencies[]` is a flat array; turn it into an adjacency map."""
    edges: dict[str, tuple[str, ...]] = {}
    depended_on: set[str] = set()
    if not isinstance(raw, list):
        return edges, depended_on

    for entry in raw:
        if not isinstance(entry, dict):
            continue
        ref = _text(entry.get("ref"))
        if not ref:
            continue
        children = tuple(
            child
            for child in (_text(c) for c in _as_list(entry.get("dependsOn")))
            if child
        )
        edges[ref] = edges.get(ref, ()) + children
        depended_on.update(children)
    return edges, depended_on


def _resolve_root_ref(
    root: Component | None,
    edges: dict[str, tuple[str, ...]],
    depended_on: set[str],
) -> str | None:
    """Find the node the graph hangs off.

    `metadata.component` is authoritative when the graph actually mentions it.
    Otherwise fall back to the single node nothing depends on; if that is
    ambiguous there is no honest root, and components stay unknown rather than
    being guessed into `direct`.
    """
    if root is not None and root.bom_ref in edges:
        return root.bom_ref
    top_level = [ref for ref in edges if ref not in depended_on]
    if len(top_level) == 1:
        return top_level[0]
    return root.bom_ref if root is not None else None


def _walk(root_ref: str | None, edges: dict[str, tuple[str, ...]]) -> dict[str, Location]:
    """Breadth-first walk from the root.

    BFS rather than recursion because real dependency graphs contain cycles,
    and because the shortest path is the one to show: a component reachable at
    depth 1 is direct even if it is also reachable at depth 3.
    """
    if root_ref is None:
        return {}

    locations: dict[str, Location] = {
        root_ref: Location(kind=ROOT, depth=0, chain=(root_ref,))
    }
    queue: deque[tuple[str, tuple[str, ...]]] = deque([(root_ref, (root_ref,))])

    while queue:
        ref, chain = queue.popleft()
        for child in edges.get(ref, ()):
            if child in locations:
                continue
            depth = len(chain)
            locations[child] = Location(
                kind=DIRECT if depth == 1 else TRANSITIVE,
                depth=depth,
                chain=chain + (child,),
            )
            queue.append((child, chain + (child,)))
    return locations


# --- vulnerabilities ------------------------------------------------------


def _parse_vulnerabilities(raw: Any, *, asserter: str = "") -> tuple[Vulnerability, ...]:
    vulnerabilities: list[Vulnerability] = []
    for entry in _as_list(raw):
        if not isinstance(entry, dict):
            continue
        identifier = _text(entry.get("id"))
        if not identifier:
            continue
        source = entry.get("source")
        affects, not_affected = _parse_affects(entry.get("affects"))
        vulnerabilities.append(
            Vulnerability(
                id=identifier,
                source_name=_text(source.get("name")) if isinstance(source, dict) else None,
                description=_text(entry.get("description")),
                cwes=_parse_cwes(entry.get("cwes")),
                ratings=_parse_ratings(entry.get("ratings")),
                affects=affects,
                not_affected=not_affected,
                analysis=_parse_analysis(entry.get("analysis"), asserter),
            )
        )
    return tuple(vulnerabilities)


def _parse_analysis(raw: Any, asserter: str) -> VexClaim | None:
    """The document-level VEX statement, carried but not obeyed.

    Read here rather than discarded because the alternative choices are both
    bad: acting on it silently would let an upstream tool decide that a
    manufacturer has nothing to report, and dropping it would hide from the
    reader that anyone had made the claim at all. So it is parsed, attributed,
    and left for layer 3 to display -- and to adopt only when the operator
    says on the command line that they trust whoever produced the SBOM.
    """
    if not isinstance(raw, dict):
        return None
    state = _text(raw.get("state"))
    if not state:
        # A block with a justification and no state asserts nothing. There is
        # no default state in CycloneDX and inventing one here would be the
        # tool making the claim rather than reporting it.
        return None
    return VexClaim(
        state=state.strip().lower(),
        justification=_text(raw.get("justification")),
        detail=_text(raw.get("detail")),
        asserted_by=asserter,
    )


def _parse_asserter(document: dict[str, Any]) -> str:
    """Who the document says produced it, for attributing its own claims.

    `metadata.tools` changed shape in 1.5 -- an object with `components` and
    `services` replaced the flat array, and both spellings are still in the
    wild -- so both are read. Authors are the fallback: a hand-written VEX
    statement has a person behind it rather than a tool, and "asserted by"
    with nothing after it is not an attribution.
    """
    metadata = document.get("metadata")
    if not isinstance(metadata, dict):
        return ""

    names: list[str] = []
    tools = metadata.get("tools")
    entries: list[Any] = []
    if isinstance(tools, dict):
        entries = list(_as_list(tools.get("components"))) + list(
            _as_list(tools.get("services"))
        )
    elif isinstance(tools, list):
        entries = tools
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = _text(entry.get("name"))
        if not name:
            continue
        version = _text(entry.get("version"))
        names.append(f"{name} {version}" if version else name)

    if not names:
        for entry in _as_list(metadata.get("authors")):
            if isinstance(entry, dict):
                name = _text(entry.get("name"))
                if name:
                    names.append(name)

    # More than a couple of names is a pipeline, not an author, and the point
    # of the field is to be readable at the end of a sentence.
    unique = list(dict.fromkeys(names))
    if len(unique) > 3:
        return ", ".join(unique[:3]) + f" and {len(unique) - 3} more"
    return ", ".join(unique)


def _parse_cwes(raw: Any) -> tuple[int, ...]:
    cwes: list[int] = []
    for value in _as_list(raw):
        if isinstance(value, bool):
            continue
        try:
            cwe = int(str(value).strip().upper().removeprefix("CWE-"))
        except (TypeError, ValueError):
            continue
        if cwe not in cwes:
            cwes.append(cwe)
    return tuple(cwes)


def _parse_ratings(raw: Any) -> tuple[Rating, ...]:
    ratings: list[Rating] = []
    for entry in _as_list(raw):
        if not isinstance(entry, dict):
            continue
        source = entry.get("source")
        ratings.append(
            Rating(
                method=_text(entry.get("method")),
                score=_number(entry.get("score")),
                severity=_text(entry.get("severity")),
                vector=_text(entry.get("vector")),
                source=_text(source.get("name")) if isinstance(source, dict) else None,
            )
        )
    return tuple(ratings)


def _parse_affects(raw: Any) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Split `affects[]` into refs to triage and refs the SBOM rules out.

    Each entry may carry `versions[]` with a `status` of affected, unaffected
    or unknown; absent `versions` means affected. A ref is dropped only when
    every version entry explicitly says `unaffected` -- anything else, unknown
    included, stays in. No version-range matching: `vers` ranges are not
    evaluated here, because a wrong range match would silently discard a real
    obligation, and this tool resolves uncertainty towards reporting.
    """
    affected: list[str] = []
    not_affected: list[str] = []
    for entry in _as_list(raw):
        if isinstance(entry, dict):
            ref = _text(entry.get("ref"))
            ruled_out = _is_ruled_out(entry.get("versions"))
        else:
            ref = _text(entry)
            ruled_out = False
        if not ref:
            continue
        target = not_affected if ruled_out else affected
        if ref not in target:
            target.append(ref)
    # A ref asserted affected anywhere wins over an unaffected assertion.
    not_affected = [ref for ref in not_affected if ref not in affected]
    return tuple(affected), tuple(not_affected)


def _is_ruled_out(versions: Any) -> bool:
    entries = [entry for entry in _as_list(versions) if isinstance(entry, dict)]
    if not entries:
        return False
    return all(
        (_text(entry.get("status")) or "affected").lower() == "unaffected"
        for entry in entries
    )


def _pair(
    vulnerabilities: tuple[Vulnerability, ...],
    by_ref: dict[str, Component],
    locations: dict[str, Location],
) -> tuple[
    tuple[Finding, ...], tuple[tuple[str, str], ...], tuple[tuple[str, str], ...]
]:
    """Join vulnerabilities onto components: one finding per affected pair."""
    findings: list[Finding] = []
    unresolved: list[tuple[str, str]] = []
    excluded: list[tuple[str, str]] = []
    for vulnerability in vulnerabilities:
        for ref in vulnerability.not_affected:
            if ref in by_ref:
                excluded.append((vulnerability.id, ref))
        for ref in vulnerability.affects:
            component = by_ref.get(ref)
            if component is None:
                unresolved.append((vulnerability.id, ref))
                continue
            findings.append(
                Finding(
                    vulnerability=vulnerability,
                    component=component,
                    location=locations.get(ref, Location()),
                )
            )
    return tuple(findings), tuple(unresolved), tuple(excluded)


# --- small helpers --------------------------------------------------------


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _text(value: Any) -> str | None:
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return None


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None
