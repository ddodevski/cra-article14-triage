"""The VEX export: `art14 <sbom> --vex out.vex.json`.

A CycloneDX VEX document carrying the dispositions this run produced. The
decision brief has always ended by telling the operator to write the rationale
down because "that becomes your VEX entry and your audit trail", and
`--adopt-upstream-vex` reads other people's VEX claims. Consuming a format
this tool refused to produce was an asymmetry with nothing behind it.

Like the HTML report, it reads the public JSON document and nothing else --
the same dict `--json` writes -- so it is a consumer of the documented schema
rather than a second path into the core. Given the same payload it writes the
same bytes: nothing here reads a clock, and no serial number is minted. The
operator commits this file, and a file that changes when nothing changed is a
diff nobody can read.

**Why CycloneDX and not CSAF.** CSAF's VEX profile requires an action
statement in `remediations[]` for every product listed as affected, chosen
from mitigation / no_fix_planned / none_available / vendor_fix / workaround.
art14 has no basis for any of those -- it does not know whether a fix exists,
and "no remediation advice" is a deliberate exclusion, not a gap. The profile
also requires publisher identity and tracking metadata: a namespace, a
document id, a revision history. Emitting CSAF would mean inventing all of it.
CycloneDX requires `bomFormat` and `specVersion` and nothing else, and every
other field this module writes is one art14 actually knows.

**What the document says, and what it deliberately does not.** Three states,
from three places in the payload:

    REPORT              -> exploitable, affects[].versions[].status affected
    ASSESS              -> in_triage
    [[no]] in --config  -> not_affected

Everything else is out of scope and the document says so in
`metadata.properties` rather than leaving a reader to infer it. A pair the
catalogue does not list is not in here: "not currently known to be exploited"
is not a statement about whether the product is affected, and art14 has no
grounds to make one. Neither are items suppressed by `--adopt-upstream-vex`,
which are somebody else's claim -- re-emitting them here would republish it
under the operator's name, and the flag is a run-time choice rather than part
of the file they commit. A VEX consumer that reads silence as "clean" would be
wrong about this document, so the document tells it what the silence means.
"""

from __future__ import annotations

import json
from typing import Any, Mapping, Sequence

# The spec version this module was written and tested against. Not the source
# SBOM's: this is our document, and emitting whatever the input happened to
# declare would mean claiming conformance to a version nothing here has read.
SPEC_VERSION = "1.6"

# The three CycloneDX `impactAnalysisState` values art14 can arrive at.
#
# `exploitable` rather than `affected`, which is not a state in this format at
# all -- `affected` lives on `affects[].versions[].status`, and both are
# written for a REPORT item. The spec glosses `exploitable` as "the
# vulnerability may be directly or indirectly exploitable", which is the claim
# a REPORT makes: the catalogue says it is exploited in the wild and the
# operator has confirmed the functionality is live here.
EXPLOITABLE = "exploitable"
IN_TRIAGE = "in_triage"
NOT_AFFECTED = "not_affected"

_SCOPE = (
    "This document states art14's dispositions for one run: items in REPORT"
    " as exploitable, items still open in ASSESS as in_triage, and items an"
    " operator ruled out in configuration as not_affected. Absence of a"
    " component-vulnerability pair from this document is not a statement that"
    " the product is unaffected by it."
)

_OMITTED_CATALOGUE = (
    "Component-vulnerability pairs the exploited-vulnerability catalogue did"
    " not list are omitted. art14 asked whether they are known to be exploited"
    " and the answer was no, which is not a determination about whether this"
    " product is affected."
)

_INCOMPLETE = (
    "This run could not establish that there was nothing further to report,"
    " so the statements below are not a complete disposition record: a pair"
    " this run never assessed is absent from this document exactly as a pair"
    " it ruled out is. An empty or short document from such a run is a"
    " coverage failure, not a clean result. The run's own account of why:"
)

_OMITTED_UPSTREAM = (
    "Items suppressed by --adopt-upstream-vex are omitted. Those rest on a"
    " not_affected claim made by whoever produced the source SBOM; that claim"
    " is already in that document, under its author's name, and re-stating it"
    " here would publish it under this document's instead."
)


def render(payload: Mapping[str, Any]) -> str:
    """The VEX document, as JSON text with a trailing newline."""
    return json.dumps(build(payload), indent=2, ensure_ascii=False) + "\n"


def build(payload: Mapping[str, Any]) -> dict[str, Any]:
    """The VEX document as a dict, for tests and for embedding."""
    triage = _block(payload, "triage")
    items = _list(triage, "items")
    ruled_out = _list(triage, "ruledOutInConfig")

    statements = [_statement(item, payload) for item in items]
    statements.extend(_statement(item, payload) for item in ruled_out)

    document: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        # No `serialNumber`. CycloneDX says a BOM SHOULD carry one, and
        # minting a uuid here would make two runs over unchanged evidence
        # differ in a field a reader cannot check -- in a file whose whole
        # purpose is to be committed and diffed. An operator who needs one can
        # add it; art14 will not invent an identity for a document and then
        # change it every time the command is run.
        "version": 1,
        "metadata": _metadata(payload),
        "vulnerabilities": statements,
    }
    external = _external_references(payload)
    if external:
        document["externalReferences"] = external
    return document


# --- document level -------------------------------------------------------


def _metadata(payload: Mapping[str, Any]) -> dict[str, Any]:
    provenance = _block(payload, "provenance")
    metadata: dict[str, Any] = {}
    # The run's own stamp, not this function's. A clock read here would be a
    # second answer to "when was this true" beside the one the payload already
    # carries, and the two would disagree by however long the write took.
    timestamp = provenance.get("generatedAt")
    if isinstance(timestamp, str):
        metadata["timestamp"] = timestamp
    tool = payload.get("art14")
    if isinstance(tool, str):
        metadata["tools"] = {
            "components": [
                {"type": "application", "name": "art14", "version": tool}
            ]
        }
    product = payload.get("product")
    if isinstance(product, str) and product:
        # The manufacturer's own name for the thing, as the SBOM's
        # `metadata.component` gave it. A label and not an identifier: the
        # payload does not carry that component's bom-ref, and inventing a
        # purl from a display name would be worse than naming it plainly.
        metadata["component"] = {"type": "application", "name": product}
    metadata["properties"] = _properties(payload)
    return metadata


def _properties(payload: Mapping[str, Any]) -> list[dict[str, str]]:
    """What this document covers, and what it leaves out.

    Written into the document rather than into the README, because the reader
    who needs it is a tool that will never see the README. Two of these say
    what silence means here; the rest say which run produced the file.
    """
    triage = _block(payload, "triage")
    counts = _block(triage, "counts")
    provenance = _block(payload, "provenance")
    quality = _block(payload, "input")
    properties = [{"name": "art14:vex:scope", "value": _SCOPE}]
    # Only when there was a catalogue to be absent from. A run that could not
    # fetch one listed nothing, and saying "art14 asked and the answer was no"
    # about every pair in the product would be this document's single worst
    # sentence: a false account of why it is empty.
    if quality.get("catalogueAvailable"):
        properties.append(
            {
                "name": "art14:vex:omitted:not-in-catalogue",
                "value": _OMITTED_CATALOGUE,
            }
        )
    # The run's own honesty flag, carried through rather than re-derived. A
    # VEX consumer reads absence as "fine", and the runs where that reading is
    # most wrong are the ones that produce the fewest statements: no
    # catalogue, or an inventory too thin to match. Whatever the cause, the
    # document says it was not in a position to rule anything out.
    if quality.get("canRuleOut") is False:
        verdict = quality.get("verdict")
        value = _INCOMPLETE
        if isinstance(verdict, str) and verdict.strip():
            value = f"{_INCOMPLETE} {verdict.strip()}."
        properties.append({"name": "art14:vex:incomplete", "value": value})
    if _int(counts, "suppressed"):
        properties.append(
            {"name": "art14:vex:omitted:upstream-vex", "value": _OMITTED_UPSTREAM}
        )
    source = payload.get("source")
    if isinstance(source, str) and source:
        properties.append({"name": "art14:source", "value": source})
    mode = provenance.get("mode")
    if isinstance(mode, str):
        properties.append({"name": "art14:provenance:mode", "value": mode})
    kev = provenance.get("kev")
    if isinstance(kev, Mapping):
        name = kev.get("source")
        fetched = kev.get("fetchedAt")
        if isinstance(name, str):
            properties.append({"name": "art14:catalogue", "value": name})
        if isinstance(fetched, str):
            properties.append({"name": "art14:catalogue:fetchedAt", "value": fetched})
    return properties


def _external_references(payload: Mapping[str, Any]) -> list[dict[str, str]]:
    """The link back to the SBOM these statements are about.

    A BOM-Link when the source document declared a serial number, which is the
    only identifier a consumer can resolve without being handed the file.
    Otherwise whatever the command line named, which at least tells a person
    where to look. Nothing at all for stdin: `-` identifies no document, and an
    external reference pointing at it would be a link with no referent.
    """
    link = payload.get("bomLink")
    if isinstance(link, str) and link:
        return [
            {
                "type": "bom",
                "url": link,
                "comment": "the SBOM these statements were made about",
            }
        ]
    source = payload.get("source")
    if isinstance(source, str) and source and source != "-":
        return [
            {
                "type": "bom",
                "url": source,
                "comment": (
                    "the SBOM these statements were made about, as the command"
                    " line named it. That document declares no serialNumber,"
                    " so there is no BOM-Link to point at instead"
                ),
            }
        ]
    return []


# --- one statement --------------------------------------------------------


def _statement(item: Mapping[str, Any], payload: Mapping[str, Any]) -> dict[str, Any]:
    state = _state(item)
    statement: dict[str, Any] = {"id": str(item.get("cve"))}
    references = _references(item)
    if references:
        statement["references"] = references
    description = item.get("description")
    if isinstance(description, str) and description:
        statement["description"] = description
    cwes = [cwe for cwe in _list(item, "cwes") if isinstance(cwe, int)]
    if cwes:
        statement["cwes"] = cwes
    statement["analysis"] = _analysis(item, state)
    statement["affects"] = [_affects(item, payload, state)]
    properties = _statement_properties(item)
    if properties:
        statement["properties"] = properties
    return statement


def _statement_properties(item: Mapping[str, Any]) -> list[dict[str, str]]:
    """The facts art14 has that CycloneDX has no field for.

    `aware` is the day the manufacturer recorded becoming aware. It is not
    `analysis.firstIssued`, which is when a statement was issued, so it goes
    here under a name that says which of the two it is. Nothing counts from it
    here either.

    `confirmedBy` names the file the verdict came out of, and `basis` what a
    REPORT rests on when no catalogue listed the CVE. A reader of this
    document should be able to see that a statement rests on the
    manufacturer's own evidence rather than on a catalogue, which is a
    distinction the `exploitable` state alone flattens.
    """
    properties: list[dict[str, str]] = []
    for name, key in (
        ("art14:aware", "aware"),
        ("art14:basis", "basis"),
        ("art14:confirmedBy", "confirmedBy"),
    ):
        value = item.get(key)
        if isinstance(value, str) and value:
            properties.append({"name": name, "value": value})
    return properties


def _state(item: Mapping[str, Any]) -> str:
    """The bucket, in CycloneDX's vocabulary.

    `ruledOutInConfig` rows arrive here with bucket NO and they are the only
    NO rows in the payload, so the mapping needs no special case: everything
    that is not REPORT or ASSESS in this document is a ruling-out somebody
    wrote down.
    """
    bucket = item.get("bucket")
    if bucket == "REPORT":
        return EXPLOITABLE
    if bucket == "ASSESS":
        return IN_TRIAGE
    return NOT_AFFECTED


def _analysis(item: Mapping[str, Any], state: str) -> dict[str, Any]:
    """The verdict and the words behind it.

    `response` is never written. Its values are can_not_fix, will_not_fix,
    update, rollback and workaround_available, every one of them a statement
    about what to do next -- which is the thing this tool does not say.

    Neither is `firstIssued` or `lastUpdated`. Those record when the statement
    was issued, and the one date art14 has is `aware`: the day the
    manufacturer learned of the vulnerability. They are different facts, and a
    consumer that counts from `firstIssued` would be counting from the wrong
    one. It is carried as a property on the statement instead, where it is
    labelled.
    """
    analysis: dict[str, Any] = {"state": state}
    justification = item.get("justification")
    if state == NOT_AFFECTED and isinstance(justification, str) and justification:
        analysis["justification"] = justification
    detail = _detail(item, state)
    if detail:
        analysis["detail"] = detail
    return analysis


def _detail(item: Mapping[str, Any], state: str) -> str | None:
    """The free text under the verdict.

    The operator's rationale, verbatim and unabridged, wherever there is one.
    That is the product: a justification is an enum a machine can sort on, and
    this is the sentence a market surveillance authority actually asks for.

    An open ASSESS item has no rationale by definition -- that is what makes
    it open -- so it carries the brief's own question instead, which says what
    is being asked rather than pretending an answer.
    """
    rationale = item.get("rationale")
    if isinstance(rationale, str) and rationale.strip():
        return rationale.strip()
    if state != IN_TRIAGE:
        return None
    question = item.get("question")
    if isinstance(question, str) and question.strip():
        return f"Not yet decided. {question.strip()}"
    return "Not yet decided."


def _affects(
    item: Mapping[str, Any], payload: Mapping[str, Any], state: str
) -> dict[str, Any]:
    """Which component the statement is about.

    A BOM-Link into the source document when that document declared a serial
    number, and the bare bom-ref otherwise. The bare form is what every
    generator emits and it is schema-valid, but it only resolves for a reader
    holding the source SBOM -- which is the argument for putting a
    serialNumber in it, and is said in the README rather than guessed at here.
    """
    ref = item.get("bomRef")
    prefix = payload.get("bomLink")
    affects: dict[str, Any] = {
        "ref": (
            f"{prefix}#{ref}"
            if isinstance(prefix, str) and prefix and isinstance(ref, str)
            else str(ref)
        )
    }
    version = _version(item)
    if version:
        # Only on a REPORT. `affected` is the one status art14 can assert here:
        # `unaffected` would turn a ruling-out about this product into a claim
        # that the component version itself is not vulnerable, which is a
        # statement about the upstream package and a different thing entirely.
        # A not_affected analysis already says what is true, at the scope it is
        # true at.
        if state == EXPLOITABLE:
            affects["versions"] = [{"version": version, "status": "affected"}]
    return affects


def _version(item: Mapping[str, Any]) -> str | None:
    """The component's version, as the payload carries it.

    Read from its own field and never split out of the `name@version` label:
    an npm component called `@scope/pkg` with no version has an `@` in it and
    nothing after it that is a version. A component the SBOM gave no version
    for has none here either, and the statement then says which component it
    is about without saying which build.
    """
    version = item.get("version")
    if not isinstance(version, str):
        return None
    return version.strip() or None


def _references(item: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The other ids for this vulnerability, each with who calls it that.

    No urls. art14 holds no per-vulnerability links, and composing one out of
    an id and a hostname would be this tool asserting that a page exists.
    """
    references: list[dict[str, Any]] = []
    for osv_id in _list(item, "osvIds"):
        if isinstance(osv_id, str) and osv_id:
            references.append({"id": osv_id, "source": {"name": "OSV"}})
    euvd = item.get("euvd")
    if isinstance(euvd, str) and euvd:
        references.append({"id": euvd, "source": {"name": "EUVD"}})
    return references


# --- payload access -------------------------------------------------------


def _block(payload: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    """One sub-document, defaulting to an empty one.

    Same stance as the HTML report: a payload written by a different build is
    a missing field here, not a traceback in the middle of writing a file
    somebody asked for.
    """
    value = payload.get(key)
    return value if isinstance(value, Mapping) else {}


def _list(payload: Mapping[str, Any], key: str) -> Sequence[Any]:
    value = payload.get(key)
    return value if isinstance(value, list) else []


def _int(payload: Mapping[str, Any], key: str) -> int:
    value = payload.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else 0
