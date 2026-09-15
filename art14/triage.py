"""Layer 3: CVE to bucket. The stage the other two exist to feed.

Three buckets, and no fourth:

    REPORT   a KEV entry, and the user has confirmed in configuration that the
             vulnerable functionality is present in this product -- or, where
             no catalogue lists the CVE, the user has confirmed it on a basis
             of their own and said which.
    ASSESS   a KEV entry, and nothing more. The default for every KEV match.
    NO       checked against the catalogue and absent.

The asymmetry between REPORT and ASSESS is the whole design. A KEV entry says
the CVE is exploited somewhere in the world, not that the vulnerable path is
live in this product. Nothing in this module infers the difference: not from
dependency depth, not from CVSS, not from how the component is named. Depth
informs the human's decision; it does not make it. The only thing that moves an
item from ASSESS to REPORT is an explicit per-component confirmation carrying a
rationale, which is also the audit trail a market surveillance authority asks
for.

An SBOM can carry its own verdict. A vulnerability's document-level `analysis`
block is a VEX statement -- "not affected, the code is not reachable" -- and by
default this module does not act on it. Acting on it silently would make the
tool a laundering channel: an upstream scanner asserts `not_affected`, art14
prints NO, and the manufacturer has a clean run that nobody in the room ever
reasoned about. So the claim is shown instead, attributed, and marked as
unverified. `--adopt-upstream-vex` lets an operator adopt it, which is a
legitimate position and has to be a stated one: the flag goes in the
provenance block, every suppression it causes is listed with its justification
and its author, and the item lands in NO on upstream's authority rather than
on a determination made here.

A catalogue is not the world. It lags, and a manufacturer with their own
telemetry, an incident, or a vendor advisory can know a CVE is being exploited
before CISA or the EUVD list it. A confirmation applies whether or not the
catalogue listed it, and carries a `basis` naming what it rests on when the
catalogue did not, so the two positions stay visibly different rather than
collapsing into one REPORT row that reads the same either way. Nothing is
synthesised to make that work: an entry naming a pair this run never matched
still stands down, because the pairs are the SBOM's and OSV's to make.

Two things deliberately have no bucket. Vulnerabilities carrying no CVE alias
were never checkable, so they are not NO -- they are a coverage statement, the
same kind as an unmatched component. And a confirmation that matched nothing is
not an error either: it is a silent false negative waiting to happen, because
the user believes something is in REPORT and it is not, so it is said out loud
rather than counted.
"""

from __future__ import annotations

import textwrap
import tomllib
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Iterable, Sequence

from .errors import Art14Error
from .kev import KevEntry, Review
from .lines import count_line
from .models import ROOT, Component, Finding, Location, Sbom, VexClaim, Vulnerability

REPORT = "REPORT"
ASSESS = "ASSESS"
NO = "NO"

# What a [[report]] rests on when the KEV catalogue does not list the CVE.
#
# A catalogue lags the world it describes: a manufacturer with their own
# telemetry, an incident, or a vendor advisory naming in-the-wild exploitation
# can know before CISA or the EUVD list it. Without a way to say so, that
# position and "the catalogue confirms it" collapse into one REPORT entry that
# reads identically, which is a worse record than either.
#
# The set is closed and it is these three, because the field exists to be read
# by a brief, a JSON consumer and an HTML report without any of them
# reimplementing judgement. Free text here would put the fact back where the
# awareness date used to be: inside a rationale, where nothing can read it.
BASES: dict[str, str] = {
    "operator evidence": "the manufacturer's own evidence",
    "vendor advisory": "a vendor advisory",
    "incident": "an incident",
}

# Why a [[no]] does not apply, in the one vocabulary a machine can read.
#
# This is CycloneDX's `impactAnalysisJustification`, taken from the 1.6 schema
# with its own wording, and it exists for exactly one consumer: the VEX
# export. A rationale is the product here and it always will be, but free text
# is not a claim another tool can act on, and a `not_affected` statement
# carrying no justification is one a reader has to take on trust.
#
# Optional, and never inferred. A rationale that says "the lookup class is
# unreachable from our code" reads to a person as `code_not_reachable`, and
# reading it that way in software would mean art14 deciding what the operator
# meant and then publishing that decision under their name. An entry without
# this field exports as `not_affected` with the rationale in `analysis.detail`
# and no justification -- which is what a justification-less claim honestly
# looks like -- rather than being dropped or guessed at.
JUSTIFICATIONS: dict[str, str] = {
    "code_not_present": "the code has been removed or tree-shaken",
    "code_not_reachable": "the vulnerable code is not invoked at runtime",
    "requires_configuration": "exploitability requires a configurable option"
    " to be set or unset",
    "requires_dependency": "exploitability requires a dependency that is not"
    " present",
    "requires_environment": "exploitability requires an environment that is"
    " not present",
    "protected_by_compiler": "exploitability requires a compiler flag to be"
    " set or unset",
    "protected_at_runtime": "exploits are prevented at runtime",
    "protected_at_perimeter": "attacks are blocked at the physical, logical or"
    " network perimeter",
    "protected_by_mitigating_control": "preventative measures are in place"
    " that reduce the likelihood or the impact",
}


# --- configuration --------------------------------------------------------
#
# TOML, read with the standard library's `tomllib`. YAML would mean a third
# runtime dependency, in a project whose entire dependency list is httpx plus
# rich, to parse a file that is a flat list of records. TOML costs nothing and
# Python 3.11 is already the floor.


@dataclass(frozen=True)
class Confirmation:
    """One statement the operator makes about their own product.

    Two directions, and the rationale is required in both. `[[report]]` says
    the vulnerable functionality is live here, which moves the item out of
    ASSESS and starts the clock. `[[no]]` says it was looked at and ruled
    out, which is the other half of the decision brief: the brief has always
    ended in "-> NO ... record the rationale, that becomes your VEX entry and
    your audit trail" and until this there was nowhere to record it. An item
    ruled out this way is in NO because a person said so, and it is never
    folded into the count -- it is listed with its reason, the same way an
    adopted VEX claim is.

    `component` is matched against the component's bom-ref, its PURL, or its
    `name@version` label -- never against a bare name. A bare name matches
    every version forever, which is how a confirmation written for 2.14.1
    silently carries itself onto 2.20.0 after the upgrade that fixed it.

    `basis` names what a `[[report]]` rests on when the catalogue is silent,
    and it is required in exactly that case: a REPORT on a CVE no catalogue
    lists is a different claim from one confirming a catalogue hit, and the
    output has to let a reader see which they are looking at. `aware` is the
    day the manufacturer recorded becoming aware. It is parsed, carried and
    printed, and nothing else -- no deadline, no elapsed time, no arithmetic
    on it anywhere. The alternative is where that date used to live, which
    is inside the rationale where nothing can read it.

    `justification` is the same move for a `[[no]]`: one value from
    CycloneDX's own vocabulary, saying which of the standard reasons the
    rationale beside it describes. Optional, because the rationale is the
    record and this is only a machine's view of it, and never derived from
    the prose -- see `JUSTIFICATIONS`.
    """

    component: str
    cve_id: str
    rationale: str
    source: str = "<config>"
    verdict: str = REPORT
    basis: str | None = None
    aware: date | None = None
    justification: str | None = None

    @property
    def rules_out(self) -> bool:
        return self.verdict == NO


@dataclass(frozen=True)
class ConfirmationUse:
    """What became of one confirmation on this run. See `Triage.unused`."""

    confirmation: Confirmation
    matched_component: bool
    # Whether this run produced the (CVE, component) pair the entry names, as
    # against merely the component. The two failures underneath a matched
    # component are different and one of them is a typo, so they are told
    # apart on the fact rather than inferred from the verdict.
    matched_pair: bool = False

    def explain(self) -> str:
        if not self.matched_component:
            return (
                f"[{self.confirmation.verdict}] {self.confirmation.component}:"
                " no component in this SBOM carries that bom-ref, PURL or"
                " name@version. Check the spelling, and check the version - an"
                " upgrade changes it."
            )
        if not self.matched_pair:
            # No vulnerability record in this run tied that CVE to that
            # component, so there is no item for the entry to land on.
            # Manufacturing one would mean art14 asserting a
            # component-to-CVE match that neither the SBOM nor OSV made.
            return (
                f"[{self.confirmation.verdict}]"
                f" {self.confirmation.component}: the component is in this"
                " SBOM, but nothing in this run matched"
                f" {self.confirmation.cve_id} to it, so there is no item to"
                " carry the entry. art14 judges the pairs the SBOM and OSV put"
                " in front of it. Check the CVE id, and check that the match"
                " was made at all -- an unmatched component is named in the"
                " coverage line."
            )
        # The pair is here and the entry still did not apply, which leaves one
        # case: a [[no]] on a CVE the catalogue does not list. A [[report]]
        # always applies to a pair that exists.
        return (
            f"[{self.confirmation.verdict}] {self.confirmation.component}: the"
            f" component is in this SBOM, but {self.confirmation.cve_id} is"
            " not in the KEV catalogue for it on this run. Nothing is being"
            " withheld; the item is in NO already and the entry has nothing"
            " left to rule out."
        )


def load_confirmations(path: str | Path) -> tuple[Confirmation, ...]:
    """Read the REPORT confirmations from a TOML file.

    Every failure here is a hard error, never a run that continues with an
    empty list. A config the tool could not read looks exactly like a config
    with nothing in it, and the difference between those two is the difference
    between exit 2 and exit 1 on the one item the user cared about most.
    """
    location = Path(path)
    # The spelling the operator typed, not the one the filesystem prefers: the
    # source is printed next to every verdict it caused, and a path that comes
    # back with different separators than the command line used reads as a
    # different file.
    given = str(path)
    try:
        with location.open("rb") as handle:
            data = tomllib.load(handle)
    except OSError as exc:
        raise Art14Error(
            f"the configuration file {location} could not be read ({exc})"
        ) from exc
    except tomllib.TOMLDecodeError as exc:
        raise Art14Error(
            f"the configuration file {location} is not valid TOML ({exc})"
        ) from exc

    out: list[Confirmation] = []
    for table, verdict in (("report", REPORT), ("no", NO)):
        out.extend(_entries(data, table, verdict, location, given))
    return tuple(out)


def _entries(
    data: dict, table: str, verdict: str, location: Path, given: str = ""
) -> list[Confirmation]:
    """One `[[report]]` or `[[no]]` block turned into records.

    The two are read identically and differ only in which bucket they name.
    Both require a rationale, for the same reason: the file is the audit
    trail, and an entry without one is a verdict with nothing behind it.
    """
    raw = data.get(table, [])
    if not isinstance(raw, list):
        raise Art14Error(
            f"{location}: `{table}` must be a list of tables, written as"
            f" repeated [[{table}]] blocks"
        )
    out: list[Confirmation] = []
    for index, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            raise Art14Error(f"{location}: [[{table}]] entry {index} is not a table")
        component = _required(item, "component", location, index, table)
        cve_id = _required(item, "cve", location, index, table)
        rationale = _required(item, "rationale", location, index, table)
        if not cve_id.upper().startswith("CVE-"):
            raise Art14Error(
                f"{location}: [[{table}]] entry {index} names `{cve_id}`, which"
                " is not a CVE id. The catalogue is keyed on CVEs; a GHSA or"
                " EUVD id here would match nothing and still read as an entry"
                " that was honoured."
            )
        out.append(
            Confirmation(
                component=component,
                cve_id=cve_id.upper(),
                rationale=rationale,
                source=given or str(location),
                verdict=verdict,
                basis=_basis(item, location, index, table),
                aware=_aware(item, location, index, table),
                justification=_justification(item, location, index, table),
            )
        )
    return out


def _basis(item: dict, location: Path, index: int, table: str) -> str | None:
    """What this entry rests on, when it is not the catalogue.

    Optional here and checked again at bucketing, because whether it is
    required depends on something this function cannot see: a `[[report]]`
    needs one exactly when the catalogue does not list the CVE, and the
    catalogue has not been consulted yet. Meaningless on a `[[no]]`, which
    rests on the rationale beside it and rules nothing in.
    """
    value = item.get("basis")
    if value is None:
        return None
    if table != "report":
        raise Art14Error(
            f"{location}: [[{table}]] entry {index} carries a `basis`. The"
            " field names what a REPORT rests on when the KEV catalogue does"
            " not list the CVE; a [[no]] rests on the rationale beside it and"
            " needs nothing else."
        )
    if not isinstance(value, str):
        raise Art14Error(
            f"{location}: [[{table}]] entry {index} needs `basis` written as a"
            " string."
        )
    # One spelling rule, stated: case is ignored and a hyphen or underscore
    # reads as a space, so `operator-evidence` and `Operator Evidence` both
    # arrive as the same value. Everything else is refused by name.
    key = " ".join(value.replace("-", " ").replace("_", " ").lower().split())
    if key not in BASES:
        permitted = ", ".join(f"`{name}`" for name in BASES)
        raise Art14Error(
            f"{location}: [[{table}]] entry {index} names `{value}` as its"
            f" basis, which is not one of {permitted}. The set is closed so"
            " that a reader can see which claims rest on the catalogue and"
            " which on the manufacturer's own knowledge; free text here would"
            " be one more thing nothing can read."
        )
    return key


def _justification(
    item: dict, location: Path, index: int, table: str
) -> str | None:
    """Which of the standard reasons a `[[no]]` rests on. Optional.

    Only on a `[[no]]`. The vocabulary exists to qualify "this does not
    affect us", and it has nothing to say about a REPORT: an entry that puts
    an item in REPORT is claiming the vulnerability does apply, and `basis` is
    the field that qualifies that one.
    """
    value = item.get("justification")
    if value is None:
        return None
    if table != "no":
        raise Art14Error(
            f"{location}: [[{table}]] entry {index} carries a"
            " `justification`. The field says why a vulnerability does not"
            " affect this product, so it belongs on a [[no]]; what a REPORT"
            " rests on is `basis`."
        )
    if not isinstance(value, str):
        raise Art14Error(
            f"{location}: [[{table}]] entry {index} needs `justification`"
            " written as a string."
        )
    # Same spelling rule as `basis`, arriving at the wire form rather than at
    # prose: `code not reachable`, `code-not-reachable` and
    # `Code_Not_Reachable` are the one value CycloneDX spells
    # `code_not_reachable`.
    key = "_".join(value.replace("-", " ").replace("_", " ").lower().split())
    if key not in JUSTIFICATIONS:
        permitted = ", ".join(f"`{name}`" for name in JUSTIFICATIONS)
        raise Art14Error(
            f"{location}: [[{table}]] entry {index} names `{value}` as its"
            f" justification, which is not one of {permitted}. The list is"
            " CycloneDX's own and art14 does not extend it: a value outside it"
            " would be written into a VEX document no consumer can read, which"
            " is worse than the field being absent. Leave it out and the"
            " rationale still carries the reason."
        )
    return key


def _aware(item: dict, location: Path, index: int, table: str) -> date | None:
    """The day the manufacturer recorded becoming aware. A date, not a clock.

    A bare TOML date and nothing else. A date-time is refused rather than
    truncated, because accepting one would invite an expectation this tool
    deliberately does not meet: the value is recorded and printed, never
    subtracted from anything. The moment two dates are subtracted here, this
    is a scheduler.
    """
    value = item.get("aware")
    if value is None:
        return None
    # `datetime` subclasses `date`, so it has to be refused first.
    if isinstance(value, datetime) or not isinstance(value, date):
        raise Art14Error(
            f"{location}: [[{table}]] entry {index} needs `aware` written as a"
            " bare TOML date, `aware = 2026-09-12` -- not a string and not a"
            " date-time. It is a day on the record; nothing is computed from"
            " it."
        )
    return value


def _required(item: dict, key: str, location: Path, index: int, table: str) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value.strip():
        raise Art14Error(
            f"{location}: [[{table}]] entry {index} needs a non-empty `{key}`."
            " Every verdict in this file rests on one of these, and the"
            " rationale is the record of why - an entry without one is a claim"
            " with no basis behind it."
        )
    return value.strip()


# --- buckets --------------------------------------------------------------


@dataclass(frozen=True)
class Item:
    """One (CVE, component) pair with a bucket on it.

    Keyed on the pair rather than on the finding, because a single OSV record
    can carry two CVE aliases and each one is its own catalogue entry and its
    own obligation. Keying on the finding would emit the first and drop the
    second without saying so.
    """

    bucket: str
    cve_id: str
    finding: Finding
    entry: KevEntry | None = None
    osv_ids: tuple[str, ...] = ()
    # The operator's own words, on the items they wrote an entry for. On a
    # REPORT item it is why the clock is running; on a NO item it is why it is
    # not, which is the half that becomes the VEX entry.
    rationale: str | None = None
    confirmed_by: str | None = None
    # What the entry rests on when the catalogue does not list the CVE, and
    # the day the operator recorded becoming aware. Both come straight off the
    # confirmation: carried and printed, never computed from.
    basis: str | None = None
    aware: date | None = None
    # Which of CycloneDX's standard reasons a [[no]] rests on, when the
    # operator named one. Never present on any other bucket.
    justification: str | None = None
    # Set only when `--adopt-upstream-vex` moved this item to NO on the
    # strength of the SBOM's own claim. It is the same object as `vex`; the
    # separate field is what distinguishes "a claim was made" from "a claim
    # was acted on", and only the second one needs to be listed out loud.
    suppressed_by: VexClaim | None = None

    @property
    def vex(self) -> VexClaim | None:
        """The SBOM's own claim about this vulnerability, adopted or not."""
        return self.vulnerability.analysis

    @property
    def ruled_out(self) -> bool:
        """A NO the operator decided, as against a NO the catalogue produced.

        Both are in NO and neither is being reported. The difference is what a
        reader may conclude from the count: a catalogue NO means art14 asked
        and the answer was no, and this one means a person looked at a live
        KEV entry and wrote down why it does not apply here.
        """
        return self.bucket == NO and self.rationale is not None

    @property
    def component(self) -> Component:
        return self.finding.component

    @property
    def location(self) -> Location:
        return self.finding.location

    @property
    def vulnerability(self) -> Vulnerability:
        return self.finding.vulnerability


@dataclass(frozen=True)
class Triage:
    """The three buckets, plus the two things that are not buckets."""

    report: tuple[Item, ...] = ()
    assess: tuple[Item, ...] = ()
    no: tuple[Item, ...] = ()
    # Findings whose vulnerability carries no CVE alias at all. Never checked,
    # and therefore never NO.
    unassessed: tuple[Finding, ...] = ()
    unused: tuple[ConfirmationUse, ...] = ()

    @property
    def pairs(self) -> int:
        """Distinct (CVE, component) pairs -- the unit the buckets count.

        One below the finding count whenever two vulnerability records alias
        the same CVE on the same component, which is ordinary: OSV and a
        scanner's own feed both carry Log4Shell. Bucketing keys on the pair
        and keeps the first, so the funnel line above the buckets would
        otherwise quote a total nothing below it adds up to.
        """
        return (
            len(self.report) + len(self.assess) + len(self.no) + len(self.unassessed)
        )

    @property
    def actionable(self) -> tuple[Item, ...]:
        """Everything a human has to look at. REPORT first, by precedence."""
        return self.report + self.assess

    @property
    def suppressed(self) -> tuple[Item, ...]:
        """The NO items that are there because the SBOM said so.

        A view over NO rather than a fourth bucket. They belong in NO -- there
        is no obligation being tracked for them on this run -- but NO is
        printed as a single count, and a suppression that arrives as part of a
        number is exactly the thing the default behaviour exists to prevent.
        So they are named separately everywhere NO is summarised.
        """
        return tuple(item for item in self.no if item.suppressed_by is not None)

    @property
    def ruled_out(self) -> tuple[Item, ...]:
        """The NO items a person decided, with the reason they wrote.

        The second view over NO, and it exists for the same reason the first
        one does. These are in the KEV catalogue: a reader who takes the NO
        count as "the catalogue said nothing about these" would be wrong about
        exactly the items somebody spent the most thought on.
        """
        return tuple(item for item in self.no if item.ruled_out)

    @property
    def decided(self) -> tuple[Item, ...]:
        """Every NO that is there because somebody said so, either way."""
        return tuple(
            item
            for item in self.no
            if item.ruled_out or item.suppressed_by is not None
        )


def triage(
    sbom: Sbom,
    review: Review,
    confirmations: Sequence[Confirmation] = (),
    *,
    adopt_upstream_vex: bool = False,
) -> Triage:
    """Put every finding in a bucket, given what the catalogue said.

    The unit is (CVE, component). One finding whose record carries two listed
    aliases produces two items; one whose record carries a listed alias and an
    absent one produces a single listed item and no NO -- the obligation is
    real and printing a NO beside it would read as a contradiction.

    `adopt_upstream_vex` is the operator saying they trust whoever produced
    the SBOM. It moves a listed item to NO when the document asserts
    `not_affected`, and only then: the other analysis states are displayed and
    never adopted. An explicit confirmation still wins, because a statement
    the operator wrote about their own product outranks one a scanner made
    about somebody's.
    """
    listed: dict[str, KevEntry] = {}
    osv_ids: dict[str, tuple[str, ...]] = {}
    for exposure in review.exposures:
        osv_ids[exposure.cve_id] = exposure.osv_ids
        if exposure.entry is not None:
            listed[exposure.cve_id] = exposure.entry

    index = _ConfirmationIndex(confirmations)

    report: list[Item] = []
    assess: list[Item] = []
    absent: list[Item] = []
    unassessed: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    for finding in sbom.findings:
        # Every component the run saw, not only the ones with a listed CVE.
        # Otherwise a confirmation whose CVE is absent from the catalogue -- the
        # correct, quiet outcome -- gets reported as a component that does not
        # exist, which sends the user hunting for a typo that is not there.
        cve_ids = [cve.upper() for cve in finding.vulnerability.cve_ids]
        index.observe(finding.component, cve_ids)
        if not cve_ids:
            unassessed.append(finding)
            continue

        hits = [cve for cve in cve_ids if cve in listed]
        if not hits:
            # Nothing listed anywhere in this record, which is not the same as
            # nothing being exploited. The catalogues lag, and a manufacturer
            # with their own telemetry, an incident, or a vendor advisory can
            # know first. A [[report]] is how they say so, and it applies here
            # exactly as it does on a listed CVE, carrying a `basis` that
            # keeps the two claims distinguishable everywhere they are shown.
            # Until it did, the entry was refused in silence: the item stayed
            # in NO, the run exited 0, and the only trace was a line saying
            # the entry did not apply.
            #
            # A [[no]] is not consulted here. The item is in NO already, and
            # listing it under the table would turn a non-event into a
            # recorded decision.
            confirmation = index.match(finding.component, cve_ids, verdict=REPORT)
            # One item for the pair, not one per alias: the aliases are the
            # same vulnerability. The CVE on it is the one the operator wrote
            # down, wherever they wrote one.
            cve_id = confirmation.cve_id if confirmation else cve_ids[0]
            key = (cve_id, finding.component.bom_ref)
            if key in seen:
                continue
            seen.add(key)
            if confirmation is None:
                absent.append(
                    Item(
                        bucket=NO,
                        cve_id=cve_id,
                        finding=finding,
                        osv_ids=osv_ids.get(cve_id, ()),
                    )
                )
                continue
            if confirmation.basis is None:
                permitted = ", ".join(f"`{name}`" for name in BASES)
                raise Art14Error(
                    f"{confirmation.source}: the [[report]] entry for"
                    f" {confirmation.cve_id} on {confirmation.component} needs"
                    f" a `basis`, one of {permitted}. The catalogue this run"
                    " read does not list that CVE, so the entry is the only"
                    " thing putting the item in REPORT and the output has to"
                    " say what it rests on. A reader cannot otherwise tell it"
                    " from an entry confirming a catalogue hit."
                )
            report.append(
                Item(
                    bucket=REPORT,
                    cve_id=cve_id,
                    finding=finding,
                    osv_ids=osv_ids.get(cve_id, ()),
                    rationale=confirmation.rationale,
                    confirmed_by=confirmation.source,
                    basis=confirmation.basis,
                    aware=confirmation.aware,
                )
            )
            continue

        for cve_id in hits:
            key = (cve_id, finding.component.bom_ref)
            if key in seen:
                continue
            seen.add(key)
            confirmation = index.match(finding.component, (cve_id,))
            claim = finding.vulnerability.analysis
            adopted = (
                claim
                if (
                    adopt_upstream_vex
                    and confirmation is None
                    and claim is not None
                    and claim.is_not_affected
                )
                else None
            )
            if confirmation:
                bucket = confirmation.verdict
            elif adopted is not None:
                bucket = NO
            else:
                bucket = ASSESS
            item = Item(
                bucket=bucket,
                cve_id=cve_id,
                finding=finding,
                # Kept even on an adopted item. It is in NO because somebody
                # said so, not because the catalogue was silent, and the entry
                # is the evidence of the difference.
                entry=listed[cve_id],
                osv_ids=osv_ids.get(cve_id, ()),
                rationale=confirmation.rationale if confirmation else None,
                confirmed_by=confirmation.source if confirmation else None,
                basis=confirmation.basis if confirmation else None,
                aware=confirmation.aware if confirmation else None,
                justification=(
                    confirmation.justification if confirmation else None
                ),
                suppressed_by=adopted,
            )
            if confirmation and not confirmation.rules_out:
                report.append(item)
            elif confirmation or adopted is not None:
                absent.append(item)
            else:
                assess.append(item)

    return Triage(
        report=tuple(report),
        assess=tuple(assess),
        no=tuple(absent),
        unassessed=tuple(unassessed),
        unused=index.unused(),
    )


class _ConfirmationIndex:
    """Matches confirmations to findings, and remembers which never matched.

    A confirmation that matches nothing is the dangerous direction of failure:
    the user believes an item is in REPORT, the tool leaves it in ASSESS, and
    the run exits 1 instead of 2 with nothing anywhere saying why.
    """

    def __init__(self, confirmations: Sequence[Confirmation]) -> None:
        self._confirmations = tuple(confirmations)
        self._matched_component: set[int] = set()
        self._matched_pair: set[int] = set()
        self._applied: set[int] = set()

    def observe(self, component: Component, cve_ids: Sequence[str] = ()) -> None:
        """Record what this run put in front of each confirmation.

        Two facts, because an entry that did not apply failed for one of two
        reasons and they need opposite responses. The component was never
        here: a typo or a stale version, and the entry is wrong. The component
        was here but this pair was not: the entry may be perfectly correct and
        simply had nothing to act on.
        """
        for position, confirmation in enumerate(self._confirmations):
            if not _identifies(confirmation.component, component):
                continue
            self._matched_component.add(position)
            if confirmation.cve_id in cve_ids:
                self._matched_pair.add(position)

    def match(
        self,
        component: Component,
        cve_ids: Sequence[str],
        *,
        verdict: str | None = None,
    ) -> Confirmation | None:
        """The first entry naming this component and one of these CVEs.

        A sequence, because one OSV record can carry several CVE aliases and
        the operator wrote down whichever one they met. Every entry that
        matches is marked applied, not only the one returned: a duplicate for
        the same pair did take effect, and reporting it as unused would send
        someone hunting for a typo that is not there.

        `verdict` narrows the search. On the path where the catalogue listed
        nothing, only a `[[report]]` has anything to change.
        """
        found: Confirmation | None = None
        for cve_id in cve_ids:
            for position, confirmation in enumerate(self._confirmations):
                if confirmation.cve_id != cve_id:
                    continue
                if verdict is not None and confirmation.verdict != verdict:
                    continue
                if not _identifies(confirmation.component, component):
                    continue
                self._applied.add(position)
                if found is None:
                    found = confirmation
        return found

    def unused(self) -> tuple[ConfirmationUse, ...]:
        return tuple(
            ConfirmationUse(
                confirmation=confirmation,
                matched_component=position in self._matched_component,
                matched_pair=position in self._matched_pair,
            )
            for position, confirmation in enumerate(self._confirmations)
            if position not in self._applied
        )


def _identifies(spec: str, component: Component) -> bool:
    """Whether one config `component` string names this component.

    Three accepted spellings, all of which pin a version or are the SBOM's own
    identifier: the bom-ref, the PURL, and `name@version`. A bare name is not
    one of them and matches nothing, which sends the item to ASSESS and prints
    a warning -- the safe direction, and a loud one.
    """
    if spec == component.bom_ref or spec == component.label:
        return True
    purl = component.purl
    if purl and (spec == purl or _bare_purl(spec) == _bare_purl(purl)):
        # Qualifiers and subpath are packaging detail, not identity:
        # `pkg:maven/g/a@2.14.1` and `...@2.14.1?type=jar` are the same
        # artefact, and a user copying one spelling out of a different tool
        # should not silently lose their confirmation over it.
        return True
    return False


def _bare_purl(purl: str) -> str:
    return purl.split("#", 1)[0].split("?", 1)[0]


# --- rendering ------------------------------------------------------------
#
# The decision brief lives here rather than in the CLI because it is the
# product, not a formatting choice. The compact table is step 7.


def no_label(result: Triage | None) -> str:
    """What the NO count may be called, given what is in it.

    "not in the KEV catalogue" is the reason section 4 gives for NO and it is
    the true one until something lands there on somebody's word. A ruled-out
    item and an adopted VEX claim are both in the catalogue, so once either is
    present the label states the bucket and stops stating a reason -- the
    reasons are listed underneath, one line each.
    """
    if result is not None and result.decided:
        return "not to report"
    return "not in the KEV catalogue"


def counts(result: Triage | None) -> list[str]:
    """The default terminal summary. NO is one line, never row by row."""
    if result is None:
        return []
    # Every bucket is counted in component-CVE pairs, and the catalogue line
    # above them is counted in distinct CVE ids. The first row says the unit
    # and the rest inherit it, rather than each repeating the word.
    out = [
        count_line(
            REPORT,
            len(result.report),
            "(component-CVE pairs; the 24h clock is running)",
        ),
        count_line(
            ASSESS,
            len(result.assess),
            "(pairs in the KEV catalogue; needs a decision now)",
        ),
        count_line(NO, len(result.no), f"(pairs {no_label(result)})"),
    ]
    if result.ruled_out:
        out.append(
            count_line(
                "of which",
                len(result.ruled_out),
                "ruled out in configuration; the reasons are below",
            )
        )
    if result.suppressed:
        out.append(
            count_line(
                "of which",
                len(result.suppressed),
                "suppressed by --adopt-upstream-vex (the SBOM's own claim)",
            )
        )
    if result.unassessed:
        out.append(
            count_line(
                "unchecked",
                len(result.unassessed),
                "(pairs whose record carries no CVE id)",
            )
        )
    return out


def unused_warning(result: Triage | None) -> list[str]:
    """Paragraphs for confirmations that did not apply. Loud, not counted.

    Split on whether the component was there at all, because that is the one
    that means a typo and needs fixing. Underneath a component that was there,
    the individual lines split again: a CVE this run never matched to it, or a
    [[no]] on a CVE the catalogue does not list. That second one has to say
    where the item actually is, or the entry reads as a decision waiting to be
    applied when the item is already in NO without it.
    """
    if result is None or not result.unused:
        return []
    missing = [use for use in result.unused if not use.matched_component]
    standing_down = [use for use in result.unused if use.matched_component]
    out: list[str] = []
    if missing:
        out.append(
            f"WARNING: {len(missing)} configured entr(ies) matched no component"
            " in this SBOM, so whatever they describe is sitting in ASSESS"
            " instead of the bucket the file names. An entry that matches"
            " nothing looks exactly like a product nobody had to decide about."
        )
        out.extend(f"  - {use.explain()}" for use in missing)
    if standing_down:
        out.append(
            f"{len(standing_down)} configured entr(ies) did not apply on this"
            " run. The component is in the SBOM, so nothing here is misspelt."
            " Each line says which of the two remaining reasons it was, and"
            " they want different things from you: a CVE that was never"
            " matched to that component leaves the entry with no item to land"
            " on and is worth checking, and a [[no]] on a CVE the catalogue"
            " does not list has simply nothing left to rule out."
        )
        out.extend(f"  - {use.explain()}" for use in standing_down)
    return out


def disposition_lines(result: Triage | None) -> list[str]:
    """Every item ruled out in configuration, one row each and its reason.

    The second place the NO bucket is listed row by row, and it is there for
    the same reason as the first: a line in NO otherwise means art14 asked the
    catalogue and the catalogue said nothing. These items are in the
    catalogue. They are in NO because a person read the brief, answered the
    question it asked, and wrote down the answer -- and that answer is the
    output. Folding it into a count would throw away the only part of the run
    that is not derivable from public data.
    """
    if result is None or not result.ruled_out:
        return []
    sources = sorted({item.confirmed_by or "<config>" for item in result.ruled_out})
    where = sources[0] if len(sources) == 1 else "configuration"
    out = [
        f"{len(result.ruled_out)} item(s) in the KEV catalogue were ruled out"
        f" in {where}. They are in NO on the rationale recorded below, which is"
        " the manufacturer's own determination and not one art14 made or"
        " checked. This is the material a VEX statement and an audit trail are"
        " written from."
    ]
    for item in result.ruled_out:
        out.append(f"  - {item.cve_id} {item.component.label}")
        if item.aware is not None:
            out.append(f"      aware {item.aware.isoformat()}")
        rationale = _flat(item.rationale)
        if rationale:
            # In full, never truncated. Everything else this tool prints can
            # be looked up somewhere else; this sentence cannot, and a
            # rationale cut off at an ellipsis is not an audit trail.
            out.append(f"      {rationale}")
    return out


def suppression_lines(
    result: Triage | None, *, requested: bool = False
) -> list[str]:
    """Every adopted claim, one row each, printed on every run that has any.

    This is the one place the NO bucket is listed row by row, and the reason
    is the same one that keeps it summarised everywhere else: a line in NO
    means art14 checked and found nothing. These lines mean art14 was told,
    and by whom. Folding them into the count would put a suppression somewhere
    a reader cannot see it, which would make the flag worse than not having
    it.

    `requested` is whether --adopt-upstream-vex was given. A flag that was
    typed and did nothing has to say so, because the failure mode is the same
    one the default behaviour exists to prevent, only inverted: the operator
    believes a determination has been taken into account and it has not.
    """
    if result is None:
        return []
    if not result.suppressed:
        return _nothing_adopted(result) if requested else []
    out = [
        f"{len(result.suppressed)} item(s) in the KEV catalogue were suppressed"
        " because --adopt-upstream-vex was given and the SBOM asserts"
        " not_affected. They are in NO on the authority below, not on any"
        " determination art14 made. The obligation remains the manufacturer's."
    ]
    for item in result.suppressed:
        claim = item.suppressed_by
        assert claim is not None  # `suppressed` selects on it
        out.append(f"  - {item.cve_id} {item.component.label} - {claim.summary()}")
        detail = _one_line(claim.detail)
        if detail:
            out.append(f"      {detail}")
    return out


def _nothing_adopted(result: Triage) -> list[str]:
    """Why --adopt-upstream-vex changed nothing on this run.

    On the ordinary path there is nothing for it to act on at all: the SBOM
    went out to OSV for its vulnerabilities, and a record fetched from a
    database carries no statement by anyone about this particular product. The
    flag is only ever meaningful on a document that arrived with its own
    `vulnerabilities` array, and not on every one of those either.
    """
    claims = sum(
        1
        for item in result.report + result.assess + result.no
        if item.vex is not None
    )
    if not claims:
        return [
            "--adopt-upstream-vex was given and nothing was suppressed: no"
            " vulnerability in this SBOM carries a document-level analysis"
            " block. The flag adopts a claim the SBOM makes about itself, and"
            " only an SBOM that arrived carrying its own vulnerabilities can"
            " make one."
        ]
    return [
        "--adopt-upstream-vex was given and nothing was suppressed: this"
        f" SBOM carries {claims} claim(s) and none of them was adoptable."
        " Only not_affected is adopted, and an item you confirmed yourself"
        " stays in REPORT. Each claim is shown with the item it belongs to."
    ]


def brief_lines(item: Item, sbom: Sbom) -> list[str]:
    """The six-point decision brief.

    A brief that only says "check this" has failed, so both dispositions are
    always stated, and the `Question` is one concrete question about the
    product rather than a description of the vulnerability.
    """
    out = [f"[{item.bucket}] {_header(item)}", ""]
    out.append(f"  Where      {_where(item, sbom)}")
    out.append(f"  What       {_wrap(_what(item))}")
    out.append(f"  Signal     {_wrap(_signal(item))}")
    if item.vex is not None:
        out.append(f"  Upstream   {_wrap(_upstream(item))}")
    if item.bucket == REPORT:
        out.append(f"  Confirmed  {_wrap(item.rationale or '')}")
        out.append(f"             stated in {item.confirmed_by}")
        if item.aware is not None:
            # Recorded, not counted from. The line below still says where the
            # clock starts; this says which day that was, in a field something
            # other than a human reader can find.
            out.append(f"  Aware      {item.aware.isoformat()}")
        out.append("")
        out.append(
            "  -> "
            + _wrap(
                "The obligation is on the record. The 24h clock runs from when"
                " you became aware, not from the catalogue date above."
                if item.entry is not None
                else "The obligation is on the record, and it does not rest on"
                " the catalogue: no catalogue this run read lists this CVE, and"
                " the Signal line above names what the entry rests on instead."
                " The 24h clock runs from when you became aware.",
                indent=5,
            )
        )
    else:
        out.append(f"  Question   {_wrap(_question(item, sbom))}")
        out.append("")
        out.append(
            "  -> REPORT  "
            + _wrap(
                "if yes, or if it cannot be ruled out. Record it as a"
                f" [[report]] entry for {item.component.label}, with the"
                " reason it is reachable."
            )
        )
        out.append(
            "  -> NO      "
            + _wrap(
                "if the component is present but the vulnerable path is never"
                f" reached. Record it as a [[no]] entry for"
                f" {item.component.label}, with the reason it is not: that is"
                " your VEX entry and your audit trail."
            )
        )
        if item.vex is not None and item.vex.is_not_affected:
            out.append(
                "  -> adopt   "
                + _wrap(
                    "if you are prepared to stand behind"
                    f" {item.vex.asserter} having made that determination for"
                    " your product. Re-running with --adopt-upstream-vex moves"
                    " this item to NO, records the claim and its author in the"
                    " output, and can change the exit code. It does not move"
                    " the obligation."
                )
            )
    context = _context(item)
    if context:
        out.append("")
        out.append(f"  context    {context}")
    return out


def _upstream(item: Item) -> str:
    """The SBOM's claim, always with what this run did about it.

    Never printed as a bare assertion. A brief that says "not affected" and
    stops has handed the reader somebody else's conclusion wearing this
    tool's voice.
    """
    claim = item.vex
    assert claim is not None  # callers check
    stated = claim.state
    if claim.justification:
        stated += f" ({claim.justification})"
    text = f"{claim.asserter} asserts {stated} for this product."
    detail = _one_line(claim.detail)
    if detail:
        text += f' "{detail}"'
    if item.bucket == REPORT:
        return (
            text
            + " Your confirmation below says otherwise and wins: a statement"
            " about your own product outranks one made about somebody's."
        )
    if not claim.is_not_affected:
        return (
            text
            + " Unverified, and not adoptable: only not_affected can be"
            " adopted, and this is a statement about the scan rather than"
            " about whether the path is live in your product."
        )
    return (
        text
        + " Unverified - art14 did not check it and this run did not act on"
        " it. The item is still yours to decide."
    )


def _header(item: Item) -> str:
    parts = [item.cve_id]
    entry = item.entry
    if entry is not None and entry.euvd_id:
        parts.append(entry.euvd_id)
    parts.append(item.component.label)
    return " - ".join(parts)


def _where(item: Item, sbom: Sbom) -> str:
    """Direct or transitive, with the chain it arrives through.

    Always shown, because section 4 calls it the first thing a human looks at
    and the single largest factor in the decision.
    """
    location = item.location
    described = location.describe()
    if location.is_direct:
        # The parent is the root component, which the header already names.
        return described
    parent = location.parent_ref
    if parent is None:
        return described
    return f"{described}  <-  {_label_for(sbom, parent)}"


def _label_for(sbom: Sbom, ref: str) -> str:
    component = sbom.component_by_ref(ref)
    return component.label if component else ref


def _what(item: Item) -> str:
    """The vulnerability in one line, as concretely as the record allows.

    OSV fills `summary`/`details` and `database_specific.cwe_ids`, but neither
    is guaranteed and a pre-enriched SBOM may carry less. What must never
    happen is a blank line where the substance goes, so the fallback names the
    record we do have rather than printing nothing.
    """
    cwes = ", ".join(f"CWE-{number}" for number in item.vulnerability.cwes)
    description = _one_line(item.vulnerability.description)
    if cwes and description:
        return f"{cwes} - {description}"
    if cwes:
        return f"{cwes} - no description on the record"
    if description:
        return description
    source = item.vulnerability.source_name or "the record"
    return (
        f"no description and no CWE on {source}. Read {item.cve_id} upstream"
        " before deciding."
    )


def _signal(item: Item) -> str:
    """Who says it is exploited, and since when. Never a countdown.

    The one field that answers "on whose word", so it is where an entry's
    `basis` belongs: a REPORT resting on the manufacturer's own evidence and
    one resting on a catalogue listing are different claims, and this is the
    line a reader is already looking at to tell them apart.
    """
    entry = item.entry
    basis = BASES.get(item.basis or "")
    if entry is None:
        if basis:
            return f"not in the KEV catalogue - reported on {basis}"
        return "not in the KEV catalogue"
    sources = ", ".join(entry.sources) if entry.sources else "EUVD KEV"
    if entry.date_added:
        signal = f"{sources} - in catalogue since {entry.date_added}"
    else:
        signal = f"{sources} - date added not stated"
    # Kept when the catalogue does list it. The entry may have been written
    # before the listing arrived, and the second basis is not made wrong by
    # the first turning up.
    return f"{signal}; also on {basis}" if basis else signal


def _question(item: Item, sbom: Sbom) -> str:
    """One concrete question about the product, answerable without the CVE.

    Built from where the component sits and what class of flaw it is -- the two
    things the tool actually knows. It never guesses reachability; it asks the
    person who can answer, and it names the component so the question can be
    answered by someone who knows the product and not the CVE.
    """
    product = sbom.root.label if sbom.root else "this product"
    component = item.component.label
    clause = _cwe_clause(item.vulnerability.cwes)
    location = item.location
    if location.kind == ROOT:
        return (
            f"{component} is the product itself. Does the shipped configuration"
            f" expose the affected functionality, and {clause}?"
        )
    if location.is_direct:
        return (
            f"{product} depends on {component} directly. Does any code path in"
            f" the product pass untrusted input to it, and {clause}?"
        )
    parent = location.parent_ref
    if parent is not None:
        return (
            f"{component} arrives through {_label_for(sbom, parent)}. Does that"
            f" path execute in the shipped build of {product}, and {clause}?"
        )
    return (
        f"{component} is in the inventory of {product} but not in its dependency"
        " graph. Is it actually shipped, and if so, does untrusted input reach"
        f" it, and {clause}?"
    )


# The question's second half. Small and deliberately incomplete: these are the
# classes where "does untrusted input reach it" is not the whole question. The
# fallback below is a real question rather than a placeholder. This is phrasing
# only -- nothing here moves an item between buckets, and an unrecognised CWE
# changes the wording and never the verdict.
_CWE_CLAUSES = {
    20: "is that input validated before it reaches the component",
    22: "can a caller influence the file paths it opens",
    77: "does any of that input end up in a command it runs",
    78: "does any of that input end up in a shell command",
    79: "is any of its output rendered into a page without escaping",
    89: "does any of that input reach a database query",
    94: "can a caller influence code or a template it evaluates",
    120: "can a caller control the size of what it is given",
    190: "can a caller control the size of what it is given",
    287: "does the product rely on it to authenticate anyone",
    295: "does the product rely on it to verify a TLS certificate",
    306: "does the product rely on it to authenticate anyone",
    327: "does the product rely on it to protect anything in transit or at rest",
    400: "can a caller control how much work it is asked to do",
    502: "does it ever deserialise data that came from outside",
    611: "does it ever parse XML that came from outside",
    787: "can a caller control the size of what it is given",
    798: "is the affected credential path used in the shipped build",
    917: "is expression or lookup evaluation enabled in this configuration",
}


def _cwe_clause(cwes: Iterable[int]) -> str:
    for number in cwes:
        clause = _CWE_CLAUSES.get(number)
        if clause:
            return clause
    return "is the affected functionality enabled in the shipped configuration"


def _context(item: Item) -> str | None:
    """Severity context for ordering work inside a bucket. Never a trigger.

    CVSS only. EPSS is deliberately absent from this tool entirely, and the
    catalogue date above is context, not a countdown.
    """
    cvss = item.vulnerability.cvss
    if cvss is not None and cvss.score is not None:
        parts = [f"CVSS {cvss.score}"]
        if cvss.severity:
            parts.append(cvss.severity)
        return " - ".join(parts)
    # `Vulnerability.cvss` ranks on the number and returns nothing without one.
    # OSV publishes the vector and leaves the arithmetic to the reader, so on
    # this tool's main path that is every record -- and an always-empty context
    # line would make the field decorative. The database's own band comes
    # first because it is the half a person reads, and the vector after it
    # because it is the half that is checkable. art14 computes neither.
    word = item.vulnerability.severity
    vector = item.vulnerability.vector
    if vector:
        return f"{word} - {vector}" if word else vector
    return word


def _flat(text: str | None) -> str | None:
    """Whitespace collapsed, nothing dropped. For text art14 must not shorten."""
    if not text:
        return None
    return " ".join(text.split())


def _one_line(text: str | None) -> str | None:
    if not text:
        return None
    flat = " ".join(text.split())
    if len(flat) <= 160:
        return flat
    return flat[:157].rstrip() + "..."


def _wrap(text: str, *, indent: int = 13, width: int = 78) -> str:
    """Fold a sentence under its label, keeping the label column intact.

    Hyphens never break. A brief is read for the identifiers in it, and
    `--adopt-upstream-vex` split across two lines is a flag the reader has to
    reassemble before they can type it.
    """
    body = textwrap.fill(
        text, width=width - indent, break_on_hyphens=False, break_long_words=False
    )
    return body.replace("\n", "\n" + " " * indent)


def as_json(result: Triage | None, sbom: Sbom | None = None) -> dict[str, object]:
    """The `triage` block. Same shape whether or not there was a catalogue.

    `available` false is not "nothing was reportable": the counts underneath it
    mean nothing was asked, and `input.informed` is false on that run.
    """
    if result is None:
        return {
            "available": False,
            "counts": {
                "report": 0,
                "assess": 0,
                "no": 0,
                "unassessed": 0,
                "ruledOut": 0,
                "suppressed": 0,
            },
            "items": [],
            "unusedConfirmations": [],
            "ruledOutInConfig": [],
            "suppressedByUpstreamVex": [],
        }
    return {
        "available": True,
        "counts": {
            "report": len(result.report),
            "assess": len(result.assess),
            "no": len(result.no),
            "unassessed": len(result.unassessed),
            # Also a subset of `no`. The items in the catalogue that a person
            # ruled out and wrote down why.
            "ruledOut": len(result.ruled_out),
            # A subset of `no`, not an addition to it. Counted separately
            # because "not in the catalogue" and "in the catalogue, and the
            # SBOM says it does not apply" are different claims resting on
            # different authorities.
            "suppressed": len(result.suppressed),
        },
        # REPORT and ASSESS carry their full brief. NO is counted, never listed
        # row by row -- that is noise and it buries the two buckets that matter.
        "items": [_item_json(item, sbom) for item in result.actionable],
        "unusedConfirmations": [
            {
                "component": use.confirmation.component,
                "cve": use.confirmation.cve_id,
                "matchedComponent": use.matched_component,
                # Both facts, not only the first. The two ways an entry can
                # stand down under a component that does exist want different
                # things from the reader, and a consumer should not have to
                # parse the prose below to tell them apart.
                "matchedPair": use.matched_pair,
                "reason": use.explain(),
            }
            for use in result.unused
        ],
        # The first exception to "NO is counted, never listed": the rows a
        # person decided. The full item rather than a summary, because a
        # consumer building a VEX document out of this needs the component,
        # the identifiers and the rationale in one place.
        "ruledOutInConfig": [_item_json(item, sbom) for item in result.ruled_out],
        # The second exception. These rows are the record of a suppression:
        # what was suppressed, why, and on whose authority. Without them the
        # flag would remove items from the output and leave nothing behind,
        # which is the failure the default behaviour exists to prevent.
        "suppressedByUpstreamVex": [
            {
                "cve": item.cve_id,
                "euvd": item.entry.euvd_id if item.entry else None,
                "bomRef": item.component.bom_ref,
                "component": item.component.label,
                "purl": item.component.purl,
                "state": item.suppressed_by.state,
                "justification": item.suppressed_by.justification,
                "detail": item.suppressed_by.detail,
                "assertedBy": item.suppressed_by.asserted_by or None,
            }
            for item in result.suppressed
            if item.suppressed_by is not None
        ],
    }


def _item_json(item: Item, sbom: Sbom | None) -> dict[str, object]:
    entry = item.entry
    return {
        "bucket": item.bucket,
        "cve": item.cve_id,
        "euvd": entry.euvd_id if entry else None,
        "osvIds": list(item.osv_ids),
        "bomRef": item.component.bom_ref,
        "component": item.component.label,
        # The version on its own, beside the `name@version` label. Splitting
        # the label back apart is not safe: an npm component named
        # `@scope/pkg` with no version has an `@` in it and no version behind
        # it, and a consumer doing that arrives at "scope/pkg" as a version
        # string. The VEX export writes this value into a CycloneDX
        # `affects[].versions[]` entry, where a wrong one is a claim about
        # which build is affected.
        "version": item.component.version or None,
        "purl": item.component.purl,
        "dependency": item.location.short,
        "where": _where(item, sbom) if sbom else item.location.describe(),
        "chain": list(item.location.chain),
        "cwes": list(item.vulnerability.cwes),
        "description": _one_line(item.vulnerability.description),
        "sources": list(entry.sources) if entry else [],
        # Severity context, not a countdown: the Article 14 clock runs from
        # when the manufacturer became aware, not from this date.
        "dateAdded": entry.date_added if entry else None,
        "cvss": item.vulnerability.cvss.score if item.vulnerability.cvss else None,
        # The other half of what the brief's context line shows, and on the
        # main path the only half there is. Without it a consumer reading the
        # JSON sees a null score where the brief showed a vector, which is the
        # one place these two views could be said to disagree.
        "cvssVector": item.vulnerability.vector,
        # The publisher's qualitative band. Usually the only severity there
        # is: OSV carries a vector and no computed score.
        "severity": item.vulnerability.severity,
        # The six fields of the brief, rendered. A consumer that wants the
        # human-readable form should not have to reimplement it and drift.
        "what": _what(item),
        "signal": _signal(item),
        "question": _question(item, sbom) if sbom else None,
        "rationale": item.rationale,
        "confirmedBy": item.confirmed_by,
        # What the entry rests on when no catalogue lists the CVE. Null on the
        # ordinary path, where `sources` above already names the basis.
        # `signal` carries the same fact in prose.
        "basis": item.basis,
        # The day the manufacturer recorded becoming aware, as the operator
        # wrote it. A recorded date: nothing here counts from it, and a
        # consumer that wants to is doing so on its own authority.
        "aware": item.aware.isoformat() if item.aware else None,
        # One value from CycloneDX's `impactAnalysisJustification`, on a NO
        # the operator ruled out and named a reason for. Null everywhere
        # else, including on a NO whose rationale says why in prose and
        # nothing more -- art14 never reads a justification out of the words.
        "justification": item.justification,
        # Present whenever the SBOM made a claim, whether or not it was
        # adopted; `adopted` says which. A consumer must be able to see the
        # claim on an item art14 is still asking about, not only on one that
        # disappeared into NO.
        "upstreamClaim": _claim_json(item),
    }


def _claim_json(item: Item) -> dict[str, object] | None:
    claim = item.vex
    if claim is None:
        return None
    return {
        "state": claim.state,
        "justification": claim.justification,
        "detail": claim.detail,
        "assertedBy": claim.asserted_by or None,
        "adopted": item.suppressed_by is not None,
        # Said in the record rather than left to be inferred from `adopted`
        # being false, because the two reasons for false are different: the
        # flag was not given, or the state is not one this tool will adopt.
        "adoptable": claim.is_not_affected,
    }
