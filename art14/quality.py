"""Input quality gate.

Three independent axes. They answer different questions and they are computed,
rendered and exited on as **one** thing -- one banner, one JSON block, one
exit rule -- because parallel warning paths can contradict each other and the
user only has to believe the reassuring one:

    informed   Did we look at all?        Matching ran (or the SBOM arrived
                                          with vulnerabilities attached) *and*
                                          the KEV catalogue could be consulted.
    quality    Could we have found        PURL and version coverage, plus
               anything if we had?        whether the lookups actually ran.
    coverage   Did the source answer?     Whether the vulnerability database
                                          returned records for the ecosystems
                                          in this inventory.

The third axis is separate rather than folded into `quality` because the two
fail differently and the reader's next move differs. A missing PURL is a
defect in the SBOM and the fix is to produce a better one. A well formed PURL
that OSV returns nothing for is not a defect anywhere: the identifier is
right, the lookup completed, and the source simply said nothing. Collapsing
the second into "degraded" would name the wrong culprit and, worse, would let
a run whose every answer was silence certify that there is nothing to report.

`informed` takes both layers because either half missing produces the same
sentence: we did not find out. A catalogue that could not be fetched is not an
empty catalogue -- every CVE would come back "not listed" -- so a run without
one fails closed rather than certifying the inventory as unexploited.
`matching_informed` is the narrower question, for the rendering that has to
say which half is missing: the user's next action is different for "your SBOM
has no PURLs" and "the catalogue was unreachable".

The failure mode both exist to prevent is a user reading an empty result as a
clean bill of health. So the tool emits exit code 0 -- which under the output
contract asserts "nothing in REPORT" -- only when it can actually stand
behind that sentence.

Neither axis can suppress a REPORT item. Poor coverage undermines negative
claims, not positive ones, so both the exit code and the result table follow
the output-contract precedence: a REPORT item wins over any complaint about
the input. `withholds_table` is where that applies here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .models import Component, Sbom

OK = "ok"
DEGRADED = "degraded"
UNUSABLE = "unusable"

# Section 9: unusable is more than half the inventory unmatchable. Compared on
# the exact ratio, never on the rounded percentage the banner prints, so that
# 50.4% and 50.6% do not both read as "50%" with different outcomes.
UNUSABLE_RATIO = 0.5

# How the vulnerabilities we are about to judge were arrived at.
BY_SBOM = "pre-enriched"
BY_OSV = "osv"


# Source coverage, by the only grouping the data supports: the PURL type, and
# its namespace when the whole group shares one. Never a list of ecosystems we
# believe OSV serves -- that would be a second database, it would go stale in
# silence, and this tool owns no databases.
COVERAGE_FULL = "full"
COVERAGE_PARTIAL = "partial"
COVERAGE_NONE = "none"


@dataclass(frozen=True)
class Ecosystem:
    """One PURL grouping, and how much of it the source answered on."""

    label: str
    queried: int
    answered: int

    @property
    def silent(self) -> bool:
        """Nothing at all came back for this group.

        Deliberately not called "uncovered". A source that does not serve an
        ecosystem and an ecosystem with nothing to report look identical from
        here, and asserting the first would be the same kind of guess as
        asserting the second.
        """
        return self.queried > 0 and self.answered == 0


@dataclass(frozen=True)
class SourceCoverage:
    """What layer 1 got back, grouped. Empty when no matching of ours ran."""

    ecosystems: tuple[Ecosystem, ...] = ()
    # Components that carried a usable identifier but were never sent, or were
    # sent and did not come back. Kept so the line can say "14 of 15 queried".
    inventory: int = 0
    ran: bool = False

    @property
    def queried(self) -> int:
        return sum(e.queried for e in self.ecosystems)

    @property
    def answered(self) -> int:
        return sum(e.answered for e in self.ecosystems)

    @property
    def silent_ecosystems(self) -> tuple[Ecosystem, ...]:
        return tuple(e for e in self.ecosystems if e.silent)

    @property
    def nothing_answered(self) -> bool:
        """Matching ran, components were sent, and not one record came back.

        The state that cannot support a negative claim. Same principle as an
        unfetched catalogue: absence of the signal is not absence of the
        thing, and a question nobody answered is not a no.
        """
        return self.ran and self.queried > 0 and self.answered == 0

    @property
    def level(self) -> str:
        if not self.ran or not self.queried:
            return COVERAGE_FULL
        if self.answered == 0:
            return COVERAGE_NONE
        if self.silent_ecosystems:
            return COVERAGE_PARTIAL
        return COVERAGE_FULL


def coverage(result: object, *, inventory: int) -> SourceCoverage:
    """Group what layer 1 sent by PURL type, against what came back.

    Takes the `MatchResult` structurally rather than by import: this module is
    the gate and knows nothing about OSV's client. None means the SBOM brought
    its own vulnerabilities, so there is no coverage of ours to measure.
    """
    if result is None:
        return SourceCoverage(inventory=inventory)
    answered_refs = {
        finding.component.bom_ref for finding in getattr(result, "findings", ())
    }
    groups: dict[str, list[int]] = {}
    namespaces: dict[str, set[str]] = {}
    for component in getattr(result, "queried", ()):
        purl_type, namespace = _purl_group(component.purl)
        counts = groups.setdefault(purl_type, [0, 0])
        counts[0] += 1
        counts[1] += 1 if component.bom_ref in answered_refs else 0
        namespaces.setdefault(purl_type, set()).add(namespace)
    ecosystems = []
    for purl_type, (queried, answered) in sorted(groups.items()):
        # The namespace is shown only when the whole group shares one, which is
        # what makes `pkg:apk/alpine` readable and stops `pkg:maven` from
        # fragmenting into one row per groupId.
        only = namespaces[purl_type]
        label = (
            f"{purl_type}/{next(iter(only))}"
            if len(only) == 1 and next(iter(only))
            else purl_type
        )
        ecosystems.append(Ecosystem(label=label, queried=queried, answered=answered))
    return SourceCoverage(
        ecosystems=tuple(ecosystems), inventory=inventory, ran=True
    )


def _purl_group(purl: str | None) -> tuple[str, str]:
    """`pkg:apk/alpine/busybox@1.30.1-r5?arch=x86_64` -> ("pkg:apk", "alpine")."""
    if not purl:
        return ("no PURL", "")
    body = purl.split("#", 1)[0].split("?", 1)[0]
    if body.startswith("pkg:"):
        body = body[4:]
    parts = [part for part in body.split("/") if part]
    if not parts:
        return ("no PURL", "")
    return (f"pkg:{parts[0]}", "/".join(parts[1:-1]))


@dataclass(frozen=True)
class InputQuality:
    """What the SBOM can support, before any verdict is printed."""

    components: int
    without_purl: tuple[Component, ...]
    without_version: tuple[Component, ...]
    # Sendable components whose OSV lookup did not complete -- a failed chunk,
    # or a cold cache with no network. Not a structural defect in the SBOM, but
    # identical in effect: we did not find out. Section 9 counts what could not
    # be matched, and these could not be.
    query_failures: tuple[Component, ...]
    # The union of all three, in SBOM order. The number the gate acts on.
    unmatchable: tuple[Component, ...]
    # Entries the document listed that the type rule kept out of the inventory
    # above. Carried so the banner can say how much was set aside and why; they
    # are in no ratio and no grade. A reader has to be able to see that the
    # denominator was narrowed and on what rule -- silently dropping two thirds
    # of a document is the same class of error as silently treating an
    # unmatched component as clean.
    non_packages: tuple[Component, ...]
    level: str
    informed: bool
    informed_by: str | None
    # Whether layer 2 had a catalogue to consult. Folded into `informed`, and
    # kept separately so the output can name which half of the run is missing
    # rather than blaming an SBOM that was fine.
    catalogue_available: bool = True
    # The third axis. Empty on a pre-enriched run: no matching of ours ran, so
    # there is no answer rate of ours to report.
    source: SourceCoverage = SourceCoverage()

    @property
    def document_components(self) -> int:
        """How many entries the document listed, before the type rule."""
        return self.components + len(self.non_packages)

    @property
    def narrowed(self) -> bool:
        """Whether the type rule set anything aside on this run."""
        return bool(self.non_packages)

    @property
    def non_package_types(self) -> tuple[str, ...]:
        """Which types were set aside, commonest first.

        Named rather than counted, because the rule is the part a reader has
        to be able to check.
        """
        counts: dict[str, int] = {}
        for component in self.non_packages:
            counts[component.type] = counts.get(component.type, 0) + 1
        return tuple(
            name for name, _ in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
        )

    @property
    def matching_informed(self) -> bool:
        """Whether layer 1 produced answers, catalogue aside.

        `informed` is the run-level question and a missing catalogue makes it
        false. This is the one the renderers branch on when they need to say
        what specifically was not done.
        """
        return self.informed_by is not None

    @property
    def unmatchable_ratio(self) -> float:
        return len(self.unmatchable) / self.components if self.components else 1.0

    @property
    def unmatchable_percent(self) -> int:
        return round(self.unmatchable_ratio * 100)

    @property
    def without_purl_percent(self) -> int:
        if not self.components:
            return 0
        return round(len(self.without_purl) / self.components * 100)

    @property
    def matching_was_ours(self) -> bool:
        """True when our own matching is what the result rests on.

        Section 9 counts components that are *unmatchable* -- a property
        relative to the matching we are about to perform. When the SBOM already
        carries vulnerabilities there is no such matching to perform, so the
        ratio has no denominator and the gate has nothing to gate. The coverage
        numbers are still reported; they just do not block.
        """
        return self.informed_by != BY_SBOM

    @property
    def blocks(self) -> bool:
        """True when the input alone cannot support a result table.

        Subject to the output-contract precedence: call `withholds_table`
        rather than this, because a REPORT item is positive evidence and is
        never withheld by a warning about coverage.
        """
        return self.level == UNUSABLE and self.matching_was_ours

    def withholds_table(self, *, report_items: int, assess_items: int) -> bool:
        """Whether to actually suppress the table, precedence applied.

        Poor coverage undermines negative claims, not positive ones. A table
        that lists only the well formed minority reads as complete and is a
        false negative -- so it is withheld. A reportable vulnerability in that
        minority was still genuinely matched against a real catalogue entry,
        and suppressing it would be the same failure the gate exists to
        prevent, pointed the other way.

        ASSESS counts for exactly the same reason. It is a real catalogue entry
        against a real matched component, it is what drives exit 1, and a run
        that exits non-zero while printing only a coverage complaint is this
        gate pointed backwards.
        """
        return self.blocks and not (report_items or assess_items)

    @property
    def can_certify_nothing_to_report(self) -> bool:
        """Whether exit code 0 would be an honest thing to say.

        Not informed means we never looked. Unusable means we looked at a
        minority of the product. Neither supports "nothing in REPORT".

        It applies to a pre-enriched run too, and deliberately, even though
        the gate on the result table does not. The reason is different there:
        the components are not ones we failed to match, they are ones we
        cannot tell whether anybody matched. Exit 0 is the one code that makes
        a negative claim, and "most of this inventory is unidentifiable and
        the file does not say what was checked" is not a basis for one.

        The third axis joins it on the same principle. A run whose every
        lookup completed and whose every answer was silence has established
        nothing: a source that does not serve an ecosystem is indistinguishable
        from an ecosystem with nothing to report, and only one of those two
        supports exit 0.
        """
        return (
            self.informed
            and self.level != UNUSABLE
            and not self.source.nothing_answered
        )


def assess(
    sbom: Sbom,
    *,
    matching_performed: bool = False,
    matched_by: str | None = None,
    query_failures: Sequence[Component] = (),
    catalogue_available: bool = True,
    source: SourceCoverage | None = None,
) -> InputQuality:
    """Measure one SBOM, after matching has had its chance.

    `query_failures` are components the matcher tried and could not resolve.
    They are folded into the same ratio as the structurally unmatchable ones
    rather than warned about separately, because a second warning path is a
    second thing the user can choose not to believe -- and the question both
    answer is the same: how much of this product did we actually assess?

    `catalogue_available` is the layer 2 half of the same question. It defaults
    to True so that callers measuring an SBOM in isolation are not asserting
    anything about a catalogue they never asked about; the CLI passes what
    actually happened.
    """
    failed_refs = {c.bom_ref for c in query_failures}
    without_purl = tuple(c for c in sbom.components if not c.purl)
    without_version = tuple(c for c in sbom.components if not _has_version(c))
    unmatchable = tuple(
        c
        for c in sbom.components
        if not c.purl or not _has_version(c) or c.bom_ref in failed_refs
    )

    # Both layers, because either one missing means the same thing: we did not
    # find out. `informed_by` deliberately still records layer 1, so the output
    # can tell "never looked up" from "looked up, no catalogue to judge with".
    informed = (sbom.is_pre_enriched or matching_performed) and catalogue_available
    if sbom.is_pre_enriched:
        informed_by: str | None = BY_SBOM
    elif matching_performed:
        informed_by = matched_by or BY_OSV
    else:
        informed_by = None

    return InputQuality(
        components=len(sbom.components),
        without_purl=without_purl,
        without_version=without_version,
        query_failures=tuple(
            c for c in sbom.components if c.bom_ref in failed_refs
        ),
        unmatchable=unmatchable,
        non_packages=sbom.non_packages,
        level=_level(len(sbom.components), len(unmatchable)),
        informed=informed,
        informed_by=informed_by,
        catalogue_available=catalogue_available,
        source=source if source is not None else SourceCoverage(),
    )



def _level(components: int, unmatchable: int) -> str:
    # An SBOM with no components cannot produce a finding, and calling that
    # "ok" because zero of zero are unmatchable is the exact false negative
    # this gate exists for.
    if components == 0:
        return UNUSABLE
    if unmatchable == 0:
        return OK
    if unmatchable / components > UNUSABLE_RATIO:
        return UNUSABLE
    return DEGRADED


def _has_version(component: Component) -> bool:
    """Whether anything gives OSV a version to query with.

    A PURL can carry its own version, so a component with an empty `version`
    field is not necessarily unmatchable. This only answers yes or no; it does
    not extract the version, because `pkg:deb/debian/openssl@1.1.1n?arch=amd64`
    punishes naive splitting and a miscount here moves the gate threshold.
    """
    if component.version:
        return True
    purl = component.purl
    if not purl:
        return False
    name = purl.split("#", 1)[0].split("?", 1)[0].rsplit("/", 1)[-1]
    return "@" in name


# --- rendering ------------------------------------------------------------
#
# Both axes are spoken in one voice here. Nothing else in the codebase prints
# a coverage warning or an "unmatched" caveat.


def _ours_to_fix(quality: InputQuality) -> bool:
    """True when the shortfall is our failed lookups, not the SBOM's contents.

    Which determines who is told to fix what. A perfectly formed SBOM run
    against a cold cache with no network produces a fully unusable result, and
    "your SBOM is not fit for Article 14 purposes" would be simply false.
    """
    return len(quality.query_failures) == len(quality.unmatchable)


def shortfall(quality: InputQuality) -> str:
    """Why the unmatchable components are unmatchable, named accurately.

    A cold cache with no network produces a fully unusable run out of a
    perfectly well formed SBOM. Telling that user their PURLs are missing sends
    them to fix the wrong thing.
    """
    structural = len(quality.unmatchable) - len(quality.query_failures)
    if not quality.query_failures:
        return "no PURL or no version"
    if not structural:
        return "a lookup that did not complete"
    return "no PURL, no version, or a lookup that did not complete"


def banner(quality: InputQuality) -> list[str]:
    """The input quality banner, printed before any result."""
    if not quality.components:
        head = (
            f"input: no package components in {quality.document_components} entries"
            if quality.narrowed
            else "input: no components"
        )
        return [
            head,
            *_narrowing_line(quality),
            f"       {_grade_line(quality)}",
            *_coverage_lines(quality),
        ]
    noun = "package components" if quality.narrowed else "components"
    return [
        f"input: {quality.components} {noun}"
        f" - {len(quality.without_purl)} without PURL"
        f" ({quality.without_purl_percent}%)"
        f" - {len(quality.without_version)} without version",
        *_narrowing_line(quality),
        f"       {_grade_line(quality)}",
        *_coverage_lines(quality),
    ]


def _coverage_lines(quality: InputQuality) -> list[str]:
    """The third axis, printed only when it has something to say.

    An inventory every ecosystem of which answered needs no line: the grade
    above already covers identifiers and the funnel carries the counts. A
    silent ecosystem does need one, whether or not it changes the exit code,
    because in a mixed SBOM it is invisible otherwise -- `pkg:maven` answering
    while `pkg:apk` says nothing is the same blind spot as the whole run
    saying nothing, over a smaller part of the product.
    """
    source = quality.source
    if not source.silent_ecosystems:
        return []
    if source.level == COVERAGE_NONE:
        return [
            f"       source coverage: none - nothing came back for any of the"
            f" {source.queried} queried"
        ]
    silent = ", ".join(e.label for e in source.silent_ecosystems)
    return [
        f"       source coverage: partial - nothing came back for {silent}",
    ]


def _narrowing_line(quality: InputQuality) -> list[str]:
    """What the type rule set aside, and under what name.

    `syft -o cyclonedx-json` lists one `file` component per file it walked, so
    a 14-package Alpine image arrives as 76 components. Those entries are not
    packages, nothing can be matched against them, and counting them would
    report an 82% unmatchable rate against an inventory that is in fact fully
    matchable. They are not graded -- which means both that they were not
    assessed and that they were not counted against the input.
    """
    if not quality.narrowed:
        return []
    types = ", ".join(quality.non_package_types)
    return [
        f"       {quality.document_components} entries in the document;"
        f" {len(quality.non_packages)} are not packages ({types})"
        " and are not graded"
    ]


def _grade_line(quality: InputQuality) -> str:
    """The grade, named after what it actually graded.

    On a run that did its own matching the number is this run's coverage:
    these components could not be matched, so they were not assessed. On a
    pre-enriched run no matching of ours ran at all, and calling the same
    number "matching quality" reports a coverage failure against a stage that
    never happened. The measurement is still worth printing -- it says how
    identifiable the inventory is -- so it keeps its grade and loses the claim.
    """
    if quality.matching_was_ours:
        return f"matching quality: {quality.level} - see README"
    if quality.level == OK:
        # Nothing to misread: a grade of ok says the inventory is identifiable
        # either way, and the caveat would be the longest thing on the line.
        return f"SBOM quality: {quality.level} - see README"
    return f"SBOM quality: {quality.level} - no matching ran here, see README"


def verdict_line(quality: InputQuality) -> str:
    """One sentence naming the combined state, for the banner and the JSON."""
    if not quality.components:
        if quality.narrowed:
            return (
                f"none of the {quality.document_components} entries in this"
                " SBOM is a package"
            )
        return "this SBOM lists no components"
    if not quality.matching_informed:
        if quality.level == UNUSABLE:
            return (
                "nothing was looked up, and this SBOM could not have been "
                "matched anyway"
            )
        return "nothing was looked up yet"
    looked = (
        "the SBOM arrived with vulnerabilities attached"
        if quality.informed_by == BY_SBOM
        else "vulnerabilities were looked up"
    )
    if not quality.catalogue_available:
        # Layer 1 ran and layer 2 did not. Which half is missing decides what
        # the user does next, so the sentence names it rather than collapsing
        # into the generic "nothing was looked up".
        return f"{looked}, but the exploitation catalogue could not be consulted"
    if not quality.matching_was_ours and quality.level != OK:
        # Nothing here matched anything, so "they describe a minority of the
        # product" would be a claim about the upstream tool's coverage, which
        # this run has no way to measure.
        return f"{looked}; how much of the product they cover is not knowable here"
    if quality.level == UNUSABLE:
        return f"{looked}, but they describe a minority of the product"
    if quality.level == DEGRADED:
        return f"{looked}; some components could not be matched"
    return looked


def warnings(
    quality: InputQuality, *, report_items: int, assess_items: int
) -> list[str]:
    """The paragraphs under the banner. Empty when there is nothing to warn.

    The catalogue paragraph comes first when there is one: a run that could not
    consult the catalogue has judged nothing, which outranks any complaint
    about how well the inventory could have been matched.
    """
    out: list[str] = []
    if not quality.catalogue_available:
        out.append(
            "WARNING: the EUVD KEV catalogue could not be consulted on this"
            " run, so nothing here has been checked for known exploitation."
            " An unreachable catalogue is not an empty one: absence of the"
            " signal is not absence of the thing. Re-run with a network"
            " connection or a warm cache before treating any of this as a"
            " statement about the product."
        )
    out.extend(
        _coverage_warnings(
            quality, report_items=report_items, assess_items=assess_items
        )
    )
    out.extend(_source_warnings(quality))
    return out


def _source_warnings(quality: InputQuality) -> list[str]:
    """What silence from the source means, and what it does not mean.

    The failure this exists for, found on `syft alpine:3.10 -o cyclonedx-json
    | art14 -`: fourteen well formed apk PURLs, every lookup completed, no
    records returned, an empty result and exit 0 on an image another scanner
    finds 125 vulnerabilities in. Nothing in the identifier coverage was
    wrong, so nothing in the grade above said a word.
    """
    source = quality.source
    if not source.silent_ecosystems:
        return []
    if source.level == COVERAGE_NONE:
        return [
            f"WARNING: nothing came back for any of the {source.queried}"
            " components queried. Their PURLs are well formed and every lookup"
            " completed, so this is not a defect in the SBOM: it is a question"
            " that went unanswered. A source that holds nothing for an"
            " ecosystem and an ecosystem with nothing to report are"
            " indistinguishable from here, and only one of them is a clean"
            " result.",
            "This run will not certify that there is nothing to report. Absence"
            " of the signal is not absence of the thing. If this is an OS image,"
            " a scanner that carries its own vulnerability list will answer"
            " where OSV did not: `grype <image> -o cyclonedx-json | art14 -`.",
        ]
    lines = ", ".join(
        f"{e.label} ({e.queried} queried)" for e in source.silent_ecosystems
    )
    return [
        f"Nothing came back for {lines}, while the rest of the inventory was"
        " answered. Those components carry usable identifiers and their"
        " lookups completed, so they are neither unmatchable nor clean: the"
        " source said nothing about them. Treat that part of the product as"
        " unassessed.",
    ]


def _coverage_warnings(
    quality: InputQuality, *, report_items: int, assess_items: int
) -> list[str]:
    """What the inventory itself can and cannot support."""
    total = quality.components
    unmatchable = len(quality.unmatchable)

    if not total:
        # Its own sentence, because the majority wording below reads as
        # "0 of 0 components" here and a ratio with no denominator is not an
        # explanation of anything.
        if quality.narrowed:
            # A document of files and nothing else. Not an empty one, and not
            # an assessable one either: there is no inventory in it to match,
            # so this is an input we cannot assess rather than a product with
            # nothing to report.
            types = ", ".join(quality.non_package_types)
            return [
                f"All {quality.document_components} entries in this SBOM are"
                f" of a type that is not a package ({types}). There is nothing"
                " here that can be matched against a vulnerability database,"
                " so an empty result says nothing about the product.",
                "This is an input that cannot be assessed, not a clean one.",
                "Your SBOM is not fit for Article 14 purposes. That is itself"
                " a finding, and usually a true one.",
            ]
        return [
            "This SBOM lists no components at all. There is no inventory to"
            " match against, so an empty result says nothing about the"
            " product.",
            "Your SBOM is not fit for Article 14 purposes. That is itself"
            " a finding, and usually a true one.",
        ]

    if not quality.matching_informed:
        if quality.blocks:
            # Nothing was looked up, so there is no REPORT item that could
            # override the gate here. The table is always withheld.
            return [
                "Unusable input. More than half of this SBOM"
                f" ({unmatchable} of {total} components) has {shortfall(quality)},"
                " so nothing could be matched against it. No result"
                " table is printed, because any table would describe the"
                " minority of the product that happens to be well formed.",
                "Your SBOM is not fit for Article 14 purposes. That is itself"
                " a finding, and usually a true one.",
            ]
        return [
            "Nothing has been looked up: this SBOM carries no vulnerabilities"
            " and matching has not run. This is NOT a statement that the"
            " product is free of reportable vulnerabilities.",
        ]

    if not quality.matching_was_ours:
        # The SBOM brought its own answers, so the unmatchable count is not a
        # coverage figure for this run at all.
        return _carried_warnings(quality)

    if quality.level == UNUSABLE:
        # The most misleading state there is: results exist and they rest on an
        # inventory that cannot support them.
        withheld = quality.withholds_table(
            report_items=report_items, assess_items=assess_items
        )
        # Who is told to fix what. A perfectly formed SBOM run against a cold
        # cache with no network lands here too, and blaming its PURLs would be
        # simply false.
        ours = _ours_to_fix(quality)
        scale = f"{unmatchable} of {total} components ({quality.unmatchable_percent}%)"
        if ours:
            head = f"WARNING: {scale} were not assessed: the lookup did not complete."
            closing = (
                "The lookups are what failed here, not the SBOM. Re-run with a"
                " network connection or a warm cache before treating this as a"
                " statement about the product."
            )
        else:
            head = (
                f"WARNING: {scale} have {shortfall(quality)}. Whatever produced"
                " this SBOM could not have matched them either."
            )
            closing = (
                "Your SBOM is not fit for Article 14 purposes. That is itself"
                " a finding, and usually a true one."
            )

        if withheld:
            # Nothing positive to show, so a table would be a false negative.
            tail = (
                "No result table is printed, because there is nothing assessed"
                " to put in it."
                if unmatchable == total
                else "No result table is printed: it could only list what was"
                " assessed, and that is a minority of the product."
            )
            return [
                f"{head} {tail}",
                "Read this as no assessment rather than as a short one. A result"
                " that looks complete and is not is worse than no result at all.",
                closing,
            ]
        if report_items or assess_items:
            # Both halves, in one breath. Either alone misleads.
            return [
                f"{head} The findings below therefore describe a minority of"
                " the product.",
                "Those findings were matched against a real catalogue entry and"
                " stand on their own: poor coverage cannot weaken positive"
                " evidence. What it does mean is that nothing here rules out"
                f" further reportable vulnerabilities in the {unmatchable}"
                " components that were not assessed.",
                closing,
            ]
        return [
            f"{head} The vulnerabilities below therefore describe a minority"
            " of the product.",
            "Read this as no assessment rather than as a short one. A result"
            " that looks complete and is not is worse than no result at all.",
            closing,
        ]

    if quality.level == DEGRADED:
        return [
            f"{unmatchable} of {total} components could not be matched"
            f" ({quality.unmatchable_percent}%): {shortfall(quality)}. Those"
            " components are unassessed, not clean.",
        ]

    return []


def _carried_warnings(quality: InputQuality) -> list[str]:
    """What missing identifiers mean when the matching was somebody else's.

    A weaker and differently shaped claim than the one the matched runs make.
    There, a component with no PURL is one this run could not look up, and the
    consequence is ours: it was not assessed. Here the lookups already
    happened somewhere else, against evidence this file does not carry -- a
    scanner reading an image has package databases and file hashes that never
    reach the CycloneDX output. So a missing PURL does not say the component
    went unassessed. It says this run cannot tell whether it did, which is why
    it still stops the run from certifying that there is nothing to report.
    """
    total = quality.components
    unmatchable = len(quality.unmatchable)
    if quality.level == OK:
        return []
    scale = f"{unmatchable} of {total} components ({quality.unmatchable_percent}%)"
    prefix = "WARNING: " if quality.level == UNUSABLE else ""
    out = [
        f"{prefix}{scale} have {shortfall(quality)}. This SBOM arrived with its"
        " own vulnerability list, so nothing here was matched by art14 and that"
        " number is not a coverage figure for this run.",
        "It is a statement about the inventory: whatever produced the file may"
        " not have identified those components either, and nothing in the file"
        " says whether it did. Treat them as unverified rather than clean.",
    ]
    if quality.level == UNUSABLE:
        out.append(
            "More than half the inventory is in that position, so this run"
            " cannot tell how much of the product the list below covers. It"
            " will not certify that there is nothing to report."
        )
    return out


def as_json(
    quality: InputQuality, *, report_items: int, assess_items: int
) -> dict[str, object]:
    """The `input` block. Present, and identically shaped, on every run."""
    failed = {c.bom_ref for c in quality.query_failures}
    return {
        "informed": quality.informed,
        "informedBy": quality.informed_by,
        # Whether layer 2 had a catalogue at all. False makes `informed` false
        # on its own: a run that could not consult the catalogue has judged
        # nothing, however well the SBOM matched.
        "catalogueAvailable": quality.catalogue_available,
        "quality": quality.level,
        # The third axis, named separately because it fails differently:
        # `quality` is about identifiers in the SBOM, this is about whether
        # the source answered on them. Per-ecosystem rates are in `matching`.
        "sourceCoverage": quality.source.level,

        # Whether coverage is good enough that an absence of findings means
        # anything. Not a verdict on the product, and not the exit code: a run
        # with a REPORT item exits 2 and an open ASSESS item exits 1, and both
        # may still say true here. `triage.counts` says which happened.
        "canRuleOut": quality.can_certify_nothing_to_report,
        "verdict": verdict_line(quality),
        # `components` is the graded inventory. `documentComponents` is what
        # the file listed, so the two together say how much the type rule set
        # aside and a consumer can check the narrowing rather than take it.
        "components": quality.components,
        "documentComponents": quality.document_components,
        "nonPackageComponents": len(quality.non_packages),
        "nonPackageTypes": list(quality.non_package_types),
        "withoutPurl": len(quality.without_purl),
        "withoutPurlPercent": quality.without_purl_percent,
        "withoutVersion": len(quality.without_version),
        "queryFailures": len(quality.query_failures),
        "unmatchable": len(quality.unmatchable),
        "unmatchablePercent": quality.unmatchable_percent,
        # Whether the result table was actually withheld, precedence applied.
        "gated": quality.withholds_table(
            report_items=report_items, assess_items=assess_items
        ),
        # Section 9: unmatched components are listed, not just counted.
        "unmatchableComponents": [
            {
                "bomRef": component.bom_ref,
                "name": component.name,
                "version": component.version or None,
                "purl": component.purl,
                "reason": _reason(component, failed),
            }
            for component in quality.unmatchable
        ],
    }


def _reason(component: Component, failed: set[str]) -> str:
    """Why one component was not assessed. Structural causes first: a component
    with no PURL was never sendable, so a failed lookup is not the story."""
    if not component.purl:
        return "no PURL"
    if not _has_version(component):
        return "no version"
    if component.bom_ref in failed:
        return "lookup did not complete"
    return "not matched"
