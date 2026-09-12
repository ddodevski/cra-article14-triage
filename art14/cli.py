"""Command line entry point.

The flag set is the one the output contract calls for, and nothing beyond it.
Exit codes are part of that contract and are wired from the start, by
precedence: `2` a REPORT item exists (wins over everything), `1` the run
cannot support a negative claim -- or a genuine error, `0` nothing to report.
See `_exit_code`.

What this module owns is the order things are said in: the input banner, then
the one-line result, then the caveats, then the funnel, then the bucket counts
with the table glued underneath them.
Two crops decide that order -- the top of the output, and the table on its
own -- because both of them are screenshots somebody will read without the
rest. Every line itself is rendered by the module that owns the number:
`quality`, `kev`, `triage` and `table`.
"""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
from typing import Sequence

from dataclasses import replace

from . import (
    __version__,
    kev as kev_module,
    provenance as provenance_module,
    quality as quality_module,
    table as table_module,
    triage as triage_module,
)
from .cyclonedx import SUPPORTED_SPEC_VERSIONS, parse_source, version_caveat
from .errors import Art14Error
from .kev import CatalogueLoad, CatalogueUnavailable, KevClient, Review
from .lines import count_line, note_line
from .models import Sbom
from .osv import MatchResult, OsvClient
from .provenance import Provenance, SourceStamp
from .quality import InputQuality
from .triage import Confirmation, Triage

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_REPORT = 2

# Raw text: the composition examples must not be re-wrapped into prose.
EPILOG = """\
art14 never scans images, containers or filesystems. SBOM in, verdict out.
Image workflows are served by composition:

  syft ghcr.io/acme/gateway:1.4 -o cyclonedx-json | art14 -
  grype ghcr.io/acme/gateway:1.4 -o cyclonedx-json | art14 -
  art14 sbom.cdx.json

Every KEV match starts in ASSESS. Nothing promotes an item to REPORT except an
explicit entry in --config naming the component and the CVE, with the reason
you concluded the vulnerable path is live. That reason is the audit trail.

Exit codes, by precedence: 2 at least one REPORT item, 1 an open ASSESS item or
an input that cannot rule out (or a genuine error), 0 nothing to report. A REPORT
item always wins -- poor SBOM coverage undermines negative claims, not positive
ones. Exit 0 is only emitted when the input can support it and nothing is left
open; an SBOM that could not be matched, or one that was never matched, exits 1
with the reason on stdout under --json.

This does not replace a legal assessment of scope.
"""


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="art14",
        description=(
            "Extract from an SBOM the vulnerabilities that trigger a reporting\n"
            "obligation under Article 14 of Regulation (EU) 2024/2847."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
    )
    parser.add_argument(
        "sbom",
        metavar="SBOM",
        help=(
            "path to a CycloneDX "
            + ", ".join(SUPPORTED_SPEC_VERSIONS)
            + " JSON SBOM, or - to read stdin"
        ),
    )
    parser.add_argument(
        "--brief",
        action="store_true",
        help="print the full decision brief for every REPORT and ASSESS item",
    )
    parser.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="machine readable output for CI and downstream processing",
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        help=(
            "TOML file of per-component REPORT confirmations. There is no"
            " auto-discovery: a REPORT verdict is a statement about the"
            " product, and the command line records what it rested on"
        ),
    )
    parser.add_argument(
        "--adopt-upstream-vex",
        action="store_true",
        help=(
            "honour the SBOM's own document-level not_affected claims, moving"
            " those items to NO. Off by default: adopting them is a statement"
            " that you trust whoever produced the SBOM, and every suppression"
            " is listed in the output with its justification and its author"
        ),
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help=(
            "never open a network connection; answer from the cache only."
            " Components with no cached answer are reported as unassessed"
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"art14 {__version__}",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    try:
        # Before anything else, including the network. A config that cannot be
        # read looks exactly like a config with nothing in it, and the run that
        # continues on that assumption under-reports the one item the user
        # cared enough about to write down.
        confirmations = (
            triage_module.load_confirmations(args.config) if args.config else ()
        )
    except Art14Error as exc:
        print(f"art14: {exc}", file=sys.stderr)
        return EXIT_ERROR

    try:
        sbom = parse_source(args.sbom)
    except Art14Error as exc:
        # Nothing parseable on stdout. That silence is what distinguishes a
        # failed run from a gated one, which does emit JSON and also exits 1.
        print(f"art14: {exc}", file=sys.stderr)
        return EXIT_ERROR

    result = _match(sbom, offline=args.offline)
    document = _with_matches(sbom, result)

    # Layer 2. A failure here is not an empty catalogue: it is no catalogue,
    # and the difference is the whole asymmetry this tool is built on. The run
    # continues so the user still sees what was matched and why the judgment is
    # missing, but it can no longer certify anything.
    catalogue = _load_catalogue(offline=args.offline)
    review = (
        None
        if catalogue is None
        else kev_module.review(document.vulnerabilities, catalogue.catalogue)
    )

    # The gate is always measured against the SBOM as it arrived. Assessing the
    # post-match document instead would see the vulnerabilities we just found
    # and conclude the input was pre-enriched, which turns our own matching
    # into someone else's and stops the gate from gating.
    quality = quality_module.assess(
        sbom,
        matching_performed=result is not None,
        query_failures=result.failed if result else (),
        catalogue_available=catalogue is not None,
        # The third axis: what the source answered, grouped by PURL type. Its
        # denominator is the same inventory the gate grades, so it is measured
        # against the pre-match document for the same reason.
        source=quality_module.coverage(result, inventory=len(sbom.components)),
    )

    # Layer 3. None when there was no catalogue: with no catalogue there is no
    # NO bucket either, and an empty triage block would read as one.
    result_triage = (
        None
        if review is None
        else triage_module.triage(
            document,
            review,
            confirmations,
            adopt_upstream_vex=args.adopt_upstream_vex,
        )
    )
    # The single place these numbers are produced. Every consumer takes them as
    # required keywords, so a miswiring is a TypeError rather than a silently
    # reverted precedence rule.
    report_items = len(result_triage.report) if result_triage else 0
    assess_items = len(result_triage.assess) if result_triage else 0

    provenance = provenance_module.build(
        adopt_upstream_vex=args.adopt_upstream_vex,
        tool=__version__,
        matching=result,
        kev=_kev_stamp(catalogue),
    )

    if args.as_json:
        json.dump(
            _inventory(
                document,
                quality,
                result,
                review,
                provenance,
                result_triage,
                report_items=report_items,
                assess_items=assess_items,
            ),
            sys.stdout,
            indent=2,
        )
        print()
    else:
        _print_inventory(
            document,
            quality,
            result,
            review,
            provenance,
            result_triage,
            report_items=report_items,
            assess_items=assess_items,
            brief=args.brief,
        )

    return _exit_code(
        quality,
        report_items=report_items,
        assess_items=assess_items,
        untested_input=version_caveat(document.spec_version) is not None,
    )


def _match(sbom: Sbom, *, offline: bool) -> MatchResult | None:
    """Run layer 1, or None when the SBOM already carries its own answers.

    Section 3: a CycloneDX document with a `vulnerabilities` array came from
    grype, Dependency-Track or cdxgen, and re-querying OSV would second-guess a
    tool that had more context than we do. Returning None rather than an empty
    result keeps `informed_by` able to say which of the two happened.
    """
    if sbom.is_pre_enriched:
        return None
    with OsvClient(offline=offline) as client:
        return client.match(sbom.components)


def _load_catalogue(*, offline: bool) -> CatalogueLoad | None:
    """Layer 2's catalogue, or None when this run could not get one.

    The failure is swallowed here rather than raised, and that is deliberate:
    a crash writes nothing parseable to stdout, and section 6 reserves that
    silence for a genuine error. This is not one. The run has a real, useful
    result to show -- the inventory, the matches, the coverage -- and one thing
    it cannot say. So it says exactly that, in full, and exits 1 through the
    quality gate rather than dying.
    """
    try:
        with KevClient(offline=offline) as client:
            return client.load()
    except CatalogueUnavailable as exc:
        print(f"art14: {exc}", file=sys.stderr)
        return None


def _kev_stamp(catalogue: CatalogueLoad | None) -> SourceStamp | None:
    """The catalogue's own two timestamps, never the run's.

    None means there was no catalogue at all. That is absence rather than
    staleness, and `provenance.lines` prints it as such.
    """
    if catalogue is None:
        return None
    return SourceStamp(
        name="euvd-kev",
        fetched_at=catalogue.fetched_at,
        cache_age_seconds=catalogue.cache_age_seconds,
    )


def _with_matches(sbom: Sbom, result: MatchResult | None) -> Sbom:

    """Fold matches into the document so downstream sees one shape.

    A matched SBOM and a pre-enriched one are then indistinguishable to every
    renderer and to the triage stage, which is the point: layer 2 must not be
    able to behave differently depending on where layer 1's answers came from.
    """
    if result is None:
        return sbom
    findings = tuple(
        replace(finding, location=sbom.location_of(finding.component.bom_ref))
        for finding in result.findings
    )
    return replace(
        sbom, vulnerabilities=result.vulnerabilities, findings=findings
    )


def _exit_code(
    quality: InputQuality,
    *,
    report_items: int,
    assess_items: int,
    untested_input: bool = False,
) -> int:
    """The one place an exit code is decided.

    Precedence, not four independent states. The first branch that matches
    wins, and the order is the whole point:

        2   a REPORT item exists            wins over everything, always
        1   cannot rule out, no REPORT item  input supports no negative claim
        0   can rule out, no REPORT item    asserts "nothing to report"

    An open ASSESS item lands in the middle branch. Coverage may be perfect and
    the SBOM impeccable, and the run still cannot say "nothing to report" while
    a KEV-listed CVE sits in the product undecided: 0 is the one code that
    makes a negative claim, and section 4 resolves uncertainty towards
    reporting. `input.canRuleOut` stays true on such a run and the triage
    counts say which branch was taken, so a consumer can tell the two kinds of
    1 apart.
    """
    if report_items:
        # Positive evidence. The component was matched, the catalogue entry is
        # real, the clock is real. Downgrading this to 1 over a coverage
        # warning would read to a gating pipeline as infrastructure flake --
        # retried or ignored, and the Article 14 trigger missed.
        return EXIT_REPORT
    if assess_items or not quality.can_certify_nothing_to_report:
        return EXIT_ERROR
    if untested_input:
        # Parsing a spec version this build has not been read against is the
        # one fail-open path in a tool that is fail-closed everywhere else, and
        # 0 is where that would cost something: if the version renamed a field
        # this parser reads, every component lands outside the dependency graph
        # and the run certifies on an inventory it misread. Keeping the run
        # alive was the point; letting it make a negative claim was not.
        return EXIT_ERROR
    return EXIT_OK


def _inventory(
    sbom: Sbom,
    quality: InputQuality,
    result: MatchResult | None,
    review: Review | None,
    provenance: Provenance,
    result_triage: Triage | None,
    *,
    report_items: int,
    assess_items: int,
) -> dict[str, object]:
    """The full JSON document: what each of the three layers found.

    The shape is the same on every run -- gated, matched, pre-enriched or
    offline -- so a consumer can read `input.quality` without first branching
    on which kind of run it got.
    """
    return {
        "art14": __version__,
        "specVersion": sbom.spec_version,
        # Null unless the document is newer than this build was read
        # against, in which case it says what was assumed.
        "specVersionCaveat": version_caveat(sbom.spec_version),
        "product": sbom.root.label if sbom.root else None,
        # Always present, and the same shape on every run: a consumer reads
        # `provenance.mode` without first branching on what kind of run it got.
        "provenance": provenance_module.as_json(provenance),
        "input": quality_module.as_json(
            quality, report_items=report_items, assess_items=assess_items
        ),
        "matching": _matching_json(result),
        "kev": _kev_json(review),
        "counts": {
            # The graded inventory, matching `input.components`. What the
            # document listed is `input.documentComponents`; the difference is
            # the entries the type rule set aside.
            "components": len(sbom.components),
            "documentComponents": sbom.document_components,
            "vulnerabilities": len(sbom.vulnerabilities),
            "findings": len(sbom.findings),
        },
        "findings": [] if quality.withholds_table(
            report_items=report_items, assess_items=assess_items
        ) else [
            {
                "id": finding.vulnerability.id,
                "aliases": list(finding.vulnerability.aliases),
                "component": finding.component.label,
                "purl": finding.component.purl,
                "dependency": finding.location.short,
                "where": finding.location.describe(),
                "chain": list(finding.location.chain),
                "cwes": list(finding.vulnerability.cwes),
                # Upstream's own stamp for this record, kept per record: the
                # run-level block says when we asked, this says how current
                # the particular answer was.
                "modified": finding.vulnerability.modified or None,
                "cvss": (
                    finding.vulnerability.cvss.score
                    if finding.vulnerability.cvss
                    else None
                ),
            }
            for finding in sbom.findings
        ],
        "unresolvedAffects": [
            {"id": vuln_id, "ref": ref} for vuln_id, ref in sbom.unresolved_affects
        ],
        "excludedAffects": [
            {"id": vuln_id, "ref": ref} for vuln_id, ref in sbom.excluded_affects
        ],
        # Section 6: the JSON carries every field of the decision brief, so a
        # consumer never has to reproduce the wording and drift from it.
        "triage": triage_module.as_json(result_triage, sbom),
    }


def _kev_json(review: Review | None) -> dict[str, object]:
    """What layer 2 asked and what came back.

    Identically shaped whether or not there was a catalogue, so a consumer
    reads `kev.available` rather than testing for a missing key. `available`
    false is not "no CVEs were listed" -- the zero counts underneath it mean
    nothing was asked, and `input.informed` is false on that run.
    """
    if review is None:
        return {"available": False, **Review().as_json()}
    return {"available": True, **review.as_json()}


def _matching_json(result: MatchResult | None) -> dict[str, object]:
    """What layer 1 actually did. Null source means the SBOM brought its own."""
    if result is None:
        return {"source": None, "queried": 0, "failed": 0, "stale": 0}
    source = quality_module.coverage(result, inventory=len(result.queried))
    return {
        "source": "osv",
        "queried": len(result.queried),
        "answered": source.answered,
        # Answer rates by PURL type. Zero for one group while another answered
        # is a blind spot over part of the product, and it is invisible in the
        # totals -- which is the whole reason this is grouped.
        "coverage": {
            "level": source.level,
            "ecosystems": [
                {
                    "purlType": ecosystem.label,
                    "queried": ecosystem.queried,
                    "answered": ecosystem.answered,
                }
                for ecosystem in source.ecosystems
            ],
        },
        "failed": len(result.failed),
        # Answered from a cache entry past its freshness window. Offline runs
        # are allowed to do this; they are not allowed to hide it.
        "stale": len(result.stale),
        "fromCache": result.from_cache,
        "fetched": result.fetched,
    }


def _coverage_lines(quality: InputQuality) -> list[str]:
    """The funnel's source-coverage block, or nothing.

    The total first, in the same shape as the rows around it, then one line
    per PURL grouping. All the groups are listed rather than only the silent
    ones, because "pkg:apk 14 queried, 0 answered" means something different
    beside "pkg:maven 36 queried, 31 answered" than it does alone.
    """
    source = quality.source
    if not source.silent_ecosystems:
        return []
    out = [
        count_line(
            "osv coverage",
            source.answered,
            f"(of {source.queried} queried came back with records)",
        )
    ]
    for ecosystem in source.ecosystems:
        # No gloss on a zero: the line above says what zero means, and the
        # block has to hold together at 80 columns like every other row here.
        out.append(
            note_line(
                f"{ecosystem.label}   {ecosystem.queried} queried,"
                f" {ecosystem.answered} answered"
            )
        )
    return out


def _print_inventory(
    sbom: Sbom,
    quality: InputQuality,
    result: MatchResult | None,
    review: Review | None,
    provenance: Provenance,
    result_triage: Triage | None,
    *,
    report_items: int,
    assess_items: int,
    brief: bool = False,
) -> None:
    product = sbom.root.label if sbom.root else "unknown product"
    print(f"art14 {__version__} - CycloneDX {sbom.spec_version} - {product}")
    print()
    for line in quality_module.banner(quality):
        print(line)
    # Same kind of statement as the gate's own lines -- this much was not
    # assessed -- so it belongs in the banner rather than in a caveat further
    # down that reads as weaker.
    uncheckable_line = kev_module.banner_line(review) if review else None
    if uncheckable_line:
        print(uncheckable_line)

    # The answer, one line, above every warning. The warnings below are loud by
    # design and they are about a different question; a reader who takes only
    # the top of this output has to leave with the verdict, not with a
    # complaint about the input.
    table_module.print_result_line(result_triage)

    # An untested spec version is a statement about how much of this run can be
    # relied on, so it goes with the other ones rather than in a footnote.
    caveat = version_caveat(sbom.spec_version)
    if caveat:
        print()
        print(textwrap.fill(caveat, width=76))

    # The warning is printed in every state, including the ones that exit 2.
    # Quality and verdict are different axes and the output says both.
    for paragraph in quality_module.warnings(
        quality, report_items=report_items, assess_items=assess_items
    ):
        print()
        print(textwrap.fill(paragraph, width=76))

    uncheckable = kev_module.uncheckable_warning(review) if review else None
    if uncheckable:
        print()
        print(textwrap.fill(uncheckable, width=76))

    # A confirmation that matched nothing leaves the user believing an item is
    # in REPORT when it is in ASSESS. Same failure mode as an unmatched
    # component, so it gets the same treatment: loud, and never suppressed.
    for paragraph in triage_module.unused_warning(result_triage):
        print()
        # The per-entry lines are already indented as a list; keep their hang.
        indent = "    " if paragraph.startswith("  - ") else ""
        print(textwrap.fill(paragraph, width=76, subsequent_indent=indent))

    if result is not None and result.stale:
        print()
        print(
            textwrap.fill(
                f"{len(result.stale)} of {result.attempted} components were"
                " answered from a cache entry older than a day. Offline runs"
                " are allowed to do that; a vulnerability published since then"
                " is not in this result.",
                width=76,
            )
        )

    # A stale catalogue quietly producing NO verdicts is the same failure mode
    # as an unmatchable SBOM, so it gets the same treatment: loud, on stdout,
    # in every state, and never suppressed by the table being suppressed.
    staleness = provenance_module.staleness_warning(provenance)
    if staleness:
        print()
        print(textwrap.fill(staleness, width=76))

    if brief:
        # Article 14 turns on when you became aware and on what basis. The
        # stamp is that evidence, so it prints before anything that could cut
        # the output short.
        print()
        for line in provenance_module.lines(provenance):
            print(line)

    if quality.withholds_table(
        report_items=report_items, assess_items=assess_items
    ):
        # Section 9: no result table, because any table here would describe
        # only the well formed minority and read as complete.
        return
    if not quality.matching_informed:
        # The warning above already said that nothing was looked up. There is
        # no inventory of vulnerabilities to print under it. A run that matched
        # but found no catalogue is a different case: what layer 1 found is
        # real and is still worth printing under the warning that says it has
        # not been judged.
        return

    print()
    # The funnel, top first: what came in, what it became, and how much of it
    # survives to the buckets below. Section 6's asymmetry is this block plus
    # the three lines under it, and it has to hold together on its own -- a
    # screenshot of the first fifteen lines is how most people will see it.
    # The top of the funnel is the inventory that was graded, not everything
    # the file listed. When those differ the line says so rather than quietly
    # counting one and printing the other.
    print(
        count_line(
            "components",
            len(sbom.components),
            f"(of {sbom.document_components} in the SBOM;"
            f" {len(sbom.non_packages)} are not packages)"
            if sbom.non_packages
            else "(read from the SBOM)",
        )
    )
    print(
        count_line(
            "vulnerabilities",
            len(sbom.vulnerabilities),
            f"({_match_source(result)})",
        )
    )
    # Two records aliasing one CVE on one component are one pair to bucket
    # and two findings here, so the head of the funnel can sit one above the
    # total of the buckets. Said on the line rather than left as arithmetic
    # that does not work.
    collapses = result_triage is not None and result_triage.pairs != len(sbom.findings)
    print(
        count_line(
            "component-CVE pairs",
            len(sbom.findings),
            "(one record can affect several components;"
            if collapses
            else "(one record can affect several components)",
        )
    )
    if collapses:
        print(
            note_line(
                f"several can name one CVE: {result_triage.pairs} distinct pairs)"
            )
        )
    if result is not None:
        # Two different units, so two rows. On one row "(2 from cache, 7
        # fetched)" reads as "2 cached and 7 not", when in fact all 2 were
        # cached and the 7 counts vulnerability records behind them.
        print(
            count_line(
                "components queried",
                len(result.queried),
                f"({result.from_cache} answered from cache)",
            )
        )
        # How much of what was asked came back, by ecosystem. Printed only
        # when a group returned nothing at all: a run every group of which
        # answered has nothing here the counts above do not already say.
        for line in _coverage_lines(quality):
            print(line)
        print(
            count_line(
                "records fetched",
                result.fetched,
                "(vulnerability records downloaded this run)",
            )
        )
    if sbom.excluded_affects:
        print(
            count_line(
                "ruled out",
                len(sbom.excluded_affects),
                "(SBOM asserts the component is not affected)",
            )
        )
    if sbom.unresolved_affects:
        print(
            count_line(
                "unresolved",
                len(sbom.unresolved_affects),
                "(affected component not in this SBOM)",
            )
        )
    if review is not None:
        for line in kev_module.summary_lines(review):
            print(line)

    if result_triage is None:
        return

    print()
    table_module.print_counts(result_triage)

    if brief:
        # Section 6 puts the full brief here and the compact table in the
        # default output. REPORT first: precedence is the same everywhere.
        for item in result_triage.actionable:
            print()
            for line in triage_module.brief_lines(item, sbom):
                print(line)
    elif result_triage.actionable:
        # Section 6's compact table. No blank line above it: the counts are
        # its heading, and a crop that takes the table has to take the verdict
        # with it.
        table_module.print_table(result_triage)

    # After the table rather than between the counts and the table, so that
    # block stays one piece. Printed on every run rather than only under
    # --brief: a determination the reader has to ask for is one they will not
    # see. The operator's own rulings come before the adopted ones, because
    # they are the ones somebody in this room is answerable for.
    for paragraph in triage_module.disposition_lines(
        result_triage
    ) + triage_module.suppression_lines(
        result_triage, requested=provenance.adopt_upstream_vex
    ):
        # A blank line separates blocks, not the rows inside one. The rows
        # and the reason under each of them are a list and have to read as
        # one, or five determinations become five loose paragraphs.
        lead = len(paragraph) - len(paragraph.lstrip(" "))
        if not lead:
            print()
        indent = " " * (lead + 4 if paragraph.startswith("  - ") else lead)
        print(
            textwrap.fill(
                paragraph,
                width=76,
                subsequent_indent=indent,
                break_on_hyphens=False,
                break_long_words=False,
            )
        )

    if not brief and result_triage.actionable:
        print()
        print(
            textwrap.fill(
                f"{len(result_triage.actionable)} item(s) need a decision."
                " Run again with --brief for the full decision brief on each:"
                " where it sits, what it is, who says it is exploited, and the"
                " one question to answer about this product.",
                width=76,
            )
        )



def _match_source(result: MatchResult | None) -> str:
    """Where the vulnerabilities came from, in the unit they are counted in.

    Records, not pairs: the row under this one is pairs and the two numbers
    differ. Both notes are sized to leave the row inside 80 columns, which is
    the width the README block and a pasted terminal are read at.
    """
    if result is None:
        return "records carried by the SBOM, not matched here"
    return "records matched against OSV.dev"


def run() -> None:
    sys.exit(main())
