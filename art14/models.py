"""Data model shared by the parser, the triage logic and the renderers.

The parser produces these and knows nothing about KEV, buckets or output.
Everything here is plain data: no network, no I/O, no formatting decisions
beyond the short labels the table and the brief both need.
"""

from __future__ import annotations

from dataclasses import dataclass

# How a component sits in the dependency graph. Direct dependencies are usually
# reachable and transitive ones often are not, which is the first thing a human
# looks at in an ASSESS decision.
ROOT = "root"
DIRECT = "direct"
TRANSITIVE = "transitive"
UNKNOWN = "unknown"

# Which `component.type` values are not packages.
# A closed set of the things CycloneDX lets a document carry alongside its
# inventory: `file` for the individual files a scanner walked, and the three
# 1.6 additions that describe assets rather than shipped software. Everything
# else is inventory, including a type this build has never seen -- the
# denylist runs this way round on purpose. Excluding a real package
# under-reports silently, which is the failure this rule exists to fix;
# including something package-shaped that is not costs an unmatchable entry in
# the denominator and a worse grade, which is the conservative direction and
# is visible in the banner.
NOT_PACKAGE_TYPES = frozenset(
    {"file", "machine-learning-model", "data", "cryptographic-asset"}
)

# Preference order when an SBOM carries several CVSS ratings for one
# vulnerability. Highest-precedence method that has a score wins.
_CVSS_METHOD_ORDER = ("CVSSv4", "CVSSv31", "CVSSv3", "CVSSv2")


@dataclass(frozen=True)
class Component:
    """One component from the SBOM, addressed by its bom-ref."""

    bom_ref: str
    name: str
    version: str = ""
    purl: str | None = None
    type: str = "library"

    @property
    def label(self) -> str:
        """`name@version`, or just the name when the SBOM omits a version."""
        return f"{self.name}@{self.version}" if self.version else self.name

    @property
    def is_package(self) -> bool:
        """Whether this entry belongs in the inventory that gets graded.

        `syft -o cyclonedx-json` emits one `file` component per file it walked,
        so a 14-package Alpine image arrives as 76 components. Grading those
        would report an 82% unmatchable rate against an inventory that is in
        fact fully matchable.
        """
        return self.type not in NOT_PACKAGE_TYPES


@dataclass(frozen=True)
class Location:
    """Where a component sits relative to the SBOM root component.

    `chain` runs from the root to the component inclusive, along the shortest
    path, and is empty when the component is not in the dependency graph at all.
    """

    kind: str = UNKNOWN
    depth: int | None = None
    chain: tuple[str, ...] = ()

    @property
    def is_direct(self) -> bool:
        return self.kind in (ROOT, DIRECT)

    @property
    def short(self) -> str:
        """Single-character `D/T` column for the compact table."""
        if self.kind == ROOT:
            return "R"
        if self.kind == DIRECT:
            return "D"
        if self.kind == TRANSITIVE:
            return "T"
        return "?"

    @property
    def parent_ref(self) -> str | None:
        """bom-ref of the component this one arrives through, if any."""
        return self.chain[-2] if len(self.chain) >= 2 else None

    def describe(self) -> str:
        """The `Where` line of the decision brief, minus the parent label."""
        if self.kind == ROOT:
            return "the product itself"
        if self.kind == DIRECT:
            return "direct dependency"
        if self.kind == TRANSITIVE:
            return f"transitive, depth {self.depth}"
        return "not in the dependency graph"


@dataclass(frozen=True)
class Rating:
    """One severity rating carried by the SBOM. Context only, never a trigger."""

    method: str | None = None
    score: float | None = None
    severity: str | None = None
    vector: str | None = None
    source: str | None = None


@dataclass(frozen=True)
class VexClaim:
    """A vulnerability's own `analysis` block: the SBOM's verdict on itself.

    This is document level. It says "this vulnerability does not affect this
    product" about the whole SBOM, which is a different assertion from
    `affects[].versions[].status`, which says it about one component and which
    the parser already acts on.

    art14 does not act on this one by default. It is carried, attributed and
    printed, so that a reader can see the claim, see who made it, and see that
    nothing in this run verified it.
    """

    state: str
    justification: str | None = None
    detail: str | None = None
    # Whoever the document says produced it: `metadata.tools` first, then
    # `metadata.authors`. Empty when the SBOM names nobody, which is itself
    # worth printing -- an unattributed claim is a weaker one.
    asserted_by: str = ""

    @property
    def is_not_affected(self) -> bool:
        """The one state that can be adopted.

        The others (`false_positive`, `resolved`, `resolved_with_pedigree`)
        are displayed and never adopted. `resolved` says the vulnerability was
        fixed, which contradicts the version the SBOM itself reports, and
        `false_positive` is a statement about the scanner rather than about
        the product. Neither is a claim this tool can convert into "nothing to
        report" on someone else's behalf.
        """
        return self.state == "not_affected"

    @property
    def asserter(self) -> str:
        """Who to name in the output, never blank."""
        return self.asserted_by or "the SBOM producer (unnamed)"

    def summary(self) -> str:
        """One line: the state, why, and on whose authority."""
        head = self.state
        if self.justification:
            head += f" ({self.justification})"
        return f"{head}, asserted by {self.asserter}"


@dataclass(frozen=True)
class Vulnerability:
    """One `vulnerabilities[]` entry.

    CVEs come from the SBOM. The KEV dump keyed by CVE id decides the bucket
    later; it cannot discover vulnerabilities on its own, so everything the
    decision brief needs -- description, CWEs, CVSS -- has to be picked up
    here.
    """

    id: str
    source_name: str | None = None
    description: str | None = None
    cwes: tuple[int, ...] = ()
    ratings: tuple[Rating, ...] = ()
    # Other ids for the same vulnerability. OSV's own id is often a GHSA while
    # the KEV catalogue keys on CVE ids, so layer 2 looks here as well as at
    # `id` -- discarding aliases would lose the only CVE we have.
    aliases: tuple[str, ...] = ()
    # The upstream record's own `modified` stamp, carried through untouched.
    # art14 holds no vulnerability data of its own, so this is the only honest
    # answer to "how current is this particular record" -- it is upstream's
    # word, not ours. Empty when the SBOM brought the vulnerability with it.
    modified: str = ""
    # bom-refs to triage: the SBOM says affected, says unknown, or says nothing.
    affects: tuple[str, ...] = ()
    # bom-refs the SBOM explicitly asserts are not affected. Never triaged.
    not_affected: tuple[str, ...] = ()
    # The document-level `analysis` block, if there was one. Distinct from
    # `not_affected` above in both scope and consequence: that one is per
    # component and is acted on here; this one covers the vulnerability and is
    # acted on only when the operator says so on the command line.
    analysis: VexClaim | None = None

    @property
    def cve_ids(self) -> tuple[str, ...]:
        """Every CVE id this vulnerability is known by, `id` first if it is one.

        The KEV lookup in layer 2 needs a CVE and OSV frequently hands us a
        GHSA, so both ends are checked rather than assuming the shape of `id`.
        """
        candidates = (self.id, *self.aliases)
        return tuple(
            dict.fromkeys(c for c in candidates if c.upper().startswith("CVE-"))
        )

    @property
    def severity(self) -> str | None:
        """The qualitative band, where any rating carries one.

        Separate from `cvss` because the two come from different places and
        one of them is usually missing: OSV publishes a vector and no number,
        so the score is absent on most of this tool's main path while the word
        is there. Whoever published the record chose the word; art14 neither
        computes it from a vector nor rewrites it into another scale's
        vocabulary.
        """
        for rating in self.ratings:
            if rating.severity:
                return rating.severity
        return None

    @property
    def vector(self) -> str | None:
        """The CVSS vector, where any rating carries one.

        Its own property for the same reason `severity` is: on this tool's
        main path the number is missing and the vector is what is there, and
        the two views that show severity have to show the same thing. art14
        does not compute a score from it.
        """
        for rating in self.ratings:
            if rating.vector:
                return rating.vector
        return None

    @property
    def cvss(self) -> Rating | None:
        """Best available CVSS rating, by method precedence then by score."""
        scored = [r for r in self.ratings if r.score is not None]
        if not scored:
            return None

        def rank(rating: Rating) -> tuple[int, float]:
            method = (rating.method or "").replace(".", "")
            try:
                order = _CVSS_METHOD_ORDER.index(method)
            except ValueError:
                order = len(_CVSS_METHOD_ORDER)
            return (order, -(rating.score or 0.0))

        return sorted(scored, key=rank)[0]


@dataclass(frozen=True)
class Finding:
    """A (vulnerability, component) pair -- one row of the compact table.

    One CVE can affect several components, so findings are the unit that gets
    counted and bucketed. Counting vulnerabilities instead would make the
    summary line disagree with the rows above it.
    """

    vulnerability: Vulnerability
    component: Component
    location: Location = Location()


# eq=False: the `locations` dict would otherwise give this a generated
# __hash__ that raises on use.
@dataclass(frozen=True, eq=False)
class Sbom:
    """Everything the parser extracts from one CycloneDX document."""

    spec_version: str
    root: Component | None
    components: tuple[Component, ...]
    vulnerabilities: tuple[Vulnerability, ...]
    locations: dict[str, Location]
    findings: tuple[Finding, ...]
    # (vulnerability id, bom-ref) pairs whose affected component is not in the
    # document. Reported rather than dropped silently: the tool never claims to
    # have seen more than it did.
    unresolved_affects: tuple[tuple[str, str], ...] = ()
    # (vulnerability id, bom-ref) pairs dropped because the SBOM asserts the
    # component is not affected. Counted, not listed: an ASSESS brief for a
    # component the SBOM rules out is exactly the noise this tool exists to
    # discard, but silently losing it would be dishonest.
    excluded_affects: tuple[tuple[str, str], ...] = ()
    # Entries the document carries that are not packages, kept out of
    # `components` so they never reach matching or the quality denominator,
    # and kept here so the run can say how many were set aside and under what
    # rule. They still resolve through `component_by_ref`, so a vulnerability
    # affecting one is reported rather than counted as unresolved.
    non_packages: tuple[Component, ...] = ()

    @property
    def document_components(self) -> int:
        """How many components the document listed, before the type rule."""
        return len(self.components) + len(self.non_packages)

    @property
    def is_pre_enriched(self) -> bool:
        """True when the SBOM already carries vulnerabilities.

        grype, Dependency-Track and cdxgen emit them, and when they are there
        the matching stage is skipped entirely. When they are absent, an empty
        finding list means *not yet matched* -- never that the product is
        clean.
        """
        return bool(self.vulnerabilities)

    def component_by_ref(self, bom_ref: str) -> Component | None:
        for component in self.components + self.non_packages:
            if component.bom_ref == bom_ref:
                return component
        if self.root is not None and self.root.bom_ref == bom_ref:
            return self.root
        return None

    def location_of(self, bom_ref: str) -> Location:
        return self.locations.get(bom_ref, Location())
