"""The compact table: the default terminal view, one row per decision.

Grouped by bucket, REPORT first, then ASSESS, then a single summary row for
NO. NO is never listed row by row: the whole point of the demo is that a few
hundred findings collapse to a handful that need a person, and printing the
other few hundred destroys it. The summary row is still there rather than
omitted, because a table that ends after the actionable rows reads as if
nothing else was looked at.

The row is `CVE | component@version | D/T | bucket | listed by`. There is no
severity column: the bucket is the verdict, and a severity word beside it
invites the reader to treat the two as views of the same thing, which is the
reflex this tool exists to break. It also cost the component column eight
characters, and the row it truncated was the one direct dependency in the
walkthrough's ASSESS block -- the row the table most wants read. Severity
stays in `--brief` and `--json`, where a reader has already stopped skimming.

The table is presentation and nothing else. Every value it shows is derived in
`triage`, so the same run through `--brief` or `--json` says the same thing,
and a column that has to truncate truncates only what the other two views
carry in full.
"""

from __future__ import annotations

import shutil
import sys
from dataclasses import dataclass

from rich import box
from rich.console import Console
from rich.table import Table

from .triage import ASSESS, NO, REPORT, Item, Triage, counts, no_label

# The default is designed for 100 columns and verified at 80. The constraint
# is not the developer's terminal, it is the screenshot: the README image and
# the post it gets embedded in are read at a few hundred pixels on a phone, and
# a table that filled a 200-column terminal would be unreadable in the one
# place most people meet this tool first. So a wide terminal is allowed to give
# the component column more room, up to a point, and a narrow one is never
# required to have more than it has.
TARGET_WIDTH = 100
MIN_WIDTH = 60
MAX_WIDTH = 120

# Catalogue ids are machine-shaped; the column is eight characters wide and
# the reader needs to recognise the authority, not the field name.
SOURCE_LABELS = {"cisa_kev": "CISA", "eu_kev": "EU"}

BUCKET_STYLES = {REPORT: "bold red", ASSESS: "yellow"}

# CVE, D/T, bucket, listed by and the padding between them. Everything left
# over goes to the component, which is the only column whose content has no
# fixed size.
FIXED_COLUMNS = 48

# What the D/T column means, long form and short. Everything else in the
# output that is not self-evident carries a parenthetical gloss; two bare
# letters in a column heading were the one thing that did not. The short forms
# exist so a table carrying all four kinds still explains itself on one line
# rather than wrapping into the prose below it.
DEPENDENCY_GLOSS = {
    "R": ("R = the product itself", "R = the product"),
    "D": ("D = direct dependency", "D = direct"),
    "T": ("T = transitive (pulled in by another component)", "T = transitive"),
    "?": ("? = not in the dependency graph", "? = not in the graph"),
}


@dataclass(frozen=True)
class Row:
    """One rendered line. Pure data, so the shape can be tested without rich."""

    cve: str
    component: str
    dependency: str
    bucket: str
    listed_by: str


def rows(result: Triage | None) -> list[Row]:
    """Every actionable item, REPORT first. Precedence is the same everywhere."""
    if result is None:
        return []
    return [_row(item) for item in result.actionable]


def summary_row(result: Triage | None) -> str | None:
    """The one line the NO bucket gets, or None when the bucket is empty.

    It sits under the rows rather than among them because it is an accounting
    line and not a finding, and a reader skimming the bucket column must not
    be able to mistake it for one.
    """
    if result is None or not result.no:
        return None
    return f"+ {len(result.no)} item(s) {no_label(result)}"


def result_line(result: Triage | None) -> str | None:
    """The whole answer in one line, shaped like the `input:` banner above it.

    Colour is not enough on its own. This line is read in a screenshot on a
    light README and in a pasted email, and neither carries the red the
    terminal would have given the REPORT row, so the headline has to be legible
    in plain text. Three numbers, always the same three, always in the same
    order, so that a crop of the first few lines carries the finding.
    """
    if result is None:
        return None
    return (
        f"result: {len(result.report)} to report"
        f" - {len(result.assess)} to assess"
        f" - {len(result.no)} {no_label(result)}"
    )


def dependency_key(result: Triage | None, width: int = TARGET_WIDTH) -> str | None:
    """The gloss for the D/T column, covering only the letters in the table."""
    present = [
        letter
        for letter in DEPENDENCY_GLOSS
        if any(row.dependency == letter for row in rows(result))
    ]
    if not present:
        return None
    line = ""
    for form in (0, 1):
        line = ", ".join(DEPENDENCY_GLOSS[letter][form] for letter in present)
        if len(line) <= width:
            break
    return line


def render_width(terminal: int | None = None) -> int:
    """How wide to draw, given the terminal there is.

    `COLUMNS` is honoured because `shutil` honours it, which is what makes the
    two sizes this was designed against reproducible from a shell.
    """
    if terminal is None:
        terminal = shutil.get_terminal_size(fallback=(TARGET_WIDTH, 24)).columns
    return max(MIN_WIDTH, min(terminal, MAX_WIDTH))


def print_table(
    result: Triage | None,
    *,
    console: Console | None = None,
    width: int | None = None,
) -> None:
    """The default view. Nothing is printed when nothing needs a decision.

    A table whose only row is the NO summary would be a table about the
    absence of work, and the count block above it already said that in a line.
    """
    if result is None or not result.actionable:
        return
    width = render_width(width)
    console = console or make_console(width)
    console.print(_table(result, width, _box_for(getattr(console.file, "encoding", ""))))
    # Both lines belong to the table and both are printed under it, because a
    # screenshot of the table alone is a thing that happens and it has to
    # explain its own columns and account for what is not in it.
    key = dependency_key(result, width)
    if key:
        console.print(f"[dim]{key}[/dim]", soft_wrap=True)
    summary = summary_row(result)
    if summary:
        # Under the table rather than set as its caption: a caption is padded
        # to the table's width, and a line of trailing spaces is the kind of
        # thing that survives into a copy-paste and a screenshot.
        console.print(f"[dim]{summary}[/dim]")


def make_console(width: int | None = None) -> Console:
    """One console for everything this module prints."""
    return Console(file=sys.stdout, width=render_width(width), highlight=False)


def print_result_line(
    result: Triage | None, *, console: Console | None = None
) -> None:
    """The headline, in red when there is something to report."""
    line = result_line(result)
    if line is None:
        return
    console = console or make_console()
    console.print(line, style=_headline_style(result), markup=False, soft_wrap=True)


def print_counts(result: Triage | None, *, console: Console | None = None) -> None:
    """The bucket counts, with REPORT in red when it is not zero.

    Colour is the second signal here and never the only one: the count itself
    says it, and so does the headline above. What the colour buys is the eye
    landing on the verdict rather than on the coverage warning beside it,
    which is loud by design and is about a different question.
    """
    if result is None:
        return
    console = console or make_console()
    for line in counts(result):
        style = (
            _headline_style(result)
            if result.report and line.lstrip().startswith(REPORT)
            else ""
        )
        console.print(line, style=style, markup=False, soft_wrap=True)


def _headline_style(result: Triage) -> str:
    return "bold red" if result.report else ""


def _box_for(encoding: str | None) -> box.Box:
    """Line-drawing characters only where the stream can carry them.

    `art14 sbom.json > report.txt` on a Windows console writes through a cp1252
    stream, and a box character there is an exception rather than a smudge.
    Rich substitutes for the legacy console itself; it does not know what a
    redirected file can encode, so this asks.
    """
    try:
        "\u2500".encode(encoding or "utf-8")
    except (LookupError, UnicodeEncodeError):
        return box.ASCII
    return box.SIMPLE


def _table(
    result: Triage, width: int = TARGET_WIDTH, style: box.Box = box.SIMPLE
) -> Table:
    # Sized to its contents rather than stretched to the terminal: a table that
    # filled a 200-column window would put the CVE and its bucket at opposite
    # ends of the screen, and the screenshot this becomes is read on a phone.
    lines = rows(result)
    table = Table(
        box=style,
        pad_edge=False,
        show_edge=False,
    )
    table.add_column("CVE", no_wrap=True)
    # The one column that may lose characters, and the one a reader can
    # recover in full from --brief or --json. Letting it wrap instead would
    # put a single finding on two lines and break the scan down the bucket
    # column, which is the column the table exists for.
    table.add_column(
        "component",
        overflow="ellipsis",
        no_wrap=True,
        max_width=_component_width(width),
    )
    table.add_column("D/T", no_wrap=True)
    table.add_column("bucket", no_wrap=True)
    # Right-justified because it is now the last column, and rich pads a
    # left-justified cell out to the column width: "CISA" under a nine-
    # character heading left five trailing spaces on every row, which is
    # exactly the thing a caption was rejected for. It survives a copy-paste
    # into an email and a README code block.
    table.add_column("listed by", no_wrap=True, justify="right")
    for row in lines:
        table.add_row(
            row.cve,
            row.component,
            row.dependency,
            f"[{BUCKET_STYLES[row.bucket]}]{row.bucket}[/]"
            if row.bucket in BUCKET_STYLES
            else row.bucket,
            row.listed_by,
        )
    return table


def _component_width(width: int) -> int:
    """What is left for the component once the fixed columns have theirs."""
    return max(18, width - FIXED_COLUMNS)


def _row(item: Item) -> Row:
    return Row(
        cve=item.cve_id,
        component=item.component.label,
        dependency=item.location.short,
        bucket=item.bucket,
        listed_by=_listed_by(item),
    )


def _listed_by(item: Item) -> str:
    """Which catalogue says so. Never art14's own word for it."""
    entry = item.entry
    if entry is None or not entry.sources:
        return "-"
    return ", ".join(SOURCE_LABELS.get(source, source) for source in entry.sources)
