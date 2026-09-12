"""One shape for the counted lines of the terminal output.

Three modules print them -- the funnel in the CLI, the catalogue's own summary
in `kev`, the buckets in `triage` -- and they are read as a single block: how
many components came in, how many CVEs that made, how many of those the
catalogue knows are exploited, and how few of those need a person. That
narrowing is the entire pitch, and it only reads as a narrowing if the numbers
sit in one column. Padded independently in three files they drift by a digit,
and the shape disappears.

The block also changes unit twice on its way down -- records, then pairs, then
distinct CVE ids, then pairs again -- and every transition is correct and none
of them is obvious. So each gloss names the unit its number is in.
"""

from __future__ import annotations

LABEL_WIDTH = 20
VALUE_WIDTH = 4


def note_line(note: str) -> str:
    """A second line of gloss, aligned under the first one's note column.

    Some glosses have to name two units to be read correctly -- five CVE ids
    across seven component-CVE pairs -- and a number whose unit is guessed is
    worse than one line more of output.
    """
    return f"{' ' * (LABEL_WIDTH + VALUE_WIDTH + 5)}{note}"


def count_line(label: str, value: object, note: str) -> str:
    """`  label   value   note`, with the value right-aligned in its column.

    Right-aligned because the eye compares magnitudes down the column, and a
    four-digit count beside a one-digit one is the comparison this output
    exists to make.
    """
    return f"  {label:<{LABEL_WIDTH}}{value:>{VALUE_WIDTH}}   {note}"
