"""One shape for the counted lines of the terminal output.

Three modules print them -- the funnel in the CLI, the catalogue's own summary
in `kev`, the buckets in `triage` -- and they are read as a single block: how
many components came in, how many CVEs that made, how many of those the
catalogue knows are exploited, and how few of those need a person. That
narrowing is the entire pitch, and it only reads as a narrowing if the numbers
sit in one column. Padded independently in three files they drift by a digit,
and the shape disappears.
"""

from __future__ import annotations

LABEL_WIDTH = 20
VALUE_WIDTH = 4


def count_line(label: str, value: object, note: str) -> str:
    """`  label   value   note`, with the value right-aligned in its column.

    Right-aligned because the eye compares magnitudes down the column, and a
    four-digit count beside a one-digit one is the comparison this output
    exists to make.
    """
    return f"  {label:<{LABEL_WIDTH}}{value:>{VALUE_WIDTH}}   {note}"
