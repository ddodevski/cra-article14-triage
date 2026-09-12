"""Exceptions used across art14.

Anything raised here is a user-facing error: the CLI catches Art14Error,
prints the message without a traceback, and exits 1.
"""


class Art14Error(Exception):
    """Base class for every error the CLI reports to the user."""


class SbomError(Art14Error):
    """The input file is not an SBOM we can read."""
