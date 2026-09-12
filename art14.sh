#!/usr/bin/env sh
# art14 launcher -- runs the tool without installing anything into your Python.
#
#   ./art14.sh examples/log4j-app.cdx.json
#   syft ghcr.io/acme/gateway:1.4 -o cyclonedx-json | ./art14.sh -
#
# Four ways to run, tried in this order: the environment in .venv/ next to
# this script, if an earlier run built one; an art14 you have already
# installed yourself; `uv`, if it is on PATH; and failing all of those, a
# fresh .venv/ built here. Nothing ever lands in your system or user Python,
# and an environment you already have is used rather than duplicated. Delete
# .venv/ to start over.
#
# Bootstrap chatter goes to stderr, so piping into and out of this script
# stays clean. On Windows, use art14.cmd instead.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
venv="$here/.venv"

# Windows Python -- Git Bash, MSYS, Cygwin -- puts console scripts under
# Scripts/ rather than bin/. Resolve rather than assume, so reaching for
# art14.sh there fails with a real result instead of "No such file".
bindir() {
    if [ -d "$venv/Scripts" ]; then
        printf '%s' "$venv/Scripts"
    else
        printf '%s' "$venv/bin"
    fi
}

entry="$(bindir)/art14"
[ -x "$entry" ] && exec "$entry" "$@"
[ -x "$entry.exe" ] && exec "$entry.exe" "$@"

python=$(command -v python3 || command -v python) || python=""

# Someone who has already run `pip install -e .` has a working art14, and
# building a second copy of it beside the first is surprising rather than
# helpful -- doubly so on Windows, where `art14` typed in this directory
# reaches art14.cmd before it reaches the console script they installed.
# -P keeps the check honest: without it, `import art14` would find the
# source tree next to this script and succeed with no dependencies present.
if [ -n "$python" ] && "$python" -P -c "import art14" >/dev/null 2>&1; then
    printf '%s\n' "art14.sh: using the art14 already installed for $python" >&2
    exec "$python" -m art14 "$@"
fi

if command -v uv >/dev/null 2>&1; then
    exec uv run --quiet --project "$here" art14 "$@"
fi

if [ -z "$python" ]; then
    printf '%s\n' "art14.sh: no python3 on PATH (Python 3.11+ required)" >&2
    exit 1
fi

printf '%s\n' "art14.sh: creating $venv (first run only)" >&2
"$python" -m venv "$venv" >&2
"$(bindir)/python" -m pip install --quiet --upgrade pip >&2
"$(bindir)/python" -m pip install --quiet --editable "$here" >&2

entry="$(bindir)/art14"
[ -x "$entry" ] || entry="$entry.exe"
exec "$entry" "$@"
