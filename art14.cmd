@echo off
rem art14 launcher -- runs the tool without installing anything into your Python.
rem
rem     art14.cmd examples\log4j-app.cdx.json
rem     syft ghcr.io/acme/gateway:1.4 -o cyclonedx-json | art14.cmd -
rem
rem Four ways to run, tried in this order: the environment in .venv\ next to
rem this script, if an earlier run built one; an art14 you have already
rem installed yourself; `uv`, if it is on PATH; and failing all of those, a
rem fresh .venv\ built here. Nothing ever lands in your system or user Python,
rem and an environment you already have is used rather than duplicated. Delete
rem .venv\ to start over.
rem
rem That second step matters more here than it does on Linux. cmd.exe resolves
rem the current directory before PATH, so someone who ran `pip install -e .`
rem and then typed `art14` from this directory reaches this file rather than
rem the console script they installed. Finding their art14 and using it is the
rem difference between that being invisible and it being a surprise thirty
rem second venv build.
rem
rem Bootstrap chatter goes to stderr, so piping into and out of this script
rem stays clean.
rem
rem This is a .cmd rather than a .ps1 for two reasons: PowerShell scripts do
rem not forward a pipeline to a child process, which would break `syft ... |`,
rem and an unsigned .ps1 in a fresh clone is blocked by the default execution
rem policy. Both work here from cmd.exe and from PowerShell alike.

setlocal enableextensions
set "HERE=%~dp0"
set "VENV=%HERE%.venv"
set "ENTRY=%VENV%\Scripts\art14.exe"

if exist "%ENTRY%" goto :run

call :findpy
if not defined PY goto :try_uv

rem -P keeps the check honest: without it, `import art14` would find the
rem source tree next to this script and succeed with no dependencies present.
"%PY%" -P -c "import art14" >nul 2>&1
if errorlevel 1 goto :try_uv
echo art14.cmd: using the art14 already installed for "%PY%" 1>&2
"%PY%" -m art14 %*
exit /b %ERRORLEVEL%

:try_uv
where uv >nul 2>&1
if errorlevel 1 goto :bootstrap
uv run --quiet --project "%HERE%." art14 %*
exit /b %ERRORLEVEL%

:bootstrap
if not defined PY (
    echo art14.cmd: no python on PATH ^(Python 3.11+ required^) 1>&2
    exit /b 1
)
echo art14.cmd: creating %VENV% ^(first run only^) 1>&2
"%PY%" -m venv "%VENV%" 1>&2 || exit /b 1
"%VENV%\Scripts\python.exe" -m pip install --quiet --upgrade pip 1>&2 || exit /b 1
"%VENV%\Scripts\python.exe" -m pip install --quiet --editable "%HERE%." 1>&2 || exit /b 1

:run
"%ENTRY%" %*
exit /b %ERRORLEVEL%

:findpy
set "PY="
for %%P in (python.exe py.exe) do if not defined PY (
    for /f "delims=" %%I in ('where %%P 2^>nul') do if not defined PY set "PY=%%I"
)
goto :eof
