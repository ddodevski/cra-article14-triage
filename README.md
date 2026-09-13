# art14

An SBOM goes in. Out comes the short list of vulnerabilities that need a
reporting decision under Article 14 of [Regulation (EU) 2024/2847][cra], and
a written reason for every one of them.

Article 14 does not turn on severity. What it attaches to is an [actively
exploited vulnerability][cra-reporting]: a CVSS 10.0 that nobody is exploiting
is not that, and a moderate that is being exploited in the wild may be exactly
that. This is the reading art14 is built on, and it is one to check against
[the regulation itself][cra] rather than take from a README. The mistake
runs in both directions -- a queue ordered by severity score reports what it
need not, and misses what it must.

The example in this repository is a Java application with 36 components.
OSV.dev matches 138 vulnerabilities against it. Seven of those are in the
exploited-vulnerability catalogue, and those seven are the ones a person has to
look at. Collapsing 138 to 7, and saying why for each, is the whole tool.

art14 is not a scanner. It never reads images, containers or filesystems.
SBOM in, verdict out.

## What it says

![A run of art14 against the Log4j example SBOM: 36 components, 138
vulnerabilities matched, 136 CVE ids put to the KEV catalogue, 5 of them
listed there, nothing confirmed reportable and 7 items left for a human to
decide](docs/img/01-funnel.svg)

`art14 examples/log4j-app.cdx.json`, with no configuration and no argument
beyond the file:

```
art14 0.1.0 - CycloneDX 1.6 - gateway@3.2.0

input: 36 components - 0 without PURL (0%) - 0 without version
       matching quality: ok - see README
       1 vulnerability with no CVE id - not checkable against the KEV catalogue
result: 0 to report - 7 to assess - 131 not in the KEV catalogue

1 vulnerability carries no CVE id, so the KEV catalogue could not be asked
about it. It is not absent from the catalogue: the question was never put.
Treat it as unassessed for exploitation, exactly as you would an unmatched
component -- not as clear.

  components            36   (read from the SBOM)
  vulnerabilities      138   (records matched against OSV.dev)
  component-CVE pairs  140   (one record can affect several components;
                             several can name one CVE: 139 distinct pairs)
  components queried    36   (36 answered from cache)
  records fetched        0   (vulnerability records downloaded this run)
  CVEs checked         136   (distinct CVE ids put to the EUVD KEV catalogue)
  known exploited        5   (distinct CVE ids listed in the catalogue,
                             across 7 component-CVE pairs)
  not checkable          1   (records with no CVE id; no key to look up)

  REPORT                 0   (component-CVE pairs; the 24h clock is running)
  ASSESS                 7   (pairs in the KEV catalogue; needs a decision now)
  NO                   131   (pairs not in the KEV catalogue)
  unchecked              1   (pairs whose record carries no CVE id)
CVE            | component                     | D/T | bucket | listed by
---------------+-------------------------------+-----+--------+----------
CVE-2022-22965 | spring-boot-starter-web@2.5.6 | D   | ASSESS |      CISA
CVE-2022-22965 | spring-webmvc@5.3.12          | T   | ASSESS |      CISA
CVE-2022-22965 | spring-beans@5.3.12           | T   | ASSESS |      CISA
CVE-2021-45046 | log4j-core@2.14.1             | D   | ASSESS |      CISA
CVE-2021-44228 | log4j-core@2.14.1             | D   | ASSESS |      CISA
CVE-2025-24813 | tomcat-embed-core@9.0.54      | T   | ASSESS |      CISA
CVE-2023-44487 | tomcat-embed-core@9.0.54      | T   | ASSESS |      CISA
D = direct dependency, T = transitive (pulled in by another component)
+ 131 item(s) not in the KEV catalogue

7 item(s) need a decision. Run again with --brief for the full decision
brief on each: where it sits, what it is, who says it is exploited, and the
one question to answer about this product.
```

Exit code 1: seven items are open.

`see README`, here and in the blocks further down, points at [Matching
quality](#matching-quality). Every block on this page is a verbatim copy of a
real run, so they all say what the terminal says.

The 131 in NO are not listed row by row, and never will be. A tool that prints
the other 131 has handed the problem back unsolved.

`gateway@3.2.0` is a constructed example and says so in its own metadata: no
such application exists. Every component and version in it is real, which is
the point -- the vulnerabilities are fetched from OSV.dev when you run it and
are not carried in the file. The KEV hits it is written around were verified
against the live catalogue on 2026-09-12; if an entry is withdrawn later your
run will show fewer rows than this README does, and that is the catalogue
talking rather than a bug.

## Run it

```
git clone https://github.com/ddodevski/cra-article14-triage
cd cra-article14-triage
```

Then, from the root:

```
./art14.sh examples/log4j-app.cdx.json      # Linux, macOS
art14.cmd examples/log4j-app.cdx.json       # Windows
```

Nothing lands in your Python: the launcher finds or builds what it needs beside
itself, and [Installing it](#installing-it) has the rest.

## What it says once somebody has decided

![The same SBOM run against a file of recorded decisions: 1 item to report, 1
left open on purpose, 136 not to report, five of them ruled out in
configuration with the written rationale for each printed under the
table](docs/img/02-decisions.svg)

Run the same SBOM against a file of recorded decisions:

```
art14 examples/log4j-app.cdx.json --config examples/dispositions.toml
```

That file is TOML, and every entry needs a component, a CVE and a rationale:

```toml
[[report]]
component = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
cve = "CVE-2021-44228"
rationale = """
Reachable and confirmed by test. GatewayRequestFilter logs the X-Forwarded-For
header at INFO on every inbound request, the value is attacker-controlled, and
the shipped configuration uses the default PatternLayout with message lookups
enabled (log4j2.formatMsgNoLookups is not set and the JRE is 8u292, below the
com.sun.jndi.ldap.object.trustURLCodebase default change). A JNDI callback was
observed against an internal listener on 2026-09-11. Mitigation in progress;
upgrade to 2.17.1 scheduled, but the product is shipping today.
Decided 2026-09-11 by the platform security team.
"""

[[no]]
component = "pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@9.0.54"
cve = "CVE-2025-24813"
rationale = """
Not reachable. The partial-PUT path requires the default servlet to be running
with readonly=false and either file-based session persistence or a library
that deserialises uploaded content. gateway leaves the default servlet
read-only, has no PUT route, and uses Redis-backed sessions rather than the
FileStore. Confirmed against the packaged conf/web.xml and the session
configuration in application.yml.
Decided 2026-09-11 by the platform security team.
"""
```

```
result: 1 to report - 1 to assess - 136 not to report

  REPORT                 1   (component-CVE pairs; the 24h clock is running)
  ASSESS                 1   (pairs in the KEV catalogue; needs a decision now)
  NO                   136   (pairs not to report)
  of which               5   ruled out in configuration; the reasons are below
  unchecked              1   (pairs whose record carries no CVE id)
CVE            | component                | D/T | bucket | listed by
---------------+--------------------------+-----+--------+----------
CVE-2021-44228 | log4j-core@2.14.1        | D   | REPORT |      CISA
CVE-2023-44487 | tomcat-embed-core@9.0.54 | T   | ASSESS |      CISA
D = direct dependency, T = transitive (pulled in by another component)
+ 136 item(s) not to report

5 item(s) in the KEV catalogue were ruled out in examples/dispositions.toml.
They are in NO on the rationale recorded below, which is the manufacturer's
own determination and not one art14 made or checked. This is the material a
VEX statement and an audit trail are written from.
  - CVE-2022-22965 spring-boot-starter-web@2.5.6
      Precondition not met. Spring4Shell requires the application to be
      deployed as a WAR on a servlet container running on JDK 9 or later.
      gateway ships as an executable jar on the embedded Tomcat and runs on
      JDK 8u292; neither the packaging nor the runtime satisfies the
      exploit. Verified against the built artefact, not against the build
      file, because the two can disagree. Decided 2026-09-11 by the platform
      security team.
  [... four more, each with its own recorded reason ...]
```

Exit code 2: one item is in REPORT. One item is still open on purpose --
CVE-2023-44487 has not been looked at yet, and the configuration says nothing
about it, so it stays visible.

Everything that leaves ASSESS leaves it on somebody's written word, and that
word is printed under the table rather than folded into a count. It is the
material a CSIRT or a market surveillance authority asks for.

## Two runs against a real image

The walkthrough above is a fixture. These two are not: `alpine:3.10`, an image
that went end-of-life in 2021, put through two real scanners. They are here
because they demonstrate opposite halves of the same principle, and because
one of them is what a wrong answer looks like.

Both SBOMs are committed, so both runs reproduce without a scanner or a
daemon: `art14 examples/alpine-3.10-grype.cdx.json` and `art14
examples/alpine-3.10-syft.cdx.json`. The output is the same whether the
document arrives down the pipe or by path, line for line. One exception, in
the second block: the cache count reads `0 answered from cache` until you
have run it once.

### A source that answered

```
$ grype alpine:3.10 -o cyclonedx-json | art14 -
art14 0.1.0 - CycloneDX 1.7 - alpine@3.10

input: 15 package components - 1 without PURL (7%) - 0 without version
       76 entries in the document; 61 are not packages (file) and are not graded
       SBOM quality: degraded - no matching ran here, see README
result: 0 to report - 0 to assess - 125 not in the KEV catalogue

1 of 15 components (7%) have no PURL or no version. This SBOM arrived with
its own vulnerability list, so nothing here was matched by art14 and that
number is not a coverage figure for this run.

It is a statement about the inventory: whatever produced the file may not
have identified those components either, and nothing in the file says
whether it did. Treat them as unverified rather than clean.

  components            15   (of 76 in the SBOM; 61 are not packages)
  vulnerabilities      125   (records carried by the SBOM, not matched here)
  component-CVE pairs  125   (one record can affect several components)
  CVEs checked          65   (distinct CVE ids put to the EUVD KEV catalogue)
  known exploited        0   (distinct CVE ids listed in the catalogue)

  REPORT                 0   (component-CVE pairs; the 24h clock is running)
  ASSESS                 0   (pairs in the KEV catalogue; needs a decision now)
  NO                   125   (pairs not in the KEV catalogue)
```

Grype carried 125 vulnerabilities over 65 distinct CVEs. Every one of them is
real, and not one of them is in the EUVD KEV catalogue: nothing here triggers
an Article 14 reporting obligation. Grype grades the same image 8 critical and
71 high.

Exit code 0: the source answered, the catalogue was asked, and nothing came
back that has to be reported. That is the one code that makes a claim, and
this run is entitled to it.

Both tools are right. That gap is the entire premise: severity ranks work,
exploitation evidence decides what has to be reported, and the second question
is not answered by turning up the first.

### A source that said nothing

```
$ syft alpine:3.10 -o cyclonedx-json | art14 -
art14 0.1.0 - CycloneDX 1.7 - alpine@3.10

input: 15 package components - 1 without PURL (7%) - 0 without version
       76 entries in the document; 61 are not packages (file) and are not graded
       matching quality: degraded - see README
       source coverage: none - nothing came back for any of the 14 queried
result: 0 to report - 0 to assess - 0 not in the KEV catalogue

1 of 15 components could not be matched (7%): no PURL or no version. Those
components are unassessed, not clean.

WARNING: nothing came back for any of the 14 components queried. Their PURLs
are well formed and every lookup completed, so this is not a defect in the
SBOM: it is a question that went unanswered. A source that holds nothing for
an ecosystem and an ecosystem with nothing to report are indistinguishable
from here, and only one of them is a clean result.

This run will not certify that there is nothing to report. Absence of the
signal is not absence of the thing. If this is an OS image, a scanner that
carries its own vulnerability list will answer where OSV did not: `grype
<image> -o cyclonedx-json | art14 -`.

  components            15   (of 76 in the SBOM; 61 are not packages)
  vulnerabilities        0   (records matched against OSV.dev)
  component-CVE pairs    0   (one record can affect several components)
  components queried    14   (14 answered from cache)
  osv coverage           0   (of 14 queried came back with records)
                             pkg:apk/alpine   14 queried, 0 answered
  records fetched        0   (vulnerability records downloaded this run)
  CVEs checked           0   (distinct CVE ids put to the EUVD KEV catalogue)
  known exploited        0   (distinct CVE ids listed in the catalogue)

  REPORT                 0   (component-CVE pairs; the 24h clock is running)
  ASSESS                 0   (pairs in the KEV catalogue; needs a decision now)
  NO                     0   (pairs not in the KEV catalogue)
```

Same image, same 15 packages, and an empty result -- but not a clean one.
Syft emits no vulnerabilities of its own, so art14 asked OSV. All fourteen
`pkg:apk/alpine/...` PURLs are well formed, every lookup completed, and not
one record came back. OSV holds Alpine advisories; that PURL form is not what
reaches them.

An earlier build exited 0 here. Nothing was wrong with the SBOM, so the input
grade had nothing to say, and a question nobody answered was reported as a
negative answer -- on an image the run above finds 65 CVEs in. That is the
exact failure this tool exists to prevent, and it took a real image to find
it: no fixture would have been written with an ecosystem the source is silent
on.

So silence is now its own axis. The run says what came back, by ecosystem,
and refuses to certify an inventory the source answered nothing about: exit
code 1, the same code as an unreachable catalogue and an unmatchable SBOM,
because it is the same thing. A question went unanswered.

Against your own SBOM it is `art14 your-sbom.cdx.json`. If you have an image
and no SBOM, `grype <image> -o cyclonedx-json | art14 -` makes one on the way
through.

## The report

`--report PATH` writes one self-contained HTML file, laid out for A4, for
the reader who decides and will never open a terminal.

![Page one of the report printed to A4: the product gateway@3.2.0, a
provenance block naming the SBOM file, the CycloneDX version, the run
timestamp, the tool version and the age of each cache, and then the funnel --
36 components, 28 with records, 136 CVE ids, 5 known exploited and 1 to
report](docs/img/03-report.svg)

That is page one of five, from the same run as the decision record above:

```
art14 examples/log4j-app.cdx.json \
      --config examples/dispositions.toml --report report.html
```

The verdict, the coverage gate, the decision briefs and the recorded NO
rulings follow on the pages after it.

The file is written alongside whatever else the run prints, and it is
standalone in the literal sense: the stylesheet is inline, the funnel is
inline SVG, there is no JavaScript and nothing is fetched at render time or at
view time, so it opens from a memory stick on a machine with no network and
looks the same in three years. It is made to be printed and attached to an
email, and it carries the provenance block, the funnel, the bucket counts, the
coverage gate above the findings rather than below them, and the full decision
brief for every REPORT and ASSESS item. The NO bucket is one line there too.

It is built from the same document `--json` writes and from nothing else, which
makes it a worked example of that schema for anyone building their own view.
There is no severity chart, no top-N table, no health score and no remediation
advice; severity appears once per brief, as context.

## How it decides

Three stages, and only the third is interesting:

1. **Parse** the CycloneDX document: components, versions, PURLs, and whether
   each component is a direct or a transitive dependency.
2. **Match** components to vulnerabilities with OSV.dev. Skipped entirely when
   the SBOM already carries its own `vulnerabilities` array, as grype,
   Dependency-Track and cdxgen emit.
3. **Judge**: every CVE is put to the EUVD catalogue of known exploited
   vulnerabilities, and the answer decides the bucket.

```
REPORT   the vulnerable functionality is present and reachable in this product
ASSESS   in the exploited-vulnerability catalogue, and nobody has decided yet
NO       not in the catalogue, or decided and ruled out
```

**Nothing promotes itself to REPORT.** A KEV entry means the CVE is exploited
somewhere in the world; it says nothing about whether the vulnerable path is
live in your product, and art14 will not guess. The only thing that moves an
item into REPORT is an entry in `--config` naming the component and the CVE,
with the reason you concluded it is reachable. There is no auto-discovery of
that file either: the command line always records what a verdict rested on.

Being in a catalogue is not the trigger. [Article 3(42)][cra] defines an
actively exploited vulnerability as one for which there is reliable evidence
that a malicious actor has exploited it in a system without permission of the
system owner, and [Recital 68][cra] puts good-faith testing, investigation,
correction and disclosure outside that. A catalogue is a record that somebody
found such evidence. It is not the definition, and it is neither necessary
nor sufficient: exploitation seen only against your own customers is in no
catalogue at all, and a listed CVE in a component whose vulnerable path your
product never reaches is a catalogue hit with nothing behind it. Which is
why the third stage ends in a question rather than a verdict.

Severity is deliberately not in the table. The bucket is the verdict, and a
severity word beside it invites the reader to treat the two as views of the
same thing. Severity is in `--brief` and `--json`, where a reader has already
stopped skimming.

`--brief` prints the full decision brief for every open item:

```
[ASSESS] CVE-2021-44228 - EUVD-2021-34768 - log4j-core@2.14.1

  Where      direct dependency
  What       CWE-20, CWE-400, CWE-502, CWE-917 - Remote code injection in
             Log4j
  Signal     cisa_kev - in catalogue since 2021-12-10
  Question   gateway@3.2.0 depends on log4j-core@2.14.1 directly. Does any
             code path in the product pass untrusted input to it, and is that
             input validated before it reaches the component?

  -> REPORT  if yes, or if it cannot be ruled out. Record it as a [[report]]
             entry for log4j-core@2.14.1, with the reason it is reachable.
  -> NO      if the component is present but the vulnerable path is never
             reached. Record it as a [[no]] entry for log4j-core@2.14.1, with
             the reason it is not: that is your VEX entry and your audit
             trail.

  context    critical - CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H
```

That brief asks a question instead of starting a clock, which is the order
the regulation puts them in. The 24 hours in [Article 14(2)][cra] run from
when the manufacturer became aware, and the Commission's guidance on the CRA
([C(2026) 5252][cra-guidance] of 27 July 2026, paragraph 213) reads becoming
aware as the point at which, after an initial assessment, there is a
reasonable degree of certainty that a vulnerability in the product is being
actively exploited. A catalogue hit is the suspicious event that assessment
starts from. The same guidance is explicit that nothing is retroactive
(paragraph 217): exploitation a manufacturer already knew of before
11 September 2026 is not notifiable. It is also explicit that it binds
nobody (paragraph 8) and that only the Court of Justice can settle the
question -- the same instruction as the one at the top of this page, pointed
at a different document.

### Exit codes

```
2   at least one REPORT item
1   an open ASSESS item, an input that cannot rule out, or an error
0   nothing to report
```

In that order of precedence. A REPORT item always wins: poor SBOM coverage
undermines negative claims, not positive ones.

Exit 0 asserts something, which is why it is the hardest one to get. It is
emitted only when nothing is left open *and* the run can stand behind the
sentence "there is nothing here to report". An SBOM that could not be matched,
one that was never matched, or a run whose catalogue could not be fetched exits
1 with the reason on stdout.

The table above gives exit 1 three causes. For a machine reading the output
there are two cases, and under `--json` stdout is what tells them apart. A run
that got to an answer writes the whole document to stdout -- items left open,
an input it could not match, a catalogue it could not fetch, a confirmation
that matched nothing, each with its reason in the document. A run that died
writes nothing at all to stdout and puts its diagnostics on stderr. There is no
message to parse: JSON on stdout means the run reached a verdict, whether or
not it would certify it, and an empty stdout means it never got that far.

One thing to hold on to when wiring this into CI: a bucket is a statement about
the day it was made. The catalogue changes, and a CVE that is not in it today
can be in it next week with no change to your SBOM at all. Today's NO is not a
permanent NO, and a green pipeline is not a standing clearance.

## Matching quality

The banner grades the input before any verdict is printed, and points here:

```
input: 36 components - 0 without PURL (0%) - 0 without version
       matching quality: ok - see README
```

It answers two questions at once, on one line, because two parallel warning
paths can contradict each other and a reader only has to believe the reassuring
one.

**Did we look at all?** Matching ran, or the SBOM arrived with vulnerabilities
attached, *and* the catalogue could be consulted. A catalogue that could not be
fetched is not an empty catalogue -- every CVE would come back "not listed" --
so a run without one fails closed rather than certifying an inventory as
unexploited.

**Could we have found anything if we had?** That is the grade:

```
ok          every component carries a PURL and a version, and every lookup
            completed. An empty result means something.
degraded    some components could not be matched: no PURL, no version, or a
            lookup that did not complete. They are unassessed, not clean. The
            banner says how many; `--json` names every one of them and why.
unusable    more than half the inventory is in that position. The result table
            is withheld unless something is in REPORT or ASSESS, because a
            table listing only the well-formed minority reads as complete and
            is a false negative.
```

### What gets graded

The grade is computed over the packages in the document, not over everything
the document lists. `syft alpine:3.10 -o cyclonedx-json` emits 76 components
for an image of 14 packages: one `file` entry per file it walked. Those
entries are not packages, nothing can be matched against them, and counting
them reports an 82% unmatchable rate against an inventory that is in fact
fully identifiable -- and then withholds the result on the strength of it.

So `component.type` decides. Four types are not packages and are not graded:
`file`, `machine-learning-model`, `data` and `cryptographic-asset`. Everything
else is inventory, including a type this build has never seen. The rule runs
that way round deliberately: excluding a real package under-reports in
silence, while keeping something package-shaped that is not costs one
unmatchable entry and a worse grade, which a reader can see.

Nothing is set aside quietly. Where the two numbers differ, the banner says
so and names the rule, and the funnel underneath counts the same inventory:

```
input: 15 package components - 1 without PURL (7%) - 0 without version
       76 entries in the document; 61 are not packages (file) and are not graded
       SBOM quality: degraded - no matching ran here, see README

  components            15   (of 76 in the SBOM; 61 are not packages)
```

A document whose entries are *all* non-packages is not an SBOM with nothing
to report. It is an input that cannot be assessed: it grades `unusable`, says
so in those words, and does not exit 0.

**Did the source answer?** The third axis, and separate from the grade on
purpose. A missing PURL is a defect in the SBOM and the fix is to produce a
better one. A well formed PURL that OSV returns nothing for is a defect
nowhere: the identifier is right, the lookup completed, and the source simply
said nothing. Collapsing the second into `degraded` would name the wrong
culprit, and it would let a run whose every answer was silence certify that
there is nothing to report.

```
       source coverage: none - nothing came back for any of the 14 queried

  osv coverage           0   (of 14 queried came back with records)
                             pkg:apk/alpine   14 queried, 0 answered
```

Answer rates are grouped by PURL type, because a total hides the case that
matters: `pkg:apk` answering nothing while `pkg:maven` answers is the same
blind spot over a smaller part of the product. Any silent group is named
whether or not it changes the exit code. If *every* group is silent, the run
cannot support a negative claim and exits 1.

There is no list of ecosystems art14 believes OSV serves. That would be a
second database, it would go stale in silence, and this tool owns none. What
it reports is what happened on this run: this many asked, this many answered.

The grade is named after what it graded. On an SBOM that arrived with its own
vulnerability list, no matching of ours ran, so the same number prints as
`SBOM quality` instead: it still says how identifiable the inventory is,
without claiming a coverage figure for a stage that never happened.

Neither axis can suppress a REPORT item.

## Other ways to run it

```
--brief                 the full decision brief for every REPORT and ASSESS item
--json                  machine readable, for CI and downstream processing
--report PATH           an HTML report to print and file -- see The report
--config PATH           the TOML file of recorded decisions
--adopt-upstream-vex    honour the SBOM's own not_affected claims
--offline               cache only, never open a connection
```

`--json` carries every field the brief carries, so a consumer never has to
reproduce the wording and drift from it, plus a provenance block saying which
sources were consulted, when, and whether from cache or from the network.

`--adopt-upstream-vex` is off by default. Adopting an SBOM's own
`not_affected` claims is a statement that you trust whoever produced it, so it
is a decision made on the command line, and every suppression it causes is
printed with its justification and its author.

Image workflows are served by composition rather than by absorbing a scanner:

```
syft ghcr.io/acme/gateway:1.4 -o cyclonedx-json | art14 -
grype ghcr.io/acme/gateway:1.4 -o cyclonedx-json | art14 -
```

## Installing it

The launchers put nothing in your Python. They try, in order, a `.venv/`
next to the script if an earlier run built one, an `art14` you have already
installed yourself, `uv` if it is on PATH, and failing all of those a fresh
`.venv/` built in place. Delete `.venv/` to start over.

If you would rather install it:

```
pip install -e .
art14 examples/log4j-app.cdx.json
```

`python -m art14 examples/log4j-app.cdx.json` works too, and is the fallback
when a console script is awkward to reach.

Python 3.11 or later. The only dependencies are `httpx` and `rich`.

The first run needs the network: OSV.dev for matching, the EUVD KEV catalogue
for the verdict. Both are public and neither needs a key. Both are cached on
disk, so later runs and `--offline` work without one. The cache lives in
`~/.cache/art14` (`%LOCALAPPDATA%\art14\cache` on Windows), and
`ART14_CACHE_DIR` overrides it, which is what a CI cache restore points at.

## Limitations

Stated openly, because a tool in this position that implies completeness is
worse than no tool.

- **This does not replace a legal assessment of scope.** art14 identifies
  candidates from technical evidence. Whether an obligation applies to your
  product, and what it requires of you, is not a question this tool answers.
- **art14 holds no list of the ecosystems OSV.dev answers on.** A list like
  that is a second database and goes stale in silence. What gets reported is
  the answer rate this run came back with, per PURL type.
- **A source can be silent on an ecosystem, and that is not a clean result.**
  art14 names the silence and will not certify a run nothing answered, but it
  cannot tell you what a source covers -- only what came back. Measured, with
  the output, in [A source that said nothing](#a-source-that-said-nothing).
- **The EUVD exploited list is close to CISA KEV plus a small EU margin.** On
  2026-09-12 the dump this tool reads held 1721 records, of which 1710 carry
  CISA's tag and 11 the EU's alone. CISA's own catalogue that day held 1709
  entries, every one of them already in the dump. VulnCheck
  [found][vulncheck-euvd] the EU list a strict subset of CISA KEV in May 2025;
  the margin has appeared since, and it is small. The list is public and takes
  no key, which is why it is the source here. A CVE absent from it may still be
  exploited in the wild: VulnCheck KEV [says][vulncheck-kev] it carries roughly
  80% more CVEs exploited in the wild than any other public catalogue, and it
  is free to registered community members - but it takes an account and an API
  key, and this tool asks for neither by design. The difference is a rate, not
  a backlog: VulnCheck [counted][vulncheck-2024] 768 CVEs first publicly
  reported as exploited during 2024, against the 186 entries CISA KEV carries
  with a 2024 date. That is more exploitation research, not a queue waiting to
  drain into CISA. Absence of the signal is not absence of the thing.
- **Every result is a point-in-time snapshot.** The catalogue changes daily.
- **Unmatched components are reported, never treated as clean.** So are
  vulnerabilities with no CVE id: they are counted apart and never fall into
  NO, because the catalogue is keyed on CVE and the question was never put.
- **Affectedness is OSV's judgement, not art14's.** Version range arithmetic
  happens upstream, and this tool does not second-guess it. Affected components
  an SBOM names but does not contain are reported rather than dropped.
- **CycloneDX only.** 1.5, 1.6 and 1.7 are read and tested. A later 1.x is
  parsed with a stated caveat rather than refused, because a scanner piping
  into this tool upgrades on its own schedule. 2.x is refused. SPDX is not
  supported.
- **A `[[report]]` or `[[no]]` entry is somebody's word.** art14 records it,
  names the file it came from, prints it in full, and does not check it. The
  same goes for an upstream `not_affected` claim adopted with
  `--adopt-upstream-vex`, which is additionally printed with its author.

## What this is not

Not a scanner, not an SCA platform, not a vulnerability database. It reads no
images, no containers and no filesystems, and it keeps no state beyond an HTTP
cache. Scanning is a solved problem with good tools; this one starts where they
stop.

There are no notification templates here either. What to send, to whom, and
when is not a thing to template out of a repository.

Other CRA tooling bundles the scanner, or files the report for you. This does
neither on purpose: the scan belongs to the tools that already do it well, and
the filing belongs to whoever has to sign it.

## Tests

```
pip install -e ".[dev]"
pytest
```

The suite never opens a connection: the OSV and KEV fixtures are pinned.

## Author

Davor Dodevski - [LinkedIn](https://www.linkedin.com/in/davordodevski/)

Twenty years in engineering and security, including end-to-end CVE triage
ownership for Cisco Webex Meeting Server: thousands of vulnerabilities,
SBOM-based dependency analysis, and the escalate-or-not decision this tool is
built around.

## Licence

MIT. See [LICENSE](LICENSE).

[cra-reporting]: https://digital-strategy.ec.europa.eu/en/policies/cra-reporting
[cra]: https://eur-lex.europa.eu/eli/reg/2024/2847/oj
[cra-guidance]: https://digital-strategy.ec.europa.eu/en/library/commission-publishes-new-guidance-support-timely-cyber-resilience-act-implementation
[vulncheck-euvd]: https://www.vulncheck.com/blog/enisa-euvd
[vulncheck-kev]: https://www.vulncheck.com/kev
[vulncheck-2024]: https://www.vulncheck.com/blog/2024-exploitation-trends
