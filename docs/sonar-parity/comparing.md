# Comparing sonda with SonarQube

How sonda's findings are compared with SonarQube's on the same code, and how
a difference is traced to its cause
([ADR-0007](../adr/0007-sonarqube-rule-parity.md),
[release-1.0.md](../release-1.0.md), M4). The results, language by language,
are in [differences.md](differences.md).

The work has three steps: scan a real project with both tools at one
commit, compare the two sets of issues, and classify every difference as a
bug (fixed, with a test), a known gap or a deliberate change. When a
difference isn't explained by reading the code, the fourth step is to
calibrate: measure what SonarQube does on small files, one case at a time.

## What you need

- A SonarQube server and a token that can create projects and run
  analyses. The Community Build covers JavaScript, TypeScript, Python,
  Java, C# and Rust; C and C++ need a commercial edition or SonarCloud.
- SonarSource's scanner, pinned: `npx --yes @sonar/scan@5.0.2`. It needs
  Node.js and downloads a Java runtime on first use. C# is the exception:
  SonarQube analyzes it during a build, with SonarScanner for .NET. A
  container image with the .NET SDK, a Java runtime and the scanner builds
  a calibration project:

  ```dockerfile
  FROM mcr.microsoft.com/dotnet/sdk:8.0
  RUN apt-get update -qq && apt-get install -y -qq openjdk-17-jre-headless
  RUN dotnet tool install --global dotnet-sonarscanner --version 10.3.0
  ENV PATH="${PATH}:/root/.dotnet/tools"
  ```

  and inside it, `dotnet sonarscanner begin /k:KEY /d:sonar.host.url=...
  /d:sonar.token=...`, `dotnet build`, `dotnet sonarscanner end
  /d:sonar.token=...`. The container must reach the server.
- A release build of sonda, from the branch you're checking.

For a public project analyzed on SonarCloud, the server is
`https://sonarcloud.io` and reading issues needs no token, but SonarCloud
must have analyzed the commit you scan. Nothing needs building: the
project's own analysis had its classes. Check the project's quality
profile first (`api/qualityprofiles/search?project=...&organization=...`):
a project with its own profile, or changed rule parameters, measures its
conventions, not the analyzers; pick one on a built-in profile. SonarCloud
runs a newer analyzer than a given SonarQube: where they disagree, measure
the case on your SonarQube, which is the reference. And check whether the
project uses automatic analysis (`autoscanEnabled` in
`api/navigation/component`): without a build, SonarCloud leaves out what
needs a library's types, so rules that need types differ. A project made
of git submodules needs each submodule at the commit the parent pins.

## 1. Scan a project at one commit

Export the commit rather than scanning a working tree, so neither tool sees
uncommitted or ignored files:

```sh
git -C project archive "$SHA" | tar -x -C /tmp/compare/project
```

Give SonarQube a `sonar-project.properties` in the export:

```properties
sonar.projectKey=sonda-compare-project
sonar.sources=src
# Test files: SonarQube runs few rules on them, and the comparison skips them.
sonar.tests=test
# Records the commit, which the comparison checks.
sonar.scm.disabled=true
sonar.scm.revision=<the full SHA>
# Per language, as the project needs:
sonar.python.version=3.13
sonar.java.binaries=target/classes
```

Then scan with both:

```sh
cd /tmp/compare/project
SONAR_TOKEN=... npx --yes @sonar/scan@5.0.2 -Dsonar.host.url=http://sonarqube:9000
sonda scan . -f json -o ../project.json --no-gate --new-code none
```

SonarQube processes the report in the background: wait for the task the
scanner prints (`api/ce/task?id=...`) to be `SUCCESS` before reading
results. Java needs `sonar.java.binaries`, the compiled classes, so build
the project first.

## 2. Compare

```sh
python3 scripts/sonar_compare.py --server http://sonarqube:9000 \
    --token-file ~/.sonar_token --project sonda-compare-project \
    --report ../project.json --sonda ./target/release/sonda \
    --commit "$SHA" --details ../differences.json
```

It pairs issues by file, SonarQube rule key (the keys a sonda rule's `sonar`
field lists) and line, at most one apart (`--tolerance`). The summary has:

- SonarQube's issues sonda also raises, and the ones it doesn't: with the
  sonda rule on, off by default, or no sonda rule at all.
- sonda's issues SonarQube doesn't raise, counted only when SonarQube's
  quality profile has the rule's key active.
- What isn't compared: test files, files SonarQube couldn't parse (it
  indexed them without lines of code), sonda's rules with no SonarQube key
  or whose key is off there.
- For a project in more than one language, both counts per language.
- A table per key, most differences first.

It compares security hotspots too, which the issue search leaves out
(`api/hotspots/search`), and leaves out issues imported from other
analyzers (`external_roslyn:IDE0028` and the like, from .NET's own),
which aren't SonarQube's rules.

Past 10,000 issues, the most one search returns, the script fetches them
language by language, and rule by rule within a language still past it.
SonarCloud gives such a total as 10,000 exactly, and a facet lists 100
values at most, so splitting by rule alone left some out. A key SonarQube
raised on a language's files counts as active there even when the
profile's rule search leaves it out, as SonarCloud's does for a few rules.

`--details` writes every difference with SonarQube's message, for your
review only: the docs describe differences in sonda's own words, and never
copy SonarSource's text. `--commit` warns when SonarQube's last analysis is
of another commit, for instance after CI analyzed a newer one.

## 3. Classify every difference

Read each difference in the source. It is one of:

- **A bug** in sonda: fix it, with a test that pins the case, and a line
  under "Changed rule results" in the changelog.
- **A known gap**: SonarQube needs something sonda doesn't read, such as
  types from another module or a library's signatures.
- **Deliberate**: sonda's rule is narrower or broader on purpose, and says
  why.

Record the result in [differences.md](differences.md): the project, the
commit, both counts, and each remaining difference by kind. Before
publishing a fix, run the comparisons of every language already done, to
see that nothing else moved.

## 4. Calibrate

When the source doesn't explain a difference, measure SonarQube directly.

- **Small files, one case each**, in a project of their own
  (`sonda-calibrate-<language>`). Vary one thing per file: the construct,
  where it sits, what surrounds it. Generate the files with a script, on
  several lines each.
- **Read back** the issues per file (rule key and line) and, for metrics,
  the measures per file (`api/measures/component_tree` with
  `metricKeys=cognitive_complexity`). Compare with sonda using the script
  with `--tolerance 0`, so a position difference shows.
- **Bisect real code** when a small case doesn't reproduce it: split a file
  into one file per top-level definition, or copy a function as it is and
  remove one thing at a time.
- **Read SonarQube's description** of a rule that never fires as expected
  (`api/rules/show?key=python:S7517`): its stated exceptions, and whether
  it is the rule sonda thinks it is. Read it to understand; never copy it.
- **Confirm on the real project.** A calibration file can mislead: an
  undefined base class in a small file behaved differently from a real one
  in CPython.

Pin each measured case in a test, with a comment that it is SonarQube's
behavior on the version measured.

## Things learned

- **Whole blocks, first bindings, inner nodes.** Several differences were
  conventions, not checks: SonarQube judges a block of comment lines as a
  whole, reports a name once where it's first bound, reports the inner
  `if` of two that merge, and the element rather than its attribute.
- **A rule and its metric can differ.** In JavaScript, S3776 scores each
  function on its own, while the file's `cognitive_complexity` counts
  callbacks one level deeper.
- **Analyzers differ by language.** JavaScript's cognitive complexity
  ignores `||`; Python's counts `or`. Measure each language anew.
- **Keys can be wrong.** Three Python rules carried a key whose SonarQube
  rule checks something else; two never matched anything. A rule that
  never matches is worth reading SonarQube's description for.
- **Parse failures.** SonarQube couldn't parse Python 3.15's `lazy import`;
  such files have no lines of code and are left out of the comparison.
- **Minified files.** Both tools skip a JavaScript or TypeScript file whose
  lines average over 200 characters, so a calibration file written on one
  line isn't analyzed.
- **Zero isn't a value.** SonarQube omits a measure that is 0, such as the
  cognitive complexity of a file without branches.
- **Wording counts.** Java's S1133 skips a deprecation whose Javadoc tag
  says what to use instead or when it goes, by matching words in the text.
  Only a series of small files, one wording each, showed it: the elements
  it skipped and the ones it reported looked alike.
- **Calibrating frameworks without building them.** Annotations such as
  Spring's `@Transactional`, Lombok's `@Data` or JUnit's `@Test` can be
  small stub files in their real packages: SonarQube recognizes them by
  name. A library's types go in a jar passed as `sonar.java.libraries`, so
  SonarQube treats them as a library's, not the project's.
- **One per class, or each.** Several rules reported the first member of a
  class where SonarQube reports every field, constructor or label group:
  a calibration file with two of each catches it.
- **Counts.** A rule can report once per pattern in sonda and once per
  occurrence in SonarQube; the comparison counts each issue.
- **Line ends.** A file whose lines end with a carriage return alone is one
  line to a parser that only splits on line feeds: every issue lands on
  line 1. SonarQube counts each carriage return.
- **A key can name another rule.** `js/global-isnan` carried S6679, a
  value compared with itself; SonarQube reported S7773 on the same lines.
  When one side's issues sit exactly where the other's are, under another
  key, read both rules' descriptions.
- **Check what the reference skips.** SonarCloud, with a newer analyzer,
  reported `var` in a few of eGovFrame's files and not in the others;
  SonarQube 26.7 reports every one. A calibration file decides it.
- **Version tags.** SonarQube tags the rules it runs only from a Java
  version, `java9` to `java22` (`api/rules/search?tags=java21`): a
  project's target version leaves them out, so compare with the version
  its build file gives.
- **Once per pattern.** SonarQube reports some regex rules once per
  occurrence: two `[0-9]` in one pattern are two issues, sonda's one.
- **Calibrate the shape, not only the case.** A rule can depend on what
  surrounds the construct: `synchronized` on a field is reported only when
  the class reassigns the field, `SELECT *` only in a string passed to a
  call, `parseInt` only outside a `try` that catches its failure.
- **Libraries by version.** Some Java rules run only when a library of a
  given version is on the classpath, which SonarQube reads from the jar's
  name: S4488 needs `spring-web` 4.3 or later. A calibration jar named
  `stubs.jar` turns such a rule off; name it like the library
  (`spring-web-5.3.30.jar`).
- **Real libraries for C#.** A stub of a logger in its namespace isn't
  enough for C#'s logging rules: they fired only with NLog's and
  Microsoft.Extensions.Logging's packages referenced. A NuGet reference in
  the calibration project gives the real types.
- **Infer, then measure.** A project's own results can say much about a
  rule before calibrating: over Prowlarr's 113 duplicated-string issues,
  none had fewer than four uses or under five characters, and literals
  naming a parameter were never reported. Calibration then confirmed each
  point, and found the one SonarCloud's newer analyzer does differently.
- **Check the fetch.** A first count of eGovFrame's issues stopped at the
  search limit and missed about 500 of them; compare the script's total
  with the project's page in SonarQube.
- **Read the message.** SonarCloud's S1479 issue on Prowlarr said "at most
  30 or have only one statement per case": every 30-case switch measured
  before had one statement per case, so none was reported. The message
  named the condition the calibration had missed.
- **Install what the code imports.** SonarJS reads TypeScript's types,
  for JavaScript too: whether `substr` is deprecated depends on the value
  being a string, a Lodash call on whether its argument is an array, and
  `ReactDOM.findDOMNode` on React's version. A JavaScript calibration
  project has a `package.json` and installs React, PropTypes and Lodash.
  SonarQube skips a large file it takes for a bundle; set
  `sonar.javascript.detectBundles=false` to measure one.
- **C and C++ from SonarCloud only.** SonarQube 26.7's edition here has no
  C/C++ analyzer, so a C++ rule's conditions come from what SonarCloud
  reported on public projects, and didn't, checked across two of them. A
  rule's parameters matter as much as its logic: SonarCloud's message gave
  C++'s cognitive-complexity threshold, 25, away ("from 35 to the 25
  allowed"). Read the issues a rule reports and the ones it leaves out
  side by side before choosing its condition: S3230 looked like "a literal
  in the initializer list" until the misses showed enumerators, `x_()` and
  template parameters, and the extras showed only the first constructor
  counts.
- **Count only compared keys.** A sonda issue on a key the server's profile
  has off isn't a match, even when no difference lists it: eGovFrame's
  SonarCloud profile has S1226 off, so its 147 issues there were never
  compared. Read the summary's "not compared" lines before calling a rule
  calibrated by a project.
- **Rerun after each change.** A rule measured on invented cases can still
  be too broad on the project: an empty class deriving from another was
  reported on SonarQube 26.7, but Prowlarr's twelve new extras all derived
  from abstract classes, which no invented case had. Copying a project's
  own lines into a calibration project is the next check, before calling a
  difference SonarCloud's newer analyzer.

## Projects

On the comparison server, as of 2026-11-11:

| Project key | What | Commit |
|---|---|---|
| `lvaoliveira_arandu` | arandu (JavaScript) | `ecb5cc9` |
| `sonda` | sonda's own code (TypeScript, Rust, Python scripts), by CI | latest `main` (`f9c9bba` in the results) |
| `sonda-compare-cpython-lib` | CPython: 7 packages of `Lib/` | `bf6623a` |
| `sonda-compare-budgetthuis` | ha-budgetthuis-prices (Python) | `f563c0d` |
| `sonda-calibrate-cc` | JavaScript and TypeScript calibration | |
| `sonda-calibrate-js8` to `js13` | JavaScript and TypeScript calibration for Prowlarr's React frontend (`js8` with React, PropTypes and Lodash installed) | |
| `sonda-calibrate-js-browser`, `sonda-calibrate-js-browser2` to `7` | JavaScript calibration: browser scripts, regexes | |
| `sonda-calibrate-py`, `sonda-calibrate-py13`, `sonda-calibrate-py14` | Python calibration | |
| `sonda-compare-commons-lang-3` | Apache Commons Lang (Java 8), compiled first | `5d2715b` |
| `sonda-calibrate-java`, `sonda-calibrate-java-*` | Java calibration (`-egov`, `-egov2`, `-egov3` for eGovFrame's, Java 17) | |
| `apiaddicts_apigen.springboot` on SonarCloud | apigen.springboot (Java 21, Spring Boot) | `ef13838` |
| `Prowlarr_Prowlarr` on SonarCloud | Prowlarr (C#, from a CI build; JavaScript and TypeScript) | `d2d1fc0` |
| `sonda-calibrate-cs1` to `cs15` | C# calibration, built with SonarScanner for .NET (`cs7`, `cs8`, `cs11` to `cs13` with ASP.NET Core, `cs8` with Swashbuckle) | |
| `diegoiast_qutepart-cpp` on SonarCloud | qutepart-cpp (C++, Qt) | `1099377` |
| `dejwk_roo_display` on SonarCloud | roo_display (C++, C) | `f139977` |
| `jinahya_egovframe-common-components-spring-boot` on SonarCloud | eGovFrame common components (Java 17, Spring; browser JavaScript), with its submodule | `14313bc` |

Next: more C++ rules, the most frequent missing keys first (S6022,
S5817, S6177).
