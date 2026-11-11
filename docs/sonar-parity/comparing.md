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
  SonarQube analyzes it during a build, with SonarScanner for .NET.
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
- A table per key, most differences first.

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

## Projects

On the comparison server, as of 2026-11-11:

| Project key | What | Commit |
|---|---|---|
| `lvaoliveira_arandu` | arandu (JavaScript) | `ecb5cc9` |
| `sonda` | sonda's own code (TypeScript, Rust, Python scripts), by CI | latest `main` |
| `sonda-compare-cpython-lib` | CPython: 7 packages of `Lib/` | `bf6623a` |
| `sonda-compare-budgetthuis` | ha-budgetthuis-prices (Python) | `f563c0d` |
| `sonda-calibrate-cc` | JavaScript and TypeScript calibration | |
| `sonda-calibrate-py`, `sonda-calibrate-py13`, `sonda-calibrate-py14` | Python calibration | |
| `sonda-compare-commons-lang-3` | Apache Commons Lang (Java 8), compiled first | `5d2715b` |
| `sonda-calibrate-java`, `sonda-calibrate-java-*` | Java calibration | |
| `apiaddicts_apigen.springboot` on SonarCloud | apigen.springboot (Java 21, Spring Boot) | `ef13838` |
| `jinahya_egovframe-common-components-spring-boot` on SonarCloud | eGovFrame common components (Java 17, Spring), with its submodule | `14313bc` |

Next: C# and C++ on public projects that SonarCloud analyzes.
