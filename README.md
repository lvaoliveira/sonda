# sonda

Open-source static analysis and quality gates, in the spirit of SonarQube, as a single fast binary.

sonda scans JavaScript/TypeScript, Python, Java and C/C++ code for bugs, vulnerabilities and code smells. It measures size, complexity, duplication and coverage, and fails your CI build when **new code** does not meet your quality gate.

```
$ sonda scan . --new-code origin/main --coverage coverage/lcov.info

src/payments/refund.js
*   42:9    MAJOR     Bug            js/eqeqeq                        Use '===' or '!==' instead.
*   88:3    CRITICAL  Code smell     common/cognitive-complexity      Refactor 'applyRefund' to reduce its cognitive complexity from 23 to the 15 allowed.

Summary (new code = changes since origin/main, marked *)
  Files 170 · Lines of code 29123 · Functions 3836 · Complexity 6756
  Bugs 3 (1 new) · Vulnerabilities 0 (0 new) · Code smells 307 (12 new)
  Duplication 1.6% · Coverage 71.3% (new code 84.0%) · Debt 8d 4h

Quality gate: FAILED
  ✗ fails if new_bugs > 0 (actual: 1)
  ✓ fails if new_vulnerabilities > 0 (actual: 0)
  ✓ fails if new_coverage < 80 (actual: 84)
  ✓ fails if new_duplicated_lines_density > 3 (actual: 0.4)
  – fails if new_severe_vulnerable_dependencies > 0 (actual: no data, ignored: no advisory data)
```

## Features

- **Rules** for bugs, vulnerabilities and code smells. See [docs/rules.md](docs/rules.md).
- **Metrics**: lines of code, comment lines, functions, cyclomatic and cognitive complexity, and technical debt.
- **Duplication**: token-based copy-paste detection across files.
- **Coverage**: imported from LCOV, which istanbul/c8/vitest, coverage.py, gcov/lcov and llvm-cov all produce.
- **New code**: everything changed since the merge base with a branch (committed or not), plus untracked files. Each issue and metric is reported both overall and for new code, the "clean as you code" approach.
- **Quality gate**: configurable conditions on any metric. Exit code 1 when it fails.
- **Output**: human-readable text, JSON, or SARIF 2.1.0 for GitHub code scanning, GitLab and IDEs. Security rules carry their CWE ids and OWASP Top 10 categories.
- **Dependencies (SBOM)**: the packages a project's lockfiles pin (`package-lock.json`, `yarn.lock` (Yarn 1 to 4), `pnpm-lock.yaml`, `bun.lock`, `Cargo.lock`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, pinned `requirements*.txt`), in the JSON report and exportable as CycloneDX 1.6 or SPDX 2.3 with `sonda sbom`. Read offline; no package manager runs. With `--advisories DIR` (an unzipped OSV export), they're checked against known vulnerabilities, listed in the report, and counted in the `vulnerable_dependencies` and `severe_vulnerable_dependencies` gate metrics, and in their `new_` variants for the ones the change brought, compared with the lockfiles at the new-code reference; a sonda server checks them continuously ([ADR-0009](docs/adr/0009-dependencies-and-advisories.md)).
- **Suppression**: put `// NOSONAR` or `// sonda-ignore` on a line to suppress every issue on it. Put `// sonda-ignore: js/no-var, js/eqeqeq` to suppress only the listed rules.
- **Fast**: files are analyzed in parallel, and `.gitignore` is respected.
- **Deterministic**: the same code and config produce byte-identical reports, whatever the thread count or filesystem order. The one exception is a file that hits its time budget, which is reported as a warning.

## Install

```sh
cargo install --path crates/sonda
```

## Usage

```sh
sonda scan [PATH]                         # analyze, print a report, exit 1 if the gate fails
sonda scan . --new-code origin/main       # judge only what changed since main
sonda scan . --coverage lcov.info         # import coverage (repeatable)
sonda scan . --format sarif -o sonda.sarif
sonda scan . --format json --only-new     # list only issues on new code
sonda scan . --advisories osv/            # also check dependencies against OSV records in osv/
sonda sbom . -o sbom.cdx.json             # SBOM of the lockfiles' dependencies (CycloneDX)
sonda sbom . --format spdx                # the same as SPDX 2.3 JSON
sonda rules                               # list rules
sonda init                                # write a default sonda.toml
sonda -v scan .                           # log progress to stderr (-vv, -vvv for more)
sonda scan . --jobs 4                     # limit parallelism (default: every CPU)
sonda scan . --sandbox require            # refuse to scan if workers cannot be sandboxed
sonda scan . --no-isolation               # parse in-process (debugging); see SECURITY.md
sonda upload report.json --server https://sonda.example.com \
  --project payments --branch main --commit "$GITHUB_SHA"   # token from SONDA_TOKEN or SONDA_TOKEN_FILE
                                          # --project-version 2.3.0: a new version starts a new code period
sonda scan . --upload --server https://sonda.example.com \
  --project payments --branch main --commit "$GITHUB_SHA"   # both at once, recording the scan's duration
```

Without `--new-code`, sonda picks what new code is compared with ([ADR-0010](docs/adr/0010-default-new-code.md)): in a GitHub Actions pull request, its base branch; in a push, the commits it pushed; on a branch with commits its default branch lacks, their merge base; otherwise (a local run on `main`, say) uncommitted changes. The report says which it used. `--new-code none` (or `scan.new_code = "none"`) counts the whole project as new code.

Each issue in a JSON or SARIF report has a `fingerprint` that stays the same across scans while the flagged line's text does not change, even if the line moves or is re-indented. Each file in a JSON report has the `sha256` of the bytes analyzed and, with `--coverage`, its `coverage` as `covered` and `uncovered` line numbers, its `branch_coverage` (`line`, `taken`, `total`) and its `function_coverage` (`name`, `line`, `calls`) when the LCOV report has branch and function records. The JSON format is versioned by `report_version`. Its `dependencies` list each package's ecosystem, name, version, package URL, lockfile, whether it's direct where the lockfile says, and its license where recorded. `sonda sbom` stamps the SBOM with the current time, or with `SOURCE_DATE_EPOCH` when set, for reproducible output.

Exit codes: `0` means the gate passed, `1` means it failed, and `2` means an error (bad config, unknown rule id, git failure, and so on). Use `--no-gate` to always exit 0.

### Server

`sonda-server` keeps analyses over time and serves the web app:
- the Overview and its drill-downs;
- issues with triage;
- the rule catalog;
- users with roles.

It runs with Docker Compose, as a `sonda` container plus PostgreSQL. See
[docs/server.md](docs/server.md).

### GitHub Actions

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0            # sonda needs the base branch or the pushed range
- run: cargo install --git <this repo> sonda
- run: sonda scan . --format sarif -o sonda.sarif   # new code: the PR's or the push's changes
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: sonda.sarif
```

## Configuration

`sonda.toml` in the project root (or `--config FILE`). Run `sonda init` for a commented default. Unknown keys, rule ids and metrics are errors, not ignored.

```toml
[scan]
exclude = ["**/node_modules/**", "**/dist/**", "**/*.min.js"]
max_file_size_kb = 1024    # larger files are skipped with a warning
skip_minified = true       # skip JS/TS that looks minified (average line > 200 chars)
file_timeout_secs = 10     # per-file parse + rule-matching budget
git_timeout_secs = 120     # each git process used for new code
new_code = "auto"          # or "none", or a git ref such as "origin/main" (ADR-0010)

[rules]
enabled = ["js/prefer-const"]   # rules that are off by default (`sonda rules` marks them)
disabled = ["js/no-console"]

[rules.severity]
"common/function-length" = "minor"

[thresholds]
cognitive_complexity = 15
function_lines = 80
parameters = 7

[duplication]
min_tokens = 100
min_lines = 10

[[gate.conditions]]
metric = "new_bugs"        # fail when new_bugs > 0
op = "gt"
threshold = 0

# Optional: fail on any dependency with a known blocker or critical
# vulnerability, not only the ones a change brought (the default gate's
# new_severe_vulnerable_dependencies). Needs advisory data: `--advisories DIR`,
# or a server with advisories.
[[gate.conditions]]
metric = "severe_vulnerable_dependencies"
op = "gt"
threshold = 0
```

Gate metrics: `files`, `lines`, `ncloc`, `functions`, `complexity`, `cognitive_complexity`, `issues`, `bugs`, `vulnerabilities`, `code_smells`, `blocker_issues`, `critical_issues`, `major_issues`, `debt_minutes`, `duplicated_lines`, `duplicated_lines_density`, `coverage`. Most also have a `new_` variant for new code only: `new_lines`, `new_issues`, `new_bugs`, `new_vulnerabilities`, `new_code_smells`, `new_blocker_issues`, `new_critical_issues`, `new_major_issues`, `new_debt_minutes`, `new_duplicated_lines`, `new_duplicated_lines_density` and `new_coverage`. For dependencies: `vulnerable_dependencies` and `severe_vulnerable_dependencies` (packages with a blocker or critical known vulnerability), and `new_vulnerable_dependencies` and `new_severe_vulnerable_dependencies` (those whose finding wasn't there at the new-code reference: added, or moved into an affected version), which have data only when checked against advisories. Each finding in the report's `vulnerabilities` says whether it's new (`is_new`). A condition on a metric with no data, such as coverage without a report, is shown as "no data" and does not fail the gate. Some conditions are "ignored" instead, with the reason, and don't fail it either: as in SonarQube, with fewer than 20 new lines, those on `new_coverage`, `new_duplicated_lines` and `new_duplicated_lines_density` (one uncovered line in a two-line change is 50% coverage); and without advisory data, those on dependencies. The default gate fails on new bugs, new vulnerabilities, coverage of new code below 80%, duplication of new code above 3%, and new dependencies with a blocker or critical known vulnerability.

## Web app (preview)

[`web/`](web/) is the Sonda web app, built from the design handoff in
[`docs/designs/`](docs/designs/). Overview, Issues and Rules are done so far.
It runs against a typed API contract with mock data until `sonda server`
exists. See [web/README.md](web/README.md).

## How it works

Each file is parsed with [tree-sitter](https://tree-sitter.github.io/). sonda
runs the rules' queries and structural checks on it and collects metrics and
tokens. Duplication is then detected across all files, new code is computed
from git, and everything is combined into measures and a quality gate.
[ARCHITECTURE.md](ARCHITECTURE.md) describes the pipeline and the layers.

## Security

sonda treats the repository it analyzes as untrusted input:
- It never runs code from the repository, and it only asks git to read
  objects.
- One file can't crash or stall a scan.
- Symlinks are not followed.
- Control characters from the repository are escaped before they reach your
  terminal.

In CI, load `sonda.toml` from a trusted place so a pull request can't weaken
its own gate. [SECURITY.md](SECURITY.md) has the threat model, the known
limitations, and how to report a vulnerability.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), including [how to add a rule](CONTRIBUTING.md#adding-a-rule). Changes are listed in [CHANGELOG.md](CHANGELOG.md).

## Compared with SonarQube

sonda covers SonarQube's core loop: analyze, measure, judge new code, and gate the build. It does not (yet) have:

- PR decoration (SARIF upload covers PR annotations on GitHub), single sign-on, or several of the server's screens yet (see [docs/roadmap.md](docs/roadmap.md))
- data-flow or taint analysis: the rules are syntactic, so they are fast and predictable but miss deeper bugs
- SonarQube's rule depth: it ships thousands of rules per language, while sonda currently has 31
- coverage formats other than LCOV (JaCoCo and Cobertura XML are planned)

## Roadmap

- [ ] An equivalent for every SonarQube rule key in the supported languages ([ADR-0007](docs/adr/0007-sonarqube-rule-parity.md); progress in [docs/sonar-parity/](docs/sonar-parity/README.md))
- [ ] JaCoCo and Cobertura coverage import
- [ ] Caching, to skip re-analyzing unchanged files
- [ ] Baseline file to accept existing issues without suppressing them line by line
- [x] Server: store analyses, track trends, web dashboard, users and roles
- [ ] Single sign-on (OpenID Connect): designed, deferred ([docs/roadmap.md](docs/roadmap.md))
- [ ] More languages (Go, Rust, C#, PHP, Ruby, Kotlin)
- [ ] Data-flow analysis for injection-style vulnerabilities

Smaller deferred items, with why each waits, are in [docs/roadmap.md](docs/roadmap.md).

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.

