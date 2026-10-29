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
```

## Features

- **Rules** for bugs, vulnerabilities and code smells. See [docs/rules.md](docs/rules.md).
- **Metrics**: lines of code, comment lines, functions, cyclomatic and cognitive complexity, and technical debt.
- **Duplication**: token-based copy-paste detection across files.
- **Coverage**: imported from LCOV, which istanbul/c8/vitest, coverage.py, gcov/lcov and llvm-cov all produce.
- **New code**: everything changed since the merge base with a branch (committed or not), plus untracked files. Each issue and metric is reported both overall and for new code, the "clean as you code" approach.
- **Quality gate**: configurable conditions on any metric. Exit code 1 when it fails.
- **Output**: human-readable text, JSON, or SARIF 2.1.0 for GitHub code scanning, GitLab and IDEs.
- **Suppression**: put `// NOSONAR` or `// sonda-ignore` on a line to suppress every issue on it. Put `// sonda-ignore: js/no-var, js/eqeqeq` to suppress only the listed rules.
- **Fast**: files are analyzed in parallel, and `.gitignore` is respected.
- **Deterministic**: the same code and config produce byte-identical reports, whatever the thread count or filesystem order. The one exception is a file that hits its time budget, which is reported as a warning.

## Install

```sh
cargo install --path .
```

## Usage

```sh
sonda scan [PATH]                         # analyze, print a report, exit 1 if the gate fails
sonda scan . --new-code origin/main       # judge only what changed since main
sonda scan . --coverage lcov.info         # import coverage (repeatable)
sonda scan . --format sarif -o sonda.sarif
sonda scan . --format json --only-new     # list only issues on new code
sonda rules                               # list rules
sonda init                                # write a default sonda.toml
sonda -v scan .                           # log progress to stderr (-vv, -vvv for more)
```

Without `--new-code`, the whole project counts as new code.

Exit codes: `0` means the gate passed, `1` means it failed, and `2` means an error (bad config, unknown rule id, git failure, and so on). Use `--no-gate` to always exit 0.

### GitHub Actions

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0            # sonda needs history to find the merge base
- run: cargo install --git <this repo> sonda
- run: sonda scan . --new-code origin/${{ github.base_ref }} --format sarif -o sonda.sarif
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
file_timeout_secs = 10     # per-file parse + rule-matching budget

[rules]
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
```

Gate metrics: `files`, `lines`, `ncloc`, `functions`, `complexity`, `cognitive_complexity`, `issues`, `bugs`, `vulnerabilities`, `code_smells`, `blocker_issues`, `critical_issues`, `major_issues`, `debt_minutes`, `duplicated_lines`, `duplicated_lines_density`, `coverage`. Most also have a `new_` variant for new code only: `new_lines`, `new_issues`, `new_bugs`, `new_vulnerabilities`, `new_code_smells`, `new_blocker_issues`, `new_critical_issues`, `new_major_issues`, `new_debt_minutes`, `new_duplicated_lines`, `new_duplicated_lines_density` and `new_coverage`. A condition on a metric with no data, such as coverage without a report, is shown as "no data" and does not fail the gate.

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

- a server with history, a dashboard, or PR decoration (SARIF upload covers PR annotations on GitHub)
- data-flow or taint analysis: the rules are syntactic, so they are fast and predictable but miss deeper bugs
- SonarQube's rule depth: it ships thousands of rules per language, while sonda currently has 31
- coverage formats other than LCOV (JaCoCo and Cobertura XML are planned)

## Roadmap

- [ ] More rules per language, plus a security hotspot category
- [ ] JaCoCo and Cobertura coverage import
- [ ] Caching, to skip re-analyzing unchanged files
- [ ] Baseline file to accept existing issues without suppressing them line by line
- [ ] Server: store analyses, track trends, web dashboard
- [ ] More languages (Go, Rust, C#, PHP, Ruby, Kotlin)
- [ ] Data-flow analysis for injection-style vulnerabilities

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.
