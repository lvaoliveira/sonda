# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The project uses
[Semantic Versioning](https://semver.org/) for the CLI, the configuration
file, the report formats and the public library API.

## [Unreleased]

### Added

- `sonda scan` analyzes JavaScript/TypeScript, Python, Java and C/C++ with 31
  rules. See [docs/rules.md](docs/rules.md), which shows noncompliant and
  compliant examples for each rule.
- Metrics: lines of code, comment lines, functions, cyclomatic and cognitive
  complexity, technical debt, and cross-file duplication.
- LCOV coverage import (`--coverage`).
- New-code detection against a git reference (`--new-code`), with every
  metric reported both overall and on new code.
- A configurable quality gate (`[[gate.conditions]]`). Exit codes: 0 when the
  gate passes, 1 when it fails, 2 on errors.
- Text, JSON and SARIF 2.1.0 reports; `--only-new` lists only new issues.
- Suppression comments: `NOSONAR`, `sonda-ignore` and
  `sonda-ignore: rule-id, ...`.
- `sonda rules` and `sonda init` commands.
- `-v`/`-vv`/`-vvv` (or `RUST_LOG`) for structured logs on stderr: phase
  timings, counts, and skipped files.
- A library API in the `sonda-core` crate: `sonda_core::run`,
  `sonda_core::load_config`, and `sonda_core::Error`. The `sonda` crate is
  the CLI.
- Files are parsed in worker processes (ADR-0003), so a crash in a
  tree-sitter grammar costs only that file. `--no-isolation` parses
  in-process; `--jobs N` limits parallelism. Overhead measured at +6% on
  29k lines and +1% on 1M lines.
- Analysis workers sandbox themselves (ADR-0004): a seccomp allow-list on
  Linux and Seatbelt on macOS, plus no core dumps and no new file
  descriptors. `--sandbox best-effort|require|off`.
- Rule queries are compiled per language on first use, which made scans of
  a 29k-line JavaScript/C project 40% faster.
- Web app preview (`web/`): Overview, Issues and Rules screens from the
  design handoff, on a typed API contract with mock data. Supply chain: no
  package version younger than 14 days, and `pnpm audit` runs in CI.
- Fuzz targets for analysis in every grammar and for config parsing, run
  weekly in CI with the C grammars instrumented by AddressSanitizer.
- Report fields for tracking issues across scans (ADR-0005): each issue has
  a `fingerprint`, each file a `sha256` of the bytes analyzed, and the JSON
  report has a `report_version` (1). SARIF results carry the fingerprint as
  `partialFingerprints`, so GitHub code scanning follows an issue when its
  line moves.
- `sonda upload` sends a JSON report and the source of every analyzed file
  to a sonda server, gzip-compressed (ADR-0005).
  - Refused before connecting: unsafe paths, files changed since the scan,
    and plain HTTP except to localhost.
  - The token comes from `SONDA_TOKEN` or `--token-file`.

### Security

- The analyzed repository is treated as untrusted. sonda never runs `git diff`
  or other commands that can start programs configured in the repository.
  git is limited to object reads.
- `--new-code` references are validated and passed after `--end-of-options`.
- Deeply nested files can no longer overflow the stack. Each file has a size
  cap and a time budget for parsing and rule matching.
- Control characters and bidi overrides from the repository are escaped in
  text reports, errors and logs.
- Duplication detection was quadratic on repetitive input. A 160 KB file
  that repeated one token took 75 s, and the per-file time budget didn't
  apply. It is now linear: the same file takes 5 ms.

- A file or parent directory swapped for a symlink or FIFO during a scan is
  detected by device and inode and skipped, instead of being followed outside
  the root or hanging the scan (Unix).
- Every git process is killed after `scan.git_timeout_secs` (default 120),
  so a pathological repository can no longer hang `--new-code`.

### Fixed

- When `git cat-file` exited early, its empty answer was read as "blob
  missing", which silently marked files as entirely new code. It is now an
  error.

- A node ending in a line break, such as an unterminated string at the end
  of a file or a C `#include` line, counted the following line as code. In
  a real project this added one line of code to every C file that had a
  blank line after its includes. Found by the new fuzz property test.
