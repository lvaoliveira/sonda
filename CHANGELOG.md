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
- `sonda-server`, the foundation (ADR-0005):
  - A PostgreSQL schema with migrations.
  - `/api/health`, and serving the web app.
  - Secrets from environment variables or files.
  - A Docker image (distroless, non-root, 69 MB) and a `compose.yaml` that
    runs it with PostgreSQL. See [docs/server.md](docs/server.md).
- `sonda-server` stores uploads (`POST /api/analyses`) and tracks issues
  across a branch's analyses by fingerprint:
  - Issues are new, kept, fixed or reopened.
  - A human status survives moves, fixes and reopening.
  - `sonda upload` prints the counts the server returns.
- `sonda-server` browser sessions and read authorization:
  - `POST /api/session` exchanges the token for an `HttpOnly` session
    cookie.
  - Reads need the token or a session when the server isn't listening on
    loopback only.
  - `GET /api/rules` serves the rule catalog with live open-issue counts
    per rule on each project's main branch.
- `sonda-server` issues API:
  - `GET /api/issues` filters (severity, category, status, component,
    file, assignee, new code), paginates, and counts facets.
  - `GET /api/issues/{id}` adds the rule, the triage history, and the
    surrounding code with syntax highlighting.
  - `PATCH /api/issues/{id}` changes status or assignee and records it.
- `sonda_core::highlight`: a dependency-free syntax highlighter for showing
  code.
- The web app shows real data from `sonda-server`:
  - **Sign-in:** a session cookie the page cannot read.
  - **Issues:** filters, facets and paging done by the server; code,
    history and triage per issue.
  - **Rules:** read-only.

  The Overview stays on sample data under `pnpm dev`, and says it comes
  next when running against the server. The production build no longer
  contains any sample data.
- The Overview is built from real history (`GET /api/overview`):
  - KPIs with trends.
  - Ratings per ADR-0005.
  - Where to focus, issue flow, open issues by severity, and project
    health.
  - Gate history and recent analyses.

  A project's first analysis counts as its baseline. What the server
  doesn't know (teams, coverage when not uploaded, commit messages) is
  shown as such, never invented.
- Users and roles (ADR-0006):
  - **Sign-in:** username and password, with Argon2id hashes.
  - **First admin:** created from `secrets/admin_password` while no users
    exist.
  - **Administration page:** create users, change roles, disable or enable
    them, reset passwords. The last admin is protected.
  - **Account page:** change your own password.
  - **Audit:** triage history records who made each change.

  The API token now serves only machines: uploads and scripts.
- Sign-in throttling: after 5 failed sign-ins for a username in 15 minutes,
  each attempt waits longer, up to 15 minutes (`429` with `Retry-After`).
  Unknown usernames are throttled alike, and refused before hashing.
- Overview drill-downs from real data (`GET /api/drill/{metric}`): each
  metric opens what's behind it, by directory and file, with each file's
  most severe issue. A file opens its issues. Owners and per-file coverage
  are left out rather than invented.
- Owners from CODEOWNERS:
  - `sonda upload` sends the repository's CODEOWNERS file, read
    symlink-safe from GitHub's three locations.
  - Drill-downs show each directory's majority owner, matched with
    GitHub's rules: gitignore patterns, last match wins.
- Compatibility with SonarQube rules, groundwork (ADR-0007, ADR-0008):
  - **Keys:** rules record the SonarQube rule keys they're equivalent to
    (`sonar`), and `docs/rules.md` and `sonda rules --format json` show them.
  - **Compatibility table:** `docs/sonar-parity/` tracks which keys sonda
    covers, kept up to date by `scripts/sonar_parity.py`.
  - **Catalog:** the rule catalog is split per language.
  - **Semantic layer:** ADR-0008 plans scopes, control flow and data flow
    for the rules that need them.

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
