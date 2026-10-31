# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The project uses
[Semantic Versioning](https://semver.org/) for the CLI, the configuration
file, the report formats and the public library API.

## [Unreleased]

### Added

- `sonda scan` analyzes JavaScript/TypeScript, Python, Java and C/C++ with 888
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
- JavaScript/TypeScript: 28 rules equivalent to SonarQube's default-profile
  bugs and vulnerabilities, such as jumps out of `finally`, repeated
  conditions, comparisons with `NaN`, impossible `typeof` results, `.only`
  tests, disabled TLS verification and weak hashes. Each was reviewed for
  false positives on real projects and about 120 MB of third-party
  JavaScript.
- JavaScript/TypeScript: 34 rules equivalent to SonarQube's default-profile
  code smells, such as switch fall-through, empty functions and blocks,
  nested ternaries, labels, legacy octal, `isNaN()`, and bare
  `eslint-disable` comments. The JSX loading/empty/list idiom
  (`{a ? <X/> : b ? <Y/> : <Z/>}`) is not reported as a nested ternary.
- JavaScript/TypeScript: 42 rules equivalent to SonarQube's default-profile
  React, accessibility and test-framework rules: list keys, hook and state
  misuse, legacy React APIs, alt text and link/heading content, assertions
  that can't fail or check the wrong thing, and test-suite structure. JSX
  rules run on `.js`, `.jsx` and `.tsx` files.
- JavaScript/TypeScript: 34 more rules equivalent to SonarQube's
  default-profile bugs and vulnerabilities: unreachable code, infinite
  loops, unsafe optional chaining, misplaced `super()`, recursive accessors,
  weak TLS versions, ciphers, modes and keys, `jwt` with `none`,
  world-writable files, hard-coded passwords and secrets, insecure cookies,
  CORS for every origin, and disabled helmet protections.
- A semantic layer for JavaScript/TypeScript ([ADR-0008](docs/adr/0008-semantic-layer.md),
  phase S1): scopes, declarations and references per file, with hoisting,
  destructuring, imports and TypeScript types. Six rules use it: unused
  local variables and functions, unused imports, reassigned constants and
  imports, redeclared names, and assignments to undeclared names.
  Declaration files (`.d.ts`) are skipped. A file whose model can't be built
  within the per-file timeout keeps its other findings, with a warning.
- JavaScript/TypeScript: six more rules on the semantic layer: a `var` used
  outside the block that declares it, collections that are only added to,
  unused private class fields, and, off by default, unused trailing
  parameters, shadowed variables, and `let` that could be `const`.
- Dependencies (ADR-0009, phase 1): `sonda scan` reads `package-lock.json`
  and `npm-shrinkwrap.json` (v2/v3), `Cargo.lock`, `poetry.lock` (with
  `pyproject.toml` for direct dependencies), `uv.lock` and pinned
  `requirements*.txt`, and lists each pinned package in the JSON report's
  `dependencies` with its package URL, lockfile, whether it's direct, and
  its license where recorded. `sonda sbom` exports them as CycloneDX 1.6
  or SPDX 2.3 JSON, honoring `SOURCE_DATE_EPOCH`. Lockfiles are read
  offline, never by running a package manager; ones sonda recognizes but
  doesn't read yet (pnpm, Yarn, Bun, Go, Gradle) are named in a warning.
- A new code period on the server (ADR-0011): on each project's main
  branch, issues first seen after the period's starting analysis (the
  first, unless an admin moved it) are new, and nothing ages out. The
  server recomputes `is_new`, the new-issue measures, `new_lines` (from
  stored sources) and the gate on each main-branch upload; coverage and
  duplication on new code keep the scan's values. Admins move the start
  from the project page (`PUT /api/projects/{key}/new-code`), audited.
- "Previous version" for the server's new code period:
  `sonda upload --project-version` records the project's version, and on
  the main branch each new version starts a new period at its first
  analysis, unless an admin set the start. `sonda_core::upload::Meta` gains
  a `version` field.
- Per-file coverage: with `--coverage`, each file in the JSON report has
  `coverage` (`covered` and `uncovered` line numbers). The server uses it
  to compute coverage on its main-branch new code period, instead of
  keeping the scan's value, and the Overview's coverage drill-down lists
  each project's least covered files.
- The default gate also fails on `new_severe_vulnerable_dependencies > 0`:
  dependencies a change added or upgraded into with a blocker or critical
  known vulnerability. Without advisory data, dependency conditions are
  `ignored` ("no advisory data") rather than "no data", so projects that
  don't use advisories keep a passing gate, not a partial one. Ignored
  conditions now carry a `reason`. Projects last scanned with an older CLI
  show under a custom gate on the Quality gates page until their next scan.
- Yarn v1's `yarn.lock` is read for the SBOM and vulnerability checks:
  each entry's resolved version, `npm:` aliases as the real package, and
  which packages are direct from the `package.json` next to it. Yarn 2+
  (Berry) lockfiles, which are YAML, are named in a warning.
- The server treats an empty secret variable (`SONDA_TOKEN_FILE: ""`) as
  unset, so a git-ignored `compose.override.yaml` turns the shared token off
  once pipelines use their own tokens (docs/server.md).
- User and analysis tokens, as in SonarQube (ADR-0012): users generate
  user tokens (`sonda_u_`, acting as them), project analysis tokens
  (`sonda_p_`, uploading one project) and global analysis tokens
  (`sonda_a_`, uploading any project) under Account, expiring in 30, 60 or
  90 days or not at all. Secrets are shown once and stored as SHA-256;
  tokens stop when revoked, expired or their owner is disabled; admins see
  and revoke everyone's. Uploads record their token, and actions by token
  are audited as `ada (token ci-shop)`. `SONDA_TOKEN` keeps working and is
  now optional.
- `sonda scan --upload` scans and uploads in one step, with the same
  options as `sonda upload` (checked before the scan starts), and sends
  how long the scan took, which Recent analyses, the analyses list and the
  analysis page show. The report itself doesn't carry it, so it stays the
  same for the same inputs.
- `sonda upload` sends the commit's subject line, read from git's objects
  when `--root` has the commit, and the server shows it in Recent
  analyses, the analyses list and the analysis page (`message`).
- Bun's text `bun.lock` and pipenv's `Pipfile.lock` are read: registry
  packages, aliases resolved, and direct ones from Bun's workspaces or the
  `Pipfile`. Bun's binary `bun.lockb` gets a warning naming
  `bun install --save-text-lockfile`, which writes `bun.lock`.
- `pnpm-lock.yaml` (lockfile versions 5 to 9, pnpm 6 and later) and Yarn
  2+'s `yarn.lock` are read too: registry packages with their versions,
  peer suffixes and aliases resolved, and direct ones from pnpm's
  importers or Yarn's workspaces. Local, git and tarball packages are left
  out with a note. YAML is parsed with `yaml-rust2`'s event parser only:
  aliases are refused, so a hostile lockfile can't expand ("billion
  laughs"), and nesting is capped.
- `new_vulnerable_dependencies` and `new_severe_vulnerable_dependencies`
  gate metrics: vulnerable packages the change brought, compared with the
  lockfiles at the new-code reference (the same advisory on the same
  package at another version isn't new). Each finding in the JSON report's
  `vulnerabilities` has `is_new`. On the server's main branch they're
  computed against the new code period's start.
- Branch and function coverage: `sonda scan --coverage` reads LCOV's
  `BRDA`, `FN` and `FNDA` records into each file's `branch_coverage` and
  `function_coverage` in the JSON report, and the coverage report shows
  Branches and Functions columns and totals, like Istanbul's, and marks the
  lines that left a branch untaken and the functions never called.
- A coverage report in the web app, like an LCOV HTML report: line
  coverage by directory and file, and each file's source with uncovered
  lines in red and a way to step through them. The project page's
  Coverage tile opens it. `GET /api/projects/{key}/coverage` and
  `.../coverage/file?path=` serve it.
- A default for new code (ADR-0010): without `--new-code`, `auto` judges
  what the run changed. In a GitHub Actions pull request, that's against
  its base branch; in a push, the commits it pushed; on a branch with
  commits its default branch lacks, their merge base; otherwise
  uncommitted changes. `scan.new_code` sets it (`auto`, `none` or a ref);
  reports add `new_code_basis` and `new_code_description`. Gates on
  existing projects now judge changes instead of all their debt.
- `sonda upload` reads the token file from `SONDA_TOKEN_FILE` as well as
  `--token-file`, as the server reads its secrets and as docs/server.md
  already said; setting a token file and `SONDA_TOKEN` together is an
  error.
- Gate conditions on vulnerable dependencies: `vulnerable_dependencies`
  and `severe_vulnerable_dependencies` (packages with a blocker or critical
  finding). `sonda scan --advisories DIR` checks dependencies against the
  OSV records in DIR, fills these metrics, and lists the vulnerabilities
  in the report (JSON `vulnerabilities`, a text section); without it they
  have no data. A server with advisories evaluates them itself, reviews
  included, on upload, on advisory import or sync, and on review, and
  stores the result with the analysis.
- Triage of vulnerable dependencies: confirm a finding, or accept it with
  a reason (required), from the Dependencies page or
  `PATCH /api/projects/{key}/dependencies/reviews`. Reviews are per
  project, package and advisory, so they last through rescans; accepted
  findings stay listed but don't count; every change is audited. The
  Security screen adds open vulnerable dependencies across projects, by
  severity, with the most severe and the version that fixes each.
- Opt-in advisory sync: with `SONDA_ADVISORY_SYNC=true` the server fetches
  what changed in OSV daily (OSV's `modified_id.csv`, then only changed
  records from the allowed databases; HTTPS only, no redirects, capped
  sizes; a failed run is retried from where the last complete one ended).
  `sonda-server advisories sync` runs it once, for cron.
  `SONDA_ADVISORY_SYNC_URL` points it at a mirror.
- Known vulnerabilities in dependencies (ADR-0009, phase 3):
  `sonda-server advisories import PATH...` imports OSV records (GitHub,
  RustSec, PyPA and Go advisories; others skipped by license), and each
  dependency is matched against them when read, with each ecosystem's own
  version order (SemVer, PEP 440), so new advisories flag existing
  analyses. Severity comes from the CVSS v3 base score; aliased records
  count once; unparseable versions are reported as unchecked. The
  Dependencies page lists vulnerabilities most severe first with the
  version that fixes each, and filters vulnerable packages; the project
  page counts them. A new `advisory` fuzz target covers the parser and
  version ordering.
- Server and web app (ADR-0009, phase 2): uploads store each analysis's
  dependencies. `GET /api/projects/{key}/dependencies` lists them with
  counts by ecosystem, lockfile and license, and what changed since the
  branch's previous analysis; a project's page summarizes them and links to
  a Dependencies page with search and ecosystem and direct-only filters.
- Security standards: each vulnerability rule (and any other with one)
  records the CWE ids and OWASP Top 10 categories it relates to, in both
  the 2025 and 2021 editions. 2021 categories are as SonarQube reports
  them; 2025 categories follow from the rule's CWE ids and OWASP's list of
  the CWEs each 2025 category covers. `sonda rules` shows them (JSON `cwe`,
  `owasp_2025` and `owasp_2021`); SARIF reports carry them as CWE and OWASP
  Top 10 (2025 and 2021) taxonomies with rule relationships, plus
  `external/cwe/cwe-NNN` tags for GitHub code scanning. In the web app,
  rules are searchable by `cwe-89`, `owasp-a05` (2025) or `owasp2021-a03`
  and show their standards, the Security screen groups open
  vulnerabilities by OWASP category (2025 by default, 2021 on request),
  and each finding to fix first shows its CWE ids.
  `scripts/sonar_parity.py` reports where they differ from SonarQube's.
- Rules can be off by default, like rules outside SonarQube's default
  profile: `rules.enabled` in sonda.toml turns them on. `sonda rules`, the
  JSON catalog (`on_by_default`), docs/rules.md and the web app's Rules page
  mark them.
- Vulnerability rules skip test files (`*.test.*`, `*.spec.*`, `test_*.py`,
  `*_test.*`, and `test`, `tests`, `__tests__`, `spec` or `__mocks__`
  directories), where credentials and weak settings are fixtures.
- Web app: the Projects screen lists every project with its gate, score,
  ratings, coverage, duplication, issues and size, filtered by gate,
  language and name (kept in the URL). A project's page shows its gate
  conditions, measures overall and on new code, its last 12 analyses, and
  its components with owners, per branch. `GET /api/projects` and
  `GET /api/projects/{key}` serve them, and `GET /api/issues` takes
  `project=` and `branch=`.
- Web app: the Quality gates screen shows the gates projects use, read-only:
  projects with the same `sonda.toml` conditions share one, and sonda's
  default is recognized. Each gate shows its conditions with how many
  projects fail each now, its projects, its last 40 evaluations and its
  most common failure, and the `sonda.toml` that sets it. `GET /api/gates`
  serves it. Every screen in the design is now built; unknown addresses
  show "Page not found".
- Web app: the Security screen shows open vulnerabilities by severity, the
  ten to fix first, a twelve-week risk trend, affected projects, the
  riskiest components, the most common rules, and time to fix.
  `GET /api/security` serves it. The roadmap now plans CWE/OWASP mapping,
  hotspots and reachability.
- Web app: the Components screen lists every project's top-level directories
  with owners, files, lines, issues and debt, filtered by project, owner
  and search. A component's page shows its open issues, an eight-week trend,
  its CODEOWNERS owners and its files, next to the project's other
  components. `GET /api/components` and
  `GET /api/projects/{key}/components/{component}` serve them.
- Web app: the Analyses screen lists every analysis, newest first, filtered
  by gate and project. An analysis's page shows its gate result, what it
  introduced and resolved, its warnings, its measures, and links to the
  previous and next analyses on the branch. `GET /api/analyses` and
  `GET /api/analyses/{id}` serve them. The Overview's recent analyses and a
  project's history link to them.
- Rules with the same query share one compiled pattern, so the tree is
  matched against it once.
- Rules can report a node inside the one their query captures, so rules
  that match a container (a switch, an object) point at the offending case
  or member.
- JavaScript/TypeScript files that look minified (an average line longer than
  200 characters, as SonarQube decides) are skipped with a warning, like
  `*.min.js` already was by name. `scan.skip_minified = false` analyzes them.
- Each language's rule queries are matched in a single pass over the file
  instead of one pass per rule. With the 28 new rules, a scan of 120 MB of
  JavaScript is 30% faster than before them, and a 20,000-term expression
  that took 6 s now takes 0.4 s.

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

- On the server, `new_vulnerable_dependencies` and its severe variant
  counted every vulnerable dependency as new when the main branch's new
  code period started at an analysis from a CLI that didn't upload
  dependencies yet, so projects older than that failed the default gate.
  The base is now the first analysis of the period that recorded
  dependencies.

- Moving the main branch's new code start on a project page reloaded the
  page into a skeleton and back to the Overall measures, so the admin
  lost the New code view they were acting on. Reloads now keep showing
  the page until the new data arrives. This also fixes an intermittently
  failing web test.

- An issue's details showed only its file name as Location, cut off when
  long. Location now has its own full-width row with the whole path,
  wrapping at slashes, and the line range.

- "Where to focus" called issues first detected in the range "new", which
  disagreed with the gate when a rule added to sonda found them in old
  code. They now read "Detected · 6h ago" and "1 blocker issue detected
  in arandu".

- "Where to focus" on the Overview opened the drawer of every blocker and
  critical issue for an item about specific new issues. It now opens the
  Issues page filtered to them (project, branch, severity, and file when
  they share one), with the first one open. The Issues page reads `sev=`
  and `issue=` from its URL for this.

- Gates with fewer than 20 new lines no longer fail, or stay "partial",
  on coverage and duplication of new code: those conditions are
  `ignored`, as in SonarQube, in the CLI and on the server, and the report,
  the project page and `sonda scan`'s text say so. A two-line change with
  one uncovered line used to fail at 50% coverage; a main branch with no
  new lines showed "partial" for lack of coverage on new code.

- The Overview's key metrics were colored by their trend only, so with no
  change every tile was green, even a 0% gate pass rate. Each tile is now
  colored by how its value stands (`tone` in `GET /api/overview`), and the
  delta keeps the trend's color, gray when unchanged.

- On the server's main-branch new code period, an issue first seen after
  the start no longer counts as new unless its line changed since then.
  Rules added in a sonda release made old, untouched code fail the gate
  with "new" issues.

- When `git cat-file` exited early, its empty answer was read as "blob
  missing", which silently marked files as entirely new code. It is now an
  error.

- A node ending in a line break, such as an unterminated string at the end
  of a file or a C `#include` line, counted the following line as code. In
  a real project this added one line of code to every C file that had a
  blank line after its includes. Found by the new fuzz property test.
