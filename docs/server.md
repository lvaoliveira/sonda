# Running the sonda server

The server stores analyses uploaded by `sonda upload` and serves the web app
([ADR-0005](adr/0005-sonda-server.md)). It runs as two containers: `sonda`
(the server and the web app) and `db` (PostgreSQL).

**Status:** the server receives uploads, tracks issues across them, has
users with roles, and serves the Overview, issues (with triage) and the rule
catalog. The web app shows all of it: open http://127.0.0.1:9000 and sign in
as `admin`.

## Quick start (Docker Compose)

From the repository root:

```sh
mkdir -m 700 secrets
openssl rand -hex 32 > secrets/db_password
openssl rand -hex 32 > secrets/sonda_token
openssl rand -base64 18 > secrets/admin_password
chmod 644 secrets/*        # the containers read them as non-root users

docker compose up -d --wait
curl http://127.0.0.1:9000/api/health     # {"status":"ok"}
open http://127.0.0.1:9000                # sign in as admin, password in secrets/admin_password
```

`secrets/` is git-ignored, and the directory's `700` mode keeps other users
on the machine out.

- **`secrets/admin_password`:** creates the first user, `admin`, the first
  time the server starts. Add more users under Administration. Once any user
  exists, this file is ignored, so changing it never resets a password.
  Change the admin's password under Account.
- **`secrets/sonda_token`:** the API token `sonda upload` needs:

```sh
export SONDA_TOKEN_FILE=secrets/sonda_token   # or --token-file, or SONDA_TOKEN
```

Stop with `docker compose down`. Data lives in the `pgdata` volume, so it
survives restarts and upgrades. `docker compose down -v` deletes it.

## Uploading analyses

```sh
sonda scan . -f json -o report.json
sonda upload report.json --server http://127.0.0.1:9000 --token-file secrets/sonda_token \
  --project payments --branch main --commit "$(git rev-parse HEAD)"
# sonda: uploaded 170 files for payments/main to http://127.0.0.1:9000: 331 open issues (61 new, 2 fixed)
```

The first upload creates the project. Each upload becomes the branch's
latest analysis, ordered by when it arrives, not by commit date. Issues are
matched to the branch's earlier ones by fingerprint:

- **New:** a fingerprint the branch has not seen.
- **Kept:** an issue still present. It moves to its new line, and its status
  (confirmed, accepted) and assignee stay.
- **Fixed:** an issue missing from the upload.
- **Reopened:** a fixed issue that comes back, with its earlier status.

Branches are tracked separately. Unchanged files are stored once, however
many analyses include them.

`POST /api/analyses` needs `Authorization: Bearer <token>`. It takes the JSON
`sonda upload` sends, gzipped or plain, up to 128 MiB as sent and 800 MiB
uncompressed. It answers `201` with
`{"analysis_id": 2, "issues": {"open": 331, "new": 61, "reopened": 0, "fixed": 2}}`.
A rejected upload stores nothing:

| Status | Meaning |
|---|---|
| `401` | Missing or wrong token. |
| `400` | Not gzip, or not a sonda upload. |
| `413` | Too large, compressed or after decompression. |
| `415` | A `Content-Encoding` other than gzip or identity. |
| `422` | Well-formed but invalid, e.g. a source that doesn't match its SHA-256, an unknown rule, an unsafe path, or an unsupported `report_version`. |

## Users and sign-in

Users and roles are described in [ADR-0006](adr/0006-users.md).

| Role | Can |
|---|---|
| **member** | Read, and triage: status and assignee. |
| **admin** | The same, plus manage users. |

- **Where each credential works:**
  - People sign in with username and password.
  - The API token is for machines: `sonda upload`, and scripts reading or
    triaging with `Authorization: Bearer <token>`. It cannot manage users,
    and it no longer signs browsers in.
- **Who can read:** anyone, while the server listens on loopback only (the
  default without Docker). Otherwise, as in the Docker image, every read
  needs a signed-in user or the token, because the server holds source code.

| Endpoint | |
|---|---|
| `GET /api/session` | `{"user": {...} or null, "authenticated": false, "readsRequireAuth": true}` |
| `POST /api/session` `{"username": "...", "password": "..."}` | `204` and the cookie, or `401` "invalid username or password" |
| `DELETE /api/session` | `204`. Ends the session and clears the cookie. |
| `PUT /api/me/password` `{"current": "...", "new": "..."}` | `204`. Your other sessions end. |
| `GET /api/users`, `POST /api/users`, `PATCH /api/users/{id}` | Admins only. List users; create one; change display name, role, disabled, or reset the password. |

- **Passwords:** at least 12 characters, stored as Argon2id hashes.
- **Failed sign-ins:** every failure gets the same answer after the same
  amount of hashing, so nobody can probe which usernames exist.
- **Throttling:** after 5 failures for a username within 15 minutes,
  further attempts wait 1, 2, 4 ... seconds (up to 15 minutes) and get
  `429` with `Retry-After`. Usernames that don't exist are throttled the
  same way.
- **Users are disabled, never deleted,** so the audit trail keeps their
  names.
- **Ending sessions:** disabling a user or resetting their password signs
  them out everywhere.
- **Lockout protection:** the last active admin cannot be disabled or
  demoted.
- **Audit:** triage changes record who made them, as a username or
  `api-token`.

The cookie is `__Host-sonda_session`: `HttpOnly` (page scripts cannot read
it), `Secure`, `SameSite=Strict`, and valid for 12 hours. The database keeps
only a SHA-256 hash of each session. Browsers treat `http://localhost` as
secure, so signing in works locally without TLS.

## Issues

`GET /api/issues` lists issues, most severe first. By default it covers
each project's main branch. Every filter is optional:

| Parameter | |
|---|---|
| `project`, `branch` | One project; a branch other than its main one |
| `severity`, `category`, `status`, `component` | Comma-separated values; `status` is `open`, `confirmed`, `accepted` or `fixed` |
| `file` | Any part of the path |
| `assignee`, `new=true` | Assigned to someone; on new code only |
| `offset`, `limit` | Paging; `limit` is 1-200, default 50 |

An unknown value or parameter is a `400`, so a typo never looks like "no
issues". The answer holds `total`, the page of `items`, and `facets`: for
severity, category, status and component, the count per value. Each facet
ignores its own selection, so choosing *critical* still shows how many
*major* issues there are. A component is a path's top-level directory, or
`.` for files at the root.

`GET /api/issues/{id}` adds:
- the rule's name, description and examples;
- its triage history;
- the code around the issue, up to 80 lines, as of the latest analysis
  that saw it. Each line is a list of `{text, role}` tokens, so the browser
  needs no highlighter.

The server highlights with a small built-in lexer, not tree-sitter: it
runs on uploaded code inside the server process, where sonda never runs its
C parsers (ADR-0003 keeps them in sandboxed workers).

`PATCH /api/issues/{id}` with `{"status": "confirmed"}` (or `open`,
`accepted`) and/or `{"assignee": "alice"}` (`""` unassigns) changes triage.
Each change is recorded in the issue's history. `fixed` cannot be set: it
is decided by analyses. A change needs the token, or a browser session plus
a `Sonda-Csrf` header.

## Overview

`GET /api/overview?range=7d|30d|90d` (default `90d`) builds the portfolio
from stored analyses.

**Snapshots.** Each chart point is a snapshot: every project's latest
main-branch analysis received by then. Points are daily for 7 and 30 days
and weekly for 90. Points from before any project was analyzed are left
out, so a trend never compares against "nothing existed yet".

**A project's first analysis is its baseline.** Its issues count as open,
but not as introduced or new. Otherwise, uploading an existing project would
look like a flood of new problems. SonarQube does the same.

**Ratings** follow ADR-0005's table:
- **Reliability and Security:** the worst open bug or vulnerability. Issues
  marked *accepted* don't count. None is 5, minor 4, major 3, critical 2,
  blocker 1.
- **Maintainability:** the debt ratio, debt ÷ (lines of code × 30 min):
  ≤ 5% is 5, ≤ 10% 4, ≤ 20% 3, ≤ 50% 2, otherwise 1.
- **Coverage:** ≥ 80% is 5, ≥ 70% 4, ≥ 60% 3, ≥ 50% 2, otherwise 1. With
  no coverage uploaded, the level is null ("no data"), never a guess.
- **Portfolio:** each dimension is the average of the project levels,
  weighted by lines of code. Its score is that level scaled to 0-100. The
  health score is the average of the dimensions that have data.

**Key metrics** each carry a `tone` for how the value stands, whatever
its trend, and the page colors the tile by it (the delta beside it is the
trend: green improving, red worsening, gray unchanged):
- **Gate pass rate:** ≥ 90% ok, ≥ 60% warn, otherwise crit.
- **Critical issues and vulnerabilities:** ok at 0, otherwise crit.
- **Coverage:** ≥ 80% ok, ≥ 60% warn, otherwise crit, as the coverage bars
  color it.
- **Duplication:** ≤ 3% ok (the default gate's limit on new code), ≤ 5%
  warn, otherwise crit.
- **Technical debt:** the maintainability bands: ratio ≤ 5% ok, ≤ 20%
  warn, otherwise crit.
- `neutral` without data.

**Where to focus** lists two kinds of items, most severe first:
- projects whose main branch fails its gate, with the number of
  consecutive failing analyses;
- blocker or critical issues first detected in the range, per project,
  opening the Issues page on them. "Detected", not "new": a rule added
  to sonda finds issues in old code too, and those aren't new code for
  the gate (see "New code on the main branch").

**What the server doesn't know** is null, and the page leaves it out:
- teams, so the response says `teams: false` and the "My team" scope is
  not offered;
- components;
- commit messages and scan durations;
- the change in health score, which would need ratings history.

## Drill-downs

`GET /api/drill/{metric}`, for `gate`, `critical`, `vulns`, `coverage`, `dup`
or `debt`, is what's behind one Overview metric. It's grouped by component
(a project's top-level directory) and then by file, from each project's main
branch. Accepted issues don't count.

| Metric | Components by | Files show |
|---|---|---|
| `critical`, `vulns` | open blocker and critical issues, or vulnerabilities | count, and the most severe issue |
| `debt` | hours of fix effort | effort, and the most severe issue |
| `gate` | failed conditions, per project failing its gate | files with the most new issues |
| `dup` | share of duplicated lines | duplicated share per file |
| `coverage` | coverage per project, lowest first | each project's least covered files (from per-file coverage) |

**Owners** come from the repository's CODEOWNERS file, which `sonda upload`
sends along. It looks in `.github/`, the root, then `docs/`, as GitHub does,
and reads the file like a source: symlinks are never followed, and files over
128 KiB are left out. A directory's owner is whoever owns most of its files,
under GitHub's rules (gitignore patterns, last matching line wins). A
project's owner, on project-level rows, is worked out the same way. Without a
CODEOWNERS file, owners are null.

In the web app, a file opens its issues.

## Projects

`GET /api/projects` lists every project as of its main branch's latest
analysis:
- gate state, score and ratings (computed as the Overview computes them:
  from the issue tracker, accepted issues excluded);
- coverage, duplication, open issues, lines of code and languages;
- when it was analyzed.

The response also lists every language in any project, for filters.

`GET /api/projects/{key}?branch=` is one project on one branch (its main
branch by default). It returns:
- the analyzed branches;
- the latest analysis: commit, tool version, new-code reference;
- the gate's conditions with their actual values;
- the measures, overall and on new code;
- the branch's last 12 analyses;
- its components: top-level directories with languages, files, lines, open
  issues, debt, and owners from the uploaded CODEOWNERS file;
- a summary of its dependencies (total, direct, by ecosystem), or null when
  the analysis recorded none.

An unknown project is `404`; a branch without analyses is `400`, naming
the analyzed branches.

`GET /api/issues` takes `project=` and `branch=` to list one project's
issues, which is how the project page links to them.

## Quality gates

`GET /api/gates` lists the quality gates projects use, read-only. A gate is
defined in each repository's `sonda.toml` and stored with every analysis.
Projects whose latest main-branch analysis used the same conditions share
a gate, whatever their order in the file. The one equal to sonda's
built-in default is named "Default"; others are "Custom gate 1", "2", and
so on. The default comes first, then the rest by how many projects use them.

Each gate has:
- an `id`: a short hash of its conditions, stable while they don't change;
- its conditions, each with how many of the gate's projects fail it now
  and how many lack data;
- its projects with their current gate state;
- its last 40 evaluations on those projects' main branches, the share that
  passed (partial counts as passing), and its most common failure.

## Security

`GET /api/security` summarizes vulnerabilities across projects, each
project's main branch. Open means present and not accepted. It returns:
- open vulnerabilities by severity, how many appeared in the last 7 days,
  and how many projects have any;
- counts by status: open, confirmed, accepted, and fixed in the last 30
  days;
- the ten to fix first: most severe, then longest open;
- twelve weekly points: open count, a severity-weighted risk (blocker 10,
  critical 5, major 2, minor 1), and how many were found and fixed that
  week (baseline issues don't count as found);
- affected projects (blocker and critical, then the rest), the six riskiest
  components, and the six most common rules;
- median days from first seen to fixed, over the last 90 days: for blockers
  and criticals, and for all.

Hotspots, CWE/OWASP mappings and reachability aren't recorded; see the
roadmap.

## Components

A component is a project's top-level directory, or `.` for files at its
root. Nothing records monorepo layouts or dependencies between components.

`GET /api/components` lists every project's components on its main branch,
optionally for one project (`project=`). Each row has the languages, files,
lines, open issues, debt and owner. The response also lists every owner,
for filters.

`GET /api/projects/{key}/components/{component}?branch=` is one component on
one branch (the main branch by default). It returns:
- its languages, files and lines;
- its owner, and every CODEOWNERS owner of its files with how many files
  each owns;
- its open issues by severity and category, how many are on new code, and
  its debt;
- open issues at the end of each of the last eight weeks (accepted issues
  left out);
- its files with their issues, debt and most severe issue;
- the project's other components.

An unknown project or component is `404`; a branch without analyses is
`400`.

`GET /api/projects/{key}/dependencies?branch=` lists the packages the
branch's latest analysis pinned, from the lockfiles in its report
([ADR-0009](adr/0009-dependencies-and-advisories.md)):
- one row per package URL, with its version, whether it's direct, its
  license, and every lockfile that pins it;
- counts by ecosystem, lockfile and license;
- what changed since the branch's previous analysis: packages added,
  removed, or pinned at different versions (null for the first analysis).

Uploads carry them in the report's `dependencies` (at most 200,000, each
checked: a known ecosystem, a `pkg:` URL, bounded fields, a safe relative
lockfile path, no duplicates). Reports from an older CLI have none.

## Coverage

The project page's Coverage tile opens a line coverage report like an
LCOV HTML report (Istanbul's, genhtml's): directories add up their files,
each opens to its subdirectories and files, and a file shows its source
with uncovered lines in red and covered ones marked, lines that left a
branch untaken ("◆ 1/2 branches") and functions never called, stepping
through the uncovered blocks and untaken branches. It's built from the
per-file coverage in the report (`sonda scan --coverage lcov.info`): lines
from LCOV's `DA` records, branches from `BRDA`, functions from `FN` and
`FNDA`, shown as Lines, Branches and Functions columns like Istanbul's.
Reports without branch or function records show "—" for them. Files the
coverage reports don't list show "no data":
Istanbul and c8 list only the files the tests loaded unless told to
include all.

- `GET /api/projects/{key}/coverage?branch=` lists every file of the
  branch's latest analysis with its covered and uncovered line counts,
  and `branches` and `functions` as `{covered, total}` (each null without
  data), and the analysis's `coverage` measure.
- `GET /api/projects/{key}/coverage/file?path=&branch=` returns one file's
  highlighted source (at most 20,000 lines; `truncated` says when it's
  longer) with its `covered` and `uncovered` line numbers, its `branches`
  (`{line, taken, total}`) and its `functions` (`{name, line, calls}`).

An unknown project or file is `404`; a branch without analyses is `400`.

## New code on the main branch

Branches are judged on the change their scan compared with: a pull request,
a push, or the merge base (ADR-0010). The main branch also gets a long-term
view, as in SonarQube: a **new code period** that starts at an analysis
([ADR-0011](adr/0011-new-code-period.md)).

- **The default start is the first analysis of the project's current
  version** ("previous version", SonarQube's default). Upload with
  `--project-version 2.3.0`: the period restarts at the first main-branch
  analysis after the last one with a different version. Uploads without a
  version don't count, so without versions it's the project's first
  analysis. What was there at the start is accepted, and an issue first
  seen after it, on a line changed since, is new until it's fixed. Issues a
  newly added rule finds on unchanged lines are old debt, not new code.
  Nothing ages out.
- **What the server computes.** On each main-branch upload, it marks issues
  new or not (so the Issues page, drill-downs and filters agree) and
  recounts the new-issue measures. It also computes `new_lines`, by diffing
  each file's stored source against the start's. Lines here are non-blank
  ones, since the server doesn't parse code; the CLI counts code lines.
  Then it re-evaluates and stores the latest analysis's gate. As the CLI
  does, with fewer than 20 new lines, conditions on coverage and
  duplication of new code are `ignored` (shown as such) rather than
  failing or missing data, so a quiet main branch passes.
- **Coverage on new code** is computed the same way, from each file's
  covered and uncovered lines in the report (`sonda scan --coverage`):
  covered lines among the changed lines the coverage reports list. Reports
  from older CLIs don't carry it per file, so their scan's value stays.
- **Duplication on new code** keeps the scan's value, because the server
  has no per-line data for it. The project page says which values come
  from the scan.
- **Admins can move the start** to a later analysis of the main branch, for
  example after a cleanup: `PUT /api/projects/{key}/new-code` with
  `{"analysis": id}`. That start wins over versions until an admin sends
  `null`, which goes back to following them. It's on the project page under
  Measures → New code, and every move is recorded with who made it.
- **The API:** `GET /api/projects/{key}` returns `newCodePeriod` on the
  main branch (its starting analysis, whether an admin moved it, the
  version that started it, and which measures come from the scan), and
  `null` on other branches. Analyses carry their `version`.

## Known vulnerabilities

Dependencies are checked against advisories the server stores
([ADR-0009](adr/0009-dependencies-and-advisories.md)). It has none until
they're synced or imported. The server only connects out if you ask it to:

- **Daily sync, opt-in.** With `SONDA_ADVISORY_SYNC=true`, the server
  fetches what changed in OSV since its last sync, at startup and then every
  24 hours.
  - **The first sync** fetches every advisory sonda keeps, about 26,000
    records, in about 10 minutes. Later ones take seconds.
  - **What it fetches:** per ecosystem, OSV's `modified_id.csv`, then only
    the records modified since the last sync, from the databases below.
  - **Failures:** if any record can't be fetched or stored, that
    ecosystem's progress isn't saved and the next sync retries.
  - **Limits:** redirects are refused and responses are size-capped.
- **Once, from cron.** `sonda-server advisories sync` does the same in one
  run, for installs that prefer cron to the server's own schedule.
- **Offline.** Import exports carried in by hand:

```sh
# OSV's exports per ecosystem, unzipped (about 1.3 GB for all three).
for e in npm PyPI crates.io; do
  curl -fsSLO "https://osv-vulnerabilities.storage.googleapis.com/$e/all.zip"
  unzip -q -o all.zip -d "osv/$e" && rm all.zip
done
DATABASE_URL=... sonda-server advisories import osv/
```

- **What's kept.** The import reads every `*.json` record under the paths
  it's given (each at most 4 MB). It keeps only advisories from databases
  whose terms allow any use with attribution: the GitHub Advisory
  Database, PyPA and Go (CC-BY 4.0), and RustSec (CC0). It keeps only
  packages in ecosystems sonda reads lockfiles for. Everything else is
  skipped, including OSV's other sources, some of them non-commercial.
- **Re-importing.** Re-running the import replaces only records whose
  `modified` time is newer, so a daily cron with fresh exports keeps the
  data current. The full export imports in under a minute. Sync and import
  can be mixed: both store the same records.
- **When matching happens.** Matching runs whenever dependencies are read,
  against each analysis's dependencies. So a newly imported advisory flags
  projects without new analyses.
- **How versions are compared.** Each ecosystem uses its own version order:
  SemVer for npm and crates.io, PEP 440 for PyPI. A version that doesn't
  parse leaves the advisory **unchecked**, which is listed, never guessed.
- **Duplicates and withdrawals.** Records from several databases that alias
  each other count once. Withdrawn advisories match nothing.
- **Severity** comes from the CVSS v3 base score, computed from the
  advisory's vector, else from the database's own rating.

`GET /api/projects/{key}/dependencies` adds to each package its
advisories (id, aliases, summary, severity, CWE ids, source, and
`fixedIn`: the lowest later version that fixes it). It also returns
`advisoryData` (when advisories were last imported, and how many), and
`summary.vulnerable`. The project summary carries `vulnerable` too.

`PATCH /api/projects/{key}/dependencies/reviews` triages a finding, like
an issue. The body is `{ecosystem, name, advisory, status, reason}`, where
status is `open`, `confirmed` or `accepted`.
- **Who:** it needs the same rights as changing an issue.
- **Accepting** needs a reason of at most 500 characters.
- **Scope:** a review covers the project's package and that advisory on
  every branch, and lasts through rescans and through upgrades that stay
  vulnerable.
- **Counts:** accepted findings stay listed with their review, but don't
  count as vulnerable.
- **Audit:** every change is recorded with who made it.

**Gate conditions** on `vulnerable_dependencies` or
`severe_vulnerable_dependencies` are evaluated by the server once it has
advisories. It re-evaluates them, accepted findings left out, when an
analysis is uploaded, when advisories are imported or synced (each
branch's latest analysis), and when a finding is reviewed. The result is
stored with the analysis, so every page agrees. Until advisories exist,
these conditions are ignored ("no advisory data"), as in the CLI without
`--advisories`, so they don't fail the gate or make it partial. The
default gate has `new_severe_vulnerable_dependencies > 0`.

`new_vulnerable_dependencies` and `new_severe_vulnerable_dependencies`
count the packages whose finding wasn't there when the main branch's new
code period started (ADR-0011): added, or moved into an affected version.
The same advisory on the same package at another version isn't new. Both
sides are checked against today's advisories. Other branches keep the
CLI's values, which compared with the branch's own reference.

`GET /api/security` adds `dependencies`: open and confirmed findings
across each project's main branch, by severity, with how many packages
and projects they affect, the ten most severe, and when advisories were
last imported.

## Analyses

`GET /api/analyses` lists stored analyses, newest first, 50 at a time
(`offset=`, `limit=` up to 100). Filters: `project=`, `branch=`, and
`gate=failed` or `gate=passed` (passing includes partial). Each row has:
- the project, branch, commit and tool version;
- the gate state and the labels of the conditions that failed;
- issue counts and the number of warnings.

`GET /api/analyses/{id}` is one analysis. It returns:
- the gate's conditions;
- the measures, overall and on new code;
- the files analyzed, per language, and the components;
- the warnings the CLI reported (skipped files, syntax errors, timeouts);
- the issues it introduced and the issues it fixed, with exact counts per
  severity and the 50 most severe listed;
- the previous and next analyses on the same branch.

A branch's first analysis is its **baseline**: its issues are what was
there, not new.

Commit messages, scan durations and stage logs aren't uploaded, so they
aren't reported.

## Rules

`GET /api/rules` returns sonda's rule catalog: name, description, languages
(as ids such as `javascript` or `tsx`, the same as in reports), category,
severity, effort, and noncompliant and compliant examples. It adds live
counts: open or confirmed issues on each project's main branch, and how many
projects have them. A project's main branch is the first branch analyzed.

The catalog is read-only. Rules are configured in each repository's
`sonda.toml`, not on the server.

## Exposing it beyond this machine

The port is published on `127.0.0.1` only. To reach the server from other
machines, put a reverse proxy that terminates TLS (Caddy, nginx, a cloud
load balancer) in front of `127.0.0.1:9000`. `sonda upload` refuses plain
HTTP to anything but localhost, so the token never crosses the network
unencrypted.

## Configuration

Secrets come from environment variables or files (`*_FILE`), never from
command-line flags. Setting both a variable and its `_FILE` form is an error.

| Variable | Meaning |
|---|---|
| `DATABASE_URL` / `DATABASE_URL_FILE` | `postgres://user@host:port/db`. Required. |
| `DATABASE_PASSWORD` / `DATABASE_PASSWORD_FILE` | The database password, if not in the URL. |
| `SONDA_TOKEN` / `SONDA_TOKEN_FILE` | The API token, at least 32 characters. Required. Kept in memory only as a SHA-256 hash and compared in constant time. |
| `SONDA_ADMIN_PASSWORD` / `SONDA_ADMIN_PASSWORD_FILE` | Creates the first admin while no users exist; ignored afterwards. At least 12 characters. |
| `SONDA_ADMIN_USERNAME` | That admin's username. Default `admin`. |
| `SONDA_ADVISORY_SYNC` | `true` syncs advisories from OSV daily (see [Known vulnerabilities](#known-vulnerabilities)). Off by default: the server makes no outbound connections. |
| `SONDA_ADVISORY_SYNC_URL` | A mirror of OSV's exports to sync from instead: `https://`, or `http://` to localhost only. |
| `SONDA_LISTEN` (`--listen`) | Address to listen on. Default `127.0.0.1:9000`; the image sets `0.0.0.0:9000`. |
| `SONDA_WEB_DIR` (`--web-dir`) | The built web app to serve. The image sets it. |
| `RUST_LOG` | Log filter. Default `sonda=info,sqlx=warn`. |

PostgreSQL 15 or newer. On startup the server waits up to 30 seconds for
the database, then applies pending migrations, each in a transaction. If a
migration fails, the server exits instead of serving.

## Running without Docker

```sh
cargo build --release -p sonda-server
DATABASE_URL=postgres://sonda@localhost/sonda DATABASE_PASSWORD_FILE=... \
  SONDA_TOKEN_FILE=... target/release/sonda-server --web-dir web/dist
```

## Backups

Everything durable is in PostgreSQL:

```sh
docker compose exec -T db pg_dump -U sonda -Fc sonda > sonda.dump
```

## Development

The database tests run against a throwaway database on any PostgreSQL
server you point them at. Without one, they skip:

```sh
docker run -d --name sonda-test-pg -e POSTGRES_PASSWORD=test -p 127.0.0.1:55432:5432 postgres:17
SONDA_TEST_DATABASE_URL=postgres://postgres:test@127.0.0.1:55432/postgres cargo test -p sonda-server
```

CI runs them against PostgreSQL 15, the oldest supported version, with
`SONDA_REQUIRE_DB_TESTS=1`, so a missing database fails the build instead of
skipping silently.
