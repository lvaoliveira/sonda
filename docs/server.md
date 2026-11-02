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
scripts/setup-server.sh
open http://127.0.0.1:9000     # sign in as admin, password in secrets/admin_password
```

It creates the secrets below once, then builds this checkout and starts it,
waiting until it's healthy. It's safe to rerun, so upgrading is
`git pull && scripts/setup-server.sh`. Its options are kept in `.env`, so
later runs need none:

| Option | |
|---|---|
| `--port PORT` | Publish on `127.0.0.1:PORT` instead of 9000, when 9000 is taken. |
| `--github-app ID KEY.pem` | Decorate pull requests with this GitHub App (see [Decorating pull requests on GitHub](#decorating-pull-requests-on-github)). |
| `--lan [IP]` | Also serve plain HTTP on this machine's LAN address, for a trusted network (see [On a home network](#on-a-home-network)). |
| `--https [IP][:PORT]` | Also serve HTTPS on this machine's LAN address, port 9443 by default (see [HTTPS on a LAN address](#https-on-a-lan-address)). |
| `--public-url URL` | The server's address in those decorations. Default the HTTPS address, else `http://localhost:PORT`. |

To do it by hand instead:

```sh
mkdir -m 700 secrets
openssl rand -hex 32 > secrets/db_password
openssl rand -hex 32 > secrets/sonda_token
openssl rand -base64 18 > secrets/admin_password
chmod 644 secrets/*        # the containers read them as non-root users

docker compose up -d --wait
curl http://127.0.0.1:9000/api/health     # {"status":"ok"}
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

Or scan and upload in one step, which also records how long the scan
took (a report can't carry it: reports are byte-identical for the same
inputs). The server, project, branch and token are checked before the
scan starts; the server gets the full JSON report whatever `--format`
the scan prints:

```sh
sonda scan . --upload --server http://127.0.0.1:9000 --token-file secrets/sonda_token \
  --project payments --branch main --commit "$(git rev-parse HEAD)"
```

The first upload creates the project. Each upload becomes the branch's
latest analysis, ordered by when it arrives, not by commit date. When
`--root` is a git clone that has the commit, the upload carries the
commit's subject line, read from git's objects (ADR-0002), which Recent
analyses, the analyses list and the analysis page show. Issues are
matched to the branch's earlier ones by fingerprint:

- **New:** a fingerprint the branch has not seen.
- **Kept:** an issue still present. It moves to its new line, and its status
  (confirmed, accepted, false positive), reason and assignee stay.
- **Fixed:** an issue missing from the upload.
- **Set aside:** an issue missing because the scan didn't run its rule (a
  rule profile or `sonda.toml` turned it off; the report's `active_rules`
  says which ran). It leaves the open issues like a fixed one, but isn't
  counted or listed as fixed anywhere, and when the rule runs again and
  finds it, it's back without counting as reopened. If the rule runs and
  it's gone, it's fixed then. Uploads from an older `sonda`, without
  `active_rules`, mark every missing issue fixed.
- **Reopened:** a fixed issue that comes back, with its earlier status.

Branches are tracked separately. Unchanged files are stored once, however
many analyses include them.

`POST /api/analyses` needs `Authorization: Bearer <token>`. It takes the JSON
`sonda upload` sends, gzipped or plain, up to 128 MiB as sent and 800 MiB
uncompressed. It answers `201` with
`{"analysis_id": 2, "issues": {"open": 331, "new": 61, "reopened": 0, "fixed": 2}, "gate": {...}}`,
with `issues.set_aside` when some were set aside.
`gate` is the server's quality gate for that analysis, with the reviews
made on the server taken into account: `passed`, `state` and the labels of
its `failing` conditions.

**CI follows the server's gate when it uploads** (ADR-0014), as SonarQube's
scanner does with `sonar.qualitygate.wait`. `sonda upload` and
`sonda scan --upload` print it and exit with it: `1` when it fails, even
when the local gate passed, and `0` when it passes, even when the local gate
failed because of a finding someone accepted or marked a false positive on
the server:

```
sonda: quality gate on the server, reviews included: FAILED (New vulnerabilities > 0)
```

`--no-gate` still always exits `0`. A server that sends no `gate` (an older
one) leaves the local gate deciding. Without an upload, the local gate
decides, with `sonda-ignore` comments for findings that are never a
problem.

A rejected upload stores nothing:

| Status | Meaning |
|---|---|
| `401` | Missing, wrong, revoked or expired token. |
| `403` | A token that can't upload this project, or a browser session (uploads need a token). |
| `400` | Not gzip, or not a sonda upload. |
| `413` | Too large, compressed or after decompression. |
| `415` | A `Content-Encoding` other than gzip or identity. |
| `422` | Well-formed but invalid, e.g. a source that doesn't match its SHA-256, an unknown rule, an unsafe path, or an unsupported `report_version`. |

## Users and sign-in

Users and roles are described in [ADR-0006](adr/0006-users.md).

| Role | Can |
|---|---|
| **member** | Read, and triage: status, reason and assignee. |
| **admin** | The same, plus manage users. |

- **Where each credential works:**
  - People sign in with username and password.
  - Machines use tokens, as `Authorization: Bearer <token>` (see Tokens
    below). No token manages users or tokens, or signs browsers in.
- **Who can read:** anyone, while the server listens on loopback only (the
  default without Docker). Otherwise, as in the Docker image, every read
  needs a signed-in user or a user token, because the server holds source
  code.

| Endpoint | |
|---|---|
| `GET /api/session` | `{"user": {...} or null, "authenticated": false, "readsRequireAuth": true}` |
| `POST /api/session` `{"username": "...", "password": "..."}` | `204` and the cookie, or `401` "invalid username or password" |
| `DELETE /api/session` | `204`. Ends the session and clears the cookie. |
| `PUT /api/me/password` `{"current": "...", "new": "..."}` | `204`. Your other sessions end. |
| `GET /api/users`, `POST /api/users`, `PATCH /api/users/{id}` | Admins only. List users; create one; change display name, role, disabled, or reset the password. |

- **Service users:** `POST /api/users` without a `password` creates a
  service user, such as `ci`. It can't sign in (no password matches) and
  only owns tokens generated for it by an admin (see Tokens below). It
  must be a member: an admin has to be able to sign in, or a passwordless
  admin could count as the last one while nobody can act as it. Setting a
  password later makes it an ordinary user. The users list shows it with
  `hasPassword: false`.

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
- **Audit:** triage changes record who made them: a username,
  `ada (token scripts)` for a user token, or `api-token`.

## Tokens

Each user generates their own tokens under Account, as in SonarQube
([ADR-0012](adr/0012-api-tokens.md)). A token belongs to its owner and
never has more rights than them: disabling the owner stops every token
they own, CI ones included.

**CI tokens belong to a service user.** So that a pipeline doesn't stop
when a person leaves, an admin creates a **service user** such as `ci`
(Add a user → Service user) and generates the pipelines' tokens for it on
the Admin page: choose the owner, then the type,
project and expiry. The token acts as `ci`, uploads show
`ci (token shop)`, and the token lists say which admin generated it.

| Type | Prefix | Can |
|---|---|---|
| **User** | `sonda_u_` | What its owner can: read, triage and upload. Not manage users or tokens. |
| **Project analysis** | `sonda_p_` | Upload analyses of one project, any branch, and read the rule settings its scans apply; nothing else. Best for CI. |
| **Global analysis** | `sonda_a_` | Upload analyses of any project, and read the rule settings their scans apply; nothing else. |

- **Expiry** is chosen when generating: 30, 60 or 90 days, or none. An
  expired token stops working and stays listed.
- **Secrets are shown once.** The server keeps their SHA-256, and lists show
  only the first 12 characters. The prefixes let secret scanners, such as
  GitHub's custom patterns, recognize leaked tokens.
- **Revoking** is immediate and final; revoked tokens stay listed with who
  revoked them. Admins see and revoke everyone's tokens on the Admin page.
- **Uploads record their token:** the analyses list and page show
  `ada (token ci-shop)`, or `api-token` for the shared `SONDA_TOKEN`.

| Endpoint | |
|---|---|
| `GET /api/me/tokens` | Your tokens, revoked and expired ones included. |
| `POST /api/me/tokens` `{"name": "ci-shop", "type": "project_analysis", "project": "shop", "expiresInDays": 30}` | `201` with `token`, the secret, this once. `type` is `user`, `project_analysis` or `global_analysis`; `expiresInDays` is 30, 60, 90 or null. |
| `DELETE /api/me/tokens/{id}` | `204`. Revokes one of yours. |
| `GET /api/tokens`, `DELETE /api/tokens/{id}` | Admins only: everyone's tokens, and revoking any. |
| `POST /api/tokens` `{"user": "ci", "name": "shop", ...}` | Admins only: generates a token owned by `user`, with the same fields as `POST /api/me/tokens`. `createdBy` records the admin. `422` for an unknown or disabled user. |

These need a signed-in session (and the `Sonda-Csrf` header for changes),
never a token, so a leaked token can't generate more.

**Moving off `SONDA_TOKEN`.** The shared token still works with its old
rights, and is now optional. For each pipeline, generate a project
analysis token (for a `ci` service user, as above), put it in the pipeline's secret (`SONDA_TOKEN` or
`SONDA_TOKEN_FILE`, which `sonda upload` and `sonda scan --upload` read),
and check the analyses list shows it as the uploader. Once no recent
analysis shows `api-token`, turn the shared token off. With Docker
Compose, add a `compose.override.yaml` (git-ignored, merged automatically)
and restart with `docker compose up -d`, or rerun `scripts/setup-server.sh`
if it started the server (its `.env` lists the compose files to merge):

```yaml
services:
  sonda:
    environment:
      SONDA_TOKEN_FILE: ""   # empty counts as unset: no shared token
```

The old token then gets `401`, and only users' tokens upload. Removing
the override turns it back on.

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
| `severity`, `category`, `status`, `component` | Comma-separated values; `status` is `open`, `confirmed`, `accepted`, `false_positive` or `fixed` |
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

`PATCH /api/issues/{id}` with `{"status": "confirmed"}` and/or
`{"assignee": "alice"}` (`""` unassigns) changes triage. A change needs the
token, or a browser session plus a `Sonda-Csrf` header. Each change is
recorded in the issue's history, with its reason. The statuses (ADR-0014):

| Status | |
|---|---|
| `open` | Not reviewed yet. |
| `confirmed` | A real problem, to fix. |
| `accepted` | A real problem whose risk is accepted. Needs a `reason`. |
| `false_positive` | Not a problem: the rule is wrong here. Needs a `reason`. |
| `fixed` | Gone from the latest analysis. Set by analyses, never by hand. |

A `reason` is 1-500 characters, as in
`{"status": "accepted", "reason": "Behind the VPN only."}`; `422` without
one. **Accepted and false-positive issues are decided:** they stay listed,
with their reason, but leave the issue measures (overall and on new code),
the ratings, the open counts and the gate. The stored gate is re-evaluated
on each status change, so reviewing the last new vulnerability makes the
gate pass, as in SonarQube. Reopening counts the issue again.

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

The response also lists every language in any project, for filters, and
as `waiting` the projects whose main branch has no analysis yet: their key,
name and GitHub repository.

### Connecting a repository

On a new server, the empty Overview offers admins **Connect a repository**
(also on Projects), which sets a GitHub repository up in one form
([ADR-0023](adr/0023-connecting-a-repository.md)):

1. Paste the repository's GitHub URL, such as
   `https://github.com/acme/shop` (its SSH address or `owner/name` work
   too). sonda creates the project (keyed by the repository's name,
   editable), links the repository for pull request
   decoration, and generates a project analysis token.
2. Add the token as the repository's `SONDA_TOKEN` secret, on GitHub's page
   it opens.
3. Commit the workflow it writes, in GitHub's editor it opens filled in, on
   a new branch with a pull request: that pull request is the first one
   decorated.

The page shows the steps one at a time, in order, each confirmed before the
next opens: committing the workflow runs CI at once, so the secret, and a
self-hosted runner's CLI, must be there first. **Done** then waits for the
first analysis, which proves it's connected, and links to it.

Choose where CI runs. On a self-hosted runner on the server's machine, the
workflow uploads to `http://localhost:PORT` with the CLI from
`scripts/install-cli.sh`, installed as a step before the workflow. On GitHub's runners, it builds the CLI and needs
the server's public `https://` address. sonda never writes to the
repository: the GitHub App keeps its permissions. Until its main branch is
analyzed, the project is listed as waiting, where an admin can show its
steps again with a new token.

| Endpoint | |
|---|---|
| `POST /api/projects` `{"key": "shop", "mainBranch": "main"}` | Admins: an empty project, `201`. `mainBranch` defaults to `main`. An existing key, a deleted one, or an invalid key or branch is a `422`. |

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

### Project settings

A project's settings ([ADR-0017](adr/0017-project-settings.md)) are on its
**Settings** page, linked from its page. Members read them; admins change
them, and each change is recorded with who made it, from what to what.

- **Display name:** optional, 1 to 100 characters. Screens show it with
  the key under it. The key never changes, so CI's `--project`, project
  analysis tokens and links keep working. `GET /api/projects` and
  `GET /api/projects/{key}` return it as `name` (null without one).
- **Main branch:** at first the first branch analyzed; admins choose any
  branch with analyses. Every screen counts the new one at once. Its new
  code period starts over on it, from its first analysis or its current
  version's, and a start an admin set on the old branch no longer applies.
  The old branch keeps its numbers until its next analysis, which judges
  its new code by its scan again, as on any other branch.
- **Quality gate:** `sonda.toml`'s, or a server gate an admin chooses (see
  [Quality gates](#quality-gates)).

| Endpoint | |
|---|---|
| `GET /api/projects/{key}/settings` | `name`, `mainBranch`, `qualityGate` (a server gate's `id` and `name`, or null for `sonda.toml`'s), the `branches` with analyses (how many, and the latest's time), and the last 50 `changes`, newest first. |
| `PATCH /api/projects/{key}/settings` `{"name": "Payments", "mainBranch": "develop", "qualityGate": 3}` | Admins: any of them; `"name": null` removes the name, `"qualityGate": null` goes back to `sonda.toml`'s gate. A name over 100 characters, a branch without analyses, or an unknown gate is a `422`. |

#### Deleting a project

Admins delete a project in its Settings page's Danger zone, by typing its
key. It's permanent: its analyses, issues and their history, sources (file
contents no other project's analyses share), dependencies, reviews and
settings. Its project analysis tokens are revoked, recorded as revoked by
that admin.

**Its key is then refused.** Uploads create a project the first time they
see a key, so a forgotten pipeline would bring a deleted project back,
empty. Instead, uploads to it are a `403` saying who deleted it and when,
and `sonda scan --upload` fails before scanning, when it fetches the
project's rule settings. A project analysis token for the key can't be
generated either. An admin allows the key again on the Administration
page, which lists every deleted project with who deleted it and when; the
next upload then starts a new project.

| Endpoint | |
|---|---|
| `DELETE /api/projects/{key}` `{"confirm": "<key>"}` | Admins: deletes it; answers the deletion record. Any other `confirm` is a `422`. |
| `GET /api/deleted-projects` | Admins: deleted projects, newest first: `key`, `name`, `analyses`, `deletedBy`, `deletedAt`, and `allowedBy`/`allowedAt` once its key is allowed again. |
| `POST /api/deleted-projects/{id}/allow` | Admins: uploads to the key work again. |

## Quality gates

A project's gate comes from one of two places
([ADR-0017](adr/0017-project-settings.md)):

- **Its repository's `sonda.toml`** (the default): the gate is stored with
  every analysis. Projects whose latest main-branch analysis used the same
  conditions share a gate, whatever their order in the file. The one equal
  to sonda's built-in default is named "Default"; others are "Custom gate
  1", "2", and so on.
- **A server gate**, which admins create, edit and delete on the Quality
  gates page, with the same metrics and operators as
  `[[gate.conditions]]`, and which a project uses once an admin chooses it
  in its Settings. It wins over `sonda.toml`'s: the server judges the
  project's latest analysis on every branch by it at once, and every
  upload after. The upload's answer carries its result, so
  `sonda scan --upload` passes or fails on it (ADR-0014). A scan without an
  upload still uses `sonda.toml`'s. Editing a server gate judges its
  projects again at once; choosing `sonda.toml`'s again brings back each
  analysis's own conditions. A gate a project uses can't be deleted.

The project and analysis pages say which gate judged a result
(`gate.serverGate`: its `id` and `name`, or null for `sonda.toml`'s).

`GET /api/gates` lists them all: the default first, then server gates
(even those no project uses yet), then the rest by how many projects use
them. It also lists the `metrics` a condition can test.

| Endpoint | |
|---|---|
| `POST /api/quality-gates` `{"name": "Strict", "conditions": [{"metric": "new_coverage", "op": "lt", "threshold": 90}]}` | Admins: a server gate. Names are unique, 1 to 100 characters, with 1 to 50 conditions; an unknown metric or operator is a `422`. |
| `PUT /api/quality-gates/{id}` (the same body) | Admins: its name and conditions; answers the projects judged again. |
| `DELETE /api/quality-gates/{id}` | Admins: a `422` naming the projects that use it, if any. |
| `PATCH /api/projects/{key}/settings` `{"qualityGate": 3}` | Admins: the project's server gate, or `null` for `sonda.toml`'s (see [Project settings](#project-settings)). |

Each gate has:
- an `id`: a short hash of its conditions, stable while they don't change,
  or `server-<id>` for a server gate, which also has `server` (its `id`,
  and who changed it last and when);
- its conditions, each with how many of the gate's projects fail it now
  and how many lack data;
- its projects with their current gate state;
- its last 40 evaluations on those projects' main branches, the share that
  passed (partial counts as passing), and its most common failure.

## Security

`GET /api/security` summarizes vulnerabilities across projects, each
project's main branch. Open means present and not decided (accepted or
false positive). It returns:
- open vulnerabilities by severity, how many appeared in the last 7 days,
  and how many projects have any;
- counts by status: open, confirmed, accepted, false positive, and fixed
  in the last 30 days;
- the ten to fix first: most severe, then longest open;
- twelve weekly points: open count, a severity-weighted risk (blocker 10,
  critical 5, major 2, minor 1), and how many were found and fixed that
  week (baseline issues don't count as found);
- affected projects (blocker and critical, then the rest), the six riskiest
  components, and the six most common rules;
- median days from first seen to fixed, over the last 90 days: for blockers
  and criticals, and for all.

Reachability isn't recorded; see the roadmap.

### Review queue

`GET /api/security/review` is the Security screen's **To review** queue
(ADR-0014): vulnerabilities to decide on, most severe first, then those on
new code, then the oldest. Every filter is optional:

| Parameter | |
|---|---|
| `project`, `branch` | One project; a branch other than its main one (needs `project`) |
| `status` | `open` (the default), `confirmed`, `accepted`, `false_positive` or `all` |
| `severity` | Comma-separated severities |
| `owasp`, `edition` | An OWASP Top 10 category id, `A01` to `A10`, in `edition` `2025` (the default) or `2021` |
| `assignee`, `new=true` | Assigned to someone; on new code only |

It returns the first 200 matching `items`, each with its rule and the
rule's name, CWE ids and OWASP categories, its location, status, reason,
assignee and when it was first seen, and `total`. `progress` counts every
finding in scope by status, whatever the other filters, with the share
`reviewed` (no longer open, 0-100); `newCode` is the same on new code.
Decisions go through `PATCH /api/issues/{id}`. Dependency findings are
reviewed on their own (see Known vulnerabilities), without "false positive",
which is for code issues only.

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

### Pull requests

An upload can belong to a pull request
([ADR-0021](adr/0021-pull-request-decoration.md)): `pull_request` carries
its `number`, `base` and `head` branches, and from GitHub Actions its
`head_sha` and `repository` (`owner/name`). `sonda` sends it in a GitHub
Actions `pull_request` job, or with `--pull-request` and
`--pull-request-base`.

- **Stored apart from branches**, under the branch key `pr:<number>`
  (which no git branch can have, since git refuses `:` in branch names;
  uploads with such a `branch` are a `422`). Issue tracking, new code, the
  gate (a server gate too) and triage work as on any branch.
- **Not a branch:** pull requests aren't in a project's `branches`, its
  main-branch choices, or anything counted on the main branch (Overview,
  Projects, Security, Rules). `GET /api/projects/{key}` lists them as
  `pullRequests` (number, branches, latest analysis, gate, new issues),
  and analyses carry `pullRequest` (`number`, `base`, `head`), null on a
  branch's. `GET /api/issues?branch=pr:12` lists a pull request's issues.
- **A project first seen through a pull request** gets its base as the
  main branch.
- **Removed 30 days** after a pull request's last analysis, with its issues
  and the file contents nothing else has. The server checks hourly.

#### Decorating pull requests on GitHub

With a GitHub App configured, the server shows each pull request's result
on the pull request itself:

- **A `sonda` check run** on its head commit. Its conclusion is `success`
  when the gate passes, `failure` when it fails, and `neutral` when
  conditions lack data, so branch protection can require it. Its summary
  says which conditions fail, the new issues by type and severity, and
  coverage and duplication on new code.
- **Annotations** on the new issues, at most 50, most severe first. Each
  analysis's check run replaces the previous one, so a fixed issue's
  annotation is gone with it. Accepted and false-positive issues get none.
- **One summary comment**, found again by a hidden marker and edited in
  place, never added twice.

It's posted after the server judges the gate, by a background task, so a
GitHub that's down never fails the upload or CI. The task retries with a
doubling backoff for a day, and only a pull request's latest analysis is
posted. The analysis page says whether it was posted, and if not, why.

**Setting it up:**

1. Create a GitHub App (Settings → Developer settings → GitHub Apps) with
   these repository permissions: Checks (read and write), Pull requests
   (read and write), Metadata (read). It needs no webhook: uncheck its
   Active box. Note the App ID, then create a private key under
   Credentials → Key pairs → New key, which downloads it.
2. Install it on the repositories to decorate.
3. Give the server the App: `scripts/setup-server.sh --github-app ID
   KEY.pem`, with the App's id and the downloaded key. It copies the key
   into `secrets/` and adds `compose.github.yaml`. Without the script, set
   `SONDA_GITHUB_APP_ID`, `SONDA_GITHUB_APP_PRIVATE_KEY_FILE` and
   `SONDA_PUBLIC_URL` (see [Configuration](#configuration)).
4. In each project's Settings, an admin links its repository
   (`owner/name`). Uploads from any other repository post nothing, so a
   project can't decorate someone else's pull requests.

The server signs a short-lived JWT with the key and exchanges it for a
token limited to the one repository, which lasts an hour and lives only
in memory. Neither is stored or logged. What's sent to GitHub is the
summary and each annotation's path, lines, rule and message, never source
code. Without an App, the server makes none of these calls.

| Endpoint | |
|---|---|
| `PATCH /api/projects/{key}/settings` `{"githubRepository": "acme/shop"}` | Admins: the repository, or `null`. `GET` returns it, and `githubApp`, whether the server has an App. |
| `GET /api/analyses/{id}` | A pull request's analysis has `decoration`: `state` (`pending`, `posted`, `failed`, `not_posted`, `superseded`), `attempts`, `lastError` and `postedAt`. |

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
- the previous and next analyses on the same branch;
- `ruleSettings`: the `[rules]` settings of `sonda.toml` the scan ran
  with (`disabled`, `enabled` and `severity`), or null for an upload from
  an older `sonda` that didn't send them (ADR-0016).

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
Each rule also has:
- `serverOff`: who turned it off on the server for every project, when and
  why; null when it isn't;
- `offIn`: in how many projects it's off, by what turned it off
  (`sondaToml`, `server`); null when it's on everywhere.

### Rule profiles and settings

Rules run as each repository's `sonda.toml` says, unless the server sets
them. The server holds **rule profiles**
([ADR-0018](adr/0018-rule-profiles.md)): named sets of rules, each on or
off, optionally with a severity. Rules a profile doesn't mention keep their
catalog default.

- **"sonda way"** is built in and read-only: the catalog's defaults. It's
  the default profile until an admin makes another one the default.
- **A project uses** the default profile, or one an admin chooses. Admins
  can also adjust single rules for one project, on or off, over its
  profile ([ADR-0016](adr/0016-rule-settings-on-the-server.md)).
- **`sonda scan --upload` applies them:** before scanning it fetches the
  project's settings, and where the server sets a rule, the server wins;
  `sonda.toml` decides the rest. The report records what it applied.
- **Findings already stored** of a rule that's off are left out of issue
  lists, measures, ratings, counts and the gate at once, which CI follows
  when it uploads (ADR-0014). Changing a profile, a project's choice or an
  adjustment recounts the latest analyses. Turning the rule back on brings
  its issues back with their history.

| Endpoint | |
|---|---|
| `GET /api/rule-profiles`, `GET /api/rule-profiles/{id}` | Profiles, the default first, with the projects using each; one profile with the rules it sets. |
| `POST /api/rule-profiles` `{"name": "Strict", "copyFrom": 1}` | Admins: a new profile, empty or a copy. |
| `PATCH /api/rule-profiles/{id}` `{"name": "...", "isDefault": true}` | Admins: rename it (not "sonda way"), or make it the default. |
| `DELETE /api/rule-profiles/{id}` | Admins: delete a profile that isn't the default, built in, or used by a project. |
| `PUT /api/rule-profiles/{id}/rules` `{"rule": "js/no-var", "state": "off", "severity": "major", "note": "..."}` | Admins: `on`, `off`, or `inherit` to leave it at its default; `severity` is optional. |
| `PUT /api/projects/{key}/rule-profile` `{"profile": 3}` | Admins: the project's profile, or `null` for the default. |
| `PUT /api/projects/{key}/rule-settings` `{"rule": "js/no-var", "state": "on", "note": "..."}` | Admins: `on` or `off` for this project, over its profile, or `inherit`. |
| `PUT /api/rule-settings` `{"rule": "js/no-var", "off": true}` | Admins: off in the default profile, or back on. When "sonda way" is the default, a "Server settings" profile takes its place. |
| `GET /api/projects/{key}/rule-profile` | What a scan of the project applies: `profile`, `revision` and its `rules` (`rule`, `on`, `severity`). A project not uploaded yet gets the default profile's. Analysis tokens may read it, for their project only. |
| `GET /api/projects/{key}/rules` | The rules for the project's languages, each with its state there. |

The project's rules are those for the `languages` of its main branch's
latest analysis, each with the catalog's description (as in
`GET /api/rules`), its `openIssues` and `hiddenIssues` (open findings
that count, and those the server leaves out), and its `state`: whether
it's `on`, what set it (`setBy`: `default`, `sonda_toml`, `profile`, or
`project`), the setting's note, author and time (`change`), its
`severity` and what changed it (`severityBy`), and the project's own
setting (`projectSetting`). The answer also gives the project's `profile`
and whether that analysis applied the current settings
(`profileApplied`). It also returns
`sondaToml`, the repository's `[rules]` in that analysis (null when
unknown: it came from an older `sonda`), and `tomlChanges`, when the
repository changed them, newest first.

When the latest scan didn't apply the server's settings (no upload, `sonda
upload` of an earlier report, or an older `sonda`), a rule the server
turns on but `sonda.toml` leaves off never ran: the view marks it
`conflict`. Notes are at most 500 characters, and an unknown rule id is a
`422`.

## Exposing it beyond this machine

The port is published on `127.0.0.1` only. To reach the server from other
machines, put a reverse proxy that terminates TLS (Caddy, nginx, a cloud
load balancer) in front of `127.0.0.1:9000`, or reach it through an SSH
tunnel (`ssh -L 9000:127.0.0.1:9000 host`).

Plain HTTP on another address needs `SONDA_PLAIN_HTTP`: by default the
session cookie is `__Host-` and `Secure`, which browsers accept only over
HTTPS or on `localhost`, so the page would load but sign-in would fail.

### On a home network

For a server on a network you trust, such as your home's:

```sh
scripts/setup-server.sh --lan
```

It serves plain HTTP on this machine's LAN address too, the one its default
route uses, such as `http://192.168.1.10:9000` (`--lan 192.168.1.20` names
another), and keeps `127.0.0.1` for uploads from this machine. It sets
`SONDA_PLAIN_HTTP=true`, so the session cookie is `sonda_session`, without
`Secure`, and browsers keep it over plain HTTP. Nothing to install on any
device.

**The trade-off:** passwords and session cookies cross the network
unencrypted, so anyone who can see its traffic, on the same Wi-Fi say, can
take a session. Many self-hosted tools on home networks work this way; on a
network you don't fully trust, use HTTPS instead. The server warns when it
starts in this mode. Uploads from other machines still need HTTPS: the CLI
sends a token over plain HTTP only to localhost.

### HTTPS on a LAN address

For a server on a home or office network, with no domain name, and without
plain HTTP's trade-off:

```sh
scripts/setup-server.sh --https
```

It adds Caddy (`compose.https.yaml`) on this machine's LAN address, the one
its default route uses, such as `https://192.168.1.10:9443`, published on
that address only. `--https 192.168.1.20` names another address, and
`--https :8443` or `--https 192.168.1.20:8443` another port. No public authority certifies a private address, so the certificate
comes from Caddy's own local authority. The script copies its root
certificate to `caddy-root.crt`; install it once on each device that opens
the server:

| Device | |
|---|---|
| macOS | `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain caddy-root.crt` |
| Windows | `certutil -addstore -f Root caddy-root.crt`, as administrator |
| Linux | Copy it to `/usr/local/share/ca-certificates/` and run `sudo update-ca-certificates` |
| iPhone, iPad | Send it to the device and install the profile, then turn it on under Settings → General → About → Certificate Trust Settings |
| Android | Settings → Security → Encryption & credentials → Install a certificate → CA certificate |

Firefox on Linux keeps its own list: import it under Settings → Privacy &
Security → Certificates. The authority's keys live in the `caddy_data`
volume and survive upgrades, so devices keep trusting it. **Treat that
volume like a password:** a device that trusts this root trusts any
certificate it signs, for any name.

Uploads stay on `127.0.0.1`: the CLI trusts only public authorities, so it
refuses this certificate. Decorations' links point at the HTTPS address
unless `--public-url` says otherwise. `sonda upload` refuses plain
HTTP to anything but localhost, so the token never crosses the network
unencrypted.

## Configuration

Secrets come from environment variables or files (`*_FILE`), never from
command-line flags. Setting both a variable and its `_FILE` form is an error.

| Variable | Meaning |
|---|---|
| `DATABASE_URL` / `DATABASE_URL_FILE` | `postgres://user@host:port/db`. Required. |
| `DATABASE_PASSWORD` / `DATABASE_PASSWORD_FILE` | The database password, if not in the URL. |
| `SONDA_TOKEN` / `SONDA_TOKEN_FILE` | The shared API token, at least 32 characters. Optional since users have their own tokens (see Tokens); empty counts as unset. Kept in memory only as a SHA-256 hash and compared in constant time. |
| `SONDA_ADMIN_PASSWORD` / `SONDA_ADMIN_PASSWORD_FILE` | Creates the first admin while no users exist; ignored afterwards. At least 12 characters. |
| `SONDA_ADMIN_USERNAME` | That admin's username. Default `admin`. |
| `SONDA_ADVISORY_SYNC` | `true` syncs advisories from OSV daily (see [Known vulnerabilities](#known-vulnerabilities)). Off by default: the server makes no outbound connections. |
| `SONDA_ADVISORY_SYNC_URL` | A mirror of OSV's exports to sync from instead: `https://`, or `http://` to localhost only. |
| `SONDA_GITHUB_APP_ID` | The GitHub App that decorates pull requests ([ADR-0021](adr/0021-pull-request-decoration.md)), with its key. Unset by default: the server never calls GitHub. |
| `SONDA_GITHUB_APP_PRIVATE_KEY` / `SONDA_GITHUB_APP_PRIVATE_KEY_FILE` | The App's private key, PEM, as GitHub downloads it. Set with the App's id, or neither. |
| `SONDA_GITHUB_API_URL` | A GitHub Enterprise Server's API, such as `https://github.example.com/api/v3`. Default `https://api.github.com`. |
| `SONDA_PUBLIC_URL` | The server's address as people reach it, such as `https://sonda.example.com`, for links in pull request decorations; `http://` only to localhost, or anywhere with `SONDA_PLAIN_HTTP`. Without it, they have no link. |
| `SONDA_PLAIN_HTTP` | `true` lets browsers sign in over plain HTTP anywhere, not only on `localhost`: the session cookie is `sonda_session`, without `Secure`. For a trusted network only (see [On a home network](#on-a-home-network)). Off by default. |
| `SONDA_LISTEN` (`--listen`) | Address to listen on. Default `127.0.0.1:9000`; the image sets `0.0.0.0:9000`. |
| `SONDA_METRICS_LISTEN` (`--metrics-listen`) | Address to serve Prometheus metrics on, at `/metrics`. Unset by default, so no metrics are served. Unauthenticated: never the public address. See [Metrics](#metrics). |
| `SONDA_WEB_DIR` (`--web-dir`) | The built web app to serve. The image sets it. |
| `RUST_LOG` | Log filter. Default `sonda=info,sqlx=warn`. |
| `SONDA_LOG_FORMAT` | `text` (the default) or `json`, one object per line for log collectors. See [Logs](#logs). |

PostgreSQL 15 or newer. On startup the server waits up to 30 seconds for
the database, then applies pending migrations, each in a transaction. If a
migration fails, the server exits instead of serving.

## Logs

Every response carries an `x-request-id` header. A reverse proxy's own
`x-request-id` is kept when it is 1 to 64 letters, digits, `.`, `_` or
`-`, so its logs and sonda's share the id. Otherwise the server makes one
up. When a user reports an error, that id finds it in the logs.

Each API request logs one line when it completes, at `info` (`warn` for
5xx), and every line written while handling it, such as `internal error`,
carries the same span:

```
INFO request{id=4f0c... method=GET route=/api/projects/{key}}: request status=200 duration_ms=12.4
```

- `route` is the route's template, never the path: no project keys, file
  paths or search text reach the logs, and neither do headers, which carry
  tokens and session cookies.
- `/api/health` and the web app's files log at `debug`.
- `RUST_LOG=sonda=warn` keeps only 5xx and errors, still with their ids.

With `SONDA_LOG_FORMAT=json`, the event's fields are top-level keys and the
request's are under `span`:

```json
{"timestamp":"...","level":"INFO","message":"request","status":200,"duration_ms":12.4,"target":"sonda_server::observability","span":{"id":"4f0c...","method":"GET","route":"/api/projects/{key}","name":"request"}}
```

## Metrics

With `SONDA_METRICS_LISTEN` set, the server opens a second listener that
serves `GET /metrics`, in the OpenMetrics text format Prometheus reads,
and nothing else. The API's port never serves them.

The endpoint needs no authentication, so who can reach it is up to where
it listens: `127.0.0.1:9090` for a Prometheus on the same machine, or, in
Docker Compose, `0.0.0.0:9090` without publishing the port, so only
containers on the compose network reach it:

```yaml
services:
  sonda:
    environment:
      SONDA_METRICS_LISTEN: 0.0.0.0:9090   # no `ports:` entry for it
```

| Metric | Labels | Meaning |
|---|---|---|
| `sonda_http_requests_total` | `method`, `route`, `status` | Requests completed. |
| `sonda_http_request_duration_seconds` | `method`, `route` | Time to answer, as a histogram from 5 ms to the 30 s request timeout. |
| `sonda_uploads_total` | `result` | Uploads that reached the handler: `stored`; `rejected` (invalid, unsupported encoding, a token for another project); `failed` (an internal error); `cancelled` (the request timed out or the client went away). Unauthenticated and oversized uploads are refused before that, and show only in the request metrics. |
| `sonda_upload_duration_seconds` | | Time to store an analysis, for stored uploads only: decoding, storing, and refreshing new code and gates. |
| `sonda_db_pool_connections` | `state` | Database connections open, `idle` or `in_use`, read at each scrape. |
| `sonda_db_pool_max_connections` | | The most connections the pool opens (10). |
| `sonda_advisory_sync_runs_total` | `result` | Runs of the daily sync (`SONDA_ADVISORY_SYNC=true`): `ok`, `record_errors` (completed, some records not imported), or `failed`. `sonda-server advisories sync` from cron runs in its own process and isn't counted. |
| `sonda_advisory_sync_last_success_timestamp_seconds` | | When a sync last completed, as a Unix time; 0 until one has. |
| `sonda_advisory_sync_advisories_imported_total` | | Advisories the daily sync added or updated. |

Labels are bounded, so the number of series is too:
- `route` is the route's template (`/api/projects/{key}`), or `-` for
  paths that match none, including the web app's files;
- `method` is one of the standard methods, or `other`;
- project keys, branches and users never become labels.

Counters start at zero when the server starts, as Prometheus expects, and
every `result` is listed from the start, so `rate()` and alerts work
before the first one happens. Alerts worth having:

```yaml
- alert: SondaUploadsFailing
  expr: increase(sonda_uploads_total{result=~"failed|cancelled"}[1h]) > 0
- alert: SondaDatabasePoolFull
  expr: sonda_db_pool_connections{state="in_use"} >= sonda_db_pool_max_connections
  for: 5m
# Only with SONDA_ADVISORY_SYNC=true: two missed daily syncs.
- alert: SondaAdvisorySyncStale
  expr: time() - sonda_advisory_sync_last_success_timestamp_seconds > 2 * 86400
```

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
