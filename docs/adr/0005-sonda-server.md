# ADR-0005: `sonda server` — stored analyses behind the web app's API

- Status: **accepted**
- Date: 2026-10-29
- Builds on [ADR-0001](0001-architecture.md) (layering) and the web app's API contract
  (`web/src/api/types.ts`)

## Context

The web app ([web/README.md](../../web/README.md)) runs against a typed API
contract served by mock data. sonda today is a CLI: each scan produces one
report and forgets it. To show real data, something must keep analyses over
time and answer the contract's questions.

A CLI JSON report already has most per-scan facts: 29 measures, issues with
positions and effort, per-file metrics, duplications and the gate result.
What is missing:

| Needed by the UI | Missing from a report today |
|---|---|
| Projects, branches, "analyzed 12m ago" | project name, branch, commit, timestamp |
| Issue status that survives the next scan (confirm, accept, assign) | a stable issue identity across scans |
| "Introduced vs resolved", NEW/fixed | a diff between consecutive scans of a branch |
| The code viewer in issue detail | the source of the analyzed files |
| Trends, sparklines, gate history | history: many reports, not one |

## Decision

### Shape: a Cargo workspace, three crates

ADR-0001 named "when the server starts" as the trigger to split the crate:

- `sonda-core`: today's library (analysis, rules, measures, gate, report
  model). It stays free of HTTP and storage.
- `sonda`: the CLI, unchanged for users.
- `sonda-server`: storage, ingestion and the HTTP API. It depends on
  `sonda-core` for the rule catalog and the report model, so the server and
  CLI can never disagree on rule ids or report shape.

The module layering (domain, infrastructure, interface) carries over
unchanged. Only crate boundaries are added, and those are enforced by the
compiler instead of by the textual fitness tests.

### Ingestion: `sonda upload`, decoupled from `scan`

```sh
sonda scan . --new-code origin/main -f json -o report.json
sonda upload report.json --server https://sonda.internal --project payments \
  --branch main --commit "$GITHUB_SHA"        # token from SONDA_TOKEN
```

Scanning stays offline and deterministic; uploading is a separate,
authenticated step that CI can retry. The JSON report gains two fields (an
additive, backwards-compatible change):

- **`fingerprint`** per issue: a hash of the rule id, the path, and the
  issue's source line with whitespace normalized, plus an occurrence index
  for identical lines. It survives edits elsewhere in the file and line
  moves. SARIF output also uses it as `partialFingerprints`, which GitHub
  understands.
- **`sha256`** per file: the hash of the exact bytes that were analyzed.

**Sources are uploaded with every analysis, as SonarQube does.** `sonda
upload` sends the full source of every file in the report, so the server
can show any file, not only the lines around issues. It reads each file
again at upload time and refuses to upload when the hash differs from the
report's, so the stored code always matches the issues. There is no
opt-out, again as in SonarQube; access is controlled on the read side
instead (see the security model). Highlighting happens on the server when a
file is served, using sonda-core's tree-sitter grammars and the contract's
token roles, so uploads carry plain text only.

### Storage: PostgreSQL

The server is shared infrastructure that CI pipelines write to concurrently,
so it uses a real database server: concurrent writers, backups, replicas,
and several server instances against one database. PostgreSQL only, not
"PostgreSQL or MySQL":

- **Transactional DDL:** a failed migration rolls back completely; MySQL
  commits each DDL statement implicitly.
- **Features the design uses:** `JSONB` for measures, and partial indexes
  (open issues per branch).
- **One engine to test:** every query and migration is tested against
  exactly what runs in production.

Access goes through `sqlx`, with only its `postgres`, `runtime-tokio` and
`tls-rustls` features: a pure-Rust driver, so no C dependency. Migrations
are versioned files applied at startup (`sqlx::migrate!`), each in a
transaction. Queries are checked at compile time against a committed offline
schema (`.sqlx/`), so building does not need a running database. Tables:
- `projects`
- `analyses`: project, branch, commit, time, measures (JSON), gate result
- `issues`: keyed by project + branch + fingerprint, with the first-seen and
  last-seen analysis, the status workflow and the assignee
- `issue_events`: the audit trail for status changes and undo

Ingesting one report is one transaction: insert the analysis, then match its
fingerprints against the open issues of that branch. New issues are
inserted, issues still present are touched, and issues that are gone are
marked fixed. A human status, such as *accepted*, survives re-scans.

### HTTP: the contract, read-mostly

- `GET` endpoints mirror `SondaApi`.
- `PATCH /api/issues/:id` changes status and assignee.
- `POST /api/analyses` is ingestion.

Responses are the contract's JSON exactly, and the web app gains an
`HttpApi` adapter next to the mock. The server can also serve the built web
app (`--web-dir web/dist`), so one process is the whole product.

### Security model (secure by default)

- **Listening:** binds `127.0.0.1` by default; listening elsewhere requires
  `--listen` explicitly.
- **Writes:** need a token (`SONDA_TOKEN`, stored hashed), for uploads and
  issue changes alike. Reads are open on localhost. Any other bind address
  requires a token for reads too, because the server stores source code. Uploads are compressed (gzip) and
  capped by total size.
- **Uploads are untrusted input:** size-capped and schema-validated
  (`serde` with `deny_unknown_fields`). Rule ids are checked against the
  catalog, and positions are checked like worker replies (`check_invariants`).
- **SQL:** parameterized queries only; no string-built SQL.
- **Out of scope for this ADR:** users, roles, SSO, the Admin screen. Until
  then, "assignee" is a free-text name.

### Deployment: Docker, two containers

Like SonarQube, the supported deployment is a `sonda` container plus a
database container, wired together by a `compose.yaml` shipped in the repo:

```yaml
services:
  sonda:
    image: ghcr.io/lvaoliveira/sonda:<version>   # pinned, never :latest
    ports: ["127.0.0.1:9000:9000"]   # host-local unless changed on purpose
    environment:
      DATABASE_URL_FILE: /run/secrets/database_url
      SONDA_TOKEN_FILE: /run/secrets/sonda_token
    secrets: [database_url, sonda_token]
    depends_on: { db: { condition: service_healthy } }
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
  db:
    image: postgres:17@sha256:<digest>
    environment:
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    secrets: [db_password]
    volumes: [pgdata:/var/lib/postgresql/data]
    healthcheck: { test: ["CMD", "pg_isready", "-U", "postgres"] }
    # no ports: the database is reachable only on the compose network
```

- **One image holds the whole product:** the server binary plus the built
  web app (`web/dist`). It is built in a multi-stage Dockerfile: a Rust
  build stage, a Node build stage, then a minimal runtime (distroless
  `cc`). It runs as a non-root user with a read-only root filesystem and no
  shell.
- **Inside the container** the server listens on `0.0.0.0:9000`, because it
  has to be reachable from outside its own network namespace. Under the
  security model above, that bind address makes reads require the token
  too. Compose publishes the port on the host's `127.0.0.1` only. Exposing
  it further, normally behind a TLS-terminating reverse proxy, is an
  explicit edit.
- **Secrets come from files** (Docker secrets, `*_FILE` variables), never
  from environment literals in `compose.yaml` or from image layers.
- **Startup:** the server waits for the database to be healthy, applies
  pending migrations in a transaction, and only then starts listening. If
  a migration fails, the container exits non-zero instead of serving an
  inconsistent schema.
- **Data:** everything durable lives in the Postgres volume. The `sonda`
  container is stateless, so upgrading means replacing the container with
  the new image.
- **Supply chain:** base images are pinned by digest and updated by
  Dependabot (`docker` ecosystem). CI builds the image on every PR. Images
  are published to GHCR only from tagged releases, with an SBOM and build
  provenance attestation.

The binary still runs without Docker (`sonda-server --database-url-file
...`) for development and for people with their own Postgres.

### What the UI can show with real data

Shown from stored analyses:
- the Overview KPIs and their trends
- gate history and recent analyses
- issue flow
- the severity waffle
- project health
- Issues with the full workflow
- Rules, from the real catalog with live open-issue counts

The design's ratings (pips) need a defined formula. Proposed, close to
SonarQube's so users find it familiar:

| Rating | Level 5 | 4 | 3 | 2 | 1 |
|---|---|---|---|---|---|
| Reliability / Security (worst open bug / vulnerability) | none | minor | major | critical | blocker |
| Maintainability (debt ratio = debt ÷ (ncloc × 30 min)) | ≤ 5% | ≤ 10% | ≤ 20% | ≤ 50% | > 50% |
| Coverage | ≥ 80% | ≥ 70% | ≥ 60% | ≥ 50% | < 50% |

Not shown yet, because nothing produces it: CVEs and secrets (Security
screen), hotspots, components inside monorepos, CODEOWNERS, analysis stages
and logs, members and integrations (Admin). In the contract these become
optional fields, and the UI hides a section without data instead of showing
mock numbers. "Where to focus" is derived from real gate failures and new
blockers or criticals, ranked by severity and age.

## Phases

1. **Workspace split, report fields, upload command.** Move to the
   three-crate workspace. Add fingerprints (with SARIF `partialFingerprints`)
   and per-file hashes. Add `sonda upload` with sources. The CLI behaves as
   before.
2. **Server core.** PostgreSQL schema with migrations, ingestion with issue
   tracking, token auth, the Rules and Issues endpoints, and the web app's
   `HttpApi` adapter. *Acceptance:* scanning arandu twice (with a change in
   between) shows correct new and fixed issues, and an accepted issue stays
   accepted across scans.
   This phase also adds the Dockerfile and `compose.yaml`. *Acceptance:*
   `docker compose up` on a clean machine yields a working server.
3. **Overview from history.** KPIs, trends, gate history, flow and focus
   items from stored analyses; empty states when there is not enough
   history yet.

## Decisions made in review

1. **HTTP stack:** `axum` on tokio. It was chosen over a small synchronous
   server (`tiny_http`) for maintenance and built-in routing, at the cost of
   about 60 transitive crates.
2. **Storage:** PostgreSQL only, replacing the original SQLite proposal.
   PostgreSQL 15 is the minimum supported version, the oldest release still
   supported upstream.
3. **Deployment:** Docker, one `sonda` container and one database container,
   as SonarQube is deployed.
4. **Source code:** uploaded with every analysis, with no opt-out, as
   SonarQube does.
5. **Workspace split:** done now, in phase 1. Today's crate moves into
   `crates/`.

## Amendments

- **2026-10-29, queries are checked at test time, not compile time.** The
  decision above said compile-time-checked `query!` macros with a committed
  `.sqlx/` cache. Instead, queries are plain `sqlx::query` with bound
  parameters. Every query runs against real PostgreSQL in CI (the `server`
  job, PostgreSQL 15). This avoids requiring `sqlx-cli` and a running
  database for every contributor's build. sqlx 0.9 still refuses SQL built
  from strings unless it is explicitly marked as audited, so the
  parameterized-only rule stays enforced.
- **2026-10-30, browsers sign in as users.** Browsers no longer sign in
  with the API token, which now serves only machines.
  [ADR-0006](0006-users.md) adds users, passwords and roles.
- **2026-10-29, the server's minimum Rust version is 1.94**, above the
  workspace's 1.90, because sqlx 0.9 requires it. The CLI and core library
  keep 1.90.

## Consequences

- The first networked, stateful part of sonda. It gets its own threat
  model section in SECURITY.md before release.
- Running the server needs a PostgreSQL database. The `compose.yaml` above
  is both the production deployment and the local development setup. CI runs server tests against a Postgres service
  container on Linux only, because GitHub supports service containers only
  there. The CLI's 3-OS test matrix is unaffected, since the CLI never
  touches the database.
- The database connection string is a secret: it is read from
  `DATABASE_URL` or a file, never from a command-line flag.
- The report format gains fields and becomes a contract between the CLI and
  the server, so it gets versioned (`report_version`).
- The mock adapter stays for tests and design work; the UI must handle
  missing data honestly.
