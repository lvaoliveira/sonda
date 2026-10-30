# Running the sonda server

The server stores analyses uploaded by `sonda upload` and serves the web app
([ADR-0005](adr/0005-sonda-server.md)). It runs as two containers: `sonda`
(the server and the web app) and `db` (PostgreSQL).

**Status:**
- **Server:** receives uploads, tracks issues across them, signs browsers
  in, and serves issues (with triage) and the rule catalog.
- **Web app:** shows them. Open http://127.0.0.1:9000 and sign in with the
  token.
- **Overview:** comes next, built from the stored analysis history.

## Quick start (Docker Compose)

From the repository root:

```sh
mkdir -m 700 secrets
openssl rand -hex 32 > secrets/db_password
openssl rand -hex 32 > secrets/sonda_token
chmod 644 secrets/*        # the containers read them as non-root users

docker compose up -d --wait
curl http://127.0.0.1:9000/api/health     # {"status":"ok"}
open http://127.0.0.1:9000                # the web app; sign in with secrets/sonda_token
```

`secrets/` is git-ignored, and the directory's `700` mode keeps other users
on the machine out. `secrets/sonda_token` is the token `sonda upload` needs:

```sh
SONDA_TOKEN_FILE=secrets/sonda_token   # or: export SONDA_TOKEN=$(cat secrets/sonda_token)
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

## Who can read

Anyone can read while the server listens on loopback only, which is the
default without Docker. Otherwise, as in the Docker image, every read needs
either the token as `Authorization: Bearer <token>` or a browser session,
because the server holds source code. Uploads always need the token.

A browser signs in by sending the token once; it gets a session cookie back
and never keeps the token itself:

| Endpoint | |
|---|---|
| `GET /api/session` | `{"authenticated": false, "readsRequireAuth": true}` |
| `POST /api/session` `{"token": "..."}` | `204` and the cookie, or `401` |
| `DELETE /api/session` | `204`; ends the session and clears the cookie |

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
