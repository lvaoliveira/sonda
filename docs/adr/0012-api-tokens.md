# ADR-0012: Project and personal API tokens

- Status: **proposed**
- Date: 2026-10-31
- Builds on [ADR-0005](0005-sonda-server.md) (the server and its token) and
  [ADR-0006](0006-users.md) (users and roles)

## Context

The server has one machine credential, `SONDA_TOKEN`. Every CI pipeline
uploads with it, and scripts use it for reads and triage. That has three
problems:

- **One leak exposes every project.** A token copied from one project's CI
  can upload, and overwrite the main branch's results, for any project on
  the server.
- **Rotating it breaks everything at once.** Every pipeline holds the same
  secret, so replacing it after a leak means updating all of them
  together.
- **The audit trail can't say who.** Triage by token is recorded as
  `api-token`, and uploads aren't attributed at all.

ADR-0006 left room for this: "Per-user or per-project tokens can replace
it later."

## Decision

### Two kinds of token

| | Project token | Personal token |
|---|---|---|
| **For** | CI uploading one project | scripts acting as a person |
| **Created by** | an admin | any user, for themselves |
| **Can** | upload analyses of its project, any branch | read, and triage as its user |
| **Cannot** | read, triage, or upload another project | upload, or manage users or tokens |
| **Audit name** | `token:<label>` | the user's username |

- **A project token names a project key**, which may not exist yet: the
  first upload creates the project, as today.
- **A personal token is its user.** Disabling the user stops it, and it
  never has more rights than the user. Admin routes still need a signed-in
  session, never a token (ADR-0006).
- **Least privilege.** Neither kind can do everything `SONDA_TOKEN` does.
  Uploads, the most damaging action, need a token bound to that project.

### The token itself

- **Format:** `sonda_p_` (project) or `sonda_u_` (personal) and 32 random
  bytes, base32-encoded (lowercase, no padding). The prefix lets secret
  scanners, such as GitHub's custom patterns, find leaked tokens, and makes
  the kind visible at a glance.
- **Shown once,** at creation. Afterwards the UI shows only its label, its
  first 12 characters, when it was created and by whom, when it was last
  used, and its expiry.
- **Stored as SHA-256.** These are 256-bit random values, so a slow
  password hash adds nothing. Lookup is by hash, which a unique index makes
  constant-time with respect to the token's content.
- **Expiry is chosen at creation:** 30, 90 or 365 days, or none. The
  default is 90 days for personal tokens and none for project tokens,
  since CI secrets are rotated by people, not by schedules.
- **Revocation is immediate** and kept: a revoked token stays listed, with
  who revoked it and when, and can't be reinstated.

```
api_tokens: id, kind (project | personal), project_key (project tokens),
            user_id (personal tokens), label, hash (unique), prefix,
            created_by, created_at, expires_at, last_used_at,
            revoked_at, revoked_by
analyses:   + token_id (nullable): the token that uploaded it
```

`last_used_at` is updated at most once a minute per token, so uploads and
reads don't each write to the table.

### `SONDA_TOKEN` during migration

- **It keeps working, with the same rights as today,** so existing
  pipelines don't break when the server is upgraded.
- **It becomes optional.** A server without it accepts only database
  tokens. `docs/server.md` will describe moving each pipeline to a project
  token and then removing `SONDA_TOKEN`.
- **Uploads made with it are marked** (`token_id` null, audit name
  `api-token`), so admins can see which projects still use it.

Removing it entirely is a later decision, once the migration path has been
used.

### Where it shows

- **Admin page:** project tokens, to create (label, project, expiry),
  copy once, and revoke. Each project's page lists its tokens to admins.
- **Account page:** your own personal tokens, to create and revoke.
- **Analyses:** which token uploaded each one, or `api-token`.

### Not now

- **Tokens with custom scopes**, such as read-only project tokens or upload
  rights for several projects. Two fixed kinds cover CI and scripts; more
  can be added as needs appear.
- **Branch restrictions** on project tokens.
- **Throttling failed bearer attempts.** Tokens are 256-bit random values,
  so guessing isn't practical, unlike passwords.

## Phases

1. **Project tokens:** the table, issuing and revoking from the Admin page,
   upload authorization by project, `analyses.token_id`, and `SONDA_TOKEN`
   becoming optional.
2. **Personal tokens:** issuing from the Account page, reads and triage as
   the user.

## Consequences

- **A leaked CI secret exposes one project,** and rotating it touches one
  pipeline.
- **Uploads become attributable,** per token.
- **Two credential paths exist during migration,** the shared token and
  database tokens. The audit trail shows which one each upload used.
- **The CLI doesn't change:** `sonda upload` and `sonda scan --upload`
  already send a bearer token from `SONDA_TOKEN` or `SONDA_TOKEN_FILE`.
