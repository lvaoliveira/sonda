# ADR-0012: User and analysis tokens

- Status: **accepted**
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

SonarQube's model is the reference, as for rules and new code: three token
types, each owned by the user who generated it, never more powerful than
that user, and revoked with them.

## Decision

### Three types, as in SonarQube

| | User token | Project analysis token | Global analysis token |
|---|---|---|---|
| **Prefix** | `sonda_u_` | `sonda_p_` | `sonda_a_` |
| **For** | scripts, and analyses of any project | CI of one project | CI uploading many projects |
| **Can** | everything its owner can, uploads included, except managing users and tokens | upload analyses of its one project, any branch | upload analyses of any project |
| **Cannot** | manage users or tokens (that needs a signed-in session) | read, triage, or upload another project | read or triage |

- **Every token belongs to the user who generated it.** Users generate
  their own tokens of all three types. Disabling a user stops all their
  tokens, and a token never has more rights than its owner has now.
- **Who may analyse.** SonarQube grants "Execute Analysis" per project.
  sonda has no per-project permissions yet (ADR-0006's roles are admin and
  member), so every active user may analyse, as every user may triage.
  When per-project permissions arrive, analysis rights narrow with them.
- **A project analysis token names a project key,** which may not exist
  yet: the first upload creates the project, as today.
- **Admins see and revoke every user's tokens.** They can't read a token's
  secret, which nobody can after creation.
- **Audit:** actions by token are recorded as the owner, with the token's
  name: `ada (token ci-shop)`. Uploads record the token that sent them.

### The token itself

- **Format:** the type's prefix and 32 random bytes, base32-encoded
  (lowercase, no padding). As with SonarQube's `squ_`, `sqp_` and `sqa_`,
  the prefix lets secret scanners, such as GitHub's custom patterns, find
  leaked tokens, and shows the type at a glance.
- **Shown once,** at creation. Afterwards only its name, type, project (for
  a project analysis token), first 12 characters, creation date, last use
  and expiry are shown.
- **Stored as SHA-256.** These are 256-bit random values, so a slow
  password hash adds nothing. Lookup is by hash, which a unique index makes
  constant-time with respect to the token's content.
- **Expiry is chosen at creation:** 30, 60 or 90 days, or no expiry, for
  every type. 30 days is preselected, as in SonarQube. A token past its
  expiry stops working and stays listed as expired.
- **Revocation is immediate** and kept: a revoked token stays listed, with
  who revoked it and when, and can't be reinstated.
- **Names** are unique per user, 1-100 characters, as in SonarQube.

```
api_tokens: id, user_id, type (user | project_analysis | global_analysis),
            project_key (project analysis tokens), name, hash (unique),
            prefix, created_at, expires_at, last_used_at,
            revoked_at, revoked_by
analyses:   + token_id (nullable): the token that uploaded it
```

`last_used_at` is updated at most once a minute per token, so uploads and
reads don't each write to the table.

### `SONDA_TOKEN` during migration

- **It keeps working, with the same rights as today,** so existing
  pipelines don't break when the server is upgraded.
- **It becomes optional.** A server without it accepts only users' tokens.
  `docs/server.md` will describe moving each pipeline to a project
  analysis token and then removing `SONDA_TOKEN`.
- **Uploads made with it are marked** (`token_id` null, audit name
  `api-token`), so admins can see which projects still use it.

Removing it entirely is a later decision, once the migration path has been
used.

### Where it shows

- **Account page, "Tokens":** generate a token (name, type, project for a
  project analysis token, expiry), copy it once, and see and revoke your
  own.
- **Admin page:** every user's tokens, with their owner, to revoke.
- **Analyses:** which token, and whose, uploaded each one, or `api-token`.

### Not now

- **A maximum token lifetime** set by admins (SonarQube has one). Expiry
  is each user's choice until that's needed.
- **Per-project permissions,** such as SonarQube's "Execute Analysis" per
  project. Tokens follow them when they exist.
- **Throttling failed bearer attempts.** Tokens are 256-bit random values,
  so guessing isn't practical, unlike passwords.

## Consequences

- **A leaked CI secret exposes one project** when it's a project analysis
  token, and rotating it touches one pipeline.
- **Every action by token is attributable** to a user.
- **Disabling a user who leaves cuts off their tokens,** including CI
  tokens they generated, so pipelines should use tokens of an account that
  stays, as with SonarQube.
- **Two credential paths exist during migration,** the shared token and
  users' tokens. The audit trail shows which one each upload used.
- **The CLI doesn't change:** `sonda upload` and `sonda scan --upload`
  already send a bearer token from `SONDA_TOKEN` or `SONDA_TOKEN_FILE`.
