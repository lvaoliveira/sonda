# ADR-0006: Users, sign-in and roles

- Status: **accepted**
- Date: 2026-10-30
- Builds on [ADR-0005](0005-sonda-server.md) (the server, its sessions and
  token)

## Context

The server has one secret, the API token (`SONDA_TOKEN`). CI uploads with
it, and browsers sign in by pasting it. That worked for one person, but:

- **Every browser holds the same credential.** One person can't lose access
  without everyone losing it.
- **The audit trail can't say who did what.** It records that a status
  changed, not by whom.
- **"Assign to me" relies on a name typed at sign-in,** which nothing
  checks.
- **There is nowhere to add SSO later.**

## Decision

### Users

```
users: id, username, display_name, role (admin | member),
       password_hash (nullable), disabled, created_at, last_login_at
```

- **Usernames** are lowercase letters, digits, `.`, `_` or `-`, 2-64
  characters. They are stable and used as assignees.
- **Passwords** are hashed with **Argon2id** (RustCrypto `argon2`, OWASP
  parameters: 19 MiB, 2 iterations), as self-describing PHC strings, so
  parameters can be raised later without breaking stored hashes. Hashing
  runs off the async workers.
- **Policy:** passwords must have at least 12 characters, and nothing else
  is required (NIST SP 800-63B). Long passphrases beat composition rules.
- **`password_hash` is nullable** for future SSO-only users.
- **Users are never deleted, only disabled,** so the audit trail keeps its
  references.

### The first admin

On startup, after migrations, if **no users exist** and
`SONDA_ADMIN_PASSWORD` or `SONDA_ADMIN_PASSWORD_FILE` is set, the server
creates `admin` (or `SONDA_ADMIN_USERNAME`) with that password. Once any
user exists, the variable is ignored, so changing the secret file never
resets a password.

`compose.yaml` reads it from `secrets/admin_password`, generated like the
other secrets. Without it and without users, the server still runs:
uploads work, the web app explains how to create the admin, and the server
logs a warning.

A first-visit setup page was rejected: whoever reaches a fresh server
first would own it.

### Sign-in

- **Browsers** sign in with username and password (`POST /api/session`).
  The answer is the existing `HttpOnly`, `__Host-` session cookie, which now
  belongs to a user. Browser sign-in with the API token is removed.
- **Unknown usernames** are still hashed against a fixed dummy hash, and
  every failure gets the same message, so response time and wording don't
  reveal which usernames exist.
- **Disabled users** can't sign in. Disabling someone ends their sessions.
- **Changing your own password** needs the current one, and ends your other
  sessions.

### Roles

| | member | admin |
|---|---|---|
| Read (when reads need sign-in) | ✓ | ✓ |
| Triage: status, assignee | ✓ | ✓ |
| Manage users | | ✓ |

Admins list, create and edit users: display name, role, disabled, and a
password reset. The server refuses to disable or demote the last active
admin, which would lock everyone out.

### The API token

The token stays the machine credential for `sonda upload`, and still works
as a bearer token for reads and triage from scripts. It cannot manage users.
Per-user or per-project tokens can replace it later.

### Audit

`issue_events` gains `actor`: the username of whoever changed the issue, or
`api-token`. The issue view shows it.

### Later: SSO

OpenID Connect will add an `identities` table (provider, subject, user id).
A user can then sign in with a password, through SSO, or both. It's
deferred: the design sketch and the decisions still open are in
[docs/roadmap.md](../roadmap.md#single-sign-on-openid-connect). Nothing here
needs to change for that, so the table is not created until it's used.

## Consequences

- **Upgrading needs an admin.** Existing deployments must add
  `SONDA_ADMIN_PASSWORD_FILE` (compose.yaml does) to create one.
  Token-based browser sessions are ended by the migration.
- **Sign-in throttling** was added after this ADR was accepted (migration
  0004). Failures are counted per normalized username, whether or not the
  user exists. After 5 in 15 minutes, each attempt waits 1, 2, 4 ... up to
  900 seconds, refused with `429` before any hashing. It's a wait rather
  than a lockout, so an attacker can slow a user down but not shut them
  out. There's no per-address limit: behind a proxy the server can't trust
  client addresses, so that belongs at the proxy.
