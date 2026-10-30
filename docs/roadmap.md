# Roadmap: deferred work

Work that is planned but deliberately not done yet. Each item says why it
waits and where it plugs in, so it can be picked up without re-deriving the
context. Significant ones get an ADR when they start.

## Single sign-on (OpenID Connect)

**Status:** deferred (2026-10-30). Users sign in with username and password
([ADR-0006](adr/0006-users.md)). ADR-0006 already keeps room for SSO: a
user's `password_hash` is nullable, and accounts are never deleted.

### Design sketch

- **Identities table.** `identities (provider, subject, user_id,
  created_at)`, unique on `(provider, subject)`. `subject` is the provider's
  stable `sub` claim, never an email address, which can change or be
  reassigned. A user can have a password, one or more identities, or both.
- **Providers in config, not the database.** One OpenID Connect provider at
  first, configured like the other secrets:
  - `SONDA_OIDC_ISSUER` (discovery URL), `SONDA_OIDC_CLIENT_ID`,
    `SONDA_OIDC_CLIENT_SECRET_FILE`
  - `SONDA_PUBLIC_URL` (for the redirect URI)
  - optionally `SONDA_OIDC_ALLOWED_DOMAINS` and
    `SONDA_OIDC_ADMIN_GROUP`
- **Flow.** Authorization Code with PKCE.
  - `GET /api/sso/start` sets `state` and `nonce` in a short-lived,
    `HttpOnly` cookie and redirects to the provider.
  - `GET /api/sso/callback` checks `state`, exchanges the code, and
    validates the ID token: signature against the provider's JWKS (cached,
    refreshed when a `kid` is unknown), `iss`, `aud`, `exp`/`iat` with small
    clock skew, and `nonce`.
  - It then creates the same `__Host-` session cookie password sign-in uses.
    Sessions, roles, CSRF and audit don't change.
- **Matching a login to a user.**
  1. An existing identity `(provider, sub)`: sign that user in.
  2. Otherwise, if auto-provisioning is on and the email is
     `email_verified` and in an allowed domain: create a `member` (or an
     `admin`, if in the admin group) with a username derived from the
     email, no password, and the identity.
  3. Otherwise refuse, saying an admin must invite the user.

  **Never link to an existing password account by email alone.** That
  lets anyone who controls an address at the provider take over the
  account. Linking an existing user is an explicit action: the user signs
  in with their password, then connects SSO under Account. An admin can't
  link on someone's behalf.
- **Disabled users** stay refused, whatever the provider says.
- **Password sign-in** can be turned off once SSO works
  (`SONDA_PASSWORD_LOGIN=false`). Keep at least one break-glass admin with
  a password, documented, so a provider outage can't lock everyone out.
- **Web.** The sign-in page shows "Sign in with <provider>" next to, or
  instead of, the password form. Under Account, a user can connect or
  disconnect an identity. Administration shows each user's identities.

### Decisions to make when starting

- **Provisioning:** auto-provision by domain, or invite-only (an admin
  creates the user, who then connects SSO)?
- **Roles from the provider:** map groups to roles on every sign-in, or
  only on creation?
- **Crate:** `openidconnect` (complete, larger dependency tree) versus a
  small hand-written flow on `jsonwebtoken`. Apply the usual dependency
  review: maintenance, licenses, the 14-day minimum age.
- **More than one provider** at once, or exactly one?
- **Logout:** sonda only, or also the provider's session (RP-initiated
  logout)?

### Done when

- A user signs in through a real provider (Keycloak in Docker Compose for
  the tests) and gets a normal session. Disabled users are still refused.
- Tests cover the token checks: a forged signature, the wrong audience, an
  expired token, a replayed `nonce` and a mismatched `state` are all
  refused.
- Email-based takeover is impossible. A test proves an unverified or
  foreign email never links to an existing account.
- ADR-0007 records the decisions above. SECURITY.md and docs/server.md
  describe the setup.

## Smaller items

| Item | Why it waits | Where it plugs in |
|---|---|---|
| **Teams** | No teams, so the Overview has no "My team" scope. | Teams as user groups and project ownership; the Overview's `teams` flag. |
| **Health score change** | Needs ratings history, which the server does not reconstruct yet. | Compute ratings per stored analysis; fills `health.delta` and "vs N days ago". |
| **Per-file coverage** | Reports carry coverage per project only. | Add per-file coverage to the report (from LCOV); the coverage drill-down lists files. |
| **Commit messages and scan durations** | Not uploaded; Recent analyses shows "—". | `sonda upload` sends `git log -1` and the scan duration. |
| **Remaining screens** | Projects, Components, Security, Analyses and Quality gates show "not built yet". | One per increment, from `docs/designs/`. |
| **Server-managed rule profiles** | Rules are configured per repository in `sonda.toml`; the Rules page is read-only. | A profile `sonda scan` downloads; decide what wins over `sonda.toml`. |
| **Per-user or per-project API tokens** | One server token serves every upload (ADR-0006). | Tokens owned by users or projects, revocable, shown once. |
| **Private CA for `sonda upload`** | Upload trusts Mozilla's roots only. | A `--ca-cert` option (SECURITY.md lists the limitation). |
| **Safari and `Secure` cookies on http://localhost** | Sign-in is verified in Chrome only. | Test Safari; behind TLS it doesn't matter. |
| **Release-age check for Rust crates** | Dependabot waits 14 days, but crates added by hand aren't checked. | A CI step comparing `Cargo.lock` dates, with a list of security exceptions. |
