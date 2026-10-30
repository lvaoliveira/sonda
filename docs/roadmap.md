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

## Security: CWE/OWASP mapping, hotspots, reachability

**Status:** the CWE/OWASP mapping is done (2026-10-30); hotspots and
reachability are planned, not started. The Security screen shows
vulnerabilities by severity, age, project, component, rule and OWASP
category. The design also has a hotspot review queue, and ranks findings
by whether they can be reached from a public entry point. Each needs its
own groundwork, smallest first:

1. **CWE and OWASP Top 10 mapping. Done.** Each rule records its CWE ids
   and OWASP Top 10 2021 categories (`rules/catalog/standards.rs`); its
   2025 categories are derived from the CWE ids with OWASP's own lists
   (`rules/owasp.rs`). Shown in `sonda rules`, SARIF taxonomies, the Rules
   page and the Security screen. `scripts/sonar_parity.py` reports drift
   of the 2021 categories from SonarQube's (SonarQube reports 2025 only in
   paid editions).
2. **Hotspots.** A fourth kind of finding: security-sensitive code that a
   person reviews (to review → safe, or → fix), rather than a confirmed
   vulnerability.
   - SonarQube treats several rules sonda ships as vulnerabilities as
     hotspots instead, such as weak hashes, cookie flags, CORS, commands run
     by name and file permissions. Moving them changes what the gate counts,
     so it needs an ADR.
   - Plugs into: a `hotspot` category in the core model and reports, a
     review status in the issue tracker (migration), the Security screen's
     review queue, and gate metrics (reviewed share).
3. **Reachability.** Whether a finding is on a path from a public entry
   point (an HTTP route, a CLI command).
   - Needs ADR-0008's data flow (S3) plus cross-file call summaries, which
     ADR-0008 defers to a later decision. It comes last.
   - Plugs into: a `reachable` flag on findings, used to rank the Security
     screen's "Fix these first".

## Dependencies: SBOM and known vulnerabilities

**Status:** planned, not started (2026-10-30). sonda analyzes a project's
own code only. Its third-party dependencies are a separate risk, and the
one OWASP Top 10 2025 ranks third (A03, Software Supply Chain Failures;
A06 in 2021). This item has two parts: list what a project depends on (an
SBOM), then match that list against published vulnerabilities.

### Design sketch

- **SBOM from lockfiles, in the CLI.** `sonda scan` reads lockfiles:
  - `package-lock.json`, `pnpm-lock.yaml` and `yarn.lock`;
  - `Cargo.lock`, `poetry.lock`, `uv.lock`, pinned `requirements.txt`,
    `go.sum`, and Gradle lockfiles.

  It records each package's ecosystem, name, exact version, whether it's
  direct or transitive, and which lockfile it came from. It's offline,
  like the rest of a scan, and never runs a package manager or build tool
  (docs/engineering-standards.md). Maven's `pom.xml` has no resolved
  versions without running Maven, so it waits for a lockfile-like source.
- **Export** as CycloneDX 1.6 and SPDX 2.3 JSON (`sonda sbom`, or a report
  format), with package URLs (purl) as the identifiers both formats and
  every advisory database share.
- **Vulnerability data from OSV, matched on the server.**
  - [OSV.dev](https://osv.dev) aggregates the GitHub Advisory Database,
    RustSec, PyPI, Go and others. It keys advisories by ecosystem, package
    and affected version ranges, keeps CVE ids as aliases, and publishes
    bulk exports per ecosystem.
  - CVE.org is the registry of CVE ids, not a package-to-version index, so
    it can't match a lockfile on its own. NVD adds CVSS scores for CVE
    aliases.
  - The server keeps a local mirror, synced daily from OSV's exports, and
    matches each project's latest SBOM against it. This has two benefits:
    no dependency list leaves the network, and a newly published advisory
    shows up without a rescan. `sonda scan --offline-db DIR` could match
    in the CLI for users without a server.
- **Findings.** A new kind next to code issues: a vulnerable dependency,
  with:
  - the advisory id and its CVE aliases;
  - severity from CVSS where present;
  - the fixed version, if any;
  - its CWE ids, which plug into the standards from #37.

  Gate metrics: `new_vulnerable_dependencies` and
  `vulnerable_dependencies`, by severity.
- **Web.** A Dependencies tab per project (the SBOM, filterable, with
  licenses where lockfiles record them). The Security screen counts
  vulnerable dependencies and ranks them by severity and whether a fix
  exists. Later, reachability (above) can show whether the vulnerable
  function is actually called.

### Decisions to make when starting

- **An ADR**, since this changes the report model, the gate metrics, the
  upload format and the server's database.
- **Sources:** OSV only, or also GitHub's advisories directly and NVD for
  scores? Weigh licensing too: OSV data is CC-BY 4.0, and each source
  database has its own terms.
- **Where matching happens:** server-only, or also an offline CLI mode,
  and how the mirror is distributed to air-gapped installs.
- **Licenses:** report each dependency's license (and a license policy in
  the gate) now, or later?
- **Withdrawn advisories and suppressions:** how a team marks one as not
  applicable, with an audit trail like accepted issues.

### Done when

- Scans of the reference projects produce SBOMs that validate against the
  CycloneDX and SPDX schemas and match their package managers' own
  dependency trees.
- A known-vulnerable fixture (for example a pinned old `lodash`) is
  reported with the right advisory, CVE alias and fixed version. Upgrading
  it clears the finding on the next analysis.
- A new advisory synced into the mirror flags an already-analyzed project
  without a rescan.

## Smaller items

| Item | Why it waits | Where it plugs in |
|---|---|---|
| **Teams** | No teams, so the Overview has no "My team" scope. | Teams as user groups and project ownership; the Overview's `teams` flag. |
| **Health score change** | Needs ratings history, which the server does not reconstruct yet. | Compute ratings per stored analysis; fills `health.delta` and "vs N days ago". |
| **Per-file coverage** | Reports carry coverage per project only. | Add per-file coverage to the report (from LCOV); the coverage drill-down lists files. |
| **Commit messages and scan durations** | Not uploaded; Recent analyses shows "—". | `sonda upload` sends `git log -1` and the scan duration. |
| **Design features without data** | The designs show monorepo components (go.work, Cargo and pnpm workspaces), saved views, and analysis stages and logs. Nothing records them. | Each needs its data captured first (the CLI or the rules), then the screen shows it. |
| **Narrow screens** | The app shell keeps its sidebar at phone widths, so pages scroll sideways. | Collapse the sidebar into a menu below a breakpoint, in `AppShell`. |
| **Server-managed rule profiles** | Rules are configured per repository in `sonda.toml`; the Rules page is read-only. | A profile `sonda scan` downloads; decide what wins over `sonda.toml`. |
| **Per-user or per-project API tokens** | One server token serves every upload (ADR-0006). | Tokens owned by users or projects, revocable, shown once. |
| **Private CA for `sonda upload`** | Upload trusts Mozilla's roots only. | A `--ca-cert` option (SECURITY.md lists the limitation). |
| **Safari and `Secure` cookies on http://localhost** | Sign-in is verified in Chrome only. | Test Safari; behind TLS it doesn't matter. |
| **Rest of semantic phase S1** | S1 is built for JavaScript/TypeScript with twelve rules ([ADR-0008](adr/0008-semantic-layer.md)). | On the same model: unused private methods (S1144), variables used before their declaration (S1526). Then binders for Python, Java and C/C++. |
| **Release-age check for Rust crates** | Dependabot waits 14 days, but crates added by hand aren't checked. | A CI step comparing `Cargo.lock` dates, with a list of security exceptions. |
