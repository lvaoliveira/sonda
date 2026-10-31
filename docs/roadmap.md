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

**Status:** built, per [ADR-0009](adr/0009-dependencies-and-advisories.md),
which supersedes the sketch below where they differ (2026-10-30): SBOMs,
server storage, advisory import and sync, matching, triage, the Security
screen and gate metrics, `new_vulnerable_dependencies` included. Left:
more lockfile formats (Go, Gradle; Bun's binary `bun.lockb`, which `bun install --save-text-lockfile` converts). sonda
analyzes a project's own code only. Its third-party dependencies are a
separate risk, and the one OWASP Top 10 2025 ranks third (A03, Software
Supply Chain Failures; A06 in 2021). This item has two parts: list what a project depends on (an
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

## AI auto-fix: issues, bugs and coverage gaps as pull requests

**Status:** planned (2026-10-30), nothing built. An admin adds an AI API
token and connects a GitHub or GitLab repository. From an issue (or a
failing gate condition), the server asks the model for a fix and opens a
pull request or merge request with it. A person reviews and merges; sonda
never merges anything itself.

### Design sketch

- **What can be fixed.**
  - Issues: rules with a mechanical fix first (`js/eqeqeq`, `js/no-var`,
    unused imports and variables, `c/unsafe-string-function`), then bugs,
    vulnerabilities and code smells such as cognitive complexity.
  - Coverage: tests for uncovered new code, from the LCOV data the report
    already carries.
  - Entry points: a "Fix with AI" action on an issue, a bulk action on a
    filtered list, and later an option to fix everything that fails the
    gate on a branch.
- **Integrations.** A GitHub App and a GitLab project or group token, per
  project. The server clones the branch, applies the change on a new
  `sonda/fix-<issue>` branch, and opens the PR or MR. The description
  links the issue, its rule and the analysis that found it.
- **AI provider.** One server-wide API token to start (Anthropic first,
  behind a small provider trait so others can follow), set by an admin and
  never returned by the API once saved.
- **Verify before proposing.** Re-run `sonda scan` on the patched tree and
  open the PR only if the original issue is gone and no new issue appears
  in the changed files. Run the project's own tests where a command is
  configured. For coverage fixes, require the new tests to pass and the
  covered lines to rise. A fix that fails any check is reported on the
  issue and not proposed.
- **Review stays human.** Draft PRs by default, the diff and the model's
  reasoning in the description, a per-run limit on files and lines
  changed, and no auto-merge.

### Decisions to make when starting

- **An ADR**, since this adds outbound calls to a third party, stored
  credentials for the AI provider and each forge, and the first write
  path from the server back into a user's repository.
- **The analyzed repository is untrusted input** (CLAUDE.md). Source,
  comments and file names go into a prompt, so a repository can try to
  steer the model. Treat the model's output as untrusted too: it may only
  produce a patch, never run commands, and the patch is checked (paths
  stay inside the repo, no changes to CI files, `sonda.toml`, lockfiles or
  hooks unless allowed) before it is applied.
- **Where code runs.** Cloning, applying the patch and running tests means
  executing a repository's code on the server. Decide between a sandboxed
  worker (as in ADR-0004), an external CI job the server triggers, or
  patch-only fixes with no test run.
- **What leaves the building.** Source is sent to an AI provider. Needs an
  explicit per-project opt-in, a way to exclude paths (secrets, vendored
  code), secret scanning of the prompt, and a statement about retention
  and training terms in the docs.
- **Credentials.** Encryption at rest for the AI and forge tokens, scopes
  as narrow as possible (one repo, pull requests and contents write only),
  rotation, and an audit log of every fix request, who made it and what it
  cost.
- **Cost and abuse.** Per-project and per-user budgets, rate limits, and a
  cap on concurrent runs.
- **Idempotence.** One open PR per issue; a later analysis that fixes the
  issue closes it, and a re-detected issue reopens the discussion rather
  than opening a second PR.

### Done when

- On a fixture repository, "Fix with AI" on a known issue opens a draft PR
  whose branch, when scanned, no longer reports that issue, with no new
  issues.
- A coverage fix adds tests that pass and raise the file's covered lines.
- A fix that does not verify, or a patch outside the allowed paths, opens
  no PR and shows the reason on the issue.
- A repository file that says to ignore its instructions and edit CI
  config does not change the PR's files.
- The AI and forge tokens never appear in an API response, a log line or
  a PR description, and a request over budget is refused.

## Smaller items

| Item | Why it waits | Where it plugs in |
|---|---|---|
| **Teams** | No teams, so the Overview has no "My team" scope. | Teams as user groups and project ownership; the Overview's `teams` flag. |
| **Health score change** | Needs ratings history, which the server does not reconstruct yet. | Compute ratings per stored analysis; fills `health.delta` and "vs N days ago". |
| **Design features without data** | The designs show monorepo components (go.work, Cargo and pnpm workspaces), saved views, and analysis stages and logs. Nothing records them. | Each needs its data captured first (the CLI or the rules), then the screen shows it. |
| **Narrow screens** | The app shell keeps its sidebar at phone widths, so pages scroll sideways. | Collapse the sidebar into a menu below a breakpoint, in `AppShell`. |
| **Server-managed rule profiles** | Rules are configured per repository in `sonda.toml`; the Rules page is read-only. | A profile `sonda scan` downloads; decide what wins over `sonda.toml`. |
| **Admins generate tokens for other users** | Users generate only their own tokens (ADR-0012), so a CI token belongs to a person, and disabling them stops their pipelines. | As in SonarQube: a generate form on the Admin page with an owner field, so CI tokens can belong to a `ci` service user; `POST /api/tokens` with a `user`, admins only. |
| **Private CA for `sonda upload`** | Upload trusts Mozilla's roots only. | A `--ca-cert` option (SECURITY.md lists the limitation). |
| **Safari and `Secure` cookies on http://localhost** | Sign-in is verified in Chrome only. | Test Safari; behind TLS it doesn't matter. |
| **Regex analysis** | 35 SonarQube rules (about 85 per-language instances) read a pattern as a pattern, which tree-sitter queries cannot do ([ADR-0013](adr/0013-regex-analysis.md), proposed). | A parser for the JavaScript, Python and Java dialects, then syntax rules (R1), language rules (R2) and backtracking detection (R3). |
| **Rest of semantic phase S1** | S1 is built for JavaScript/TypeScript with twelve rules ([ADR-0008](adr/0008-semantic-layer.md)). | On the same model: unused private methods (S1144), variables used before their declaration (S1526). Then binders for Python, Java and C/C++. |
| **Release-age check for Rust crates** | Dependabot waits 14 days, but crates added by hand aren't checked. | A CI step comparing `Cargo.lock` dates, with a list of security exceptions. |
