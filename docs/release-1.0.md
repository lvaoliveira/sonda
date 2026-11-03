# Plan: sonda 1.0

1.0 is a promise: upgrading within 1.x doesn't break anyone. A pipeline
keeps working when the server is upgraded, a `sonda.toml` keeps meaning the
same thing, and a server's data survives every upgrade. This plan is the
work that makes the promise true and shows it holds. Each milestone has a
"done when" to tick off in the pull requests that do it.

The features 1.0 needs are few. Most of the work is proving what's built:
both bugs found on the first real deployment (2026-11-02), the sandbox
killing most parsers in the static x86_64 CLI and coverage paths that
matched no file, got past more than 800 tests.

| Milestone | What | Size | Needs |
|---|---|---|---|
| [M0](#m0-010) | 0.1.0: the first tagged release | S | — |
| [M1](#m1-the-stability-promise) | What 1.0 promises, written down and tested | M | M0 |
| [M2](#m2-safe-upgrades) | Upgrades tested on real data, retention | M | M0 |
| [M3](#m3-release-hardening) | Binaries for every platform, image, signatures | M | M0 |
| [M4](#m4-proven-in-real-use) | Weeks of real use, in every language | L | M0, then runs alongside the rest |
| [M5](#m5-security) | The server's threat model, a review, the open limitations | M | — |
| [M6](#m6-what-the-product-still-needs) | The few features 1.0 can't ship without | M | — |

0.x releases go out as milestones land. 1.0 is cut when every "done when"
below holds, with the [exit criteria](#exit-criteria) at the end.

## Decisions to make first

- **Is the server's HTTP API part of the promise?** Proposed: no. The web
  app is its one client and moves with it; the CLI's upload protocol is
  the promised surface. Promising the HTTP API would mean versioning it.
- **How far back does a server accept a CLI?** Proposed: the previous
  minor version and the current one. CI pipelines pin a CLI while servers
  upgrade.
- **Do branch analyses expire?** Pull requests' expire after 30 days;
  branches' are kept forever, with their sources. Proposed: keep them, with
  a setting to expire analyses older than N days except each branch's
  latest, and document how storage grows.
- **Should Connect's tokens expire?** It creates analysis tokens with no
  expiry, so CI doesn't stop on a date. Proposed: keep that, and show each
  token's last use on Account → Tokens so unused ones get revoked.
- **Which platforms get release binaries?** Proposed: Linux x86_64 and
  arm64 (static), macOS arm64, Windows x86_64: the ones CI already tests.

## M0: 0.1.0

The first release anyone can download. Today everyone builds from `main`.

- [x] A release workflow: on a `v*` tag, build the CLI's static Linux
      binaries (x86_64, arm64) from the image's `cli` target, with
      SHA-256 checksums, and attach them to a GitHub Release.
- [x] `scripts/install-cli.sh` and `setup-server.sh` documented against a
      release tag, not `main`.
- [x] CHANGELOG: `Unreleased` becomes `[0.1.0]`, with a short summary of
      what sonda is at the top.
- [x] The `v0.1.0` tag, pushed by the maintainer.

**Done when** a release page has the binaries and checksums, and a fresh
machine runs the server and the CLI from it by following the docs.

## M1: the stability promise

- [ ] `docs/stability.md`: what 1.0 promises and what it doesn't (from the
      decisions above): CLI options and exit codes, `sonda.toml`, the JSON
      and SARIF reports, the upload protocol, the `sonda-core` API; not the
      server's HTTP API, the web app or rule results (rules get better).
- [ ] The compatibility window enforced in CI: the previous release's CLI
      uploads to the new server (and the new CLI to the previous server, if
      promised), on every pull request.
- [ ] What changes a rule's results is said in the changelog, under its own
      heading, since a new finding can fail a gate.
- [ ] Deprecation rule: a promised thing is deprecated with a warning for
      at least one minor release before it goes.

**Done when** the document is merged and the compatibility job is required
in CI.

## M2: safe upgrades

- [ ] A CI job that runs the previous release's server on a database it
      filled (users, projects, analyses, triage, gates, profiles), upgrades
      to the new one, and checks everything is still there and served.
- [ ] Upgrade docs: back up first (there's no downgrade), then
      `git pull && scripts/setup-server.sh` or the new image; each release
      says if it needs more.
- [ ] Retention, as decided above, and storage growth measured and
      documented (per analysis, per file, deduplicated sources).
- [ ] A migration that fails leaves the database as it was (each runs in a
      transaction) and the server says so instead of half-starting; tested.

**Done when** the upgrade job is required in CI and the docs are merged.

## M3: release hardening

- [ ] Release binaries for the platforms decided above, built and tested in
      CI (the sandbox check in `docker-cli` on each Linux one).
- [ ] The server image published to GHCR per release, pinned by digest in
      the docs, as [ADR-0005](adr/0005-sonda-server.md) intended.
- [ ] Build provenance attestations for binaries and image, and an SBOM of
      each (sonda writes CycloneDX already).
- [ ] The release workflow checks every binary runs a scan in every
      language before publishing.

**Done when** a release publishes all of it from a tag, with nothing done
by hand.

## M4: proven in real use

The longest milestone; it starts at 0.1.0 and runs while the others are
built.

- [ ] Real repositories, in CI with pull request decoration, for at least
      four weeks:
  - JavaScript and C: arandu (connected 2026-11-02);
  - TypeScript, TSX: arandu-console, uvw, and sonda's own `web/`;
  - Python: ha-budgetthuis-prices, and a larger public project;
  - Java, C#, C++: public projects that publish SonarCloud results,
    chosen when this starts.
- [ ] Findings compared with SonarQube's on the same commit for each
      language ([ADR-0007](adr/0007-sonarqube-rule-parity.md)): every
      difference is a bug, a known gap listed in `docs/rules.md`, or a
      deliberate change.
- [ ] Performance measured on a large repository (time, peak memory, worker
      count) and on a server with thousands of analyses (page and upload
      times); limits documented.
- [ ] Sign-in and the main pages checked in Safari and Firefox, not only
      Chrome.
- [ ] Every bug found gets a test that would have caught it, like the
      `docker-cli` sandbox check did for the musl one.

**Done when** four consecutive weeks of use across those repositories turn
up no new bug that loses findings, coverage or data.

## M5: security

- [ ] SECURITY.md's server section finished as a threat model, as
      [ADR-0005](adr/0005-sonda-server.md) requires before release: users
      and tokens, sessions and CSRF, uploads, the GitHub App and its key,
      `SONDA_PLAIN_HTTP` on a LAN, HTTPS through Caddy, Connect's tokens.
- [ ] `sonda upload --ca-cert`, closing the listed limitation: a server
      behind a private CA (Caddy's included) can't receive uploads from
      another machine today.
- [ ] A full security review of the server: authentication, authorization
      per endpoint, CSRF, token handling, the decoration task, the web
      app's handling of uploaded content. Findings fixed or documented.
- [ ] The Windows sandbox limitation stays documented, or is closed.

**Done when** the threat model is merged and the review's findings are
fixed or written up as accepted risks.

## M6: what the product still needs

- [ ] Pull request decoration follows triage
      ([ADR-0021](adr/0021-pull-request-decoration.md), part 3): accepting
      an issue on a pull request's latest analysis re-posts its check and
      comment. Without it, the pull request keeps showing what was
      accepted.
- [ ] Every ADR's status matches what's built (C# shipped while
      [ADR-0015](adr/0015-csharp.md) is still "proposed"; also 0013, 0020).
- [ ] Pages no longer flicker on every navigation (the roadmap's `useAsync`
      cache).
- [ ] Each roadmap item marked as before or after 1.0 (most are after:
      GitLab and Bitbucket, single sign-on, AI auto-fix, teams, the health
      trend, regex analysis, the rest of the semantic rules).

**Done when** these are merged and the roadmap says what comes after 1.0.

## Exit criteria

1.0 is tagged when all of these hold:

- M1–M6 are done.
- The compatibility and upgrade jobs are required in CI and pass.
- Four weeks of real use (M4) found no new bug that loses findings,
  coverage or data.
- The last 0.x release ran on every repository in M4 for at least a week
  with no change but fixes.
