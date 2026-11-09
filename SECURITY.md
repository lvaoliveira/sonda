# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's **"Report a vulnerability"**
button on this repository's Security tab. Don't open a public issue. Please
include a reproduction, such as a minimal repository or file that triggers
the problem.

Only the latest release receives fixes while sonda is at 0.x.

## Verifying a release

Each release's binaries and server image carry a signed build provenance
attestation, saying which commit and workflow built them, and an SBOM
(CycloneDX), attested too. With the [GitHub CLI](https://cli.github.com/):

```sh
# A binary, downloaded from the release page
gh attestation verify sonda-<version>-x86_64-linux --repo lvaoliveira/sonda
# Its SBOM
gh attestation verify sonda-<version>-x86_64-linux --repo lvaoliveira/sonda \
  --predicate-type https://cyclonedx.org/bom
# The server image, by the digest the release notes give
gh attestation verify oci://ghcr.io/lvaoliveira/sonda@sha256:<digest> --repo lvaoliveira/sonda
```

The checksums in the release's `SHA256SUMS` only say the download is intact;
the attestation says who built it. The SBOMs are also attached to the
release: `sonda-<version>-<platform>.cdx.json` for each binary (its locked
crates; the platforms are `x86_64-linux`, `aarch64-linux`, `aarch64-macos`
and `x86_64-windows`, whose binary ends in `.exe`) and `sonda-<version>-image.cdx.json` for the image (the server's
crates and the web app's packages).

## Threat model

sonda is built to analyze code you don't trust, such as a pull request from
a stranger or a downloaded archive.

**Untrusted**: everything inside the analyzed directory:
- file contents, file names, directory structure and symlinks
- `.gitignore` and `.gitattributes`
- `.git/` and its config
- the repository's own `sonda.toml`

**Trusted**: the person running sonda, the command-line arguments (which are
still validated), and the files they explicitly name (`--config`,
`--coverage`, `-o`).

### What sonda guarantees

- **No code execution.** sonda never runs, imports or evaluates analyzed code.
  It only asks git to read objects (`rev-parse`, `merge-base`, `ls-tree`,
  `cat-file`). It never runs commands that can start programs configured in
  the repository, such as fsmonitor, clean/smudge filters, textconv or
  external diff ([ADR-0002](docs/adr/0002-new-code-from-git-objects.md)).
  Tests configure each of these in a hostile repository and fail if any runs.
- **No argument injection.** A `--new-code` reference that starts with `-`
  or contains whitespace or control characters is rejected, and references
  are passed to git after `--end-of-options`.
- **A single file cannot crash or stall a scan:**
  - Reads are capped at `scan.max_file_size_kb`.
  - Parsing and rule matching stop at `scan.file_timeout_secs`.
  - Syntax trees are walked without recursion, which is tested with 100,000
    levels of nesting.
  - Duplication detection runs in linear time, even on input crafted to be
    repetitive.
- **A parser crash cannot abort a scan.** Files are parsed in worker
  processes. If one crashes or hangs, that file becomes a warning, the
  worker is restarted, and the report covers everything else. The parent
  validates every worker reply as untrusted input.
- **A parser exploit is contained on Linux and macOS**
  ([ADR-0004](docs/adr/0004-sandbox-workers.md)). Each worker sandboxes
  itself before it reads any file:
  - **Linux:** a seccomp allow-list. Opening files fails, and network
    access or starting programs kills the worker.
  - **macOS:** Seatbelt `(deny default)`.
  - **Both:** no core dumps and no new file descriptors.

  Tests check that a sandboxed worker cannot read a file, connect to a
  socket or start a program. `--sandbox require` fails the run if a worker
  cannot be sandboxed. The default, best-effort, logs a warning instead.
- **git cannot hang a scan.** Every git process is killed after
  `scan.git_timeout_secs` (default 120), and the run fails with a clear
  error instead of waiting forever.
  - Malformed files become warnings.
- **No reads outside the scan root.** Symlinks are not followed. On Unix,
  each file is opened non-blocking and checked to be a regular file, and the
  same file (device and inode) the walk listed. A file or directory swapped for a symlink or a
  FIFO between listing and reading is skipped with a warning; it is not
  followed, and it cannot hang the scan.
- **No terminal injection.** Control characters and Unicode bidi overrides
  ("Trojan Source") from the repository are shown as visible `\u{..}`
  escapes in text reports, error messages and logs. JSON and SARIF escape
  them through the serializer.
- **Deterministic output**, so results can be audited and reproduced.
- **`sonda upload` sends only what was analyzed.** The report file is
  treated as untrusted:
  - Paths must be relative, with no `..`, and may not pass through a symlink.
    So a tampered report cannot make it send `~/.ssh/id_rsa` or
    `/etc/passwd`.
  - Every file must match the SHA-256 the scan recorded, so a file edited or
    swapped since the scan is refused, not uploaded.
  - All checks run before any connection is made.
  - The repository's CODEOWNERS file, sent for owners, is read the same
    way: no symlinks, regular files only, capped at 128 KiB. Otherwise it
    is left out.
- **Tokens are scoped, and don't leak.** Users generate their own, and admins
  generate them for service users such as `ci` (ADR-0012): a project analysis token uploads one project only, and every token stops
  when its owner is disabled, expires or is revoked. The server stores only
  their SHA-256. The CLI reads the token from `SONDA_TOKEN` or a file,
  never a command-line flag, because flags are visible in `ps` and CI logs.
  It is sent only over HTTPS, except to `localhost`. Redirects are not
  followed, so it only goes to the URL you named. URLs with embedded
  credentials are refused. Server certificates are checked against Mozilla's
  root certificates (webpki-roots), or, with `--ca-cert`, against only the
  authorities it names, such as the one `setup-server.sh --https` creates. A
  file holding a private key is refused there, and so is a certificate that
  isn't a valid authority, rather than skipped.

### Known limitations

- **Windows workers are not sandboxed.** tree-sitter's runtime and grammars
  are C, called through FFI. They run in worker processes
  ([ADR-0003](docs/adr/0003-isolate-parsing.md)) everywhere, so a parser
  crash only loses one file. On Linux and macOS the workers are also
  sandboxed (above). On Windows, a crafted file that exploits a parser bug
  would run with your privileges. Use `--sandbox require` to refuse to scan
  where the sandbox is unavailable. The parsers are fuzzed weekly with
  AddressSanitizer.
- **File-swap check is Unix-only.** On Windows (where creating symlinks needs
  elevated rights) the identity check below is not available.
- **The repository's own `sonda.toml` is trusted by default.** A pull request
  can edit it to disable rules or weaken the quality gate. In CI, load the
  config from a trusted place instead, such as the base branch:

  ```sh
  git show origin/main:sonda.toml > /tmp/sonda.toml
  sonda scan . --config /tmp/sonda.toml --new-code origin/main
  ```

## The server

`sonda-server` ([docs/server.md](docs/server.md)) stores the analyses CI
uploads and serves the web app that people triage them in. It's sonda's
only networked, stateful part, so it has a threat model of its own
([ADR-0005](docs/adr/0005-sonda-server.md)).

### What it protects

- **Source code.** Every upload carries the analyzed files, so the server
  holds a copy of each project's code. This is the main asset.
- **Triage.** Issue statuses, assignees and the audit trail, which decide
  what a quality gate counts.
- **What it says on GitHub.** The `sonda` check and comment on pull
  requests, which a branch protection rule may require.
- **Credentials:** passwords, sessions, API tokens, the GitHub App's
  private key, and `SONDA_SECRET_KEY`, which encrypts that key.

### Who it trusts

| Actor | Trust | Can |
|---|---|---|
| Anyone on the network | None | Sign in, check `/api/health`; read only while the server listens on loopback |
| A member | Signed in | Read every project, triage, manage their own tokens |
| An admin | Fully | Everything a member can, plus users, tokens, projects, settings and the GitHub App |
| A user token | As its owner | Read and triage, as the user; never manage accounts or tokens |
| A global analysis token | Upload only | Upload to any project, creating it if new; read rule settings |
| A project analysis token | Upload only | Upload to its one project, creating it if new; read its rule settings |
| `SONDA_TOKEN` (shared) | A machine | Upload, read and triage; never manage accounts or tokens |
| GitHub | For its own answers | Its API's replies are parsed as untrusted JSON, capped at 4 MiB |
| The operator | Fully | The host, the environment, the database and the reverse proxy |

**Untrusted:** everything that arrives over the network: requests,
headers, and uploads, whose files, paths, issues and messages come from
whoever holds a token. What CI uploads is only as trustworthy as the CI
job that ran the scan.

**Trust boundaries:** the browser and the server (the session cookie and
the `Sonda-Csrf` header); CI and the server (an upload token); the server
and GitHub (the App's key and installation tokens); the server and
PostgreSQL (`DATABASE_URL`); and the reverse proxy in front, when there is
one.

### Exposure

- **Not exposed by default:** it listens on `127.0.0.1`. The Docker image
  listens on all interfaces inside the container, but Compose publishes the
  port on the host's localhost only. The database container publishes no
  port at all.
- **Reads need authentication off loopback.** While the server listens on
  loopback only, anyone who can reach it can read, since only the host's
  own users can. Once it listens beyond loopback, as it does in Docker,
  every read needs a token or a browser session.
- **No outbound connections unless asked:** only to GitHub, once an App is
  connected, and to OSV, with `SONDA_ADVISORY_SYNC`. The GitHub client
  follows no redirects, so a token is never sent anywhere else.
- **Metrics are on their own listener** (`SONDA_METRICS_LISTEN`), off by
  default and unauthenticated. They hold counts, never code or names, but
  they belong on an address only the monitoring system reaches.

### Users and passwords

([ADR-0006](docs/adr/0006-users.md))

- **Passwords** are stored as Argon2id hashes (OWASP parameters) and need at
  least 12 characters.
- **Uniform failures:** a failed sign-in gets the same answer, after the
  same hashing time, whether or not the username exists.
- **Throttling:** after 5 failed sign-ins for a username within 15
  minutes, each further attempt waits, doubling from 1 second up to 15
  minutes, answered `429` with `Retry-After`.
  - It applies the same to usernames that don't exist, so it reveals
    nothing.
  - Throttled attempts are refused before any hashing, so a flood of
    guesses costs almost nothing.
  - A wrong current password when changing one's own password counts the
    same, under the same name, so a session left open isn't a way around
    it.
  - It's a wait, not a lockout, so an attacker can't lock a real user out
    for long. Counts are kept in PostgreSQL and survive restarts. Rate
    limiting per client address at a reverse proxy adds depth.
- **Accounts** are disabled, never deleted. Disabling a user ends their
  sessions and stops their tokens. Changing one's own password ends one's
  other sessions; an admin resetting it ends them all. The last active admin can't be
  removed or demoted.

### Tokens

([ADR-0012](docs/adr/0012-api-tokens.md))

- **Secrets are 256 random bits,** prefixed with their type (`sonda_`), shown
  once, and stored only as their SHA-256, so a database leak yields no
  usable token.
- **Each type does one job.** Analysis tokens only upload: they can't
  read code or triage. A project analysis token uploads its one project,
  checked against the upload's project before it's stored.
- **Tokens never manage accounts.** No token can create, list or revoke
  tokens, change a password or manage users; a leaked token can't mint
  more, or lock its owner out.
- **Every token stops** when it expires (30, 60 or 90 days, or never),
  is revoked, or its owner is disabled.
- **`SONDA_TOKEN`,** the shared machine token, must be at least 32
  characters, is held in memory only as a SHA-256 hash, and compared in
  constant time.
- **Connect's tokens.** Connecting a repository
  ([ADR-0023](docs/adr/0023-connecting-a-repository.md)) generates a project
  analysis token with no expiry, so CI doesn't stop on a date, and shows it
  once, to add as the repository's `SONDA_TOKEN` secret. Showing the steps
  again generates another; the old one works until revoked, from Admin,
  Tokens.

### Sessions and CSRF

- **Browsers hold only a session cookie.** It is `__Host-` prefixed,
  `HttpOnly`, `Secure` and `SameSite=Strict`, and expires after 12 hours.
  The database stores only its SHA-256, and signing out deletes it.
- **A session alone can't change anything.** A change made with a session
  cookie also needs a `Sonda-Csrf` header, which a cross-site form or script
  can't set without a CORS preflight that the server never approves.
  Together with `SameSite=Strict`, this blocks cross-site request forgery.
  A bearer token isn't sent by a browser on its own, so a change made with
  one needs no header.
- **The page can't be framed or turned against itself.** Every response
  carries a Content Security Policy: scripts from the server only, no
  `eval`, no plugins, no `<base>`, no framing, and forms posted only to the
  server or to GitHub's App creation page. Also `X-Content-Type-Options:
  nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: same-origin` and
  `Cross-Origin-Opener-Policy: same-origin`. Inline styles are allowed,
  since the web app sets colors from data; inline scripts aren't.

### Uploads

- **Checked before they're read:** the token is checked before the body,
  so an unauthenticated client can't make the server buffer an upload.
- **Bounded:** bodies are capped at 128 MiB as sent and 800 MiB after
  decompression, so a small gzip that inflates enormously is refused.
- **Checked, not trusted:**
  - Every source is hashed again and must match the report's SHA-256.
  - Paths, project, branch and commit follow the same rules as
    `sonda upload` (shared code), and rule ids must exist.
  - A flow step in another file must name one of the upload's files.
  - An issue's category comes from sonda's own rule catalog, not the
    client.
  - Each upload is one transaction, so a rejected or failed upload leaves
    nothing behind.
- **Never parsed by C code.** The issue view's syntax highlighting uses a
  small pure-Rust lexer: linear, never recursive, and property-tested to
  lose no text. tree-sitter's C parsers stay confined to the CLI's
  sandboxed workers ([ADR-0003](docs/adr/0003-isolate-parsing.md)).
- **Shown as text.** The web app renders code, paths, messages and names
  as text, never HTML; React escapes them and refuses `javascript:` URLs,
  and the policy above blocks scripts from anywhere but the server. Links
  to advisories are built by the server (`https://osv.dev/...`), not
  taken from the upload.

### The GitHub App and its key

([ADR-0021](docs/adr/0021-pull-request-decoration.md),
[ADR-0024](docs/adr/0024-creating-the-github-app.md))

- **Least privilege:** the App asks for checks and pull requests (write)
  and metadata (read), nothing else. It never writes to a repository's
  code, and has no webhook, so GitHub never calls the server.
- **The key** comes from `SONDA_GITHUB_APP_PRIVATE_KEY` (an environment
  variable or file), or, for an App created from the web app, is stored in
  the database encrypted with AES-256-GCM under `SONDA_SECRET_KEY`, bound
  to its purpose. A database leak without that key yields no App key; the
  server refuses to create an App until it's set.
- **Installation tokens** are asked for one repository at a time, limited
  to it, kept in memory only, and dropped five minutes before they expire.
- **Creating the App** goes through GitHub's manifest flow: only an admin
  can start it, and the `state` it carries is bound to that admin, used
  once, and valid for an hour, so a forged return from GitHub can't
  connect someone else's App.
- **Decorations go only where an admin pointed them:** to the repository
  linked in the project's settings, and only if the upload says it's from
  that same repository. The pull request's number and commit come from the
  upload.
- **sonda edits only its own comment.** It finds its earlier comment on a
  pull request by a hidden marker, and only among comments its own App
  wrote, so a comment someone else writes with the marker is never edited.
- **Their content** is counts, the gate's conditions, and new issues as
  check annotations, all posted as text through GitHub's API.

### Plain HTTP and HTTPS

- **HTTPS is the default assumption.** The session cookie is `Secure`,
  which browsers keep only over HTTPS or on `localhost`. The server serves
  plain HTTP itself; HTTPS is a reverse proxy's job.
- **Through Caddy:** `scripts/setup-server.sh --https IP` puts Caddy in
  front for a LAN address, with a certificate from Caddy's own local
  authority, which each device trusts once by installing its root. No
  public authority certifies a private address. The CLI trusts that root
  with `--ca-cert`, which accepts only an authority certificate and
  refuses a file holding a private key. Caddy listens only on HTTPS, with no
  plain-HTTP port to redirect from.
- **`SONDA_PLAIN_HTTP` on a LAN** drops `Secure`, and with it the
  `__Host-` prefix, so browsers sign in over plain HTTP. Passwords and
  session cookies then cross the network readable by anyone on it, and the
  server warns at startup. It's for a trusted home network only; tokens
  still go over plain HTTP only to `localhost`, since the CLI refuses
  otherwise.
- **HSTS is the reverse proxy's,** which knows whether HTTPS is for good.
  Browsers ignore it for IP addresses, which is what Caddy's LAN setup
  serves.

### Storage and the host

- **SQL is parameterized.** sqlx 0.9 rejects SQL built from strings unless
  marked as audited; request input never becomes SQL. Filters are bound as
  arrays, with an empty array meaning no filter, so every query is a fixed
  string.
- **The schema enforces constraints** such as project keys, commit hashes
  and digest lengths, as a second line of defence behind the server's own
  validation. Migrations run in a transaction each, and a failure stops
  startup.
- **Secrets stay out of sight:** they come from environment variables or
  files, never command-line flags; errors never echo the database URL,
  which may hold the password; and logs never carry a token, password or
  session.
- **The container is locked down:** a non-root user on a distroless image
  with no shell, a read-only filesystem, all Linux capabilities dropped,
  and `no-new-privileges`.

### Accepted risks

These follow from the design, and are documented rather than fixed:

- **An upload says what it found.** The server checks an upload's files,
  paths and rule ids, but not that its issues are what sonda would find:
  it doesn't rescan. Whoever holds a project's upload token can upload any
  result for it, and with a GitHub App, set its `sonda` check on any commit
  and comment on any pull request of the linked repository. A required
  `sonda` check is as strong as that token's secret: keep it from
  workflows that run untrusted code, such as `pull_request_target`.
- **Any user can create a project,** by uploading one with a new key with
  one of their tokens: every active user may analyse, as every user may
  triage ([ADR-0012](docs/adr/0012-api-tokens.md)), until per-project
  permissions exist. A deleted project's key stays refused until an admin
  allows it again.
- **Every member reads every project.** There is no per-project access yet;
  roles are admin and member.
- **Changing a password doesn't revoke tokens.** It ends other sessions;
  a token thought leaked is revoked on its own, or stops when its owner is
  disabled.
- **Copied prompts carry uploaded code.** "Copy as prompt"
  ([ADR-0025](docs/adr/0025-fixing-with-an-ai-assistant.md)) puts an
  issue's code into text for an AI assistant, and that code can hold
  instructions aimed at the assistant. Read what the assistant proposes as
  you would a stranger's patch.
- **On loopback, reads are open** to every user of the host. On a shared
  machine, put the server in a container or behind a proxy, which makes
  reads need authentication.

### Review

**2026-11-09:** a review of the whole server: authentication, authorization
per endpoint, CSRF, tokens, the decoration task, the GitHub App's flow and
key, and the web app's handling of uploaded content. Its findings, fixed:

- sonda found its earlier pull request comment by its marker alone, so a
  comment with the marker written by someone else would have been edited,
  putting sonda's summary under their name, and sonda's own never posted.
  It now edits only comments its App wrote.
- A wrong current password on a password change wasn't throttled, so a
  session left open allowed unlimited guesses at the password. It now
  counts with sign-in's failures.
- Responses carried no Content Security Policy or framing headers. They
  now do (above), checked in a browser against every page of the web app
  and the GitHub App's creation form.

The rest is above, as properties or accepted risks.

## Supply chain

CI runs `cargo deny` (advisories, licenses, sources) and `cargo audit` on
every change. Actions are pinned to commit SHAs, and workflows get a
read-only token. `Cargo.lock` is committed. See
[docs/engineering-standards.md](docs/engineering-standards.md#12-cicd-and-supply-chain).
