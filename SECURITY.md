# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's **"Report a vulnerability"**
button on this repository's Security tab. Don't open a public issue. Please
include a reproduction, such as a minimal repository or file that triggers
the problem.

Only the latest release receives fixes while sonda is at 0.x.

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
- **The upload token does not leak.** It comes from `SONDA_TOKEN` or a file,
  never a command-line flag, because flags are visible in `ps` and CI logs.
  It is sent only over HTTPS, except to `localhost`. Redirects are not
  followed, so it only goes to the URL you named. URLs with embedded
  credentials are refused. Server certificates are checked against Mozilla's
  root certificates (webpki-roots).

### Known limitations

- **Windows workers are not sandboxed.** tree-sitter's runtime and grammars
  are C, called through FFI. They run in worker processes
  ([ADR-0003](docs/adr/0003-isolate-parsing.md)) everywhere, so a parser
  crash only loses one file. On Linux and macOS the workers are also
  sandboxed (below). On Windows, a crafted file that exploits a parser bug
  would run with your privileges. Use `--sandbox require` to refuse to scan
  where the sandbox is unavailable. The parsers are fuzzed weekly with
  AddressSanitizer.
- **Uploads to a server with a private CA fail.** `sonda upload` trusts
  Mozilla's roots, not the operating system's store or a custom CA.
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

`sonda-server` ([docs/server.md](docs/server.md)) is still being built.
What holds today:

- **Untrusted:** everything that arrives over the network, including
  uploads, which carry other people's source code.
- **Not exposed by default:** it listens on `127.0.0.1`. The Docker image
  listens on all interfaces inside the container, but Compose publishes the
  port on the host's localhost only. The database container publishes no
  port at all.
- **Secrets stay out of sight:** they come from environment variables or
  files, never command-line flags, and errors never echo the database URL,
  which may hold the password.
- **The API token** must be at least 32 characters. It is kept in memory
  only as a SHA-256 hash and compared in constant time.
- **The container is locked down:** it runs as a non-root user on a
  distroless image with no shell, with a read-only filesystem, all Linux
  capabilities dropped, and `no-new-privileges`.
- **SQL is parameterized.** sqlx 0.9 rejects SQL built from strings unless
  it is marked as audited, and the only such SQL is in tests.
- **The schema enforces constraints** such as project keys, commit hashes
  and digest lengths, as a second line of defence behind the server's own
  validation.
- **Uploads are checked, not trusted:**
  - The token is checked before the body is read, so an unauthenticated
    client cannot make the server buffer an upload.
  - Bodies are capped at 128 MiB as sent and 800 MiB after
    decompression, so a small gzip that inflates enormously is refused.
  - Every source is hashed again and must match the report's SHA-256.
  - Paths, project, branch and commit follow the same rules as
    `sonda upload` (shared code), and rule ids must exist.
  - An issue's category comes from sonda's own rule catalog, not the
    client.
  - Each upload is one transaction, so a rejected or failed upload leaves
    nothing behind.
- **Reads need authentication off loopback.** Once the server listens
  beyond loopback, as it does in Docker, every read needs the token or a
  browser session.
- **Browsers never hold the token.** Signing in exchanges it for a session
  cookie: `__Host-` prefixed, `HttpOnly`, `Secure` and
  `SameSite=Strict`, expiring after 12 hours. The database stores only a
  SHA-256 hash of each session token, so a database leak yields no usable
  session, and signing out deletes the session server-side.
- **Migrations are all-or-nothing:** each runs in a transaction, and a
  failure stops startup.

## Supply chain

CI runs `cargo deny` (advisories, licenses, sources) and `cargo audit` on
every change. Actions are pinned to commit SHAs, and workflows get a
read-only token. `Cargo.lock` is committed. See
[docs/engineering-standards.md](docs/engineering-standards.md#12-cicd-and-supply-chain).
