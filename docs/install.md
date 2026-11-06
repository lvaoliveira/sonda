# Installing sonda

sonda works where you work: install the CLI and scan a project, locally or
in CI, with nothing else to run. Add the server later, when a team wants
history, triage and quality gates in one place.

## Quick start

**1. Install the CLI.** On Linux (x86_64 or arm64), download the release
binary and check it:

```sh
v=0.2.0 arch=$(uname -m)    # x86_64 or aarch64
f=sonda-$v-$arch-linux
curl -fsSLO https://github.com/lvaoliveira/sonda/releases/download/v$v/$f
curl -fsSL https://github.com/lvaoliveira/sonda/releases/download/v$v/SHA256SUMS | grep " $f\$" | sha256sum -c -
mkdir -p ~/.local/bin && install -m 755 $f ~/.local/bin/sonda
```

On macOS or Windows, build it with [Rust](https://rustup.rs) 1.90 or newer
(a few minutes; prebuilt binaries are planned):

```sh
cargo install --git https://github.com/lvaoliveira/sonda --tag v0.2.0 sonda
```

**2. Scan a project:**

```sh
cd your-project
sonda scan .
```

It lists the issues by file, then a summary (lines of code, bugs,
vulnerabilities, code smells, duplication) and the quality gate, judged on
new code: by default your branch's changes, or your uncommitted ones on the
main branch. It exits with 1 when the gate fails, so the same command works
as a CI check.

`sonda: command not found`? See [If `sonda` isn't found](#if-sonda-isnt-found).

**Next:** `sonda init` writes a `sonda.toml` to adjust rules, and the
[README](../README.md#usage) has the other commands and report formats
(JSON, SARIF).

## Installing the CLI

### Linux

The release binaries are static, with no dependencies. The quick start's
commands download one and check it against the release's `SHA256SUMS`: the
`grep` makes sure the file checked is the one downloaded, and fails if it
isn't listed.

The checksum says the download is intact, not who built it, since it comes
from the same place. Each binary also carries a signed build attestation
that does: verify it with the [GitHub CLI](https://cli.github.com/) before
installing.

```sh
gh attestation verify $f --repo lvaoliveira/sonda
```

To install somewhere else, such as `/usr/local/bin` for every user, change
the `install` line.

### macOS and Windows

There's no prebuilt binary for these yet, so `cargo install` builds one. To
build from a clone instead: `cargo install --path crates/sonda`.

On Windows, the parsers run without a sandbox: a file crafted to exploit a
parser bug would run with your privileges. On Linux and macOS each parser
runs sandboxed. Read [SECURITY.md](../SECURITY.md) before scanning code you
don't trust on Windows.

### Linux, from a clone without Rust

`scripts/install-cli.sh` builds the same static binary in Docker from the
clone and installs it to `~/.local/bin`, or to the directory you give it.
Rerun it after `git pull` to keep the CLI at the clone's version.

### In GitHub Actions

Download the release binary rather than building it on each run:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0            # sonda needs the base branch or the pushed range
- name: Install sonda
  run: |
    v=0.2.0 f=sonda-0.2.0-x86_64-linux
    cd "$RUNNER_TEMP"
    curl -fsSLO "https://github.com/lvaoliveira/sonda/releases/download/v$v/$f"
    curl -fsSL "https://github.com/lvaoliveira/sonda/releases/download/v$v/SHA256SUMS" | grep " $f\$" | sha256sum -c -
    install -m 755 "$f" sonda
    echo "$RUNNER_TEMP" >> "$GITHUB_PATH"
- run: sonda scan .
```

The [README](../README.md#github-actions) shows sending the results to
GitHub's code scanning as SARIF.

### If `sonda` isn't found

The shell looks for commands in the directories of `PATH`, and some systems
leave `~/.local/bin` out. Check with `echo "$PATH"`, and if it's missing,
add it to your shell's startup file (`~/.bashrc`, `~/.zshrc`):

```sh
export PATH="$HOME/.local/bin:$PATH"
```

Then open a new terminal. `cargo install` puts `sonda` in `~/.cargo/bin`,
which rustup adds to `PATH` itself.

## Adding the server

The server keeps every analysis, tracks issues across them, and serves the
web app: the Overview, issues with triage, quality gates and pull request
decoration.

It needs Docker with Compose v2, `git` and `openssl`, on an amd64 or arm64
machine. From a clone of the release:

```sh
git clone --branch v0.2.0 https://github.com/lvaoliveira/sonda.git && cd sonda
scripts/setup-server.sh
```

The script creates the secrets in `secrets/`, starts the server and its
database, and waits until they're healthy. Open http://127.0.0.1:9000 and
sign in as `admin`, with the password in `secrets/admin_password`. Change
it under Account.

### Your first upload

On the server's machine, upload a scan with the server's shared token:

```sh
sonda scan . --upload --server http://127.0.0.1:9000 --token-file secrets/sonda_token \
  --project my-app --branch main --commit "$(git rev-parse HEAD)"
```

The first upload creates the project. **Use the shared token only for this
first try, never in CI or on another machine:** it can upload to every
project. For each pipeline, create a service user such as `ci` and give it
a project analysis token, which can only upload that project's analyses
([Tokens](server.md#tokens)).

### Reaching it from other machines

The server listens on `127.0.0.1` only, so nothing reaches it from the
network until you choose how:

- **HTTPS, recommended:** `scripts/setup-server.sh --https` serves it on
  this machine's LAN address through Caddy, with Caddy's own certificate
  ([HTTPS on a LAN address](server.md#https-on-a-lan-address)), or put your
  own TLS reverse proxy in front
  ([Exposing it beyond this machine](server.md#exposing-it-beyond-this-machine)).
- **Plain HTTP, only on a network you trust:** `--lan` serves it without
  TLS, so passwords and session cookies cross the network unencrypted, and
  anyone who can see that traffic can take a session. The server logs a
  warning when it starts this way. Never expose it beyond your own network
  like this ([On a home network](server.md#on-a-home-network)).

Sign-in works only over HTTPS or on `localhost`, unless `--lan` is on. The
CLI sends a token over plain HTTP only to `localhost`, so uploads from
other machines need HTTPS either way.

## Upgrading

- **The server first.** Back up the database, read the release's section in
  the [changelog](../CHANGELOG.md), then check out the new tag and rerun
  `scripts/setup-server.sh`. There's no downgrade: the server migrates its
  database as it starts. See [Upgrading](server.md#upgrading).
- **Then the CLI**, when you like: install it again, with the new version.
  A server accepts the CLI of its own minor version and the one before
  ([stability.md](stability.md#compatibility-window)).

## Uninstalling

- **The CLI:** delete `~/.local/bin/sonda`, or `cargo uninstall sonda`.
- **The server:** `docker compose down` stops it and keeps the data;
  `docker compose down -v` also deletes the database. Then delete the
  clone, `secrets/` included.

## Running a server: going further

[docs/server.md](server.md) is the operations guide. For installing, these
are the parts most often needed:

- [The published image by digest](server.md#quick-start-docker-compose),
  instead of building the clone.
- [Verifying a release](../SECURITY.md#verifying-a-release): the
  attestations of the binaries and the image, and their SBOMs.
- [A second server on one machine](server.md#a-second-server-on-one-machine),
  such as one to try a release candidate.
- [Backups](server.md#backups), [configuration](server.md#configuration)
  and [logs](server.md#logs).
- [Running without Docker](server.md#running-without-docker), against your
  own PostgreSQL.
