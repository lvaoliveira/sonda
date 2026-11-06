# Installing sonda

sonda works where you work: install the CLI and scan a project, locally or
in CI, with nothing else to run. Add the server later, when a team wants
history, triage and quality gates in one place.

## Quick start

**1. Install the CLI.** Each release has a binary for Linux (x86_64 and
arm64), macOS (Apple Silicon) and Windows (x86_64). Download yours and
check it against the release's checksums.

Linux:

```sh
v=0.2.0 f=sonda-0.2.0-$(uname -m)-linux    # x86_64 or aarch64
curl -fsSLO https://github.com/lvaoliveira/sonda/releases/download/v$v/$f
curl -fsSL https://github.com/lvaoliveira/sonda/releases/download/v$v/SHA256SUMS | grep " $f\$" | sha256sum -c -
mkdir -p ~/.local/bin && install -m 755 $f ~/.local/bin/sonda
```

macOS:

```sh
v=0.2.0 f=sonda-0.2.0-aarch64-macos
curl -fsSLO https://github.com/lvaoliveira/sonda/releases/download/v$v/$f
curl -fsSL https://github.com/lvaoliveira/sonda/releases/download/v$v/SHA256SUMS | grep " $f\$" | shasum -a 256 -c -
mkdir -p ~/.local/bin && install -m 755 $f ~/.local/bin/sonda
```

Windows, in PowerShell:

```powershell
$v = "0.2.0"; $f = "sonda-$v-x86_64-windows.exe"
$url = "https://github.com/lvaoliveira/sonda/releases/download/v$v"
Invoke-WebRequest "$url/$f" -OutFile $f; Invoke-WebRequest "$url/SHA256SUMS" -OutFile SHA256SUMS
$sum = (Select-String -Path SHA256SUMS -Pattern " $([regex]::Escape($f))$").Line
if (-not $sum -or $sum.Split(" ")[0] -ne (Get-FileHash $f).Hash) { throw "$f doesn't match SHA256SUMS" }
$dir = "$env:LOCALAPPDATA\Programs\sonda"; New-Item -ItemType Directory -Force $dir | Out-Null
Move-Item -Force $f "$dir\sonda.exe"
[Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path", "User") + ";$dir", "User")
```

On Windows, open a new terminal afterwards, so it sees the new `Path`.
Elsewhere (Intel Macs, Windows on Arm, other systems), [build it from
source](#from-source).

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

### Checking a download

The quick start checks each download against the release's `SHA256SUMS`,
matching the file's own line, so it fails if the file isn't listed. That
says the download is intact, not who built it, since the checksums come
from the same place. Each binary also carries a signed build attestation
that does: verify it with the [GitHub CLI](https://cli.github.com/) before
installing.

```sh
gh attestation verify $f --repo lvaoliveira/sonda
```

The binaries aren't signed by Apple or Microsoft yet. A download from a
browser is marked as such, and then:

- **macOS** refuses to run it, saying Apple can't check it for malicious
  software. After checking it, clear the mark:
  `xattr -d com.apple.quarantine sonda-0.2.0-aarch64-macos`. A `curl`
  download, as in the quick start, isn't marked.
- **Windows** SmartScreen may warn about it. A download with PowerShell, as
  in the quick start, isn't marked.

### Where it runs, and the sandbox

The Linux binaries are static, with no dependencies, and so is the Windows
one's C runtime. On Linux and macOS each parser runs in a sandbox. On
Windows the parsers run without one: a file crafted to exploit a parser bug
would run with your privileges. Read [SECURITY.md](../SECURITY.md) before
scanning code you don't trust on Windows.

To install somewhere else, such as `/usr/local/bin` for every user, change
the last line of the Linux or macOS commands.

### From source

On a platform without a release binary, build it with
[Rust](https://rustup.rs) 1.90 or newer. It takes a few minutes:

```sh
cargo install --git https://github.com/lvaoliveira/sonda --tag v0.2.0 sonda
```

From a clone instead: `cargo install --path crates/sonda`.

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

The shell looks for commands in the directories of `PATH`, and some
systems, macOS among them, leave `~/.local/bin` out. Check with
`echo "$PATH"`, and if it's missing, add it to your shell's startup file
(`~/.zshrc` on macOS, `~/.bashrc` on most Linux systems):

```sh
export PATH="$HOME/.local/bin:$PATH"
```

Then open a new terminal. On Windows, the quick start adds sonda's folder
to your user `Path`; a terminal opened before that doesn't see it.
`cargo install` puts `sonda` in `~/.cargo/bin`, which rustup adds to `PATH`
itself.

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

- **The CLI:** delete `~/.local/bin/sonda` (on Windows,
  `%LOCALAPPDATA%\Programs\sonda`), or `cargo uninstall sonda`.
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
