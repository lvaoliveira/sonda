# Installing sonda

sonda comes in two parts:

- **The CLI**, `sonda`, scans code and prints or writes a report. It works on
  its own, on a laptop or in CI.
- **The server**, optional, keeps analyses over time and serves the web app:
  the Overview, issues with triage, quality gates, pull request decoration.
  The CLI uploads to it.

Install the CLI to try sonda; add the server when you want history and a
place for a team to triage.

## The CLI

### Linux: the release binary

Each [release](https://github.com/lvaoliveira/sonda/releases) has a static
binary for x86_64 and arm64, with no dependencies:

```sh
v=0.2.0 arch=x86_64   # or aarch64
curl -fsSLO https://github.com/lvaoliveira/sonda/releases/download/v$v/sonda-$v-$arch-linux
curl -fsSL https://github.com/lvaoliveira/sonda/releases/download/v$v/SHA256SUMS | sha256sum -c --ignore-missing
install -m 755 sonda-$v-$arch-linux ~/.local/bin/sonda
sonda --version
```

The checksum says the download is intact. To check who built it, verify
its attestation with the [GitHub CLI](https://cli.github.com/) before the
`install` line:

```sh
gh attestation verify sonda-$v-$arch-linux --repo lvaoliveira/sonda
```

### macOS and Windows: from source

There's no prebuilt binary for these yet. Build it with Rust 1.90 or newer
([rustup](https://rustup.rs)):

```sh
cargo install --git https://github.com/lvaoliveira/sonda --tag v0.2.0 sonda
sonda --version
```

On Windows, the parsers run without a sandbox: a file crafted to exploit a
parser bug would run with your privileges. On Linux and macOS each parser
runs sandboxed. See [SECURITY.md](../SECURITY.md) before scanning code you
don't trust on Windows.

### Linux, from a checkout without Rust

`scripts/install-cli.sh` builds the same static binary in Docker from the
checkout and installs it to `~/.local/bin` (or the directory you give it).
Rerun it after `git pull` to keep the CLI at the checkout's version, such as
the server's.

### In GitHub Actions

Download the release binary rather than building it on each run:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0            # sonda needs the base branch or the pushed range
- name: Install sonda
  run: |
    v=0.2.0
    cd "$RUNNER_TEMP"
    curl -fsSLO "https://github.com/lvaoliveira/sonda/releases/download/v$v/sonda-$v-x86_64-linux"
    curl -fsSL "https://github.com/lvaoliveira/sonda/releases/download/v$v/SHA256SUMS" | sha256sum -c --ignore-missing
    install -m 755 "sonda-$v-x86_64-linux" sonda
    echo "$RUNNER_TEMP" >> "$GITHUB_PATH"
- run: sonda scan .
```

The [README](../README.md#github-actions) shows uploading the report to
GitHub's code scanning as SARIF.

## The server

### Requirements

- Docker with Compose v2.
- `git`, for the checkout, and `openssl`, which the setup script uses to
  create the secrets.
- An amd64 or arm64 machine. The database and the server both run in
  containers, so nothing else is installed on the host.

### Start it

From a checkout of a release:

```sh
git clone --branch v0.2.0 https://github.com/lvaoliveira/sonda.git && cd sonda
scripts/setup-server.sh
```

The script creates the secrets in `secrets/`, builds the checkout, starts
the server and PostgreSQL, and waits until they're healthy. Open
http://127.0.0.1:9000 and sign in as `admin`, with the password in
`secrets/admin_password`. Change it under Account.

The script is safe to rerun, and keeps its options in `.env`, so later runs
need none. Its options, what each secret is for, and setting it up by hand
are in [docs/server.md](server.md#quick-start-docker-compose).

### From the published image

To run the image the release published instead of building the checkout,
give the script its digest, from the release's notes:

```sh
scripts/setup-server.sh --image ghcr.io/lvaoliveira/sonda@sha256:<digest>
```

Pin the digest, not a tag: a digest is what you tested. To check who built
it, see [Verifying a release](../SECURITY.md#verifying-a-release).

### A second server on the same machine

`compose.yaml` names the Compose project `sonda`, so a second checkout on
the same machine would take over the first one's containers. Give the
second one its own project name and port before running the script:

```sh
printf 'COMPOSE_PROJECT_NAME=sonda-test\n' >> .env
scripts/setup-server.sh --port 9400
docker compose ps    # sonda-test-sonda-1 and sonda-test-db-1
```

### Reaching it from other machines

The server listens on `127.0.0.1` only. To open it to other machines:

- `--lan`: plain HTTP on this machine's LAN address, for a network you
  trust ([On a home network](server.md#on-a-home-network)).
- `--https`: HTTPS on a LAN address, through Caddy with its own
  certificate ([HTTPS on a LAN address](server.md#https-on-a-lan-address)).
- Or your own reverse proxy that terminates TLS
  ([Exposing it beyond this machine](server.md#exposing-it-beyond-this-machine)).

Sign-in needs HTTPS, or `localhost`, unless the server runs with `--lan`.

### Without Docker

Build `sonda-server` with Cargo and run it against your own PostgreSQL:
[Running without Docker](server.md#running-without-docker).

## Connecting the CLI to the server

Upload a scan with a token:

```sh
sonda scan . --upload --server http://127.0.0.1:9000 --token-file secrets/sonda_token \
  --project my-app --branch main --commit "$(git rev-parse HEAD)"
```

The first upload creates the project. `secrets/sonda_token` is the server's
shared token, fine for a first try. For CI, create a service user such as
`ci` and give each pipeline a project analysis token, which can only upload
that project's analyses ([Tokens](server.md#tokens)).

## Upgrading

- **The server first.** Back up the database (`docker compose exec -T db
  pg_dump -U sonda -Fc sonda > sonda.dump`), read the release's section in
  the [changelog](../CHANGELOG.md), then check out the new tag (or pass the
  new digest) and rerun `scripts/setup-server.sh`. There's no downgrade: the
  server migrates its database as it starts. Details, and what to do if a
  migration fails, are in [Upgrading](server.md#upgrading).
- **Then the CLI**, when you like: the same steps as installing, with the new
  version. A server accepts the CLI of its own minor version and the one
  before ([stability.md](stability.md#compatibility-window)).

## Uninstalling

- **The CLI:** delete `~/.local/bin/sonda`, or `cargo uninstall sonda`.
- **The server:** `docker compose down` stops it and keeps the data;
  `docker compose down -v` also deletes the database. Then delete the
  checkout, `secrets/` included.
