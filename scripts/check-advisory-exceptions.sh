#!/usr/bin/env bash
# Keeps the advisories .cargo/audit.toml ignores honest. Used by CI's
# supply-chain job, after `cargo audit`.
#
# RUSTSEC-2026-0459 (libsqlite3-sys, C SQLite) is ignored because the
# crate is in Cargo.lock only as sqlx's optional SQLite driver, which no
# release builds. This fails:
#   - if libsqlite3-sys or sqlx-sqlite becomes part of a release build:
#     the packages and targets the release workflow and Dockerfile build,
#     with build dependencies and procedural macros;
#   - after the exception's "Review by" date in .cargo/audit.toml.
#
# Being in Cargo.lock isn't enough to fail: Cargo records every optional
# dependency there. `cargo metadata` lists them too, through sqlx's weak
# features (`sqlx-sqlite?/json`), so this asks `cargo tree`, which resolves
# features as `cargo build` does.
#
# Usage: scripts/check-advisory-exceptions.sh
set -euo pipefail

cd "$(dirname "$0")/.."
config=.cargo/audit.toml

# What releases build: .github/workflows/release.yml (the CLI for each
# platform, and the image) and the Dockerfile (the server, and the CLI's
# musl build). Keep in step with them.
targets=(
  x86_64-unknown-linux-musl
  aarch64-unknown-linux-musl
  x86_64-unknown-linux-gnu
  aarch64-unknown-linux-gnu
  aarch64-apple-darwin
  x86_64-pc-windows-msvc
)
packages=(sonda sonda-server)
forbidden='^(libsqlite3-sys|sqlx-sqlite) v'

status=0
for target in "${targets[@]}"; do
  for package in "${packages[@]}"; do
    # One "name vX.Y.Z" per line; normal edges include procedural macros.
    graph=$(cargo tree --locked --quiet -p "$package" --target "$target" \
      -e normal,build --prefix none --format '{p}')
    # An empty or rootless graph means the command didn't do what's assumed
    # here: fail rather than pass on nothing.
    if ! grep -q "^$package v" <<< "$graph"; then
      echo "::error::cargo tree printed no graph for $package on $target"
      exit 1
    fi
    if found=$(grep -E "$forbidden" <<< "$graph" | sort -u); then
      echo "::error::$package on $target now builds SQLite: $(tr '\n' ' ' <<< "$found")"
      status=1
    fi
  done
done
if [ "$status" != 0 ]; then
  cat <<'EOF'
RUSTSEC-2026-0459 is ignored in .cargo/audit.toml because no release build
compiled libsqlite3-sys. One does now, so the advisory applies: remove the
ignore, and upgrade (libsqlite3-sys >= 0.39, through sqlx) or drop the
dependency that brought SQLite in (`cargo tree -i libsqlite3-sys -e features`
shows which).
EOF
  exit 1
fi

review_by=$(sed -n 's/^ *# Review by: \([0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}\).*/\1/p' "$config")
if [ -z "$review_by" ]; then
  echo "::error::$config has no '# Review by: YYYY-MM-DD' line"
  exit 1
fi
today=$(date -u +%Y-%m-%d)
if [[ "$today" > "$review_by" ]]; then
  cat <<EOF
::error::$config's exception for RUSTSEC-2026-0459 was due for review on $review_by.
Check whether a sqlx release accepts libsqlite3-sys >= 0.39 (cargo update -p
sqlx --dry-run; the sqlx changelog). If one does, upgrade and remove the
ignore. If not, confirm this script still passes and move the date.
EOF
  exit 1
fi
echo "Advisory exceptions: no release build compiles SQLite; review due $review_by."
