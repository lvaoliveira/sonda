#!/bin/sh
# Installs the sonda CLI on a Linux host without Rust: builds it in Docker
# from this checkout, as one static binary, into DIR (default ~/.local/bin).
# Rerun after `git pull` to keep it the same version as the server.
# With Rust, `cargo install --path crates/sonda` does the same.
set -eu
cd "$(dirname "$0")/.."

[ "$(uname -s)" = Linux ] ||
  { echo "install-cli: builds a Linux binary; here, use cargo install --path crates/sonda" >&2; exit 1; }
dir=${1:-"$HOME/.local/bin"}

out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
docker build --target cli --output "type=local,dest=$out" .
mkdir -p "$dir"
install -m 755 "$out/sonda" "$dir/sonda"
"$dir/sonda" --version
case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "Add $dir to PATH, or run it as $dir/sonda." ;;
esac
