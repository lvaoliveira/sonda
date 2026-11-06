#!/bin/sh
# Tests scripts/install.sh against a fake release on disk (SONDA_DOWNLOAD_URL
# as a file:// URL): it installs a download that matches SHA256SUMS, refuses
# one that doesn't or isn't listed exactly once, and leaves nothing installed
# when it refuses. Used by CI; the release workflow tries the published
# script for real.
set -eu
script="$(cd "$(dirname "$0")" && pwd)/install.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# The release's name for this machine, as install.sh works it out.
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64 | Linux-amd64) platform=x86_64-linux ;;
  Linux-aarch64 | Linux-arm64) platform=aarch64-linux ;;
  Darwin-arm64 | Darwin-aarch64) platform=aarch64-macos ;;
  *) echo "test-install: no release binary for this machine" >&2; exit 1 ;;
esac

sum() { # FILE: its SHA256SUMS line
  if command -v sha256sum > /dev/null; then h=$(sha256sum < "$1"); else h=$(shasum -a 256 < "$1"); fi
  printf '%s  %s\n' "${h%% *}" "$(basename "$1")"
}

# A release of VERSION whose "binary" prints its version, and SHA256SUMS as
# MODE makes it: good, tampered, missing or twice.
release() { # VERSION MODE
  dir="$tmp/releases/v$1"
  rm -rf "$dir" && mkdir -p "$dir"
  bin="$dir/sonda-$1-$platform"
  printf '#!/bin/sh\necho "sonda %s"\n' "$1" > "$bin"
  case $2 in
    good) sum "$bin" > "$dir/SHA256SUMS" ;;
    tampered) sum "$bin" > "$dir/SHA256SUMS" && echo '# changed' >> "$bin" ;;
    missing) : > "$dir/SHA256SUMS" ;;
    twice) { sum "$bin"; sum "$bin"; } > "$dir/SHA256SUMS" ;;
  esac
}

# install.sh with the fake releases, gh unable to check attestations (no
# signed-in account), and the install directory off PATH.
run() { # SCRIPT [ARGS]
  s=$1
  shift
  env -u GH_TOKEN -u GITHUB_TOKEN GH_CONFIG_DIR="$tmp/gh" \
    SONDA_DOWNLOAD_URL="file://$tmp/releases" SONDA_INSTALL_DIR="$tmp/bin" \
    sh "$s" "$@" > "$tmp/out" 2>&1
}
fails=0
pass() { echo "ok: $1"; }
fail() { echo "FAILED: $1" >&2; sed 's/^/  /' "$tmp/out" >&2; fails=$((fails + 1)); }
installed() { [ -x "$tmp/bin/sonda" ] && [ "$("$tmp/bin/sonda")" = "sonda $1" ]; }

release 9.9.1 good
if run "$script" --version 9.9.1 && installed 9.9.1 && grep -q "isn't on your PATH" "$tmp/out"; then
  pass "installs a checked download, and says the directory isn't on PATH"
else fail "a good download"; fi

release 9.9.2 good
if run "$script" --version v9.9.2 && installed 9.9.2; then
  pass "replaces an installed version, and takes a leading v"
else fail "an upgrade"; fi

for mode in tampered missing twice; do
  rm -rf "${tmp:?}/bin"
  release 9.9.3 "$mode"
  if ! run "$script" --version 9.9.3 && [ ! -e "$tmp/bin/sonda" ] && grep -q "not installed" "$tmp/out"; then
    pass "refuses a $mode checksum, installing nothing"
  else fail "a $mode checksum"; fi
done

for bad in ../9.9.1 9.9 'x;y'; do
  if ! run "$script" --version "$bad" && grep -q "not a version" "$tmp/out"; then pass "refuses the version $bad"; else fail "the version $bad"; fi
done

# The copy a release attaches has its version filled in.
release 9.9.4 good
sed "s/^release_version=''\$/release_version='9.9.4'/" "$script" > "$tmp/install.sh"
if run "$tmp/install.sh" && installed 9.9.4; then
  pass "a release's copy installs its own version"
else fail "a release's copy"; fi

[ "$fails" -eq 0 ] || { echo "test-install: $fails failed" >&2; exit 1; }
