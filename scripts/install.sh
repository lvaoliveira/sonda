#!/bin/sh
# Installs the sonda CLI from a GitHub release, on Linux or macOS
# (docs/install.md). Each release attaches this script with its own version
# filled in, so the latest release's installs the latest:
#
#   curl -fsSL https://github.com/lvaoliveira/sonda/releases/latest/download/install.sh | sh
#
# It picks the binary for this system, checks it against the release's
# SHA256SUMS (and its attestation, when `gh` is installed and signed in),
# and installs it only if that passes. It never uses sudo and never edits
# shell startup files: when the directory isn't on PATH, it says what to add.
# (scripts/install-cli.sh, by contrast, builds the CLI from a checkout.)
#
#   --version V   install this release, such as 0.2.1 (default: this
#                 script's release, or the latest when run from a checkout)
#   --dir DIR     install into DIR (default ~/.local/bin)
#
# SONDA_VERSION and SONDA_INSTALL_DIR set the same. SONDA_DOWNLOAD_URL
# replaces https://github.com/lvaoliveira/sonda/releases/download, for a
# mirror (https://) or a test (file://).

# Everything runs from main, called on the last line, so a download cut short
# runs nothing.
set -eu

# The release workflow fills this in on the copy it attaches.
release_version=''

repo_url=https://github.com/lvaoliveira/sonda

say() { printf 'sonda install: %s\n' "$*" >&2; }
die() { say "$*"; exit 1; }

usage() { # [STATUS]
  echo "usage: install.sh [--version V] [--dir DIR]" >&2
  exit "${1:-2}"
}

# HTTPS only (TLS 1.2 or later), and file:// for tests.
fetch() { # URL OUT
  if command -v curl > /dev/null; then
    curl --proto '=https,file' --tlsv1.2 -fsSL -o "$2" "$1"
  elif command -v wget > /dev/null; then
    case $1 in https://*) ;; *) die "wget only fetches https:// URLs: $1" ;; esac
    wget -q -O "$2" "$1"
  else
    die "needs curl or wget"
  fi
}

# The latest release's version, from where /releases/latest redirects.
latest_version() {
  command -v curl > /dev/null || die "finding the latest release needs curl; pass --version"
  url=$(curl --proto '=https' --tlsv1.2 -fsSL -o /dev/null -w '%{url_effective}' "$repo_url/releases/latest") ||
    die "couldn't reach $repo_url/releases/latest"
  case $url in
    */releases/tag/v*) echo "${url##*/releases/tag/v}" ;;
    *) die "couldn't tell the latest release from $url" ;;
  esac
}

# The release's name for this system: x86_64-linux, aarch64-linux or
# aarch64-macos.
platform() {
  os=$(uname -s) arch=$(uname -m)
  case $arch in
    x86_64 | amd64) arch=x86_64 ;;
    aarch64 | arm64) arch=aarch64 ;;
    *) die "no release binary for $arch; build it from source (docs/install.md)" ;;
  esac
  case $os in
    Linux) echo "$arch-linux" ;;
    Darwin)
      # A shell under Rosetta reports x86_64 on Apple Silicon.
      if [ "$arch" = x86_64 ] && [ "$(sysctl -n hw.optional.arm64 2> /dev/null)" = 1 ]; then
        arch=aarch64
      fi
      [ "$arch" = aarch64 ] ||
        die "no release binary for Intel Macs; build it from source (docs/install.md)"
      echo "$arch-macos"
      ;;
    *) die "no release binary for $os; on Windows, see docs/install.md" ;;
  esac
}

sha256() {
  if command -v sha256sum > /dev/null; then
    sha256sum "$1"
  elif command -v shasum > /dev/null; then
    shasum -a 256 "$1"
  else
    die "needs sha256sum or shasum to check the download"
  fi
}

main() {
  version=${SONDA_VERSION:-$release_version}
  dir=${SONDA_INSTALL_DIR:-"$HOME/.local/bin"}
  while [ $# -gt 0 ]; do
    case $1 in
      --version) [ $# -ge 2 ] || usage; version=$2; shift 2 ;;
      --dir) [ $# -ge 2 ] || usage; dir=$2; shift 2 ;;
      -h | --help) usage 0 ;;
      *) usage ;;
    esac
  done
  [ -n "$version" ] || version=$(latest_version)
  version=${version#v}
  case $version in
    [0-9]*.[0-9]*.[0-9]*) ;;
    *) die "not a version: $version" ;;
  esac
  case $version in *[!0-9A-Za-z.-]*) die "not a version: $version" ;; esac

  name="sonda-$version-$(platform)"
  base=${SONDA_DOWNLOAD_URL:-"$repo_url/releases/download"}/v$version
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  say "downloading $name"
  fetch "$base/$name" "$tmp/$name" ||
    die "couldn't download $base/$name: is there a release $version with a binary for this system?"
  fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || die "couldn't download $base/SHA256SUMS"

  # Exactly the file's own line: two spaces, as the release writes them,
  # with the name's dots matched as dots.
  line="^[0-9a-f]\{64\}  $(printf '%s\n' "$name" | sed 's/\./\\./g')\$"
  lines=$(grep -c "$line" "$tmp/SHA256SUMS" || true)
  [ "$lines" = 1 ] || die "$name has $lines lines in SHA256SUMS, not one: not installed"
  expected=$(grep "$line" "$tmp/SHA256SUMS" | cut -d' ' -f1)
  actual=$(sha256 "$tmp/$name" | cut -d' ' -f1)
  [ "$actual" = "$expected" ] || die "$name doesn't match its checksum: not installed"
  say "checksum OK"

  # gh exits with 4 when it isn't signed in: then the check is skipped, as
  # without gh; any other failure means the attestation doesn't verify.
  if command -v gh > /dev/null; then
    status=0
    gh attestation verify "$tmp/$name" --repo lvaoliveira/sonda > "$tmp/attestation" 2>&1 || status=$?
    case $status in
      0) say "attestation OK: built by lvaoliveira/sonda's release workflow" ;;
      4) say "attestation not checked (gh isn't signed in): see docs/install.md" ;;
      *)
        cat "$tmp/attestation" >&2
        die "$name's attestation didn't verify: not installed"
        ;;
    esac
  else
    say "attestation not checked (needs gh): see docs/install.md"
  fi

  mkdir -p "$dir"
  # Copied next to the target, then moved: a running sonda isn't overwritten
  # in place, and no half-written binary is ever left at the target.
  cp "$tmp/$name" "$dir/.sonda.new"
  chmod 755 "$dir/.sonda.new"
  mv -f "$dir/.sonda.new" "$dir/sonda"
  installed=$("$dir/sonda" --version) || die "installed in $dir, but it doesn't run"
  say "installed $installed in $dir"

  case ":$PATH:" in
    *":$dir:"*) ;;
    *)
      say "$dir isn't on your PATH. Add this to your shell's startup file"
      say "(~/.zshrc on macOS, ~/.bashrc on most Linux systems), then open a new terminal:"
      printf "\n  export PATH=\"%s:\$PATH\"\n\n" "$dir" >&2
      ;;
  esac
}

main "$@"
