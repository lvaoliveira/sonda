#!/usr/bin/env bash
# Regenerates crates/sonda-core/data/dotnet-8.0.json.z from the .NET
# reference packs (ADR-0022). Downloads each pack by version, checks its
# SHA-256, and runs the extractor on its reference assemblies.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# name version sha256
packs=(
  "microsoft.netcore.app.ref 8.0.11 968e8c027bc54350c10e1fbda9dc73389320002b2f1638f67b96e1ade278bf42"
  "microsoft.aspnetcore.app.ref 8.0.11 757275875c72788fa5cdda0d898b662c1ce44271ca65c59292c8eea3bd32a799"
  # Only to tag what every target has (.NET Standard 2.0); adds no types.
  "netstandard.library 2.0.3 3eb87644f79bcffb3c0331dbdac3c7837265f2cdf58a7bfd93e431776f77c9ba"
)

args=()
for pack in "${packs[@]}"; do
  read -r name version sha <<<"$pack"
  file="$work/$name.nupkg"
  curl -sSfL -o "$file" "https://api.nuget.org/v3-flatcontainer/$name/$version/$name.$version.nupkg"
  echo "$sha  $file" | shasum -a 256 -c - >/dev/null
  mkdir -p "$work/$name"
  unzip -q "$file" -d "$work/$name"
  label="$(sed -n 's:.*<id>\(.*\)</id>.*:\1:p' "$work/$name"/*.nuspec | head -1) $version"
  if [ "$name" = netstandard.library ]; then
    args+=("baseline:$label" "$work/$name/build/netstandard2.0/ref")
  else
    args+=("$label" "$work/$name/ref/net8.0")
  fi
done

cargo run --release --manifest-path "$root/tools/netref/Cargo.toml" -- \
  "$root/crates/sonda-core/data/dotnet-8.0.json.z" "${args[@]}"
cp "$work/microsoft.netcore.app.ref/LICENSE.TXT" "$root/crates/sonda-core/data/dotnet-8.0.LICENSE.txt"
