#!/bin/sh
# Checks a sonda CLI parses every analyzed language: one small file each,
# each parsed in the sandbox. A system call the build makes that the seccomp
# allow-list misses kills that language's parser, which a scan only reports
# as skipped files; this fails on it instead and, where strace is available,
# names the call. Used by CI and the release workflow.
#
#   scripts/check-languages.sh [SONDA]   (default ~/.local/bin/sonda)
set -eu
sonda=${1:-"$HOME/.local/bin/sonda"}
case $sonda in /*) ;; */*) sonda="$PWD/$sonda" ;; esac
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
cd "$dir"
printf 'export function f(a) { return a == null ? 0 : a.length }\n' > a.js
printf 'export const f = (a: string[]): number => a.length\n' > a.ts
printf 'export const C = () => <p>{1}</p>\n' > a.tsx
printf 'def f(a):\n    return len(a)\n' > a.py
printf 'class A { int f(String a) { return a.length(); } }\n' > A.java
printf 'class A { int F(string a) => a.Length; }\n' > A.cs
printf 'fn f(a: &str) -> usize { a.len() }\n' > a.rs
printf 'int f(const char *a) { return a[0]; }\n' > a.c
printf 'int f(const char *a) { return a[0]; }\n' > a.cpp
# Exit 1 is a failing gate, not an error.
status=0
"$sonda" scan . --format json -o report.json || status=$?
if [ "$status" -gt 1 ] || [ ! -s report.json ]; then
  echo "check-languages: the scan failed (exit $status)" >&2
  exit 1
fi
if jq -e '[.warnings[] | select(test("sandbox"))] | length > 0' report.json > /dev/null; then
  jq -r '.warnings[]' report.json
  if command -v strace > /dev/null; then
    strace -f -o strace.log "$sonda" scan . -o /dev/null || true
    grep -B5 SIGSYS strace.log | head -60
  fi
  exit 1
fi
analyzed=$(jq '.files | length' report.json)
if [ "$analyzed" -ne 9 ]; then
  echo "check-languages: $analyzed of 9 files analyzed" >&2
  jq -r '.files[].path, .warnings[]' report.json >&2
  exit 1
fi
jq -r '.files[] | "\(.path) \(.language)"' report.json
