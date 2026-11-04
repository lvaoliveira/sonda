#!/usr/bin/env bash
# The parts of the repository a pull request changes, as GitHub Actions
# outputs (CI's `changes` job): `rust`, `web`, `docker` and `scripts`, each
# "true" or "false". Jobs that test none of the changed parts skip.
#
# Anything else than a pull request (a push to main), a change to the
# workflows, or a diff that can't be computed sets every part: a mistake
# here may only run too much, never skip a check that was needed.
#
# Usage: EVENT=<event name> BASE=<base commit> scripts/ci-changes.sh
set -euo pipefail

out="${GITHUB_OUTPUT:-/dev/stdout}"
everything() {
  printf '%s=true\n' rust web docker scripts >> "$out"
  exit 0
}

[ "${EVENT:-}" = pull_request ] && [ -n "${BASE:-}" ] || everything
files=$(git diff --name-only "$BASE"...HEAD) || everything

rust=false web=false docker=false scripts=false
while IFS= read -r f; do
  case "$f" in
    .github/*) everything ;;
    # docs/rules.md is generated from the rules, and checked against them.
    crates/* | fuzz/* | Cargo.toml | Cargo.lock | deny.toml | rust-toolchain* | .cargo/* | docs/rules.md)
      rust=true ;;
    web/*) web=true ;;
    Dockerfile | .dockerignore | compose*.yaml | caddy/*) docker=true ;;
    scripts/*) scripts=true ;;
  esac
done <<< "$files"

{
  echo "rust=$rust"
  echo "web=$web"
  echo "docker=$docker"
  echo "scripts=$scripts"
} >> "$out"
