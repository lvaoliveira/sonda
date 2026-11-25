#!/usr/bin/env bash
# The 14-day release age for Rust crates, for the ones Dependabot doesn't
# add. Used by CI's supply-chain job on pull requests.
#
# Dependabot's `cooldown` (.github/dependabot.yml) holds back its own
# version updates for 14 days, the same rule as pnpm's minimumReleaseAge. A
# crate added or bumped by hand skips that wait, so this reads the
# registry crates `Cargo.lock` gains over BASE (default origin/main) and
# fails for any version crates.io published less than 14 days ago, unless
# .cargo/young-crates.txt lists it.
#
# A security fix outweighs the wait, as it does for Dependabot: list the
# crate there with the advisory it fixes. A line is `name version  reason`;
# a version that has aged past 14 days no longer needs its line, and the
# script says so.
#
# Usage: scripts/check-crate-age.sh [BASE]
#        (MIN_AGE_DAYS overrides the 14 days, to try the failure path.)
set -euo pipefail

cd "$(dirname "$0")/.."
base=${1:-origin/main}
exceptions=.cargo/young-crates.txt
export MIN_AGE_DAYS=${MIN_AGE_DAYS:-14} EXCEPTIONS="$exceptions"

if ! git cat-file -e "$base:Cargo.lock" 2>/dev/null; then
  echo "::error::$base has no Cargo.lock to compare with"
  exit 1
fi
git show "$base:Cargo.lock" > "${TMPDIR:-/tmp}/base-Cargo.lock"
export BASE_LOCK="${TMPDIR:-/tmp}/base-Cargo.lock"

exec python3 - <<'PY'
import datetime, json, os, sys, time, tomllib, urllib.error, urllib.request

MIN = datetime.timedelta(days=int(os.environ["MIN_AGE_DAYS"]))
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


def registry_crates(path):
    with open(path, "rb") as f:
        packages = tomllib.load(f).get("package", [])
    return {
        (p["name"], p["version"])
        for p in packages
        if p.get("source") == REGISTRY
    }


def published(name, version):
    """When crates.io says `name` `version` was published. None if it can't
    be told after a few tries; the caller fails rather than pass unchecked."""
    request = urllib.request.Request(
        f"https://crates.io/api/v1/crates/{name}/{version}",
        # crates.io asks clients to say who they are.
        headers={"User-Agent": "sonda-ci-release-age-check"},
    )
    for attempt in range(4):
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                created = json.load(response)["version"]["created_at"]
            return datetime.datetime.fromisoformat(created.replace("Z", "+00:00"))
        except (urllib.error.URLError, TimeoutError, KeyError, ValueError):
            time.sleep(2 ** attempt)
    return None


def exceptions(path):
    out = {}
    if os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if line and not line.startswith("#"):
                parts = line.split(None, 2)
                if len(parts) == 3:
                    out[(parts[0], parts[1])] = parts[2]
    return out


new = sorted(registry_crates("Cargo.lock") - registry_crates(os.environ["BASE_LOCK"]))
allowed = exceptions(os.environ["EXCEPTIONS"])
now = datetime.datetime.now(datetime.timezone.utc)
failed = False
print(f"{len(new)} crate versions are new in Cargo.lock")
for name, version in new:
    when = published(name, version)
    if when is None:
        print(f"::error::couldn't read when crates.io published {name} {version}")
        failed = True
        continue
    age = now - when
    young = age < MIN
    listed = (name, version) in allowed
    if young and not listed:
        print(
            f"::error::{name} {version} was published {age.days} days ago, under the "
            f"{MIN.days}-day release age: wait, or list it in {os.environ['EXCEPTIONS']} "
            f"with the advisory it fixes"
        )
        failed = True
    elif listed and not young:
        print(f"::notice::{name} {version} is {age.days} days old: drop its line in {os.environ['EXCEPTIONS']}")
    elif listed:
        print(f"excepted {name} {version} ({age.days} days): {allowed[(name, version)]}")
    else:
        print(f"ok {name} {version} ({age.days} days)")
sys.exit(1 if failed else 0)
PY
