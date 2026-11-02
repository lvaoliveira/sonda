#!/usr/bin/env bash
# Cleans up a sonda clone after pull requests merge:
#
#   1. prunes remote-tracking branches deleted on the remote;
#   2. removes extra worktrees whose work is merged, when they have no
#      uncommitted changes and nothing in them changed for --idle-hours;
#   3. deletes local branches whose work is merged;
#   4. in the worktrees left, sweeps build files (target/) not used for
#      --days, then the oldest ones until target/ is under --max-gb. On
#      macOS, debug builds keep debug info in per-unit object files that
#      every incremental rebuild adds to, so a busy worktree grows by tens
#      of GB in days of recent files: the cap is what keeps it bounded, at
#      the cost of a fuller rebuild after a sweep.
#
# "Merged" means the commit is in origin/main, or the branch's tip is the
# head of a pull request GitHub shows as merged (which covers squash merges).
# Nothing that isn't merged is touched, and the main worktree is never removed.
#
# Prints what it would do; pass --yes to do it.
#
#   scripts/clean-merged.sh [--yes] [--days N] [--max-gb N] [--idle-hours N]
#
# Defaults: --days 3, --max-gb 20 (as cargo-sweep counts it: files' full
# sizes, more than `du` shows), --idle-hours 12.
#
# Needs git; gh for squash-merged pull requests (skipped without it) and
# cargo-sweep for build files (`cargo install cargo-sweep`; skipped without it).
# Written for the bash 3.2 that macOS ships.

set -euo pipefail

yes=0
days=3
max_gb=20
idle_hours=12
while [ $# -gt 0 ]; do
  case "$1" in
    --yes) yes=1 ;;
    --days) days="${2:?--days needs a number}"; shift ;;
    --max-gb) max_gb="${2:?--max-gb needs a number}"; shift ;;
    --idle-hours) idle_hours="${2:?--idle-hours needs a number}"; shift ;;
    -h | --help) sed -n '2,/^$/s/^# \{0,1\}//p' "$0"; exit 0 ;;
    *) echo "clean-merged: unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done
case "$days$max_gb$idle_hours" in
  *[!0-9]*) echo "clean-merged: --days, --max-gb and --idle-hours take whole numbers" >&2; exit 2 ;;
esac

say() { printf '%s\n' "$*"; }
act() {
  if [ "$yes" = 1 ]; then
    say "  $*"
    "$@"
  else
    say "  would run: $*"
  fi
}

# The main worktree is the first one listed, wherever this runs from.
main=$(git worktree list --porcelain | sed -n '1s/^worktree //p')
cd "$main"
say "clean-merged: $main ($([ "$yes" = 1 ] && echo acting || echo dry run; true))"

git fetch --quiet --prune origin
base=$(git rev-parse origin/main)

# Heads of merged pull requests, as "branch sha" lines, when gh can say.
merged_prs=""
if command -v gh >/dev/null 2>&1; then
  slug=$(git remote get-url origin | sed -E 's#\.git$##; s#^.*[:/]([^/]+/[^/]+)$#\1#')
  owner=${slug%%/*}
  # The owner's own login, when gh has it, in case another account is active.
  token=$(gh auth token --user "$owner" 2>/dev/null || true)
  merged_prs=$(GH_TOKEN="${token:-${GH_TOKEN:-}}" gh pr list --repo "$slug" --state merged \
    --limit 1000 --json headRefName,headRefOid \
    --jq '.[] | "\(.headRefName) \(.headRefOid)"' 2>/dev/null || true)
  [ -n "$merged_prs" ] || say "  (gh gave no merged pull requests; checking origin/main only)"
fi

# Whether `branch` (may be empty for a detached HEAD) at `sha` is merged.
merged() {
  local branch=$1 sha=$2
  git merge-base --is-ancestor "$sha" "$base" && return 0
  [ -n "$branch" ] && printf '%s\n' "$merged_prs" | grep -qxF "$branch $sha"
}

# Whether anything in worktree `dir` changed in the last --idle-hours: its
# files (build output and dependencies aside), or its git state (checkout,
# commit, index).
recently_used() {
  local dir=$1 gitdir minutes=$((idle_hours * 60))
  gitdir=$(git -C "$dir" rev-parse --absolute-git-dir)
  [ -n "$(find "$dir" \( -name target -o -name node_modules -o -name .git \) -prune \
      -o -type f -mmin -"$minutes" -print 2>/dev/null | head -n 1)" ] && return 0
  [ -n "$(find "$gitdir" -maxdepth 1 -type f -mmin -"$minutes" -print 2>/dev/null | head -n 1)" ]
}

say "Worktrees:"
removed_branches=""
path="" sha="" branch="" locked=0
check_worktree() {
  [ -n "$path" ] || return 0
  if [ "$path" = "$main" ]; then
    :
  elif [ ! -d "$path" ]; then
    say "- $path: missing; pruning its record"
    act git worktree prune
  elif [ "$locked" = 1 ]; then
    say "- $path: locked, kept"
  elif ! merged "$branch" "$sha"; then
    say "- $path (${branch:-detached}): not merged, kept"
  elif [ -n "$(git -C "$path" status --porcelain)" ]; then
    say "- $path (${branch:-detached}): merged, but has uncommitted changes; kept"
  elif recently_used "$path"; then
    say "- $path (${branch:-detached}): merged, but used in the last ${idle_hours}h; kept"
  else
    say "- $path (${branch:-detached}): merged and idle; removing"
    act git worktree remove "$path"
    [ -z "$branch" ] || removed_branches="$removed_branches $branch"
  fi
  path="" sha="" branch="" locked=0
}
while IFS= read -r line; do
  case "$line" in
    "worktree "*) check_worktree; path=${line#worktree } ;;
    "HEAD "*) sha=${line#HEAD } ;;
    "branch refs/heads/"*) branch=${line#branch refs/heads/} ;;
    locked*) locked=1 ;;
  esac
done < <(git worktree list --porcelain)
check_worktree

say "Local branches:"
count=0
while IFS=' ' read -r branch sha checked_out; do
  # Checked out somewhere (and not just removed above): kept.
  if [ -n "$checked_out" ] && ! printf ' %s ' "$removed_branches" | grep -qF " $branch "; then
    continue
  fi
  if merged "$branch" "$sha"; then
    count=$((count + 1))
    act git branch --quiet -D "$branch"
  fi
done < <(git for-each-ref --format='%(refname:short) %(objectname) %(worktreepath)' refs/heads)
[ "$count" -gt 0 ] || say "  none merged"

size() { du -sh "$1" | awk '{print $1}'; }

say "Build files: unused for ${days} days, then the oldest above ${max_gb} GB:"
if ! cargo sweep --version >/dev/null 2>&1; then
  say "  skipped: cargo-sweep isn't installed (cargo install cargo-sweep)"
else
  while IFS= read -r dir; do
    [ -d "$dir/target" ] || continue
    say "- $dir/target ($(size "$dir/target") on disk)"
    for limit in "--time $days" "--maxsize ${max_gb}GB"; do
      # shellcheck disable=SC2086 # $limit is an option and its value.
      if [ "$yes" = 1 ]; then
        (cd "$dir" && cargo sweep $limit >/dev/null 2>&1)
      else
        (cd "$dir" && cargo sweep --dry-run $limit 2>&1 | tail -n 1 |
          sed -E 's/^\[INFO\] Would clean: ([^"]*) from .*/  '"${limit%% *}"': would clean \1/')
      fi
    done
    [ "$yes" = 0 ] || say "  now $(size "$dir/target")"
  done < <(git worktree list --porcelain | sed -n 's/^worktree //p')
fi
