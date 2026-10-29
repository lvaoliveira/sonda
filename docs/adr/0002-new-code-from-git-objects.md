# ADR-0002: Compute new code from git objects, not `git diff`

- Status: accepted
- Date: 2026-10-28

## Context

"New code" is every line that differs between the working tree and the merge
base with a reference branch. The obvious implementation is
`git diff --unified=0 <merge-base>`.

The analyzed repository is untrusted, including `.git/config` and
`.gitattributes`. That matters when the scanned directory comes from an
archive, a shared volume or a cache, and not from a fresh clone. Commands
that read the working tree or refresh the index will run programs named in
that config. We confirmed each of these in tests:

- `core.fsmonitor` ran during `git diff` and `ls-files`
- a clean filter (`filter.<name>.clean`) ran during `git diff`, even with
  `-c core.fsmonitor=false`
- `textconv` and `diff.external` are further vectors (the latter is off with
  `--no-ext-diff`)

There is no single git switch that turns off every such hook.

## Decision

sonda asks git only to read the object database:

1. `rev-parse --show-prefix` maps the scan root to its place in the repository.
2. `merge-base --end-of-options HEAD <ref>` finds the base commit.
3. `ls-tree -r -z --full-tree` lists base blobs (regular files only).
4. `cat-file --batch` streams base contents one at a time, capped at the
   file size limit.

sonda then diffs each working-tree file against its base blob in-process
(Myers via the `similar` crate, with a 1 s per-file deadline after which it
approximates). A file that is missing from the base is entirely new.

As defense in depth, every git call also gets `-c core.fsmonitor=false`,
`GIT_OPTIONAL_LOCKS=0` and `GIT_TERMINAL_PROMPT=0`. User references are
validated (no leading `-`, no control characters or whitespace) and passed
after `--end-of-options`.

## Consequences

- A regression test configures fsmonitor, clean and smudge filters, textconv
  and an external diff in a test repository, and fails if any of them runs.
- One more dependency (`similar`) and about 100 lines of git plumbing.
- With `--new-code`, each scanned file is read twice: once to diff, once to
  analyze. That is acceptable for now; it can be merged into one read if
  profiling shows it matters.
- Line-level results match `git diff` in normal cases (verified on a real
  repository). They may differ slightly where diff heuristics differ, for
  example with moved blocks.
- Every git process runs under a watchdog thread that kills it after
  `scan.git_timeout_secs` (default 120 s). The killed process's pipes reach
  end-of-file, and the run fails with a timeout error instead of hanging.
  Stdout and stderr are drained concurrently so a full pipe cannot deadlock
  git.
