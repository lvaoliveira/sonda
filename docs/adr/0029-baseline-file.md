# ADR-0029: A baseline file

- Status: **accepted**
- Date: 2026-11-17

## Context

A project adopting sonda has issues it won't fix soon. Two things already
keep them out of the way:

- **New code** ([ADR-0010](0010-default-new-code.md)): the default gate
  judges only issues on new lines. That works where git can say what's new,
  and a local run on the default branch has no sensible reference.
- **The server's triage** ([ADR-0014](0014-security-review.md) and the issue
  statuses): an issue marked accepted or false positive leaves the gate. That
  needs a server.

Neither helps a project that only runs the CLI, and wants `sonda scan` to
fail on what is new *as of today*, whatever the diff says: a scheduled run,
a pre-commit hook, a first scan of a legacy codebase with `--new-code none`.
Each issue already has a fingerprint that stays the same when its line moves
or is re-indented ([ADR-0005](0005-sonda-server.md), pinned by a test), so
"the issues that exist now" can be written down and compared with.

How others do it: ESLint's bulk suppressions, Ruff's per-file ignores,
mypy's baseline and SARIF's `baselineState` all keep a committed file of the
accepted findings and report only what isn't in it. SonarQube has no such
file; its server's new code period and issue statuses play that part.

## Decision

### The file

`sonda-baseline.json`, JSON, committed with the code:

```json
{
  "version": 1,
  "issues": [
    { "fingerprint": "04d724dbbd800b9d4c64c4649cd55415", "rule": "js/no-var", "path": "src/a.js", "line": 3 }
  ]
}
```

- A scan matches by `fingerprint` alone. `rule`, `path` and `line` are there
  so a person reviewing the file in a pull request can tell what is being
  accepted; `line` is where the issue was when the file was written, and is
  not kept up to date.
- Entries are sorted by path, line, rule and fingerprint, and the file ends
  with a newline, so rewriting it changes only what changed.
- A `version` this sonda doesn't know, a file that isn't this shape, or one
  over 16 MiB is an error, never an empty baseline: reading it wrong would
  quietly hide or reveal findings.

The fingerprint hashes the rule, the file's path, the flagged line's text
with whitespace removed and how many earlier issues share those three. So
editing the flagged line, or renaming or moving its file, makes the issue
unmatched, and it is reported again: that is the point, since the code the
baseline accepted is no longer there.

### Where it comes from

In this order:

1. `--baseline FILE`, which must exist.
2. `scan.baseline` in sonda.toml, a path relative to the scan root and inside
   it, which must exist.
3. `sonda-baseline.json` in the scan root, used when it exists.

`--no-baseline` ignores all three. Nothing else is searched for: no parent
directories, no home directory.

The file is an input of the scan like sonda.toml is, and the repository under
analysis can write either, so a pull request can add entries as it can
disable rules. The same review catches both, and the report says how many
issues the baseline hid, so a gate that went green because of it is visible.

### What it does

Issues whose fingerprint is in the baseline are **removed**: from the issue
list, every count and measure, the quality gate, SARIF and the exit code, as
if the rule had not reported them. Removing them, instead of marking them,
keeps every consumer of the report in agreement without each learning a new
field.

It is independent of new code. An issue is hidden by the baseline whether or
not it is on a new line; an issue that is new and not in the baseline counts.

The JSON report gains a `baseline` object when one was applied:

```json
"baseline": { "file": "sonda-baseline.json", "hidden": 120, "unmatched": 3 }
```

`hidden` is the issues it removed, `unmatched` the entries that matched no
issue (fixed, or edited since), which the terminal also says, with how to
refresh the file. Entries that match nothing are not an error: a baseline
gets stale as code improves, and failing on that would punish fixing things.

### Writing it

`sonda scan --write-baseline FILE` scans with no baseline, writes every issue
it found, and exits 0 whatever the gate says: writing the baseline is
accepting what is there. Run again later, it drops what was fixed and
accepts what is new, which is the review step: the diff of the file is the
list of issues being accepted.

### With a server

A baseline is for CLI-only use. A report that has had issues removed, once
uploaded, makes the server see them as fixed, and as new again if the
baseline is later dropped. `sonda scan --upload` therefore ignores any
baseline and says so; the server's triage is the way to accept an issue
there. `--write-baseline` and `--baseline` are errors together with it.

## Consequences

- A CLI-only project can adopt sonda on a legacy codebase with a gate that
  passes today and fails on anything new, without git history.
- A new committed file whose changes need review like a lint config's.
- The fingerprint algorithm, already a contract with servers, becomes one
  with these files too: changing it would unmatch every baseline. Its pinned
  test covers both, and `sonda-fingerprint-v1` in the hash lets a version 2
  exist beside it.
- Matching a renamed file's issues needs the baseline rewritten. Following
  renames would need git, and the baseline would depend on history.

### Not decided here

- Per-rule or per-path entries (accept a whole rule in a folder). The
  existing `scan.exclude` and `rules.disabled` do that.
- Expiring entries, or a gate condition on the baseline's size.
