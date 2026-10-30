# ADR-0010: A default for new code

- Status: **accepted; revised the same day.** The time window became
  opt-in, and `sonda baseline` sets a fixed starting point instead. See
  "Revision" below.
- Date: 2026-10-30

## Context

Quality gates judge new code ("clean as you code"): the default gate fails
on new bugs and new vulnerabilities, and on coverage and duplication of new
code. Until now, new code needed `--new-code REF`. Without it, the whole
project counted as new code.

So any existing project failed its gate on old debt from its first scan,
and kept failing on its default branch, where there is nothing sensible to
pass as `--new-code`. Analyzing arandu showed it: its gate failed on 25
"new" vulnerabilities, 24 of them in years-old C files.

SonarQube's default is "since the previous version". sonda has no version
setting, but git has tags, branches and commit dates. Scans must stay
offline and deterministic (ADR-0005) and read only git's object database
(ADR-0002).

## Decision

`scan.new_code` in sonda.toml (and `--new-code`, which overrides it) takes
`auto` (the default), `none` (the whole project) or a git ref. `auto` picks
the reference in this order:

1. **A branch that has diverged from the default branch.** HEAD has
   commits the default branch lacks, so new code is the change since their
   merge base. The default branch is what `origin/HEAD` points at, else
   `origin/main`, `origin/master`, `main` or `master`, whichever exists.
   This covers pull requests and unpushed commits.
2. **The default branch.** The latest tag reachable from `HEAD^`: changes
   since the last release. Starting from `HEAD^` means a release commit's
   own tag doesn't leave nothing new.
3. **No tag.** The last first-parent commit `scan.new_code_days` (default
   30) or more older than HEAD. The window is measured from HEAD's commit
   date, read from the commit object, not from the clock. So the same
   commit always gives the same result.
4. **Nothing found.** No repository, a history too short, or a shallow
   clone: the whole project, as before. The report says why.

Every step reads refs and commit objects only:

- `symbolic-ref`, `rev-parse`, `merge-base`, `describe` and `rev-list`;
- `cat-file` for the commit time, because `git log` would honor
  `log.showSignature` and run gpg.

They all run with ADR-0002's hardening and its timeout.

Reports say how the reference was chosen: JSON `new_code_basis` (`given`,
`default_branch`, `latest_tag`, `days`, `whole_project`) and
`new_code_description`, which is also the text report's summary line.

## Revision: a fixed baseline, not a rolling window

As first built, step 3 defaulted to 30 days. But a rolling window lets an
issue age out of new code unfixed: it counts as new for 30 days, then
silently stops, and the gate turns green with time. That defeats "clean as
you code". The window is also arbitrary, covering little in a quiet
repository and a lot in a busy one.

Instead:

- **The window is opt-in.** `scan.new_code_days` defaults to 0, for teams
  that want SonarQube's "number of days" mode.
- **A baseline you set once.** `sonda baseline` tags HEAD `sonda-baseline`:
  the commit whose existing debt the project accepts when it adopts sonda.
  `auto` picks it up like any tag, and immediately when it's on HEAD
  itself. Everything after it stays new until fixed, or until a later
  release tag.
  - **Hooks:** tagging updates a ref, which runs the repository's
    reference-transaction hook, so sonda tags with hooks off
    (`core.hooksPath=/dev/null`), as ADR-0002 requires. A test proves no
    hook runs.
  - **No push:** it doesn't push the tag; that's the user's step.
- **Without a tag,** the whole project counts, and the report says to set a
  baseline.
- **On the server (planned):** the same idea needs no git there. New code
  is what's changed since the project's first analysis, using the issues
  the server already tracks across analyses, and the baseline can be moved
  to a later analysis. It's on the roadmap.

## Consequences

- **Gates change without anyone asking.** Projects scanned without
  `--new-code` now see far fewer new issues, because only recent changes
  count. That is the intent. `scan.new_code = "none"` restores the old
  behavior.
- **CI needs history.** `auto` needs tags and history: a shallow clone
  (`actions/checkout`'s default) falls back to the whole project. The
  README's CI example uses `fetch-depth: 0`.
- **No server-side baseline yet.** "Since the first analysis" needs the
  server's knowledge, which an offline scan doesn't have. The baseline tag
  is its offline counterpart, and the server-side version is planned.
- **A library API change.** `ScanOptions::new_code_ref = None` now means
  "use `scan.new_code`" rather than "the whole project".
