# ADR-0010: A default for new code

- Status: **accepted** (second version; see "Rejected").
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

How others do it:

- **SonarQube.** The scanner doesn't decide what's new; the server does.
  Each project has a "new code period": "previous version" by default
  (changes since the version setting last changed, or since the first
  analysis if it never does), or a number of days, a reference branch, or
  a specific analysis. A pull request is always judged against its target
  branch.
- **GitHub.** Every workflow run says what it builds: a pull request and
  its base branch, or a push and the commit it replaced.

Scans must stay offline and deterministic for their inputs (ADR-0005) and
read only git's object database (ADR-0002).

## Decision

### In the CLI: what the run says changed

`scan.new_code` in sonda.toml (and `--new-code`, which overrides it) takes
`auto` (the default), `none` (the whole project) or a git ref. `auto` uses
the first of these that applies:

1. **A GitHub Actions pull request:** its base branch, `GITHUB_BASE_REF`,
   as `origin/<base>` (how actions/checkout fetches it) or `<base>`.
2. **A GitHub Actions push:** the commit it replaced, the event's `before`.
   It's skipped when the push created the branch, since `before` is then all
   zeros.
3. **A branch with commits its default branch lacks:** their merge base,
   with the default branch being what `origin/HEAD` points at, else
   `origin/main`, `origin/master`, `main` or `master`. This covers branches
   outside CI and unpushed commits.
4. **Otherwise,** such as a local run on the default branch: uncommitted
   changes, against HEAD.

The whole project counts only outside git, or with `none`.

Each step reads refs and commit objects only (`rev-parse`, `symbolic-ref`,
`merge-base`), with ADR-0002's hardening and timeout. A base or `before`
that isn't in the clone (a shallow checkout) falls through to the next
step. The CI variables are inputs like the code: the same commit in the
same pull request gives the same report.

Reports say how the reference was chosen: JSON `new_code_basis` (`given`,
`pull_request`, `push`, `default_branch`, `uncommitted`, `whole_project`)
and `new_code_description`, which the text report's summary also uses.

### On the server: a new code period (planned)

The long-term view of a project's default branch belongs to the server, as
in SonarQube:

- **The period is per project:** since the first analysis by default, with
  an action to reset it, and later "previous version" (once uploads carry
  a version), a number of days, or a specific analysis.
- **Issues** first seen within the period are new. The server already
  tracks issues across analyses by fingerprint.
- **New lines** come from diffing stored sources against the period's
  first analysis.
- **The default branch's gate** on the server uses this period, so nothing
  ages out.

This needs its own short ADR. It's on the roadmap.

## Rejected

The first version of this decision, briefly merged, compared the default
branch with its latest tag, then with the commit 30 days older than HEAD,
and added `sonda baseline` to tag a starting point. Both were dropped:

- **Tags** ask projects to adopt a tagging convention for sonda's sake, and
  a tag pushed by hand is easy to forget or move.
- **A rolling window** lets issues age out of new code without being fixed:
  the gate turns green with time.

## Consequences

- **CI judges exactly the change.** Pull requests and pushes in GitHub
  Actions are gated on their own changes, and need `fetch-depth: 0` so the
  base or `before` commit is in the clone. Other CI systems can pass
  `--new-code` until they're supported.
- **Local runs judge work in progress:** on the default branch, uncommitted
  changes are new code.
- **The default branch's long-term gate waits** for the server's new code
  period. Until then, its CLI gate covers each push.
- **A library API change.** `ScanOptions::new_code_ref = None` means "use
  `scan.new_code`" rather than "the whole project".
