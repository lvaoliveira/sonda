# ADR-0011: A new code period on the server

- Status: **accepted**
- Date: 2026-10-30

## Context

ADR-0010 made the CLI judge what each run changed: a pull request against
its base, a push against the commit it replaced, otherwise uncommitted
changes. That's right for gating changes. It leaves no long-term view of a
project's default branch, which is SonarQube's main screen: "what has
anyone added since we started caring?". There, nothing ages out, and old
debt doesn't count.

That view needs memory across analyses, which only the server has.

The server already has most of what it needs:

- **Issues** are tracked per project, branch and fingerprint, with the
  analysis that first saw each one (`issues.first_analysis_id`).
- **Every analysis's sources** are stored (`analysis_files` and `sources`).
- **Stored gates are re-evaluated** on events: ADR-0009 does this for
  dependency conditions, on upload, advisory import and review.

It lacks per-line coverage and duplicated-line data. Reports carry
project-level coverage and duplication blocks, and neither is stored per
line.

## Decision

### The period

Each project has a **new code period** for its main branch. It starts at
an analysis of that branch:

- **The default is the project's first analysis.** Its existing debt is
  accepted, and everything after it is new.
- **It can be reset to any later analysis,** such as after a big cleanup or
  a new major version. This is admin-only, because it accepts the debt up
  to that point, and it's recorded in an audit table with who, when, and
  the old and new start.
- **"Previous version"** (SonarQube's default) came in a second phase,
  once uploads carried a version (`sonda upload --project-version`). The
  period restarts at the first analysis of each new version: the first
  main-branch analysis after the last one with a different version.
  Uploads without a version don't count, so a project that never sends
  one, or only starts to, keeps its first analysis. An admin's start
  takes precedence until it's cleared.
- **No "number of days".** It ages issues out, which ADR-0010 rejected.

Other branches are unchanged: their new code is what the CLI computed (the
pull request, push or merge base), since that's what a branch is judged on.

### What it decides on the main branch

- **Issues:** an issue first seen after the period's starting analysis,
  on a line changed since then, is new. Issues already present in the
  starting analysis are accepted debt, and so are issues a newly added
  rule finds on unchanged lines (first used on arandu, where a release
  with new rules turned 56 issues in untouched code "new" and failed the
  gate). SonarQube does the same by dating such issues from blame.
  The server sets `issues.is_new` from this, instead of from the upload, so
  the Issues page, drill-downs and filters agree.
- **Issue measures:** `new_issues`, `new_bugs`, `new_vulnerabilities`,
  `new_code_smells`, `new_{blocker,critical,major}_issues` and
  `new_debt_minutes` are counted from those issues.
- **`new_lines`:** each file's stored source is diffed against its source
  in the starting analysis, with the same in-process line diff the CLI
  uses (ADR-0002). A file that didn't exist then is entirely new.
- **`new_coverage` and `new_duplicated_lines_density`** need per-line data
  the server doesn't receive. Until reports carry it (the roadmap's
  per-file coverage), these keep the scan's own values, and the UI says
  which values come from the scan. Coverage came next: each file in the
  JSON report carries its `coverage` (covered and uncovered lines), and
  the server computes `new_coverage` on the lines that changed since the
  start, as the CLI does against its reference. Duplication still keeps
  the scan's value.
- **The gate** for the main branch's latest analysis is re-evaluated with
  these values and stored. This is ADR-0009's pattern: on upload, and when
  the period is reset. Older analyses keep the gate they had.

### Where it shows

- **Project page:** "New code: since \<date\> (first analysis)", and for
  admins a "Start new code here" action on an analysis.
- **The API:** project and analysis responses add the period (its starting
  analysis and kind).

## Consequences

- **The main branch's gate becomes SonarQube-like:** stable, with nothing
  aging out, and failing only on what's been added since the period
  started.
- **Two definitions of new code,** each where it belongs. The CLI's gate
  and exit code judge a run's change; the server's main-branch view judges
  the period. Reports and the UI say which one they show.
- **Fingerprint limits.** A renamed file's issues count as new, because the
  fingerprint includes the path. So do issues on an edited line, whose
  text changed, which is right for new code. SonarQube handles renames
  with blame data, which sonda doesn't collect.
- **Cost.** Recomputing on upload means one source diff per changed file
  against the starting analysis, and one query over the branch's issues.
- **Migration.** A `projects.new_code_since` column (an analysis, null to
  follow versions) and a `new_code_resets` audit table, then an
  `analyses.project_version` column. Existing projects
  start at their first analysis, so their main-branch "new" counts change
  on the next upload.
