# ADR-0021: Pull request decoration, GitHub first

- Status: **accepted** (2026-11-02). Built: pull request analyses, and the
  GitHub App posting them. Next: updating on triage.
- Date: 2026-11-02
- Builds on ADR-0010 (new code in CI), ADR-0012 (tokens), ADR-0014 (CI follows
  the server's gate) and ADR-0017 (project settings); plans the roadmap's
  "Pull request decoration"

## Context

A pull request's scan uploads as if it were a branch named after its head.
Its result lives only on the server and in the CI log: nothing appears on
the pull request itself, apart from what a SARIF upload to GitHub code
scanning shows, which knows nothing of the server's gate, reviews or
accepted issues. SonarQube decorates pull requests on GitHub, GitLab,
Azure DevOps and Bitbucket. People expect sonda to do the same.

GitLab and Bitbucket come later. This ADR designs the parts they share, and
builds GitHub on them first.

## Decision

### Pull requests are their own kind of analysis

- **The CLI says it's a pull request.** In GitHub Actions, on a
  `pull_request` event, `sonda scan --upload` and `sonda upload` read the
  event file they already read for pushes (ADR-0010) and send
  `pull_request: {number, base, head, head_sha, repository}`.
  - `head_sha` is the pull request's head commit, which isn't what CI
    checks out: CI checks out a temporary merge commit, and GitHub shows
    a check run only on the head commit.
  - `--pull-request <n> --pull-request-base <branch>` set the same
    elsewhere. They carry no `head_sha`, so the server stores the
    analysis but can't decorate it.
- **Stored apart from branches.** Analyses get a nullable `pull_request`
  (the number) and `pull_request_base`. Pull request analyses don't
  appear in the project's branch list, the Overview, Projects or Security
  counts. They're on their own list on the project page and keep their
  own issue tracking, as a branch does.
- **Judged as branches are:** on their new code (what the scan compared
  with, normally the base branch's merge base, ADR-0010), by the project's
  gate, the server gate included (ADR-0017). Decided issues stay decided
  (ADR-0014).
- **Kept for 30 days** after a pull request's last analysis, then removed
  with their issues. Merged or closed pull requests aren't detected.

### A GitHub connection

- **A GitHub App, configured like the server's other secrets:**
  - `SONDA_GITHUB_APP_ID`;
  - `SONDA_GITHUB_APP_PRIVATE_KEY_FILE`;
  - `SONDA_GITHUB_API_URL`, for Enterprise Server; it defaults to
    `https://api.github.com`.

  The key never enters the database, so this ADR needs no encryption at
  rest. GitLab and Bitbucket will need that, along with storing tokens
  from the web app. Without an App configured, nothing changes, and the
  server makes no new outbound calls.
- **Permissions:** checks (read and write), pull requests (read and
  write), metadata (read). The App is installed on the repositories it
  decorates. The server signs a JWT and exchanges it for an installation
  token per repository. The token lasts an hour and is kept in memory
  only.
- **A project is bound to a repository** (`owner/name`) in its Settings
  (ADR-0017), by admins. An upload's `repository` must match the binding,
  or nothing is posted, so a project can't decorate another repository's
  pull requests.

### What appears on the pull request

- **A check run named `sonda`** on `head_sha`:
  - Its conclusion is `success` when the gate passes, `failure` when it
    fails, and `neutral` when it's partial. Branch protection can require it.
  - Its summary has:
    - the gate, and which conditions fail;
    - new issues by type and severity;
    - coverage and duplication on new code;
    - a link to the analysis.
- **Inline: check run annotations** on new issues in lines the pull
  request changed:
  - each annotation gives the rule, its severity, and a link to it;
  - at most 50; the rest are counted in the summary;
  - accepted and false-positive issues get none.

  Each analysis's check run replaces the previous one, so a fixed issue's
  annotation is simply gone. No review comments to track and resolve.
- **One summary comment**, edited in place on every analysis:
  - it repeats the check run's summary, for people who don't open checks;
  - it's found by a hidden marker `<!-- sonda:project=<key> -->`, so a
    re-run or a second upload never adds another.

### Posting, from the server

- **After the gate is judged:** the upload stores the analysis, judges it,
  answers CI as today (ADR-0014), and queues the decoration. A
  `decorations` table holds the analysis, attempts, the next try and the
  last error.
- **A background task posts it.** It retries with backoff for a day. A
  GitHub that's down or refuses never fails the upload; the analysis page
  shows the decoration's state and its last error.
- **Triage updates it without a scan.** Accepting an issue, marking a
  false positive, or reopening one on a pull request's latest analysis
  queues the decoration again, so the check and the comment follow.

### Pull requests from forks

Skipped for now. A fork's CI usually has no secrets, so it can't upload
with a project token. The CLI recognizes a fork pull request (the
event's head repository isn't the base repository), says it won't upload,
and still scans: the gate, the exit code and SARIF work as without a
server.

## Consequences

- With the App configured and a project bound, a pull request shows
  sonda's gate as a check and a comment. Branch protection can require
  the check, which follows what the server shows, accepted issues
  included.
- The server makes outbound calls to GitHub when an App is configured. The
  docs say which calls they are and what they send: the summary,
  annotations' paths, lines and messages, but never source code.
- Pull request analyses add rows that branches didn't. The 30-day removal
  bounds them.
- GitLab and Bitbucket reuse the pull request analyses, the queue and the
  summary. Each adds a client and a connection kind, and they bring the
  stored-credentials question this ADR avoids.

## Not now

- GitLab (merge request notes, diff discussions, commit statuses) and
  Bitbucket (Code Insights reports and annotations, build statuses): one
  ADR or PR each, on this design.
- Pull requests from forks.
- Review comments threaded on the diff, instead of annotations.
- Webhooks: noticing a pull request merged or closed to remove its
  analyses earlier, or re-posting when someone edits sonda's comment.
- Connecting GitHub from the web app (the App manifest flow), instead of
  configuration: built in
  [ADR-0024](0024-creating-the-github-app.md).

## Done when

- On a fixture repository with the App installed, a pull request that
  adds an issue gets:
  - a failing `sonda` check with one annotation on the changed line;
  - one summary comment.
- A push that fixes it turns the check green and edits the same comment,
  without adding one.
- Accepting the issue on the server, with no new scan, turns the check
  green.
- Branch protection requiring `sonda` blocks merging while it fails.
- With GitHub unreachable, the upload still succeeds and CI still gets the
  gate; decoration catches up once GitHub answers.
- A fork's pull request scans without uploading, and says why.
- The App's key and installation tokens never appear in an API response
  or a log line.
