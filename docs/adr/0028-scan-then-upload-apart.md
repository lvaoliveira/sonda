# ADR-0028: Pull requests CI can't upload: scan, then upload apart

- Status: **accepted; built** (2026-11-13)
- Date: 2026-11-13
- Builds on ADR-0021 (pull request decoration), which left pull requests
  from forks under "Not now"

## Context

A pull request is decorated after CI uploads its analysis to the server
(ADR-0021). That upload needs two things a pull request's CI often lacks:

- **A way to reach the server.** A server on a LAN or a tailnet, the usual
  self-hosted setup, can't be reached from GitHub's hosted runners. A
  self-hosted runner can reach it, but a public repository must never run a
  pull request's code on one: GitHub runs the workflow file from the pull
  request itself, so its author decides what runs on that machine.
- **A token.** GitHub gives no secrets to a fork's pull request, and only
  Dependabot secrets to Dependabot's. The CLI skips forks for that reason
  (ADR-0021).

So a public repository whose server isn't on the internet can decorate no
pull request, and no repository can decorate a fork's.

SonarQube has the same limits: its scanner uploads from CI, with a token,
to a server CI must reach, and its self-hosted server doesn't analyze
forks' pull requests out of the box.

## Decision

Split the scan from the upload, as GitHub recommends for running
privileged steps on a pull request's output: two workflows.

### 1. The scan: the pull request's code, without secrets

- On `pull_request`, on GitHub's runner. It gets no secrets and can reach
  nothing of yours, so whatever the pull request makes it run harms
  nothing.
- **`sonda scan --save-upload FILE`** writes the body `--upload` would
  send, gzipped, instead of sending it: no server, no token. It takes
  `--project`, `--branch` and `--commit` as `--upload` does.
- The file is kept as the artifact `sonda-upload`.

### 2. The upload: main's workflow, with the token

- On `workflow_run`, when the scan completes. GitHub runs this workflow as
  it is on the default branch, never as the pull request has it, so it may
  hold `SONDA_TOKEN` and run on a self-hosted runner that reaches the
  server.
- **It never checks out or runs the pull request's code.** It downloads
  the artifact, as data, and sends it with **`sonda upload --saved
  FILE`**.
- **Which pull request and commit come from GitHub's event**, never the
  artifact. The workflow finds the pull request from the run (a fork's, by
  its head), and passes its number, base, head commit and repository as
  flags: `--pull-request`, `--pull-request-base`, and the new
  `--pull-request-head-sha` and `--repository`. `--saved` replaces the
  file's project, branch, commit, version and pull request with the
  command's, and refuses a file with a field `--save-upload` doesn't
  write.
- **The server validates the rest as any upload**, and decorates it. The
  project analysis token limits it to its project (ADR-0012).

### Shipped as reusable workflows

`scan-pull-request.yml` and `upload-pull-request.yml` in this repository,
called with a few lines each, hold the parts that are easy to get wrong:
installing the CLI, the artifact, finding a fork's pull request, and never
checking out its code where the token is. sonda's own pull requests use
them, with the CLI built from source.

## Consequences

- A public repository on a self-hosted server gets pull request
  decorations without exposing the server or running a pull request's
  code on its runner: its own branches', Dependabot's and forks'.
- **Each repository needs a runner that reaches the server** for the
  upload. On a personal account a runner serves one repository; an
  organization's serves all of them.
- **Dependabot's pull requests need `SONDA_TOKEN` as a Dependabot secret
  too**: GitHub applies Dependabot's rules to the `workflow_run` its pull
  request triggers.
- **The server's rule profile isn't applied** (ADR-0018): the scan can't
  ask the server for it, so it uses `sonda.toml`'s rules, which the
  analysis records, as a scan without a server does.
- **Trust it as the pull request's CI:** its author controls the scan, so
  a fork's analysis is as trustworthy as any check the fork runs.
- The server is unchanged: it receives uploads, as before. It makes no new
  calls to GitHub and its App needs no new permission.

## Considered

- **The server fetching artifacts from GitHub** through its App, polling
  every linked repository: nothing to set up per repository but one
  workflow, and no runner. Built, then dropped: a server calling every
  repository on a timer, spending each installation's rate limit on
  repositories with nothing to fetch, to avoid setup a handful of
  repositories need once.
- **Webhooks** (`workflow_run` events) to the server: event-driven, but
  they need the server reachable from GitHub, which is the problem.
- **A tunnel or Tailscale in the pull request's job**, to upload directly:
  a pull request's code would then run with a route into your network.

## Not now

- GitLab's and Bitbucket's equivalents.
- Applying the server's rule profile to a saved scan.

## Done when

- A pull request from a branch, from a fork and from Dependabot gets the
  `sonda` check and comment, with the scan run on GitHub's runner without
  secrets, and the upload by main's workflow.
- A saved file claiming another pull request, repository or project is
  sent as the upload workflow says, not as it claims.
- A file `--save-upload` didn't write is refused before anything is sent.
