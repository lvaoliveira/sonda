# ADR-0023: Connecting a repository from the web app

- Status: **accepted; built.** The Connect page, `POST /api/projects`, and
  projects waiting for their first analysis.
- Date: 2026-11-02

## Context

Analyzing a GitHub repository on every push and pull request takes four
things today: a project, its link to the repository (for decorations,
[ADR-0021](0021-pull-request-decoration.md)), an upload token stored as a
repository secret, and a workflow that runs `sonda scan --upload`. Each
step is documented, but they're spread over the CLI, the server's
settings, the token page and GitHub, and a new server greets its admin
with an empty Overview and no way forward from it.

The server could do all of it: with write access to a repository's
contents, workflows and secrets, its GitHub App could save the secret and
open a pull request adding the workflow. That access would let a
compromised server push code to every repository the App is installed on.

## Decision

A **Connect a repository** page, for admins, linked from the empty
Overview and from Projects, does what the server can do with the access it
already has, and hands the rest to GitHub's own pages, prefilled:

1. From `owner/name`, a project key (the repository's name, editable) and
   a main branch, it creates the project (`POST /api/projects`), links the
   repository in its settings, and generates a project analysis token
   named after the repository, with no expiry, so CI doesn't stop on a
   date.
2. It shows the token once, with the secret's name, and opens GitHub's
   new-secret page for the repository.
3. It writes the workflow for the chosen runner and opens GitHub's
   new-file editor with it filled in, suggesting a new branch and pull
   request, the first one sonda decorates. On a runner on the server's
   machine, the workflow runs the CLI that `scripts/install-cli.sh`
   installs and uploads to localhost; on GitHub's runners, it builds the
   CLI and needs the server's public `https://` address, since the CLI
   sends a token over plain HTTP only to localhost.

The GitHub App's permissions don't change: sonda never writes to the
repository.

`POST /api/projects` creates an empty project, with its main branch
(`main` unless given), since settings only move the main branch to an
analyzed branch. It takes the key's lock and refuses a deleted key, as
uploads do ([ADR-0017](0017-project-settings.md)). Until its main branch
is analyzed, the project is listed apart, as **waiting**, in
`GET /api/projects` and on the Overview and Projects pages, where an admin
can show its steps again with a new token: the old one keeps working until
revoked.

## Consequences

- A new server goes from empty to a decorated pull request without the
  CLI, the token page or the docs, in two clicks on GitHub.
- The admin still adds the secret and commits the workflow on GitHub,
  which is also where they see exactly what's being added.
- Showing the steps again generates another token rather than recovering
  the first, which the server never kept.
- GitLab and Bitbucket can follow the same shape: their own new-variable
  and new-file pages.
