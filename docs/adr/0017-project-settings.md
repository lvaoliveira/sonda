# ADR-0017: Project settings

- Status: **accepted**
- Date: 2026-11-01
- Builds on ADR-0016 (rule settings) and ADR-0014 (CI follows the server's gate)

## Context

A project is created by its first upload, and nothing about it can be
changed afterwards. Its key (what CI passes as `--project`) is all it has
for a name. Its main branch is the first branch analyzed. Its quality gate
is whatever each repository's `sonda.toml` defines. And a project can't be
removed, not even one uploaded by mistake.

Admins need one place to manage a project: what it's called, which branch
is its main one, which rules and gate apply, and deleting it.

## Decision

### A Settings page per project

Each project gets a **Settings** page, linked from its page. Admins change
the settings; members see the page read-only. Every change records who
made it and when.

| Section | Setting |
|---|---|
| General | display name; main branch |
| Quality gate | the gate the server evaluates for this project |
| Danger zone | delete the project |

The new-code-period control stays on the project page.

**Rules have their own page, not a Settings section** (amended
2026-11-01, after review): a project's **Rules** page has the catalog's
Rules page structure (search, filters, list and detail), shows only the
rules for the project's languages, each with its state there and what set
it, and lets admins enable or disable each one for the project and choose
its rule profile (ADR-0016, ADR-0018).

### Display name

A project gets an optional name, such as "Payments platform", 1-100
characters. Screens show the name with the key under it; without a name,
the key alone, as today. The key never changes, so CI's `--project`,
project analysis tokens and links keep working.

### Main branch

Admins choose the main branch among the branches that have analyses. The
main branch is what screens show by default and what the Overview,
Projects, Security and Rules pages count, so changing it changes those at
once. The new code period applies to the main branch (ADR-0011), so it
starts over on the new one, from its first analysis, unless the admin
sets a start there.

### Quality gate

The server holds **gates**: named sets of conditions, on the same metrics
and with the same rules as `sonda.toml`'s `[[gate.conditions]]`.
- **The Quality gates page** keeps listing the gates projects' `sonda.toml`
  files define (read-only, as today), and gains server gates, which admins
  create, edit and delete there.
- **A project uses** "the gate in `sonda.toml`" (the default, as today) or
  one server gate. A server gate wins: the server evaluates its
  conditions instead of the uploaded ones, on the latest analyses right
  away (the recount from ADR-0014), and on every upload.
- **CI follows it.** The upload's answer carries the server's gate
  (ADR-0014), so `sonda scan --upload` passes or fails on the project's
  server gate. A scan without an upload still uses `sonda.toml`'s.
- A gate in use can't be deleted: the page lists the projects using it.

### Deleting a project

- **Confirmed by typing the key.** Deleting is permanent: analyses,
  issues and their history, sources, dependencies, reviews and settings.
- **Its key is refused afterwards.** Uploads create a project on first
  sight, so a forgotten pipeline would bring a deleted project back,
  empty. Instead, the key goes on a list of deleted keys, and uploads to
  it are refused with `403` and a message saying the project was deleted.
  An admin can allow the key again from the Admin page, and its next
  upload starts a new project.
- **Its project analysis tokens are revoked**, recorded as revoked by the
  admin who deleted it.
- **The audit trail keeps** who deleted which key and when, on the Admin
  page.

### Not now

- **Changing the key.** It would break every pipeline and token using it.
- **Archiving** a project instead of deleting it.
- **Project roles,** which would let a project's own people change its
  settings.
- **Rule parameters and severities per project** (ADR-0016 leaves them to
  `sonda.toml`).

## Consequences

- A project can be named, pointed at the right main branch, held to a
  gate chosen on the server, and removed, all without touching a
  repository.
- Two places can define the gate. The project's settings say which one
  applies, and the analysis page shows which gate each result came from.
- Deleting is permanent and can't be undone. The confirmation, the
  refused key and the audit record are the safeguards.
- A refused key needs an admin to allow it again, even for a project
  someone wants back on purpose.
