# ADR-0016: Turning rules off on the server, globally or per project

- Status: **proposed**
- Date: 2026-11-01
- Covers part of the roadmap's "Server-managed rule profiles" item

## Context

Rules are configured per repository, in `sonda.toml` (`[rules] enabled`,
`disabled` and `severity`). The server's Rules page is read-only. To turn
off a rule that's noisy for a team, someone has to edit the `sonda.toml`
of every repository, or of the one repository where it doesn't fit, and
wait for its next scan.

Admins want to do that from the server: turn a rule off for every project,
or for one project, and turn it back on for a project where it's wanted.

## Decision

### Settings: global, and per project

| Where | Setting | Who |
|---|---|---|
| Global | on (the default) or off | admins |
| Project | as global (the default), on or off | admins |

A project's setting wins over the global one, so a project can keep a rule
that's off everywhere else, or drop one that's on everywhere else.

Each change records who made it, when, and an optional note on why, shown
next to the setting.

### The server leaves findings out; the scanner is unchanged

A rule turned off on the server still runs in `sonda scan`, and the upload
still carries its findings. The server stores them, but leaves them out of
everything it shows and counts for that project, as it does for accepted
and false-positive issues (ADR-0014):
- issue lists and their facets;
- issue measures, overall and on new code;
- ratings and open counts on every screen (Overview, Projects, Components,
  Security and the review queue);
- the quality gate.

The upload's answer carries that gate, so CI follows it (ADR-0014): a
finding from a rule turned off on the server doesn't fail the build.

Changing a setting recounts, right away, the latest analysis of each
branch it affects: every project's for a global change, one project's for
a project change. The same recount runs on status changes today
(`new_code::recount`). Turning a rule back on brings its issues back, with
their status, history and assignees, since nothing was deleted.

### What the server can't do

The server only removes what the scanner reported. It can't:
- **turn on a rule the scanner didn't run:** an off-by-default rule, or one
  that `sonda.toml` disables. Its findings never reach the server;
- **change a rule's severity.** `sonda.toml` still does that.

A local scan without an upload knows nothing of the server, so it still
reports, and gates on, rules turned off there. With an upload, the
server's gate decides (ADR-0014).

### Screens

- **Rules page:** for admins, each rule gets an on/off switch with an
  optional note. The page shows "off" on rules turned off globally, and
  how many projects override it.
- **A project's Rules tab:** the project's own settings, and every rule
  that's off for that project, globally or for it alone, with who turned
  it off and why. Admins change the setting there.
- **Issues of a rule that's off** don't appear. The project's Rules tab
  says how many there are.

### Not now

- **Scanner-side profiles,** where `sonda scan` downloads the rules to
  run, which would also allow turning on off-by-default rules and
  changing severities from the server. That's the rest of the roadmap
  item, and it needs a CLI change and a new API.
- **Per-branch settings.**
- **Rule parameters,** such as thresholds.

## Consequences

- An admin turns a rule off once, without touching repositories, and the
  counts and the gate change at once, past analyses included.
- Scans take as long as before: the scanner still runs every rule.
- Trends change at the latest analysis only. Earlier points keep the
  counts they were stored with, so a chart can step down when a rule is
  turned off, as it does after reviews (ADR-0014).
- Two places decide whether a rule counts: `sonda.toml` decides what the
  scanner runs, and the server decides what counts. The project's Rules
  tab shows the server's part, and `sonda rules` the scanner's.
