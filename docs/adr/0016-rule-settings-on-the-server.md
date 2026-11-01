# ADR-0016: Rule settings on the server, and showing every rule's state

- Status: **accepted**
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

Whichever way a rule is turned off, the web app should say so. Today it
can't: the uploaded report carries findings, not the rule settings the
scan ran with, so a rule disabled in `sonda.toml` looks the same on the
server as a rule that found nothing.

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

### Uploads carry the repository's rule settings

The JSON report gains `rule_settings`: what the project's `sonda.toml` set
in `[rules]`, as the scan applied it.
- `disabled`: rules turned off;
- `enabled`: off-by-default rules turned on;
- `severity`: changed severities, by rule.

Adding a field keeps the report version. The server stores it with each
analysis. A report from an older `sonda`, without the field, shows the
repository's settings as unknown for that analysis rather than as
"nothing set".

### Every rule's state, whatever set it

For each project, the server combines both places into one state per
rule, and says what decided it:

| State | Set by |
|---|---|
| on | default |
| off | default (an off-by-default rule) |
| on | `sonda.toml` (`enabled`) |
| off | `sonda.toml` (`disabled`) |
| off | server, globally |
| off | server, this project |
| on | server, this project (over a global off) |

- **Severity** changed in `sonda.toml` is shown next to the state.
- **Conflicts are shown, not hidden.** A rule `sonda.toml` turns off stays
  off whatever the server says, since the scanner never ran it. If the
  server says on, the project's Rules tab shows "off in `sonda.toml`; the
  server setting has no effect until the repository turns it back on".
- **Changes over time:** each analysis records its settings, so the tab
  shows when the repository's settings changed, such as "`js/no-var`
  turned off in `sonda.toml` at commit `a1b2c3d`".

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

- **Rules page:** each rule shows its global server setting, and in how
  many projects it's off, split by what turned it off (`sonda.toml` or
  the server). Opening the rule lists those projects, with who turned it
  off and why. Admins get an on/off switch with an optional note.
- **A project's Rules tab:** every rule whose state differs from its
  default for this project, with the state, what set it, and the note;
  the repository's `sonda.toml` settings from the latest analysis; and
  conflicts between the two. Admins change the project's server setting
  there.
- **Issues of a rule that's off on the server** don't appear. The
  project's Rules tab says how many there are.

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
  scanner runs, and the server decides what counts. The web app shows
  both, with what set each rule's state, so a rule is never off without
  the screen saying why.
- Analyses from an older `sonda` don't carry their rule settings, so the
  repository's part shows as unknown until the project's next scan.
