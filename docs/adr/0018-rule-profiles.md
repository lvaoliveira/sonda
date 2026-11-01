# ADR-0018: Rule profiles on the server, applied by the scanner

- Status: **proposed**
- Date: 2026-11-01
- Completes the roadmap's "Server-managed rule profiles"; builds on ADR-0016

## Context

ADR-0016 lets the server turn rules off, globally or per project, but only
by leaving their findings out: the scanner still runs every rule its
`sonda.toml` asks for. The server can't turn on an off-by-default rule,
change a severity, or save the time spent on rules nobody wants.

Teams with many projects want rule sets managed in one place, like
SonarQube's quality profiles: a named set of rules, applied to the
projects that use it, without editing each repository.

## Decision

### Named profiles

- **A profile** has a name (1-100 characters, unique) and, for any rule,
  a setting: on or off, and optionally a severity. Rules it doesn't
  mention keep their catalog default.
- **One profile covers every language.** sonda's rule ids carry their
  language (`js/`, `py/`, `java/`, `cs/`), unlike SonarQube's keys, which
  repeat across languages, so there is no need for one profile per
  language. The scanner configures rules per rule, not per rule and
  language, so a per-language split couldn't be applied anyway.
- **"sonda way"** is a built-in, read-only profile: the catalog's
  defaults. Admins create profiles from scratch or as a copy of another,
  rename and delete them (not one in use, nor the default).
- **One profile is the default,** used by projects that don't choose one.
  It starts as "sonda way".
- **A project uses** the default or a profile its admin chooses, in its
  Settings (ADR-0017). ADR-0016's per-project settings stay as the
  project's own adjustments on top of its profile.

ADR-0016's global settings become a profile: migration turns them into a
profile named "Server settings" with those rules off, made the default if
any exist. `PUT /api/rule-settings` keeps working, on the default profile.

### What a scan runs

For a project, the server's settings are its profile with the project's
own adjustments on top. When `sonda scan --upload` runs:

1. Before scanning, it fetches them:
   `GET /api/projects/{key}/rule-profile`. A project that doesn't exist
   yet gets the default profile's.
2. **Where the server sets a rule, the server wins:** on, off and
   severity. `sonda.toml` decides every rule the server doesn't set.
3. The report records the profile it applied (name and revision), next
   to `rule_settings` from `sonda.toml` (ADR-0016).

So a rule off in the profile isn't run at all, and an off-by-default rule
turned on in the profile runs without touching the repository.

- **Unknown rule ids** in the server's settings (a server newer than the
  CLI) are skipped with a warning naming them.
- **If the profile can't be fetched,** the scan fails before it starts,
  like `scan --upload`'s other checks (exit 2): the upload would fail too.
  An older server without the endpoint (`404`) is the exception: the scan
  runs on `sonda.toml` alone and says so.
- **Tokens:** a project analysis token can fetch its own project's
  profile, and a global analysis token any project's. Fetching a profile
  is the one read analysis tokens get (ADR-0012).
- **A scan without an upload,** and `sonda upload` of a report made
  earlier, use `sonda.toml` alone. The server marks an analysis whose
  report applied no profile, or an older revision of it, so its Settings
  page can say "scanned without the current profile".

### Findings already stored

What the scanner applies only affects new analyses. For findings already
stored, ADR-0016's mechanism keeps working: a rule off in the project's
profile or adjustments is left out of lists, measures and the gate at
once, through the same `rule_off()`. A severity change applies from the
next scan.

### Screens

- **Quality profiles** (new page, under Configure): the profiles, which
  is the default, how many projects use each, and per profile its rules
  with on/off and severity, searchable as on the Rules page. Admins
  create, copy, rename, delete and set the default; members read.
- **A project's Settings → Rules:** the profile it uses (admins choose
  it), then each rule's state with what set it: default, profile,
  project, or `sonda.toml`, as ADR-0016's view already does.
- **The Rules page:** each rule says which profiles turn it on or off.

### Not now

- Profile inheritance (a profile extending another): copying covers it
  for now.
- Per-language profiles.
- Rule parameters, such as thresholds.
- Importing SonarQube quality profiles, which the `sonar` references on
  each rule (ADR-0007) would make possible.

## Consequences

- Admins manage rule sets in one place, and scans run exactly what the
  project's profile says, faster when it turns rules off.
- Uploading scans need the server before they start, which they already
  did for their other checks.
- Two places still configure rules, with a clear order: the server's
  profile and project adjustments, then `sonda.toml`. The project's
  Settings page shows which one decided each rule.
- Analyses from `sonda upload`, or from scans without the current
  profile, don't match the profile. The server says so rather than
  pretending otherwise.
