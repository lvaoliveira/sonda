# ADR-0034: Rules that don't report in some paths

- Status: **accepted**
- Date: 2026-11-27

## Context

What a rule should say depends on where a file is. sonda already knows two
kinds of place: test files skip the vulnerability rules (a fixture's password
isn't one), and Ruby's migrations, seeds, Rake tasks and scripts skip the ones
that read a file's shape ([ADR-0033](0033-ruby.md)). Those are our judgment of
conventions, and a project has its own: a `db/legacy` nobody will touch, a
vendored library, generated code that doesn't say it's generated.

What exists to say so is too coarse. `scan.exclude` takes the file out of the
scan, so its lines, complexity and duplication go from the measures and no rule
reports there; `rules.disabled` turns a rule off everywhere. SonarQube has
`sonar.issue.ignore.multicriteria` for this (a rule key pattern and a path
pattern), ESLint has `overrides` and Ruff `per-file-ignores`.

## Decision

`sonda.toml` gets a list of tables:

```toml
[[rules.ignore]]
paths = ["db/legacy/**", "**/*_generated.rb"]   # gitignore-style, from the scan root
rules = ["ruby/sql-interpolation", "common/*"]   # ids, or a prefix and `*`
```

- **What it does.** In the files `paths` match, the rules named don't report.
  The files are still analyzed and measured, and the other rules still report
  there. Several entries add up.
- **Patterns.** Paths are gitignore patterns, as `scan.exclude`, relative to
  the scan root and `/`-separated: `legacy/` or `legacy/**` for a directory,
  `*.generated.js` anywhere. Rules are ids, or a prefix ending in `*`
  (`ruby/*`, `common/*`; a lone `*` is every rule).
- **When.** After every pass, once the project's own passes have added what they
  find, so a cross-file taint finding is ignored by *its sink's* path (the
  file the issue is reported in), as every issue is.
- **Errors, not silence.** As the rest of `sonda.toml` (the stability promise
  allows adding keys and keeps unknown ones an error): a rule id or a prefix that
  names no rule, a `paths` or `rules` that's empty, a pattern that doesn't parse
  and a key that isn't `paths` or `rules` stop the scan with exit code 2.
- **The cache.** It keys on the whole configuration, so changing the list
  analyzes again; what is dropped is dropped after the cache is read.

Not decided here: a comment in the code (`sonda-ignore` exists for a line), a
per-path threshold, or per-path severity.

## Consequences

- A project says where a rule doesn't apply in one place that is reviewed with
  the code, instead of disabling the rule everywhere or hiding the file from
  every measure.
- The JSON report's `rule_settings` doesn't list the entries, so the server
  can't show them yet, and an issue that was in an ignored path counts there
  as gone (fixed) on the next analysis: the same as with a suppression
  comment, and the same as when the file is excluded. Reporting them is
  possible later: the report may add fields, and the server's validation of
  `rule_settings` would need to learn it first.
- The built-in notions of test and tooling files stay as they are; this is for
  what they don't know.
