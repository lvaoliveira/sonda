# ADR-0025: Fixing issues with the developer's AI assistant

- Status: **accepted** (2026-11-04). Built: the prompt, `GET
  /api/issues/prompt`, and "Copy as prompt" in the web app. Next: the CLI.
- Date: 2026-11-04
- Builds on ADR-0014 (decided issues) and ADR-0021 (pull request
  decoration); comes before any "fix with AI" in sonda itself

## Context

Developers increasingly fix code with an AI assistant, such as Claude
Code, that works in their repository: it reads the code, edits it and runs
the tests. sonda knows what to fix and why; the assistant has the code, the
tests and the context. Today a developer joins the two by hand, copying an
issue's file, line, message and rule from the web app into a chat.

Building "fix with AI" into sonda means sonda calling a model, holding
credentials for it and proposing patches it can't test. Handing the
developer's own assistant what it needs is smaller, works with any
assistant, and is what an in-product fix would build on anyway.

## Decision

### One prompt, written by the server

- **`GET /api/issues/prompt`** takes the issue list's filters, plus
  `ids` for chosen issues, and answers `text/markdown`. It's a read, with
  the issue list's authentication.
- **At most 50 issues** (`limit`, default 50): enough for a session's
  work, few enough that each fix gets attention. It says when more match.
- **The content:**
  - what to do and not do: change only what each issue needs and keep
    behaviour; don't silence a rule, say why an issue shouldn't be fixed
    instead; run the tests; check with `sonda scan`;
  - the issues by file, each with its line, message, rule, severity and
    category, and the code around it (three lines either side), its own
    lines marked;
  - each rule once, after the issues: its name, description, and its
    noncompliant and compliant examples.
- **Accepted and false-positive issues** are left out, as the list leaves
  them out (ADR-0014), unless they're chosen by `ids`.
- **One template, on the server**, so the web app, the CLI and later the
  pull request comment say the same thing.

### In the web app

- **"Copy as prompt" on an issue**, beside its triage buttons.
- **"Copy as prompt" on the list:** the selected issues, or with none
  selected, the first 50 the filters match. A toast says how many.

### In the CLI (next)

- **`sonda issues`** prints the server's prompt (or the list as JSON) for
  a project, with the same filters, so an assistant in a terminal can ask
  for it itself. It needs a user token: analysis tokens only upload.
- **`sonda explain <rule>`** prints a rule's description and examples.
- **A fast check:** scanning one file for one rule, so an assistant can
  fix, check and repeat.

### Later

- An MCP server (`sonda mcp`) with the same abilities as tools.
- `sonda init --agent`: a section for `CLAUDE.md` or `AGENTS.md`, and a
  hook that scans what changed when the assistant finishes.
- The prompt in the pull request comment, collapsed.

## Consequences

- A developer hands an issue, or fifty, to their assistant in one click,
  with what it needs to fix them well and check them.
- The prompt is the one place that decides how sonda asks for a fix. The
  rules' descriptions and examples matter more: they're what the assistant
  follows.
- sonda calls no model and holds no credentials for one.

## Done when

- An issue, a selection, or a filter copies as one prompt from the web
  app.
- `sonda issues` and `sonda explain` print the same.
- sonda's own issues are fixed this way, a rule at a time.
