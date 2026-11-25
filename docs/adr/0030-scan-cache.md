# ADR-0030: A cache of each file's analysis

- Status: **accepted**
- Date: 2026-11-25

## Context

A scan analyzes every file again, though most didn't change since the last
one: in CI on each push, in a pre-commit hook, on a laptop between edits. A
full scan is fast enough for one run (VS Code's 4 million lines take 30
seconds on 12 workers), and the roadmap kept caching back for one reason:
cross-file analysis (ADR-0020's declarations, taint phase T4) makes a file's
results depend on other files, so a file's hash alone can't key a cache.

That worry doesn't hold for how the scan is built. Analyzing a file reads
that file, its path and language, the configuration and the sonda version,
and nothing else. What crosses files is a second pass: each file's analysis
leaves *facts* (a Java file's package, a taint summary, a call into another
file), and the project passes join them after every file is analyzed. So the
per-file result can be cached by its own inputs, and the project passes run
again every scan, on the facts the cache gives back.

## Decision

`sonda scan --cache[=DIR]` keeps each file's result in `DIR` (default
`.sonda/cache`, relative to the scanned directory), and a later scan reads it
back for a file whose inputs are the same. Off by default.

- **The key** is a SHA-256 of the file's bytes, its root-relative path, its
  language (a C header is promoted to C++ before this), the whole
  configuration as JSON, the sonda version and the format of an entry. Any
  change to one is a miss; nothing is invalidated in place.
- **An entry** is `KEY.json` (issues, metrics, code lines, facts, the file's
  SHA-256) and `KEY.tok` (the duplication tokens, 12 bytes each, which are
  most of the size). The tokens are written first and an entry exists once
  its `.json` does; each is written to its own temporary file and renamed. An
  entry that doesn't read back as this version writes it is a miss.
- **Not stored**: a file whose semantic analysis ran out of time
  (`semantic_incomplete`), since another run may finish; a file that failed
  to parse, which is a warning every time. `is_new` is set after the lookup,
  from git, as it is for a fresh analysis.
- **After a scan** the entries it didn't use are removed, so the cache holds
  what the last scan needed. A project that alternates two checkouts keeps
  only the later one's.
- **The cache ignores itself** (`.gitignore` with `*` inside it), and the
  scan doesn't read it as source.

A report is the same with the cache, without it, cold or warm. A test pins
that on a project with a flow across files, after an edit, with another
configuration, and with unreadable entries, and it was checked on the JSON
reports of redis, curl, civetweb and cpp-httplib.

## Consequences

- A scan with a warm cache costs the file walk, hashing and reading each
  entry, the project passes, and duplication detection. On redis that is 2.2
  s down to 0.2 s; curl 1.6 s to 0.3 s. A cold scan costs what a plain one
  does.
- The cache is the size of the facts and tokens, 30 to 40 MB for redis (350k
  lines of C). It holds findings, facts and token hashes, not source.
- CI keeps it between runs with its cache action, keyed by anything that
  changes with a push; a restored cache from an older commit is correct, its
  unchanged files hit and the rest miss.
- A development build of sonda has the same version as the last release, so
  a cache from before a rule changed is read as current. Delete the
  directory when working on sonda itself; released versions don't have this
  problem.
- `ScanOptions` gains a field (`cache`), which a library user who builds it
  with a struct literal has to add.

## Alternatives

- **On by default**: a stale or corrupt cache silently changing a report is
  worse than a slow scan, and writing into the project unasked surprises
  people. Opt-in costs one flag.
- **A cache in the user's home**: shared by every project, it grows without
  bound unless something evicts, and a CI cache is easier to point at one
  directory in the checkout.
- **Caching the whole report, or the project passes' results**: those depend
  on every file, so any change drops them; the per-file part is where the
  time is.
- **Keying on modification time**: a fresh checkout gives every file a new
  time, which defeats the cache in CI, the case that matters most. Content
  hashes cost a read of the file the scan does anyway.
