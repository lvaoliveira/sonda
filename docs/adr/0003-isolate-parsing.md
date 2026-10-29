# ADR-0003: Run parsing in worker processes

- Status: accepted (phase 1); phase 2 to follow in its own ADR
- Date: 2026-10-29

## Context

Every file is parsed by tree-sitter's runtime and grammars. These are C code
(including hand-written external scanners), called in-process on untrusted
input. A memory-safety bug in them, triggered by a crafted file, could do one
of two things:

1. **Crash** sonda, which aborts the whole scan. This is an availability
   problem: one hostile file in a pull request blocks the quality gate.
2. **Corrupt memory in a way an attacker controls.** sonda runs with the
   user's privileges, so it can read their files, reach the network, and run
   git.

Today we reduce the *likelihood* of such bugs: grammar updates are tracked,
and both targets are fuzzed weekly with AddressSanitizer on the C code (see
CONTRIBUTING.md). Nothing *contains* a bug that does exist. Recursion, time
and size limits ([ADR-0001](0001-architecture.md)) protect sonda's own code,
not C code that misbehaves.

## Options

| Option | Contains a crash | Contains an exploit | Cost |
|---|---|---|---|
| A. Status quo (fuzzing only) | no | no | none |
| B. One process per file | yes | no | spawning a process and compiling rules (~95 ms) per file: minutes on large repositories |
| C. **Pool of worker processes** | yes | no, until sandboxed | moderate: messages over pipes, worker lifecycle |
| C + OS sandbox | yes | yes, largely | high: separate code for Linux (landlock + seccomp), macOS and Windows |
| D. Grammars compiled to WASM (wasmtime) | the grammars, partly | the grammars, partly | very high: wasmtime (100+ crates), a WASM toolchain for 7 grammars, slower; the runtime itself stays native |

## Proposal

**Phase 1: worker pool for crash containment (this ADR).**

- **Workers.** The `sonda` binary starts N workers by running itself
  (`current_exe`) with a hidden `__worker` subcommand, where N is the number
  of CPUs. Each worker compiles the rules once and then handles files one at
  a time.
- **Protocol.** It uses the existing stdin/stdout pipes and no new
  dependency. Requests and responses are length-prefixed. Analysis results
  are JSON (`serde_json` is already a dependency), except tokens, which are
  sent as packed binary; JSON would roughly triple their size, and they
  dominate the payload.
- **Failure handling:**
  - If a worker dies (signal, abort, broken pipe), the file it was analyzing
    becomes a warning ("parser crashed on this file") and the worker is
    restarted. Other files are unaffected.
  - The parent's existing per-file deadline also covers worker hangs: a
    worker that doesn't answer in time is killed.
- **Where it lives.** Process spawning is infrastructure, and the library
  API has no executable path to spawn, so it can't live in the library.
  `scanner` gets an `Analyzer` trait with two real implementations:
  - `InProcess` (today's behavior): used by the library and by
    `--no-isolation`.
  - `WorkerPool`: used by the binary by default.
- **Determinism is unaffected.** Results are collected in path order, as now.
- **Acceptance criteria:**
  - A test grammar input that aborts a worker produces one warning and a
    complete report for every other file.
  - Overhead stays at or below 15% wall time on a ~30k-line project, and is
    measured and reported on a ~1M-line project.
  - All existing tests pass in both modes.

**Phase 2: sandbox the workers (separate ADR, after phase 1 ships).**

Workers would need no filesystem or network access at all, since they only
read pipes. On Linux, `landlock` with no allowed paths plus a `seccomp`
allow-list (read/write on existing fds, memory, exit) would turn a parser
exploit into a dead worker. That is where most CI runs. macOS
(`sandbox_init`) and Windows (restricted tokens, job objects) would come
later, if at all.

## Decisions (review, 2026-10-29)

1. Isolation is **on by default** in the CLI. `--no-isolation` and the library
   API keep in-process analysis.
2. Phase 2 sandboxing covers **Linux and macOS**. Windows stays
   crash-contained only.

## Consequences

- Roughly 400 to 600 lines for the protocol, pool and lifecycle, plus tests,
  and no new dependencies in phase 1.
- Debugging a parser problem uses `--no-isolation`.
- SECURITY.md's "parsers run in-process" limitation becomes "a parser crash
  is contained; a parser exploit is not, until phase 2".
