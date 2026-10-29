# ADR-0004: Sandbox the analysis workers (Linux and macOS)

- Status: accepted (2026-10-29)
- Date: 2026-10-29
- Builds on [ADR-0003](0003-isolate-parsing.md) (phase 2; scope agreed there:
  Linux and macOS)

## Context

Since ADR-0003, files are parsed in worker processes, so a tree-sitter
*crash* only loses one file. A crafted file that *exploits* a memory-safety
bug in the C grammars would still run code with the user's privileges: read
`~/.ssh`, reach the network, start programs.

After start-up, a worker needs remarkably little:

- read its stdin and write its stdout, which are already open
- allocate and free memory
- read the clock (for the per-file deadline)
- exit

It never opens files (the parent reads them, ADR-0003), never needs the
network, and never starts processes. Anything beyond that list is a sign of
compromise.

## Decision (proposed)

Each worker **sandboxes itself after start-up** (before reading the first
file request), so start-up (the loader, std initialization, reading the
config frame) needs no exceptions. Rule queries compile lazily (ADR-0003)
and only allocate memory, so they work inside the sandbox.

### All Unix: resource limits

Set before the sandbox, with `rustix`, which wraps these calls safely:

- `RLIMIT_CORE = 0`: a crashed worker must not write a core dump. Core dumps
  contain the source code it was parsing, and sonda promises not to write
  analyzed content anywhere.
- `RLIMIT_NOFILE` set to the number of descriptors already open: no new
  files or sockets can be opened. This is a cheap second layer on both
  platforms.

### Linux: seccomp-bpf allow-list

`PR_SET_NO_NEW_PRIVS` plus a seccomp filter (via `seccompiler`, the
Firecracker project's pure-Rust filter compiler) that allows only what a
worker uses:
- `read`, `write`, `exit`, `exit_group`
- memory management: `brk`, `mmap`, `munmap`, `mremap`, `madvise`
- `futex`, the clock calls, `rt_sigreturn`, `sigaltstack`, `getrandom`

The exact list comes from running the whole test suite and the fuzz corpus
under the filter, not from guessing. Any other system call **kills the
process**, which the parent already reports as "the parser crashed" for that
file. In particular, `open`/`openat`, `socket`/`connect` and `execve` all
kill the worker.

**Amended during implementation:** `openat` returns `EACCES` instead of
killing the worker. A second, stacked filter does that, and the kernel applies
the stricter result of the two filters. Libraries probe optional files and
fall back when the probe fails. For example, the `regex` crate used by
`#match?` predicates (java/weak-hash) calls std's CPU-count probe, which
reads cgroup limits under `/proc` and `/sys`. Killing on those probes lost
every Java file. The worker still cannot open anything. `sched_getaffinity`
(its own CPU mask) is allowed for the same probe. A CI job that traced
workers under `strace` found both.

Landlock is deliberately *not* used. With `openat` denied outright, a
filesystem rule set adds nothing, and leaving it out saves a dependency and
a kernel-version matrix.

### macOS: Seatbelt via `sandbox_init`

The worker calls `sandbox_init` with the most restrictive profile that
works. The candidates, in order:

1. Apple's named `pure-computation` profile, which prohibits networking,
   writes and system services.
2. If tests show it still allows file reads: the undocumented but widely
   used custom profile `(version 1) (deny default)`.

`sandbox_init` has been deprecated since macOS 10.8 but still works, and
browsers and build tools depend on it. If Apple removes it, the worker falls
back to the resource limits above and logs that it did.

This needs about 15 lines of **`unsafe` FFI**, the first `unsafe` in sonda.
Our policy allows it only when safe Rust cannot do the job. No maintained
crate wraps `sandbox_init`; the alternative, running workers through the
`sandbox-exec` command, is weaker (the sandbox would have to allow
everything the loader and std initialization need) and equally deprecated.
The FFI would live alone in `src/sandbox/macos.rs`, with a documented
safety argument and its own tests.

### When the sandbox is unavailable

For example: an old kernel without seccomp, a container whose seccomp
profile forbids installing filters, or a future macOS.

- **Default, `--sandbox best-effort`:** the scan runs and logs a warning.
  The warning goes to the log, not to the report, because a report must not
  depend on the machine.
- **`--sandbox require`:** fails the run instead. Meant for CI that scans
  untrusted pull requests.
- **`--sandbox off`:** for debugging.

`--no-isolation` implies no sandbox.

## Verification (acceptance criteria)

1. A debug-only test seam (like ADR-0003's crash seam) makes a worker try,
   after sandboxing:
   - to read `/etc/hosts`
   - to connect to localhost
   - to start `/bin/sh`

   The test passes only if each attempt is blocked (the worker is killed or
   gets a permission error) and reports it. It runs in CI on Linux and macOS.
2. The whole test suite, the fuzz seed corpus and a scan of a real
   repository produce identical reports with the sandbox on and off. That
   proves the allow-list is complete.
3. Overhead stays within the noise of ADR-0003's measurements. The sandbox
   is installed once per worker, not per file.
4. Windows remains crash-contained only, and SECURITY.md says so.

## Alternatives considered

- **Landlock, alone or with seccomp:** redundant once `openat` is denied; see
  above.
- **Namespaces** (`unshare`, bubblewrap, nsjail): they depend on unprivileged
  user namespaces, which Ubuntu 24.04 restricts by default, or on an extra
  installed tool. Too unreliable to be the default.
- **A deny-list seccomp filter** (block `openat`, `socket`, `execve` and so
  on): easier to keep working, but anything forgotten stays allowed. The
  allow-list fails safe: a forgotten system call kills a worker, and a test
  shows it.
- **`sandbox-exec` on macOS:** avoids `unsafe`, but gives a weaker profile
  and is just as deprecated.

## Decisions (review, 2026-10-29)

1. The ~15-line `unsafe` FFI for `sandbox_init` is accepted, isolated in one
   module with a documented safety argument and tests.
2. The default is **best-effort** with a logged warning; `--sandbox require`
   makes an unavailable sandbox fatal.
3. `seccompiler` (Linux) and `rustix` (Unix) are accepted. `rustix` replaces
   the direct `libc` dependency.

## Result (implemented)

**Verified in CI on Linux and macOS:**
- The escape test (read `/etc/hosts`, connect to a local listener, run
  `/bin/sh`) is blocked. It also runs with the sandbox off, where every
  attempt must succeed, so the test cannot pass vacuously.
- Reports are byte-identical with and without isolation in the CLI suite,
  which covers all seven languages.
- On macOS, each layer was disabled in turn: Seatbelt alone blocks all three
  attempts, the resource limits alone do too, and with neither the test
  fails.

**Overhead** (release build, macOS, medians):

| Project | Sandbox off | Sandbox on | Difference |
|---|---|---|---|
| arandu, 29k lines | 90 ms | 98 ms | +8 ms (paid once per worker) |
| 1.0M lines | 2.20 s | 2.12 s | within noise |

**Found on the way:**
- `openat` probes made by libraries (see the amendment above).
- Installing the second filter after the allow-list was killed by the
  allow-list itself (`prctl` and `seccomp`). The allow-list is now
  installed last.

## Consequences

- About 300 lines in `src/sandbox/` (one module per platform), plus tests.
- When a worker is killed by the sandbox, the warning says so, distinct from
  an ordinary crash, so a missing allow-list entry is easy to spot.
- Updating dependencies, Rust std, or the C library can introduce a new
  system call. CI's sandbox-on test suite catches that before release.
