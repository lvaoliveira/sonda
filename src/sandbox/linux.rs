//! seccomp-bpf allow-list for analysis workers (ADR-0004).

use seccompiler::{TargetArch, apply_filter, compile_from_json};
use serde_json::json;

/// System calls a worker may make inside the sandbox. Any other call kills
/// it with SIGSYS, which the parent reports as a sandbox kill for the file
/// being parsed. `tgkill` is added separately, limited to this process (for
/// `abort()`).
const ALLOWED: &[&str] = &[
    // Its pipes.
    "read",
    "write",
    // Refused by the second filter (see `filter_json`); listed so that
    // refusal, not a kill, is what happens.
    "openat",
    // Std's CPU-count probe (the regex crate calls it while compiling the
    // `#match?` predicate of java/weak-hash): reads the worker's own mask.
    "sched_getaffinity",
    // Memory.
    "brk",
    "mmap",
    "munmap",
    "mremap",
    "madvise",
    "mprotect",
    // Locks, time, randomness (std::collections::HashMap seeds).
    "futex",
    "sched_yield",
    "clock_gettime",
    "clock_getres",
    "gettimeofday",
    "getrandom",
    // Signals and exit, so panics and aborts end the process normally.
    "rt_sigreturn",
    "rt_sigprocmask",
    "rt_sigaction",
    "sigaltstack",
    "getpid",
    "gettid",
    "exit",
    "exit_group",
];

fn filter_json(pid: i32) -> String {
    let mut rules: Vec<serde_json::Value> = ALLOWED
        .iter()
        .map(|name| json!({ "syscall": name }))
        .collect();
    rules.push(json!({
        "syscall": "tgkill",
        "args": [{ "index": 0, "type": "dword", "op": "eq", "val": pid }],
        "comment": "abort() may only signal this process",
    }));
    json!({
        "worker": {
            "mismatch_action": "kill_process",
            "filter_action": "allow",
            "filter": rules,
        },
        // Opening any file fails with EACCES instead of killing the worker:
        // libraries probe optional files (std reads cgroup CPU limits) and
        // fall back when that fails. The worker still cannot open anything;
        // the kernel applies the stricter result of the two filters.
        "no_files": {
            "mismatch_action": "allow",
            "filter_action": { "errno": EACCES },
            "filter": [{ "syscall": "openat" }],
        }
    })
    .to_string()
}

/// EACCES on Linux (all architectures).
const EACCES: u32 = 13;

pub(super) fn enter() -> Result<(), String> {
    let fail = |e: &dyn std::fmt::Display| format!("seccomp: {e}");
    let arch = TargetArch::try_from(std::env::consts::ARCH).map_err(|e| fail(&e))?;
    let pid = rustix::process::getpid().as_raw_nonzero().get();
    let mut filters = compile_from_json(filter_json(pid).as_bytes(), arch).map_err(|e| fail(&e))?;
    // Both filters stay active (also sets PR_SET_NO_NEW_PRIVS). The
    // allow-list must go last: installing a filter takes `prctl` and
    // `seccomp` calls, which the allow-list itself would kill.
    for name in ["no_files", "worker"] {
        let program = filters
            .remove(name)
            .ok_or_else(|| fail(&"filter missing"))?;
        apply_filter(&program).map_err(|e| fail(&e))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_compiles_for_supported_architectures() {
        for arch in [TargetArch::x86_64, TargetArch::aarch64] {
            let filters = compile_from_json(filter_json(1234).as_bytes(), arch).unwrap();
            assert!(!filters["worker"].is_empty() && !filters["no_files"].is_empty());
        }
    }
}
