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
        }
    })
    .to_string()
}

pub(super) fn enter() -> Result<(), String> {
    let fail = |e: &dyn std::fmt::Display| format!("seccomp: {e}");
    let arch = TargetArch::try_from(std::env::consts::ARCH).map_err(|e| fail(&e))?;
    let pid = rustix::process::getpid().as_raw_nonzero().get();
    let mut filters = compile_from_json(filter_json(pid).as_bytes(), arch).map_err(|e| fail(&e))?;
    let program = filters
        .remove("worker")
        .ok_or_else(|| fail(&"filter missing"))?;
    // Also sets PR_SET_NO_NEW_PRIVS.
    apply_filter(&program).map_err(|e| fail(&e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_compiles_for_supported_architectures() {
        for arch in [TargetArch::x86_64, TargetArch::aarch64] {
            let filters = compile_from_json(filter_json(1234).as_bytes(), arch).unwrap();
            assert!(!filters["worker"].is_empty());
        }
    }
}
