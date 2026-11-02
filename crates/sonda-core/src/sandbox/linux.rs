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
    // (Opening a file: refused by the second filter, see `open_calls`.)
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

/// The calls that open a file on `arch`, all refused alike. On x86_64 musl
/// opens files with the older `open`, not `openat` as glibc does (std reads
/// `/proc/self/cgroup` with it when the regex crate asks for the CPU count);
/// aarch64 has no `open`.
fn open_calls(arch: TargetArch) -> &'static [&'static str] {
    match arch {
        TargetArch::x86_64 => &["openat", "open"],
        _ => &["openat"],
    }
}

fn filter_json(pid: i32, arch: TargetArch) -> String {
    let opens = open_calls(arch);
    let mut rules: Vec<serde_json::Value> = ALLOWED
        .iter()
        .chain(opens)
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
            "filter": opens.iter().map(|name| json!({ "syscall": name })).collect::<Vec<_>>(),
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
    let mut filters =
        compile_from_json(filter_json(pid, arch).as_bytes(), arch).map_err(|e| fail(&e))?;
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
            let filters = compile_from_json(filter_json(1234, arch).as_bytes(), arch).unwrap();
            assert!(!filters["worker"].is_empty() && !filters["no_files"].is_empty());
        }
    }

    #[test]
    fn every_way_to_open_a_file_is_refused_not_killed() {
        for arch in [TargetArch::x86_64, TargetArch::aarch64] {
            let filters: serde_json::Value = serde_json::from_str(&filter_json(1, arch)).unwrap();
            for name in open_calls(arch) {
                let listed = |filter: &str| {
                    filters[filter]["filter"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|r| r["syscall"] == *name)
                };
                assert!(listed("worker") && listed("no_files"), "{name}");
            }
        }
        assert!(open_calls(TargetArch::x86_64).contains(&"open"));
    }
}
