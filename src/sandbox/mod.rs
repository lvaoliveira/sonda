//! Infrastructure: the analysis workers' sandbox (ADR-0004). A worker enters
//! it once it is set up, before it reads any file request. From then on it
//! can only use its open pipes, memory, the clock, and exit.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

/// Whether analysis workers must be sandboxed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SandboxMode {
    /// Sandbox where the platform allows it; otherwise log a warning.
    #[default]
    BestEffort,
    /// Fail the run if a worker cannot be fully sandboxed.
    Require,
    /// No sandbox (debugging).
    Off,
}

impl SandboxMode {
    /// The worker's `--sandbox` value; must match the CLI's names.
    pub(crate) fn as_arg(self) -> &'static str {
        match self {
            SandboxMode::BestEffort => "best-effort",
            SandboxMode::Require => "require",
            SandboxMode::Off => "off",
        }
    }
}

/// What a worker managed to lock down, reported to the parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Status {
    Full,
    /// Something could not be applied on a platform that has a sandbox.
    Partial(String),
    /// The platform has no sandbox (Windows): crash containment only.
    Unsupported,
    Off,
}

/// Locks the calling process down as far as possible and reports how far
/// that got; the parent decides what is acceptable.
pub(crate) fn enter(mode: SandboxMode) -> Status {
    if mode == SandboxMode::Off {
        return Status::Off;
    }
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        return Status::Unsupported;
    }
    let mut missing = Vec::new();
    #[cfg(unix)]
    if let Err(e) = limit_resources() {
        missing.push(format!("resource limits: {e}"));
    }
    if let Err(e) = platform() {
        missing.push(e);
    }
    if missing.is_empty() {
        Status::Full
    } else {
        Status::Partial(missing.join("; "))
    }
}

#[cfg(unix)]
fn limit_resources() -> std::io::Result<()> {
    use rustix::process::{Resource, Rlimit, setrlimit};
    let exactly = |n| Rlimit {
        current: Some(n),
        maximum: Some(n),
    };
    // No core dumps: they would contain the source being parsed.
    setrlimit(Resource::Core, exactly(0))?;
    // No new descriptors: only stdin, stdout and stderr stay usable.
    setrlimit(Resource::Nofile, exactly(3))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn platform() -> Result<(), String> {
    linux::enter()
}

#[cfg(target_os = "macos")]
fn platform() -> Result<(), String> {
    macos::enter()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn platform() -> Result<(), String> {
    Err("no sandbox on this platform".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The CLI parses these with clap's kebab-case value names.
    #[test]
    fn worker_arguments_match_the_cli_names() {
        let args = [
            SandboxMode::BestEffort,
            SandboxMode::Require,
            SandboxMode::Off,
        ]
        .map(SandboxMode::as_arg);
        assert_eq!(args, ["best-effort", "require", "off"]);
    }
}
