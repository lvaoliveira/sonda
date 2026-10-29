use std::path::PathBuf;

/// Why a run could not complete. Problems with individual analyzed files
/// are not errors: they become warnings in the report.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The configuration is invalid: bad TOML, unknown key, rule or metric,
    /// or an out-of-range value.
    #[error("invalid configuration: {0}")]
    Config(String),
    /// A caller-supplied argument is invalid (e.g. the new-code reference).
    #[error("{0}")]
    InvalidArgument(String),
    /// An input the caller named (config file, coverage report) is unreadable.
    #[error("cannot read {}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// git failed while determining new code.
    #[error("git: {0}")]
    Git(String),
    /// A bug in sonda, e.g. a rule query that does not compile.
    #[error("internal error: {0}")]
    Internal(String),
}
