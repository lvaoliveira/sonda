//! sonda — open-source static analysis and quality gates.
//!
//! ```no_run
//! # fn main() -> Result<(), sonda::Error> {
//! use std::path::Path;
//! let root = Path::new(".");
//! let config = sonda::load_config(None, root)?;
//! let options = sonda::ScanOptions {
//!     root: root.to_path_buf(),
//!     new_code_ref: Some("origin/main".into()),
//!     ..Default::default()
//! };
//! let outcome = sonda::run(&options, &config)?;
//! let report = sonda::report::build(&outcome, false);
//! print!("{}", sonda::report::render(&report, sonda::report::Format::Text));
//! # Ok(())
//! # }
//! ```
//!
//! Layers, with dependencies pointing down (see docs/adr/0001-architecture.md):
//!
//! - interface: `report` (and the `sonda` binary)
//! - application: this module ([`run`], [`load_config`])
//! - infrastructure: `scanner` (filesystem), `git`, `worker` (processes)
//! - domain: `project`, `measures`, `gate`, `analysis`, `duplication`,
//!   `rules`, `newcode`, `coverage`, `config` — no I/O
//! - shared types: `model`, `lang`

pub mod config;
pub mod lang;
pub mod model;
pub mod report;
pub mod rules;

mod analysis;
mod coverage;
mod duplication;
mod error;
mod gate;
mod git;
mod measures;
mod newcode;
mod project;
mod scanner;
mod worker;

pub use error::Error;
pub use gate::{ConditionResult, GateResult, Status};
pub use measures::Measures;
pub use project::ProjectAnalysis;
pub use scanner::{Isolation, ScanOptions};

use config::Config;
use std::path::Path;

/// The result of a run: the analysis, its measures and the quality gate.
pub struct Outcome {
    pub analysis: ProjectAnalysis,
    pub measures: Measures,
    pub gate: GateResult,
}

/// Analyzes `options.root` and evaluates the quality gate.
pub fn run(options: &ScanOptions, config: &Config) -> Result<Outcome, Error> {
    if !options.root.is_dir() {
        return Err(Error::InvalidArgument(format!(
            "{} is not a directory",
            options.root.display()
        )));
    }
    let started = std::time::Instant::now();
    let rules = rules::RuleSet::new(&config.rules)?;
    tracing::info!(
        rules = rules.active.len(),
        elapsed_ms = started.elapsed().as_millis(),
        "compiled rules"
    );
    let analysis = scanner::scan(options, config, &rules)?;
    let measures = measures::compute(&analysis);
    let gate = gate::evaluate(&config.gate.conditions, &measures);
    tracing::info!(passed = gate.passed, "evaluated quality gate");
    Ok(Outcome {
        analysis,
        measures,
        gate,
    })
}

/// Runs a worker process for [`Isolation::Workers`]: reads requests on
/// stdin and answers on stdout until stdin closes. The `sonda` binary calls
/// this for its hidden `__worker` subcommand.
#[doc(hidden)]
pub fn serve_worker() -> Result<(), Error> {
    worker::serve(std::io::stdin().lock(), std::io::stdout().lock())
}

/// Loads `explicit` if given, else `<root>/sonda.toml` if it exists, else
/// the defaults.
pub fn load_config(explicit: Option<&Path>, root: &Path) -> Result<Config, Error> {
    let path = match explicit {
        Some(p) => p.to_path_buf(),
        None => {
            let p = root.join(config::FILE_NAME);
            if !p.is_file() {
                tracing::info!("no sonda.toml found, using defaults");
                return Ok(Config::default());
            }
            p
        }
    };
    tracing::info!(path = %path.display(), "loading config");
    let text = std::fs::read_to_string(&path).map_err(|source| Error::Io {
        path: path.clone(),
        source,
    })?;
    Config::parse(&text).map_err(|e| match e {
        Error::Config(msg) => Error::Config(format!("{}: {msg}", path.display())),
        other => other,
    })
}

/// Entry points for the fuzz targets in `fuzz/`, behind the `fuzzing`
/// feature. Not part of the public API: no stability guarantees.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing {
    use crate::analysis::{self, FileError};
    use crate::config::Config;
    use crate::rules::RuleSet;
    use std::sync::LazyLock;
    use std::time::{Duration, Instant};

    static CONFIG: LazyLock<Config> = LazyLock::new(Config::default);
    // The built-in rules always compile: a unit test checks every query.
    static RULES: LazyLock<RuleSet> =
        LazyLock::new(|| RuleSet::new(&CONFIG.rules).expect("built-in rules compile"));

    /// Analyzes `src` in the language `selector` picks (modulo the number of
    /// languages) and panics if the result is inconsistent, which is what the
    /// fuzzer looks for. Hitting the per-file time budget is allowed:
    /// libFuzzer's own `-timeout` catches anything slower.
    pub fn analyze(selector: u8, src: &str) {
        let lang = crate::lang::ALL[usize::from(selector) % crate::lang::ALL.len()];
        let deadline = Instant::now() + Duration::from_secs(10);
        match analysis::analyze("fuzz", lang, src, &RULES, &CONFIG, deadline) {
            Ok(a) => {
                if let Err(e) = analysis::check_invariants(&a) {
                    panic!("{lang:?}: {e}");
                }
            }
            Err(FileError::ParseTimeout | FileError::QueryTimeout) => {}
            Err(e) => panic!("{lang:?}: {e}"),
        }
    }

    /// Parses an untrusted `sonda.toml`; it may be rejected, but must not panic.
    pub fn parse_config(text: &str) {
        let _ = Config::parse(text);
    }
}

/// Shared test configuration.
#[cfg(test)]
pub(crate) mod test_support {
    use proptest::test_runner::{Config, RngSeed};

    /// Property tests use a fixed seed so every run, local or CI, checks the
    /// same cases. Set PROPTEST_RNG_SEED to explore others.
    pub(crate) fn proptest_config(cases: u32) -> Config {
        let mut config = Config::with_cases(cases);
        if std::env::var_os("PROPTEST_RNG_SEED").is_none() {
            config.rng_seed = RngSeed::Fixed(0x0050_11DA);
        }
        // A fixed seed already reproduces failures; don't write files.
        config.failure_persistence = None;
        config
    }
}

/// Fitness tests for the layering in docs/adr/0001-architecture.md. They are
/// textual: they search each file, comments excluded, for forbidden paths.
#[cfg(test)]
mod architecture {
    const DOMAIN: &[(&str, &str)] = &[
        ("model.rs", include_str!("model.rs")),
        ("lang.rs", include_str!("lang.rs")),
        ("config.rs", include_str!("config.rs")),
        ("rules/mod.rs", include_str!("rules/mod.rs")),
        ("rules/catalog.rs", include_str!("rules/catalog.rs")),
        ("analysis.rs", include_str!("analysis.rs")),
        ("duplication.rs", include_str!("duplication.rs")),
        ("newcode.rs", include_str!("newcode.rs")),
        ("coverage.rs", include_str!("coverage.rs")),
        ("project.rs", include_str!("project.rs")),
        ("measures.rs", include_str!("measures.rs")),
        ("gate.rs", include_str!("gate.rs")),
    ];

    /// The file without comment lines (docs may mention other layers). Test
    /// modules are included: domain tests need no I/O either.
    fn code(src: &str) -> String {
        src.lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn domain_does_no_io() {
        let io = [
            "std::fs",
            "std::process",
            "std::net",
            "std::env",
            "File::",
            "canonicalize",
            "println!",
            "eprintln!",
            "print!(",
        ];
        for (file, src) in DOMAIN {
            for pattern in io {
                assert!(!code(src).contains(pattern), "{file} uses {pattern}");
            }
        }
    }

    #[test]
    fn domain_does_not_depend_on_outer_layers() {
        let outer = [
            "crate::scanner",
            "crate::git",
            "crate::worker",
            "crate::report",
            "crate::Outcome",
            "crate::run",
        ];
        for (file, src) in DOMAIN {
            for pattern in outer {
                assert!(!code(src).contains(pattern), "{file} depends on {pattern}");
            }
        }
    }

    #[test]
    fn shared_types_depend_on_nothing_in_the_crate() {
        for file in ["model.rs", "lang.rs"] {
            let (_, src) = DOMAIN.iter().find(|(f, _)| *f == file).unwrap();
            assert!(
                !code(src).contains("crate::"),
                "{file} imports from the crate"
            );
        }
    }
}
