use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use sonda_core::config;
use sonda_core::report::{self, Format};
use sonda_core::rules::{self, RULES};
use sonda_core::{Isolation, SandboxMode, ScanOptions};
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

mod upload;

/// Static analysis and quality gates for JavaScript/TypeScript, Python, Java and C/C++.
#[derive(Parser)]
#[command(name = "sonda", version)]
struct Cli {
    /// Log progress to stderr: -v info, -vv debug, -vvv trace. RUST_LOG overrides.
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Analyze a project and evaluate the quality gate.
    Scan(ScanArgs),
    /// List the available rules.
    Rules {
        #[arg(long, value_enum, default_value_t = RulesFormat::Text)]
        format: RulesFormat,
    },
    /// Internal: an analysis worker process (see ADR-0003).
    #[command(name = "__worker", hide = true)]
    Worker {
        #[arg(long, value_enum, default_value_t = SandboxArg::BestEffort)]
        sandbox: SandboxArg,
    },
    /// Send a JSON report and the analyzed sources to a sonda server.
    Upload(upload::UploadArgs),
    /// Write a default sonda.toml.
    Init {
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Overwrite an existing sonda.toml.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Args)]
struct ScanArgs {
    /// Project directory to analyze.
    #[arg(default_value = ".")]
    path: PathBuf,
    /// Config file (default: <path>/sonda.toml if present).
    #[arg(short, long)]
    config: Option<PathBuf>,
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
    /// Write the report to a file instead of stdout.
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Git ref new code is compared against (via merge base), e.g. origin/main.
    /// Without it, the whole project counts as new code.
    #[arg(long, value_name = "REF")]
    new_code: Option<String>,
    /// LCOV coverage report(s) to import.
    #[arg(long, value_name = "LCOV")]
    coverage: Vec<PathBuf>,
    /// Only list issues on new code (measures and gate still cover everything).
    #[arg(long)]
    only_new: bool,
    /// Always exit 0, even when the quality gate fails.
    #[arg(long)]
    no_gate: bool,
    /// Files analyzed in parallel (default: every CPU).
    #[arg(short, long, value_name = "N")]
    jobs: Option<std::num::NonZeroUsize>,
    /// Sandbox the analysis workers: best-effort logs a warning when the
    /// platform cannot; require fails the run instead (see SECURITY.md).
    #[arg(long, value_enum, default_value_t = SandboxArg::BestEffort)]
    sandbox: SandboxArg,
    /// Parse files in this process instead of in worker processes (for
    /// debugging; a parser crash then aborts the whole scan).
    #[arg(long)]
    no_isolation: bool,
}

/// CLI mirror of `SandboxMode`, keeping clap out of the library API.
#[derive(Clone, Copy, ValueEnum)]
enum SandboxArg {
    BestEffort,
    Require,
    Off,
}

impl From<SandboxArg> for SandboxMode {
    fn from(a: SandboxArg) -> SandboxMode {
        match a {
            SandboxArg::BestEffort => SandboxMode::BestEffort,
            SandboxArg::Require => SandboxMode::Require,
            SandboxArg::Off => SandboxMode::Off,
        }
    }
}

/// CLI mirror of `report::Format`, keeping clap out of the library API.
#[derive(Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Sarif,
}

impl From<OutputFormat> for Format {
    fn from(f: OutputFormat) -> Format {
        match f {
            OutputFormat::Text => Format::Text,
            OutputFormat::Json => Format::Json,
            OutputFormat::Sarif => Format::Sarif,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum RulesFormat {
    Text,
    Markdown,
    /// For tools, e.g. scripts/sonar_parity.py.
    Json,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging(cli.verbose);
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            // Errors can quote repository content (paths, git messages).
            eprintln!(
                "sonda: error: {}",
                report::terminal_safe_lines(&format!("{e:#}"))
            );
            ExitCode::from(2)
        }
    }
}

/// Logs go to stderr so stdout stays a clean report. Only sonda's own events
/// are shown unless RUST_LOG says otherwise.
fn init_logging(verbose: u8) {
    let level = match verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    // Targets match by prefix, so `sonda` also covers the library's `sonda_core`.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(format!("sonda={level}")));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(|| SafeStderr)
        .with_target(false)
        .init();
}

/// Log lines quote repository content (paths, git messages), so they get
/// the same escaping as the report. tracing-subscriber does not escape
/// `%`-formatted values here: a file name's raw ESC reached the terminal.
struct SafeStderr;

impl std::io::Write for SafeStderr {
    // The fmt layer writes each event in one call, so a buffer never ends
    // inside a multi-byte character.
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let text = String::from_utf8_lossy(buf);
        std::io::stderr().write_all(report::terminal_safe_lines(&text).as_bytes())?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stderr().flush()
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Command::Scan(args) => scan(args),
        Command::Upload(args) => upload::run(args),
        Command::Rules { format } => {
            print!("{}", list_rules(format));
            Ok(ExitCode::SUCCESS)
        }
        Command::Worker { sandbox } => {
            sonda_core::serve_worker(sandbox.into())?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Init { path, force } => {
            let target = path.join(config::FILE_NAME);
            if target.exists() && !force {
                bail!(
                    "{} already exists (use --force to overwrite)",
                    target.display()
                );
            }
            std::fs::write(&target, config::DEFAULT_TOML)
                .with_context(|| format!("writing {}", target.display()))?;
            eprintln!("sonda: wrote {}", target.display());
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn scan(args: ScanArgs) -> Result<ExitCode> {
    let cfg = sonda_core::load_config(args.config.as_deref(), &args.path)?;
    let isolation = if args.no_isolation {
        Isolation::InProcess
    } else {
        let program = std::env::current_exe().context("locating the sonda executable")?;
        Isolation::Workers {
            program,
            sandbox: args.sandbox.into(),
        }
    };
    let opts = ScanOptions {
        root: args.path,
        new_code_ref: args.new_code,
        coverage: args.coverage,
        isolation,
        jobs: args.jobs,
    };
    let outcome = sonda_core::run(&opts, &cfg)?;
    let passed = outcome.gate.passed;
    let rendered = report::render(&report::build(&outcome, args.only_new), args.format.into());

    match &args.output {
        Some(path) => {
            std::fs::write(path, rendered)
                .with_context(|| format!("writing {}", path.display()))?;
            eprintln!(
                "sonda: quality gate {} — report written to {}",
                if passed { "PASSED" } else { "FAILED" },
                path.display()
            );
        }
        None => print!("{rendered}"),
    }
    Ok(if passed || args.no_gate {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn list_rules(format: RulesFormat) -> String {
    let langs = |r: &rules::Rule| {
        let mut names: Vec<&str> = r.langs().iter().map(|l| l.name()).collect();
        names.dedup();
        names.join(", ")
    };
    let mut out = String::new();
    match format {
        RulesFormat::Text => {
            for r in RULES.iter() {
                let _ = writeln!(
                    out,
                    "{:<32} {:<9} {:<14} {}{}",
                    r.id,
                    r.severity.as_str(),
                    r.category.label(),
                    r.name,
                    if r.on_by_default() {
                        ""
                    } else {
                        " (off by default)"
                    }
                );
            }
        }
        RulesFormat::Markdown => {
            let _ = writeln!(
                out,
                "# Rules\n\nGenerated by `sonda rules --format markdown`. Rules marked \
                 *off* run only when `rules.enabled` in sonda.toml lists them.\n"
            );
            let _ = writeln!(out, "| Rule | Type | Severity | Languages | Default |");
            let _ = writeln!(out, "|---|---|---|---|---|");
            for r in RULES.iter() {
                let _ = writeln!(
                    out,
                    "| [`{}`](#{}) | {} | {} | {} | {} |",
                    r.id,
                    r.id.replace('/', ""),
                    r.category.label(),
                    r.severity.as_str(),
                    langs(r),
                    if r.on_by_default() { "on" } else { "*off*" }
                );
            }
            for r in RULES.iter() {
                let _ = writeln!(out, "\n## {}\n\n**{}.** {}", r.id, r.name, r.description);
                if !r.on_by_default() {
                    let _ = writeln!(
                        out,
                        "\nOff by default: add `\"{}\"` to `rules.enabled` to run it.",
                        r.id
                    );
                }
                if !r.sonar.is_empty() {
                    let refs: Vec<String> = r
                        .sonar
                        .iter()
                        .map(|s| format!("{}{}", s.key, if s.exact { "" } else { " (related)" }))
                        .collect();
                    let _ = writeln!(out, "\nSonarQube: {}", refs.join(", "));
                }
                if let Some(ex) = &r.example {
                    let lang = ex.lang.name();
                    let _ = writeln!(
                        out,
                        "\nNoncompliant:\n\n```{lang}\n{}\n```\n\nCompliant:\n\n```{lang}\n{}\n```",
                        ex.bad.trim_end(),
                        ex.good.trim_end()
                    );
                }
            }
        }
        RulesFormat::Json => {
            let rules: Vec<serde_json::Value> = RULES
                .iter()
                .map(|r| {
                    let mut langs: Vec<&str> = r.langs().iter().map(|l| l.name()).collect();
                    langs.dedup();
                    serde_json::json!({
                        "id": r.id,
                        "name": r.name,
                        "languages": langs,
                        "category": r.category.as_str(),
                        "severity": r.severity.as_str(),
                        "on_by_default": r.on_by_default(),
                        "sonar": r.sonar.iter().map(|s| serde_json::json!({ "key": s.key, "exact": s.exact })).collect::<Vec<_>>(),
                    })
                })
                .collect();
            // Cannot fail: built from plain JSON values.
            out = serde_json::to_string_pretty(&rules).expect("rules serialize") + "\n";
        }
    }
    out
}
