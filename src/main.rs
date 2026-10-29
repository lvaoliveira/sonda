use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use sonda::ScanOptions;
use sonda::config;
use sonda::report::{self, Format};
use sonda::rules::{self, RULES};
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

/// Static analysis and quality gates for JavaScript/TypeScript, Python, Java and C/C++.
#[derive(Parser)]
#[command(name = "sonda", version)]
struct Cli {
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
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
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

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Command::Scan(args) => scan(args),
        Command::Rules { format } => {
            print!("{}", list_rules(format));
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
    let cfg = sonda::load_config(args.config.as_deref(), &args.path)?;
    let opts = ScanOptions {
        root: args.path,
        new_code_ref: args.new_code,
        coverage: args.coverage,
    };
    let outcome = sonda::run(&opts, &cfg)?;
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
            for r in RULES {
                let _ = writeln!(
                    out,
                    "{:<32} {:<9} {:<14} {}",
                    r.id,
                    r.severity.as_str(),
                    r.category.label(),
                    r.name
                );
            }
        }
        RulesFormat::Markdown => {
            let _ = writeln!(
                out,
                "# Rules\n\nGenerated by `sonda rules --format markdown`.\n"
            );
            let _ = writeln!(out, "| Rule | Type | Severity | Languages |");
            let _ = writeln!(out, "|---|---|---|---|");
            for r in RULES {
                let _ = writeln!(
                    out,
                    "| [`{}`](#{}) | {} | {} | {} |",
                    r.id,
                    r.id.replace('/', ""),
                    r.category.label(),
                    r.severity.as_str(),
                    langs(r)
                );
            }
            for r in RULES {
                let _ = writeln!(out, "\n## {}\n\n**{}.** {}", r.id, r.name, r.description);
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
    }
    out
}
