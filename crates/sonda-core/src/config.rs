//! Configuration types and parsing. Pure: reading the file is the caller's
//! job (see `crate::load_config`).

use crate::error::Error;
use crate::model::{Condition, Metric, Op, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const FILE_NAME: &str = "sonda.toml";

/// Written by `sonda init`. Kept in sync with `Config::default()` by a test.
pub const DEFAULT_TOML: &str = r#"# sonda configuration

[scan]
# Glob patterns (gitignore syntax) to skip, in addition to .gitignore.
exclude = ["**/node_modules/**", "**/dist/**", "**/build/**", "**/vendor/**", "**/*.min.js"]
# Files larger than this are skipped (usually generated or minified).
max_file_size_kb = 1024
# Parsing and rule matching of one file give up after this many seconds
# (the file is then reported as a warning instead of analyzed).
file_timeout_secs = 10
# Each git process (used by --new-code) is killed after this many seconds.
git_timeout_secs = 120

[rules]
# Rule ids to turn off. `sonda rules` lists them all.
disabled = []

# Override the default severity of a rule.
[rules.severity]
# "js/no-console" = "info"

[thresholds]
cognitive_complexity = 15
function_lines = 80
parameters = 7

[duplication]
# A duplicated block must span at least this many tokens and lines.
min_tokens = 100
min_lines = 10

# The quality gate fails when any condition holds. Metrics prefixed with
# "new_" only look at new code (see `--new-code`).
[[gate.conditions]]
metric = "new_bugs"
op = "gt"
threshold = 0

[[gate.conditions]]
metric = "new_vulnerabilities"
op = "gt"
threshold = 0

[[gate.conditions]]
metric = "new_coverage"
op = "lt"
threshold = 80

[[gate.conditions]]
metric = "new_duplicated_lines_density"
op = "gt"
threshold = 3
"#;

#[derive(Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub scan: ScanConfig,
    pub rules: RulesConfig,
    pub thresholds: Thresholds,
    pub duplication: DuplicationConfig,
    pub gate: GateConfig,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ScanConfig {
    pub exclude: Vec<String>,
    pub max_file_size_kb: u64,
    pub file_timeout_secs: u64,
    pub git_timeout_secs: u64,
}

impl Default for ScanConfig {
    fn default() -> Self {
        ScanConfig {
            exclude: [
                "**/node_modules/**",
                "**/dist/**",
                "**/build/**",
                "**/vendor/**",
                "**/*.min.js",
            ]
            .map(String::from)
            .to_vec(),
            max_file_size_kb: 1024,
            file_timeout_secs: 10,
            git_timeout_secs: 120,
        }
    }
}

#[derive(Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct RulesConfig {
    pub disabled: Vec<String>,
    pub severity: HashMap<String, Severity>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Thresholds {
    pub cognitive_complexity: u32,
    pub function_lines: u32,
    pub parameters: u32,
}

impl Default for Thresholds {
    fn default() -> Self {
        Thresholds {
            cognitive_complexity: 15,
            function_lines: 80,
            parameters: 7,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct DuplicationConfig {
    pub min_tokens: usize,
    pub min_lines: usize,
}

impl Default for DuplicationConfig {
    fn default() -> Self {
        DuplicationConfig {
            min_tokens: 100,
            min_lines: 10,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct GateConfig {
    pub conditions: Vec<Condition>,
}

impl Default for GateConfig {
    fn default() -> Self {
        let cond = |metric, op, threshold| Condition {
            metric,
            op,
            threshold,
        };
        GateConfig {
            conditions: vec![
                cond(Metric::NewBugs, Op::Gt, 0.0),
                cond(Metric::NewVulnerabilities, Op::Gt, 0.0),
                cond(Metric::NewCoverage, Op::Lt, 80.0),
                cond(Metric::NewDuplicatedLinesDensity, Op::Gt, 3.0),
            ],
        }
    }
}

impl Config {
    /// Parses and validates TOML. Unknown keys and metric names are rejected
    /// by deserialization, so a typo fails instead of being ignored. Rule ids
    /// are checked when the rule set is built.
    pub fn parse(text: &str) -> Result<Config, Error> {
        let cfg: Config = toml::from_str(text).map_err(|e| Error::Config(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), Error> {
        let t = &self.thresholds;
        let positive = [
            (
                "thresholds.cognitive_complexity",
                t.cognitive_complexity as u64,
            ),
            ("thresholds.function_lines", t.function_lines as u64),
            ("thresholds.parameters", t.parameters as u64),
            ("scan.file_timeout_secs", self.scan.file_timeout_secs),
            ("scan.git_timeout_secs", self.scan.git_timeout_secs),
            ("duplication.min_tokens", self.duplication.min_tokens as u64),
        ];
        match positive.iter().find(|(_, v)| *v == 0) {
            Some((key, _)) => Err(Error::Config(format!("{key} must be greater than zero"))),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_toml_matches_default_config() {
        assert_eq!(Config::parse(DEFAULT_TOML).unwrap(), Config::default());
    }

    #[test]
    fn rejects_unknown_keys_metrics_and_zero_thresholds() {
        assert!(Config::parse("[thresholds]\ncomplexity = 3\n").is_err());
        let bad_metric = "[[gate.conditions]]\nmetric = \"bugz\"\nop = \"gt\"\nthreshold = 0\n";
        let err = Config::parse(bad_metric).unwrap_err().to_string();
        assert!(err.contains("bugz") && err.contains("new_bugs"), "{err}");
        let zero = Config::parse("[scan]\nfile_timeout_secs = 0\n").unwrap_err();
        assert!(zero.to_string().contains("scan.file_timeout_secs"));
    }

    #[test]
    fn partial_config_keeps_other_defaults() {
        let cfg = Config::parse("[thresholds]\nparameters = 4\n").unwrap();
        assert_eq!(cfg.thresholds.parameters, 4);
        assert_eq!(cfg.thresholds.function_lines, 80);
        assert_eq!(cfg.gate, GateConfig::default());
    }
}
