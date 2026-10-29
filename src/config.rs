use crate::gate::{Condition, Op};
use crate::measures::METRICS;
use crate::model::Severity;
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

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

#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub scan: ScanConfig,
    pub rules: RulesConfig,
    pub thresholds: Thresholds,
    pub duplication: DuplicationConfig,
    pub gate: GateConfig,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ScanConfig {
    pub exclude: Vec<String>,
    pub max_file_size_kb: u64,
    pub file_timeout_secs: u64,
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
        }
    }
}

#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct RulesConfig {
    pub disabled: Vec<String>,
    pub severity: HashMap<String, Severity>,
}

#[derive(Debug, Deserialize, PartialEq)]
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

#[derive(Debug, Deserialize, PartialEq)]
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

#[derive(Debug, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct GateConfig {
    pub conditions: Vec<Condition>,
}

impl Default for GateConfig {
    fn default() -> Self {
        let cond = |metric: &str, op, threshold| Condition {
            metric: metric.into(),
            op,
            threshold,
        };
        GateConfig {
            conditions: vec![
                cond("new_bugs", Op::Gt, 0.0),
                cond("new_vulnerabilities", Op::Gt, 0.0),
                cond("new_coverage", Op::Lt, 80.0),
                cond("new_duplicated_lines_density", Op::Gt, 3.0),
            ],
        }
    }
}

impl Config {
    /// Loads `explicit` if given, else `<root>/sonda.toml` if it exists, else defaults.
    pub fn load(explicit: Option<&Path>, root: &Path) -> Result<Config> {
        let path = match explicit {
            Some(p) => p.to_path_buf(),
            None => {
                let p = root.join(FILE_NAME);
                if !p.exists() {
                    return Ok(Config::default());
                }
                p
            }
        };
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        Config::parse(&text).with_context(|| format!("invalid config {}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Config> {
        let cfg: Config = toml::from_str(text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    // Rule ids are checked when the RuleSet is built; everything else here,
    // so a typo fails the run instead of silently doing nothing.
    fn validate(&self) -> Result<()> {
        for c in &self.gate.conditions {
            if !METRICS.contains(&c.metric.as_str()) {
                bail!(
                    "unknown gate metric '{}'; known metrics: {}",
                    c.metric,
                    METRICS.join(", ")
                );
            }
        }
        let t = &self.thresholds;
        if t.cognitive_complexity == 0 || t.function_lines == 0 || t.parameters == 0 {
            bail!("thresholds must be greater than zero");
        }
        if self.scan.file_timeout_secs == 0 {
            bail!("scan.file_timeout_secs must be greater than zero");
        }
        if self.duplication.min_tokens == 0 {
            bail!("duplication.min_tokens must be greater than zero");
        }
        Ok(())
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
    fn rejects_unknown_keys_and_metrics() {
        assert!(Config::parse("[thresholds]\ncomplexity = 3\n").is_err());
        let bad_metric = "[[gate.conditions]]\nmetric = \"bugz\"\nop = \"gt\"\nthreshold = 0\n";
        assert!(Config::parse(bad_metric).is_err());
    }

    #[test]
    fn partial_config_keeps_other_defaults() {
        let cfg = Config::parse("[thresholds]\nparameters = 4\n").unwrap();
        assert_eq!(cfg.thresholds.parameters, 4);
        assert_eq!(cfg.thresholds.function_lines, 80);
        assert_eq!(cfg.gate, GateConfig::default());
    }
}
