//! SARIF 2.1.0 output, accepted by GitHub code scanning, GitLab and most IDEs.

use super::Report;
use crate::model::{Category, Severity};
use crate::rules::RULES;
use serde_json::{Value, json};

pub fn render(r: &Report) -> String {
    let rules: Vec<Value> = RULES
        .iter()
        .map(|rule| {
            let mut properties = json!({ "tags": [rule.category.as_str()] });
            if rule.category == Category::Vulnerability {
                properties["tags"] = json!([rule.category.as_str(), "security"]);
                properties["security-severity"] = json!(security_severity(rule.severity));
            }
            json!({
                "id": rule.id,
                "name": rule.id,
                "shortDescription": { "text": rule.name },
                "fullDescription": { "text": rule.description },
                "defaultConfiguration": { "level": level(rule.severity) },
                "properties": properties,
            })
        })
        .collect();

    let results: Vec<Value> = r
        .issues
        .iter()
        .map(|i| {
            let rule_index = RULES.iter().position(|rule| rule.id == i.rule);
            json!({
                "ruleId": i.rule,
                "ruleIndex": rule_index,
                "level": level(i.severity),
                "message": { "text": i.message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": i.path, "uriBaseId": "%SRCROOT%" },
                        "region": {
                            "startLine": i.line,
                            "startColumn": i.column,
                            "endLine": i.end_line,
                            "endColumn": i.end_column,
                        }
                    }
                }],
                // Lets GitHub and other SARIF consumers track the issue
                // across commits, instead of matching on its line number.
                "partialFingerprints": { "sonda/v1": i.fingerprint.to_string() },
                "properties": {
                    "severity": i.severity.as_str(),
                    "category": i.category.as_str(),
                    "isNew": i.is_new,
                },
            })
        })
        .collect();

    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": { "name": "sonda", "version": r.version, "rules": rules } },
            "results": results,
        }]
    });
    // Cannot fail: `doc` is already a `serde_json::Value`.
    serde_json::to_string_pretty(&doc).expect("sarif serializes") + "\n"
}

fn level(s: Severity) -> &'static str {
    match s {
        Severity::Blocker | Severity::Critical => "error",
        Severity::Major => "warning",
        Severity::Minor | Severity::Info => "note",
    }
}

/// GitHub maps this 0-10 score to its critical/high/medium/low labels.
fn security_severity(s: Severity) -> &'static str {
    match s {
        Severity::Blocker => "9.5",
        Severity::Critical => "8.0",
        Severity::Major => "5.5",
        Severity::Minor => "3.0",
        Severity::Info => "1.0",
    }
}
