//! SARIF 2.1.0 output, accepted by GitHub code scanning, GitLab and most IDEs.

use super::Report;
use crate::model::{Category, Severity};
use crate::rules::{Owasp, RULES};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub fn render(r: &Report) -> String {
    let rules: Vec<Value> = RULES
        .iter()
        .map(|rule| {
            let standards = rule.standards();
            let mut tags = vec![rule.category.as_str().to_string()];
            if rule.category == Category::Vulnerability {
                tags.push("security".into());
            }
            // GitHub code scanning shows and filters by these.
            tags.extend(
                standards
                    .cwe
                    .iter()
                    .map(|c| format!("external/cwe/cwe-{c:03}")),
            );
            let mut properties = json!({ "tags": tags });
            if rule.category == Category::Vulnerability {
                properties["security-severity"] = json!(security_severity(rule.severity));
            }
            let relationships: Vec<Value> = standards
                .cwe
                .iter()
                .map(|c| relationship(c.to_string(), CWE))
                .chain(
                    standards
                        .owasp
                        .iter()
                        .map(|o| relationship(o.id().into(), OWASP)),
                )
                .collect();
            let mut rule_json = json!({
                "id": rule.id,
                "name": rule.id,
                "shortDescription": { "text": rule.name },
                "fullDescription": { "text": rule.description },
                "defaultConfiguration": { "level": level(rule.severity) },
                "properties": properties,
            });
            if !relationships.is_empty() {
                rule_json["relationships"] = json!(relationships);
            }
            rule_json
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
            "taxonomies": taxonomies(),
            "results": results,
        }]
    });
    // Cannot fail: `doc` is already a `serde_json::Value`.
    serde_json::to_string_pretty(&doc).expect("sarif serializes") + "\n"
}

/// Indexes into the run's `taxonomies`.
const CWE: usize = 0;
const OWASP: usize = 1;

fn relationship(id: String, taxonomy: usize) -> Value {
    json!({
        "target": {
            "id": id,
            "toolComponent": { "name": if taxonomy == CWE { "CWE" } else { "OWASP Top 10" }, "index": taxonomy },
        },
        "kinds": ["relevant"],
    })
}

/// CWE and the OWASP Top 10 2021, with the entries the rules refer to.
fn taxonomies() -> Value {
    let cwe: BTreeSet<u16> = RULES
        .iter()
        .flat_map(|r| r.standards().cwe.iter().copied())
        .collect();
    let owasp: BTreeSet<Owasp> = RULES
        .iter()
        .flat_map(|r| r.standards().owasp.iter().copied())
        .collect();
    json!([
        {
            "name": "CWE",
            "organization": "MITRE",
            "informationUri": "https://cwe.mitre.org/",
            "taxa": cwe.iter().map(|c| json!({
                "id": c.to_string(),
                "helpUri": format!("https://cwe.mitre.org/data/definitions/{c}.html"),
            })).collect::<Vec<_>>(),
        },
        {
            "name": "OWASP Top 10",
            "version": "2021",
            "organization": "OWASP",
            "informationUri": "https://owasp.org/Top10/",
            "taxa": owasp.iter().map(|o| json!({ "id": o.id(), "name": o.title() })).collect::<Vec<_>>(),
        },
    ])
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
