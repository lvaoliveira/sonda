//! SBOM exports of a project's dependencies (ADR-0009): CycloneDX 1.6 and
//! SPDX 2.3, as JSON. Deterministic for the same input: no random serial
//! numbers, and the caller supplies the timestamp.

use crate::deps::{Dependency, Ecosystem};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// One entry per package URL: the same package can be pinned by several
/// lockfiles.
struct Package<'a> {
    dep: &'a Dependency,
    direct: Option<bool>,
    sources: Vec<&'a str>,
}

fn packages(deps: &[Dependency]) -> Vec<Package<'_>> {
    let mut by_purl: BTreeMap<&str, Package> = BTreeMap::new();
    for d in deps {
        let p = by_purl.entry(&d.purl).or_insert(Package {
            dep: d,
            direct: None,
            sources: Vec::new(),
        });
        p.direct = match (p.direct, d.direct) {
            (Some(a), Some(b)) => Some(a || b),
            (a, b) => a.or(b),
        };
        p.sources.push(&d.source);
    }
    by_purl.into_values().collect()
}

pub fn cyclonedx(project: &str, deps: &[Dependency], timestamp: &str) -> String {
    let packages = packages(deps);
    let components: Vec<Value> = packages
        .iter()
        .map(|p| {
            let d = p.dep;
            // npm scopes are CycloneDX groups.
            let (group, name) = match (d.ecosystem, d.name.split_once('/')) {
                (Ecosystem::Npm, Some((scope, name))) if scope.starts_with('@') => {
                    (Some(scope), name)
                }
                _ => (None, d.name.as_str()),
            };
            let mut c = json!({
                "type": "library",
                "bom-ref": d.purl,
                "name": name,
                "version": d.version,
                "purl": d.purl,
            });
            if let Some(g) = group {
                c["group"] = json!(g);
            }
            if let Some(l) = &d.license {
                c["licenses"] = if is_spdx_expression(l) {
                    json!([{ "expression": l }])
                } else {
                    json!([{ "license": { "name": l } }])
                };
            }
            let mut properties: Vec<Value> = p
                .sources
                .iter()
                .map(|s| json!({ "name": "sonda:lockfile", "value": s }))
                .collect();
            if let Some(direct) = p.direct {
                properties.push(json!({ "name": "sonda:direct", "value": direct.to_string() }));
            }
            c["properties"] = json!(properties);
            c
        })
        .collect();
    let direct: Vec<&str> = packages
        .iter()
        .filter(|p| p.direct == Some(true))
        .map(|p| p.dep.purl.as_str())
        .collect();
    let doc = json!({
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": { "components": [{
                "type": "application",
                "name": "sonda",
                "version": env!("CARGO_PKG_VERSION"),
            }] },
            "component": { "type": "application", "bom-ref": PROJECT_REF, "name": project },
        },
        "components": components,
        "dependencies": [{ "ref": PROJECT_REF, "dependsOn": direct }],
    });
    // Cannot fail: built from plain JSON values.
    serde_json::to_string_pretty(&doc).expect("sbom serializes") + "\n"
}

/// The project's own `bom-ref`; purls (every other ref) start with `pkg:`.
const PROJECT_REF: &str = "project";

pub fn spdx(project: &str, deps: &[Dependency], timestamp: &str) -> String {
    let packages = packages(deps);
    // Unique per document, and the same for the same content.
    let mut hash = Sha256::new();
    hash.update(project.as_bytes());
    hash.update(timestamp.as_bytes());
    for p in &packages {
        hash.update(p.dep.purl.as_bytes());
        hash.update([0]);
    }
    let digest: String = hash.finalize().iter().map(|b| format!("{b:02x}")).collect();
    let mut spdx_packages = vec![json!({
        "SPDXID": "SPDXRef-Project",
        "name": project,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": false,
        "primaryPackagePurpose": "APPLICATION",
    })];
    let mut relationships = vec![json!({
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": "SPDXRef-Project",
    })];
    for (i, p) in packages.iter().enumerate() {
        let id = format!("SPDXRef-Package-{}", i + 1);
        let declared = p
            .dep
            .license
            .as_deref()
            .filter(|l| is_spdx_expression(l))
            .unwrap_or("NOASSERTION");
        let mut package = json!({
            "SPDXID": id,
            "name": p.dep.name,
            "versionInfo": p.dep.version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": false,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": declared,
            "primaryPackagePurpose": "LIBRARY",
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": p.dep.purl,
            }],
        });
        if let Some(direct) = p.direct {
            package["comment"] = json!(format!(
                "{} dependency, from {}",
                if direct { "Direct" } else { "Transitive" },
                p.sources.join(", ")
            ));
        }
        spdx_packages.push(package);
        // Directly or through other packages: lockfiles don't always say.
        relationships.push(json!({
            "spdxElementId": "SPDXRef-Project",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": id,
        }));
    }
    let doc = json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": project,
        "documentNamespace": format!("https://sonda.invalid/spdx/{}-{digest}", encode_segment(project)),
        "creationInfo": {
            "created": timestamp,
            "creators": [format!("Tool: sonda-{}", env!("CARGO_PKG_VERSION"))],
        },
        "packages": spdx_packages,
        "relationships": relationships,
    });
    serde_json::to_string_pretty(&doc).expect("sbom serializes") + "\n"
}

/// A URI path segment: unreserved characters kept, everything else `-`.
fn encode_segment(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '~') {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// Whether `s` reads as an SPDX license expression (`MIT`, `(MIT OR
/// Apache-2.0)`, `GPL-2.0-only WITH Classpath-exception-2.0`). npm allows
/// free text (`SEE LICENSE IN LICENSE.md`, `UNLICENSED`) that isn't one.
/// The syntax only: whether each id is on SPDX's list isn't checked.
pub(crate) fn is_spdx_expression(s: &str) -> bool {
    let spaced = s.replace('(', " ( ").replace(')', " ) ");
    let tokens: Vec<&str> = spaced.split_whitespace().collect();
    let mut pos = 0;
    expression(&tokens, &mut pos) && pos == tokens.len()
}

const OPERATORS: &[&str] = &["AND", "OR", "WITH"];

fn expression(t: &[&str], pos: &mut usize) -> bool {
    if !term(t, pos) {
        return false;
    }
    while matches!(t.get(*pos), Some(&("AND" | "OR"))) {
        *pos += 1;
        if !term(t, pos) {
            return false;
        }
    }
    true
}

fn term(t: &[&str], pos: &mut usize) -> bool {
    match t.get(*pos) {
        Some(&"(") => {
            *pos += 1;
            if !expression(t, pos) || t.get(*pos) != Some(&")") {
                return false;
            }
            *pos += 1;
            true
        }
        Some(&id) if license_id(id) => {
            *pos += 1;
            if t.get(*pos) == Some(&"WITH") {
                *pos += 1;
                if !t.get(*pos).is_some_and(|e| license_id(e)) {
                    return false;
                }
                *pos += 1;
            }
            true
        }
        _ => false,
    }
}

fn license_id(id: &str) -> bool {
    let id = id.strip_suffix('+').unwrap_or(id);
    !id.is_empty()
        && !OPERATORS.contains(&id)
        && id != "UNLICENSED"
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | ':'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(
        eco: Ecosystem,
        name: &str,
        purl: &str,
        direct: Option<bool>,
        source: &str,
        license: Option<&str>,
    ) -> Dependency {
        Dependency {
            ecosystem: eco,
            name: name.into(),
            version: "1.0.0".into(),
            purl: purl.into(),
            direct,
            source: source.into(),
            license: license.map(Into::into),
        }
    }

    fn sample() -> Vec<Dependency> {
        vec![
            dep(
                Ecosystem::Npm,
                "@babel/core",
                "pkg:npm/%40babel/core@1.0.0",
                Some(true),
                "package-lock.json",
                Some("MIT"),
            ),
            dep(
                Ecosystem::Npm,
                "left-pad",
                "pkg:npm/left-pad@1.0.0",
                Some(false),
                "package-lock.json",
                Some("SEE LICENSE IN LICENSE"),
            ),
            dep(
                Ecosystem::Npm,
                "left-pad",
                "pkg:npm/left-pad@1.0.0",
                Some(true),
                "web/package-lock.json",
                None,
            ),
            dep(
                Ecosystem::Pypi,
                "flask",
                "pkg:pypi/flask@1.0.0",
                None,
                "requirements.txt",
                None,
            ),
        ]
    }

    #[test]
    fn license_expressions() {
        for ok in [
            "MIT",
            "(MIT OR Apache-2.0)",
            "GPL-2.0-only WITH Classpath-exception-2.0",
            "Apache-2.0 AND (MIT OR BSD-3-Clause)",
            "GPL-2.0+",
            "LicenseRef-x",
        ] {
            assert!(is_spdx_expression(ok), "{ok}");
        }
        for bad in [
            "SEE LICENSE IN LICENSE.md",
            "UNLICENSED",
            "MIT OR",
            "(MIT",
            "",
            "MIT AND AND BSD",
            "Custom: see file",
        ] {
            assert!(!is_spdx_expression(bad), "{bad}");
        }
    }

    #[test]
    fn cyclonedx_merges_lockfiles_and_lists_direct_dependencies() {
        let doc: Value =
            serde_json::from_str(&cyclonedx("app", &sample(), "2026-10-30T12:00:00Z")).unwrap();
        let components = doc["components"].as_array().unwrap();
        assert_eq!(components.len(), 3);
        let babel = &components[0];
        assert_eq!(
            (babel["group"].as_str(), babel["name"].as_str()),
            (Some("@babel"), Some("core"))
        );
        assert_eq!(babel["licenses"], json!([{ "expression": "MIT" }]));
        let left_pad = &components[1];
        assert_eq!(
            left_pad["licenses"],
            json!([{ "license": { "name": "SEE LICENSE IN LICENSE" } }])
        );
        assert_eq!(
            left_pad["properties"].as_array().unwrap().len(),
            3,
            "two lockfiles and direct"
        );
        assert_eq!(
            doc["dependencies"][0]["dependsOn"],
            json!(["pkg:npm/%40babel/core@1.0.0", "pkg:npm/left-pad@1.0.0"])
        );
    }

    #[test]
    fn spdx_is_deterministic_and_relates_every_package() {
        let a = spdx("my app", &sample(), "2026-10-30T12:00:00Z");
        assert_eq!(a, spdx("my app", &sample(), "2026-10-30T12:00:00Z"));
        let doc: Value = serde_json::from_str(&a).unwrap();
        assert_eq!(doc["packages"].as_array().unwrap().len(), 4);
        assert_eq!(doc["relationships"].as_array().unwrap().len(), 4);
        assert!(
            doc["documentNamespace"]
                .as_str()
                .unwrap()
                .starts_with("https://sonda.invalid/spdx/my-app-")
        );
        assert_eq!(doc["packages"][2]["licenseDeclared"], "NOASSERTION");
    }
}
