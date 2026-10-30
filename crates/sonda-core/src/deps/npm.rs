//! `package-lock.json` and `npm-shrinkwrap.json`, lockfile versions 2 and
//! 3 (npm 7 and later): the `packages` map, keyed by install path.

use super::{Dependency, Ecosystem, Parsed, purl};
use serde_json::Value;
use std::collections::HashSet;

const ROOT_DEPENDENCIES: &[&str] = &[
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
];

pub(super) fn parse(path: &str, text: &str) -> Result<Parsed, String> {
    let lock: Value = serde_json::from_str(text).map_err(|e| format!("not valid JSON ({e})"))?;
    match lock["lockfileVersion"].as_u64() {
        Some(2 | 3) => {}
        Some(1) => {
            return Err("lockfileVersion 1 (npm 6) is not supported; \
                        regenerate it with npm 7 or later"
                .into());
        }
        _ => return Err("unknown lockfileVersion".into()),
    }
    let packages = lock["packages"].as_object().ok_or("no \"packages\" map")?;
    // The project's own manifest, at key "".
    let direct: HashSet<&str> = packages
        .get("")
        .map(|root| {
            ROOT_DEPENDENCIES
                .iter()
                .filter_map(|field| root[*field].as_object())
                .flat_map(|deps| deps.keys().map(String::as_str))
                .collect()
        })
        .unwrap_or_default();

    let mut dependencies = Vec::new();
    for (key, package) in packages {
        // Keys without node_modules/ are the project and its workspaces;
        // `link` entries point at those.
        let Some(at) = key.rfind("node_modules/") else {
            continue;
        };
        if package["link"].as_bool() == Some(true) {
            continue;
        }
        let installed_as = &key[at + "node_modules/".len()..];
        // An alias (`"a": "npm:b@1"`) is installed as `a` but is package `b`.
        let name = package["name"].as_str().unwrap_or(installed_as);
        let Some(version) = package["version"].as_str() else {
            continue;
        };
        let (namespace, bare) = match name.split_once('/') {
            Some((scope, bare)) if scope.starts_with('@') => (Some(scope), bare),
            _ => (None, name),
        };
        dependencies.push(Dependency {
            ecosystem: Ecosystem::Npm,
            name: name.to_string(),
            version: version.to_string(),
            purl: purl(Ecosystem::Npm, namespace, bare, version),
            // Top-level install of something the project declares.
            direct: Some(at == 0 && direct.contains(installed_as)),
            source: path.to_string(),
            license: package["license"].as_str().map(str::to_string),
        });
    }
    Ok(Parsed {
        dependencies,
        notes: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK: &str = r#"{
      "name": "app", "lockfileVersion": 3,
      "packages": {
        "": { "name": "app", "dependencies": { "express": "^4" }, "devDependencies": { "@types/node": "^20" } },
        "node_modules/express": { "version": "4.18.2", "license": "MIT" },
        "node_modules/@types/node": { "version": "20.1.0", "dev": true, "license": "MIT" },
        "node_modules/debug": { "version": "2.6.9" },
        "node_modules/express/node_modules/debug": { "version": "2.6.9" },
        "node_modules/ms-alias": { "name": "ms", "version": "2.0.0" },
        "packages/web": { "name": "web", "version": "1.0.0" },
        "node_modules/web": { "resolved": "packages/web", "link": true }
      }
    }"#;

    #[test]
    fn reads_installed_packages_and_which_are_direct() {
        let parsed = super::super::parse(
            super::super::FileKind::PackageLock,
            "package-lock.json",
            LOCK,
            None,
        )
        .unwrap();
        let got: Vec<(&str, &str, Option<bool>, &str)> = parsed
            .dependencies
            .iter()
            .map(|d| {
                (
                    d.name.as_str(),
                    d.version.as_str(),
                    d.direct,
                    d.purl.as_str(),
                )
            })
            .collect();
        assert_eq!(
            got,
            [
                (
                    "@types/node",
                    "20.1.0",
                    Some(true),
                    "pkg:npm/%40types/node@20.1.0"
                ),
                ("debug", "2.6.9", Some(false), "pkg:npm/debug@2.6.9"),
                ("express", "4.18.2", Some(true), "pkg:npm/express@4.18.2"),
                ("ms", "2.0.0", Some(false), "pkg:npm/ms@2.0.0"),
            ]
        );
        assert_eq!(parsed.dependencies[2].license.as_deref(), Some("MIT"));
    }

    #[test]
    fn old_and_broken_lockfiles_are_errors() {
        assert!(
            parse("p", r#"{"lockfileVersion": 1, "dependencies": {}}"#)
                .unwrap_err()
                .contains("npm 6")
        );
        assert!(parse("p", "{").is_err());
        assert!(parse("p", r#"{"lockfileVersion": 3}"#).is_err());
    }
}
