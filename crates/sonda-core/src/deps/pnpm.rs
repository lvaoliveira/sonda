//! `pnpm-lock.yaml`, lockfile versions 5 to 9 (pnpm 6 and later): the
//! `packages` map, keyed by package and version, and the `importers` (each
//! workspace, `.` included) that declare the direct ones.

use super::yaml::{self, Node};
use super::{Dependency, Ecosystem, Parsed, purl};
use std::collections::HashSet;

const IMPORTER_DEPENDENCIES: &[&str] = &["dependencies", "devDependencies", "optionalDependencies"];

pub(super) fn parse(path: &str, text: &str) -> Result<Parsed, String> {
    let mut dependencies = Vec::new();
    let mut notes = Vec::new();
    for document in yaml::load_all(text)? {
        // pnpm 11 and later write the package manager's own lockfile first:
        // its `packageManagerDependencies` and `configDependencies` are
        // tooling, not the project's dependencies.
        let tooling = document
            .get("importers")
            .is_some_and(|i| i.entries().iter().all(|(_, imp)| is_tooling(imp)));
        if tooling {
            continue;
        }
        let parsed = parse_document(path, &document)?;
        dependencies.extend(parsed.dependencies);
        notes.extend(parsed.notes);
    }
    Ok(Parsed {
        dependencies,
        notes,
    })
}

fn is_tooling(importer: &Node) -> bool {
    importer
        .entries()
        .iter()
        .all(|(k, _)| k == "packageManagerDependencies" || k == "configDependencies")
}

fn parse_document(path: &str, lock: &Node) -> Result<Parsed, String> {
    let version = lock
        .get("lockfileVersion")
        .and_then(Node::str)
        .ok_or("no lockfileVersion")?;
    // "5.4", "6.0", "9.0": version 5 keys packages `/name/1.0.0`, later
    // ones `/name@1.0.0` (6) or `name@1.0.0` (9).
    let slash_keys = match version
        .split('.')
        .next()
        .and_then(|m| m.parse::<u32>().ok())
    {
        Some(5) => true,
        Some(6..=9) => false,
        _ => return Err(format!("lockfileVersion {version} is not supported")),
    };

    // Single-project lockfiles before version 9 list the project's
    // dependencies at the top level instead of under `importers`.
    let importers: Vec<&Node> = match lock.get("importers") {
        Some(i) => i.entries().iter().map(|(_, v)| v).collect(),
        None => vec![lock],
    };
    let direct: HashSet<(String, String)> = importers
        .iter()
        .flat_map(|importer| {
            IMPORTER_DEPENDENCIES
                .iter()
                .filter_map(|field| importer.get(field))
                .flat_map(|deps| deps.entries())
        })
        .filter_map(|(name, spec)| {
            // `version: 1.0.0` (6+), or the version itself (5).
            let version = spec.get("version").and_then(Node::str).or(spec.str())?;
            // An alias before version 9 is a package key (`/real@1.0.0`).
            if version.starts_with('/') {
                return package_key(version, slash_keys).map(|(n, v)| (n.into(), v.into()));
            }
            let version = if slash_keys {
                version.split('_').next().unwrap_or(version)
            } else {
                strip_peers(version)
            };
            // An alias in version 9 is `real@1.0.0`.
            match split_at_version(version) {
                Some((real, v)) if !v.is_empty() => Some((real.to_string(), v.to_string())),
                _ => Some((name.clone(), version.to_string())),
            }
        })
        .collect();

    let mut dependencies = Vec::new();
    let mut skipped = 0;
    for (key, _) in lock.get("packages").map(Node::entries).unwrap_or_default() {
        let Some((name, version)) = package_key(key, slash_keys) else {
            skipped += 1;
            continue;
        };
        // Local, git and tarball packages aren't registry versions.
        if version.contains(':') || version.contains('/') {
            skipped += 1;
            continue;
        }
        let (namespace, bare) = match name.split_once('/') {
            Some((scope, bare)) if scope.starts_with('@') => (Some(scope), bare),
            _ => (None, name),
        };
        dependencies.push(Dependency {
            ecosystem: Ecosystem::Npm,
            name: name.to_string(),
            version: version.to_string(),
            purl: purl(Ecosystem::Npm, namespace, bare, version),
            direct: Some(direct.contains(&(name.to_string(), version.to_string()))),
            source: path.to_string(),
            // pnpm-lock.yaml doesn't record licenses.
            license: None,
        });
    }
    let notes = if skipped > 0 {
        vec![format!(
            "{skipped} packages not from the registry (local, git or tarball) left out"
        )]
    } else {
        Vec::new()
    };
    Ok(Parsed {
        dependencies,
        notes,
    })
}

/// A `packages` key's name and version, without peer-dependency suffixes:
/// `/name/1.0.0_peer@2` (version 5), `/name@1.0.0(peer@2)` (6) or
/// `name@1.0.0(peer@2)` (9), scoped names included.
fn package_key(key: &str, slash_keys: bool) -> Option<(&str, &str)> {
    let key = key.strip_prefix('/').unwrap_or(key);
    let (name, version) = if slash_keys {
        let (name, version) = key.rsplit_once('/')?;
        (name, version.split('_').next().unwrap_or(version))
    } else {
        split_at_version(strip_peers(key))?
    };
    (!name.is_empty() && !version.is_empty()).then_some((name, version))
}

/// `name@1.0.0` -> (`name`, `1.0.0`); a scope's leading `@` isn't the
/// separator.
fn split_at_version(s: &str) -> Option<(&str, &str)> {
    let at = s.get(1..)?.find('@')? + 1;
    Some((&s[..at], &s[at + 1..]))
}

/// `1.0.0(react@18.2.0)` -> `1.0.0`.
fn strip_peers(s: &str) -> &str {
    s.split('(').next().unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn got(parsed: &Parsed) -> Vec<(&str, &str, Option<bool>)> {
        parsed
            .dependencies
            .iter()
            .map(|d| (d.name.as_str(), d.version.as_str(), d.direct))
            .collect()
    }

    #[test]
    fn reads_version_9() {
        let lock = r#"lockfileVersion: '9.0'

settings:
  autoInstallPeers: true

importers:
  .:
    dependencies:
      react-dom:
        specifier: ^18.2.0
        version: 18.2.0(react@18.2.0)
      ms-alias:
        specifier: npm:ms@^2
        version: ms@2.0.0
    devDependencies:
      '@types/node':
        specifier: ^20
        version: 20.1.0
  packages/web:
    dependencies:
      lodash:
        specifier: ^4
        version: 4.17.20
      shared:
        specifier: workspace:*
        version: link:../shared

packages:
  '@types/node@20.1.0':
    resolution: {integrity: sha512-x}
  lodash@4.17.20:
    resolution: {integrity: sha512-y}
  lodash@3.10.1:
    resolution: {integrity: sha512-z}
  ms@2.0.0:
    resolution: {integrity: sha512-m}
  react-dom@18.2.0:
    resolution: {integrity: sha512-r}
  local@file:../local:
    resolution: {directory: ../local, type: directory}

snapshots:
  react-dom@18.2.0(react@18.2.0):
    dependencies:
      react: 18.2.0
"#;
        let parsed = parse("pnpm-lock.yaml", lock).unwrap();
        assert_eq!(
            got(&parsed),
            [
                ("@types/node", "20.1.0", Some(true)),
                ("lodash", "4.17.20", Some(true)),
                ("lodash", "3.10.1", Some(false)),
                ("ms", "2.0.0", Some(true)),
                ("react-dom", "18.2.0", Some(true)),
            ]
        );
        assert_eq!(parsed.dependencies[0].purl, "pkg:npm/%40types/node@20.1.0");
        assert_eq!(parsed.notes.len(), 1);
    }

    #[test]
    fn reads_versions_6_and_5() {
        let v6 = r#"lockfileVersion: '6.0'
dependencies:
  express:
    specifier: ^4.18.0
    version: 4.18.2
packages:
  /express@4.18.2:
    resolution: {integrity: sha512-a}
    dev: false
  /@babel/core@7.22.0(supports-color@5.5.0):
    resolution: {integrity: sha512-b}
    dev: true
"#;
        assert_eq!(
            got(&parse("pnpm-lock.yaml", v6).unwrap()),
            [
                ("express", "4.18.2", Some(true)),
                ("@babel/core", "7.22.0", Some(false)),
            ]
        );
        let v5 = concat!(
            "lockfileVersion: 5.4\n",
            "specifiers:\n  express: ^4\n",
            "dependencies:\n  express: 4.18.2\n",
            "devDependencies:\n  '@babel/core': 7.22.0_supports-color@5.5.0\n  ms-alias: /ms/2.0.0\n",
            "packages:\n",
            "  /express/4.18.2:\n    dev: false\n",
            "  /@babel/core/7.22.0_supports-color@5.5.0:\n    dev: true\n",
            "  /ms/2.0.0:\n    dev: true\n",
            "  /debug/4.3.4:\n    dev: false\n",
        );
        assert_eq!(
            got(&parse("pnpm-lock.yaml", v5).unwrap()),
            [
                ("express", "4.18.2", Some(true)),
                ("@babel/core", "7.22.0", Some(true)),
                ("ms", "2.0.0", Some(true)),
                ("debug", "4.3.4", Some(false)),
            ]
        );
    }

    #[test]
    fn skips_the_package_managers_own_document() {
        // pnpm 11 and later: pnpm's own install first, then the project.
        let lock = "---\nlockfileVersion: '9.0'\nimporters:\n  .:\n    configDependencies: {}\n    packageManagerDependencies:\n      pnpm:\n        specifier: 12.16.1\n        version: 12.16.1\npackages:\n  pnpm@12.16.1:\n    resolution: {integrity: sha512-p}\n---\nlockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      lodash:\n        specifier: ^4\n        version: 4.17.21\npackages:\n  lodash@4.17.21:\n    resolution: {integrity: sha512-l}\n";
        assert_eq!(
            got(&parse("pnpm-lock.yaml", lock).unwrap()),
            [("lodash", "4.17.21", Some(true))]
        );
    }

    #[test]
    fn unknown_versions_and_bad_files_are_errors() {
        assert!(
            parse("p", "lockfileVersion: '3.9'\n")
                .unwrap_err()
                .contains("3.9")
        );
        assert!(parse("p", "packages: {}\n").is_err());
        assert!(parse("p", "a: [").is_err());
    }

    proptest! {
        #![proptest_config(crate::test_support::proptest_config(256))]

        #[test]
        fn parser_accepts_any_input_without_panicking(
            body in "([a-z0-9@/_():.' -]|\n  |\n    )*"
        ) {
            let _ = parse("p", &format!("lockfileVersion: '9.0'\npackages:\n  {body}"));
        }
    }
}
