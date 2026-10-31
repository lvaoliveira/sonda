//! `yarn.lock`, in either of its formats:
//!
//! - **Yarn v1** (classic): its own format, not YAML. Each entry starts at
//!   column 0 with the specifiers it resolves (`"@babel/core@^7.0.0",
//!   "@babel/core@^7.1.0":`), and its indented fields include `version
//!   "7.1.2"`.
//! - **Yarn 2+** (Berry): YAML with a `__metadata` entry. Each entry's
//!   `resolution` names the package (`lodash@npm:4.17.21`), and the
//!   workspaces' own entries list what they declare.

use super::yaml::{self, Node};
use super::{Dependency, Ecosystem, Parsed, purl};
use serde_json::Value;
use std::collections::HashSet;

const MANIFEST_DEPENDENCIES: &[&str] = &[
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
];

/// `manifest` is the `package.json` next to the lockfile, if any: for Yarn
/// v1, its declared `name@range` specifiers tell which entries are direct.
pub(super) fn parse(path: &str, text: &str, manifest: Option<&str>) -> Result<Parsed, String> {
    if text.lines().any(|l| l.starts_with("__metadata:")) {
        return berry(path, text);
    }
    if !text.lines().any(|l| l.trim() == "# yarn lockfile v1") {
        return Err("not a Yarn v1 lockfile (no \"# yarn lockfile v1\" header)".into());
    }
    let declared = manifest.map(declared_specifiers);

    let mut dependencies = Vec::new();
    let mut entry: Option<(Vec<String>, Option<String>)> = None;
    let mut flush = |entry: Option<(Vec<String>, Option<String>)>| {
        let Some((specifiers, Some(version))) = entry else {
            return;
        };
        let direct = declared
            .as_ref()
            .map(|d| specifiers.iter().any(|s| d.contains(s)));
        let mut names: Vec<String> = specifiers.iter().filter_map(|s| package_of(s)).collect();
        names.sort();
        names.dedup();
        for name in names {
            let (namespace, bare) = match name.split_once('/') {
                Some((scope, bare)) if scope.starts_with('@') => (Some(scope), bare),
                _ => (None, name.as_str()),
            };
            dependencies.push(Dependency {
                ecosystem: Ecosystem::Npm,
                purl: purl(Ecosystem::Npm, namespace, bare, &version),
                name: name.clone(),
                version: version.clone(),
                direct,
                source: path.to_string(),
                // yarn.lock doesn't record licenses.
                license: None,
            });
        }
    };
    for line in text.lines() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') {
            flush(entry.take());
            if let Some(key) = line.strip_suffix(':') {
                entry = Some((specifiers(key), None));
            }
        } else if let (Some((_, version)), Some(value)) =
            (entry.as_mut(), line.strip_prefix("  version "))
        {
            *version = Some(unquote(value.trim()).to_string());
        }
    }
    flush(entry.take());
    Ok(Parsed {
        dependencies,
        notes: Vec::new(),
    })
}

/// Yarn 2+: registry packages from each entry's `resolution`, direct when
/// one of the entry's specifiers is one a workspace declares.
fn berry(path: &str, text: &str) -> Result<Parsed, String> {
    let lock = yaml::load(text)?;
    let mut declared: HashSet<String> = HashSet::new();
    let mut packages: Vec<(&str, &str)> = Vec::new();
    for (key, entry) in lock.entries() {
        let Some(resolution) = entry.get("resolution").and_then(Node::str) else {
            continue;
        };
        if resolution.contains("@workspace:") {
            for field in ["dependencies", "peerDependencies"] {
                for (name, range) in entry.get(field).map(Node::entries).unwrap_or_default() {
                    let Some(range) = range.str() else { continue };
                    declared.insert(format!("{name}@{range}"));
                    // Older lockfiles leave out the default protocol.
                    if !range.contains(':') {
                        declared.insert(format!("{name}@npm:{range}"));
                    }
                }
            }
            continue;
        }
        packages.push((key, resolution));
    }

    let mut dependencies = Vec::new();
    let mut skipped = 0;
    for (key, resolution) in packages {
        let Some((name, version)) = registry_package(resolution) else {
            skipped += 1;
            continue;
        };
        let (namespace, bare) = match name.split_once('/') {
            Some((scope, bare)) if scope.starts_with('@') => (Some(scope), bare),
            _ => (None, name.as_str()),
        };
        dependencies.push(Dependency {
            ecosystem: Ecosystem::Npm,
            purl: purl(Ecosystem::Npm, namespace, bare, &version),
            direct: Some(specifiers(key).iter().any(|s| declared.contains(s))),
            name,
            version,
            source: path.to_string(),
            license: None,
        });
    }
    let notes = if skipped > 0 {
        vec![format!(
            "{skipped} packages not from the registry (git, file, link or tarball) left out"
        )]
    } else {
        Vec::new()
    };
    Ok(Parsed {
        dependencies,
        notes,
    })
}

/// A Yarn 2+ `resolution`'s registry package: `name@npm:1.0.0`, or a
/// patched one (`name@patch:name@npm%3A1.0.0#...`, as Yarn applies to
/// `typescript` itself), which is still that package's code. `None` for
/// git, file, link and other sources.
fn registry_package(resolution: &str) -> Option<(String, String)> {
    let at = resolution.get(1..)?.find('@')? + 1;
    let (name, source) = (&resolution[..at], &resolution[at + 1..]);
    if let Some(version) = source.strip_prefix("npm:") {
        return (!name.is_empty() && !version.is_empty())
            .then(|| (name.to_string(), version.to_string()));
    }
    let patched = source.strip_prefix("patch:")?;
    let inner = patched.split('#').next()?;
    let inner = inner.replace("%3A", ":").replace("%40", "@");
    if inner.contains("@patch:") {
        return None;
    }
    registry_package(&inner)
}

/// `"a@^1", b@~2` -> `["a@^1", "b@~2"]`.
fn specifiers(key: &str) -> Vec<String> {
    key.split(", ")
        .map(|s| unquote(s.trim()).to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn unquote(s: &str) -> &str {
    s.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(s)
}

/// The package a specifier installs: the part before its range's `@`
/// (after a scope's leading `@`), or an alias's target (`a@npm:b@1` is
/// `b`). `None` for local packages (`file:`, `link:`), which aren't on the
/// registry, and for what doesn't parse.
fn package_of(specifier: &str) -> Option<String> {
    let at = specifier.get(1..)?.find('@')? + 1;
    let (name, range) = (&specifier[..at], &specifier[at + 1..]);
    if range.starts_with("file:") || range.starts_with("link:") {
        return None;
    }
    if let Some(target) = range.strip_prefix("npm:") {
        // `npm:b@1`, or `npm:b` for any version.
        let end = target
            .get(1..)
            .and_then(|t| t.find('@'))
            .map_or(target.len(), |i| i + 1);
        return (!target[..end].is_empty()).then(|| target[..end].to_string());
    }
    (!name.is_empty()).then(|| name.to_string())
}

/// `name@range` for each dependency `package.json` declares, as yarn.lock
/// keys them.
fn declared_specifiers(manifest: &str) -> HashSet<String> {
    let Ok(json) = serde_json::from_str::<Value>(manifest) else {
        return HashSet::new();
    };
    MANIFEST_DEPENDENCIES
        .iter()
        .filter_map(|field| json[*field].as_object())
        .flat_map(|deps| deps.iter())
        .filter_map(|(name, range)| range.as_str().map(|r| format!("{name}@{r}")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const LOCK: &str = r#"# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":
  version "7.12.13"
  resolved "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.12.13.tgz#dcfc826b"
  integrity sha512-HV1Cm0Q3ZrpCR93tkWOYiuYIgLxZXZFVG2VgK+MBWjUqZTundupbfx2aXarXuw5Ko5aMcjtJgbSs4vUGBS5v6g==
  dependencies:
    "@babel/highlight" "^7.12.13"

lodash@^4.17.20:
  version "4.17.20"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.20.tgz"

lodash@^3.0.0:
  version "3.10.1"

ms-alias@npm:ms@2.0.0:
  version "2.0.0"

local@file:../local:
  version "1.0.0"

broken@^1.0.0:
  resolved "https://example.com/no-version.tgz"
"#;

    const MANIFEST: &str = r#"{"dependencies": {"lodash": "^4.17.20"},
                               "devDependencies": {"@babel/code-frame": "^7.10.4"}}"#;

    #[test]
    fn reads_entries_and_which_are_direct() {
        let parsed = parse("yarn.lock", LOCK, Some(MANIFEST)).unwrap();
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
                    "@babel/code-frame",
                    "7.12.13",
                    Some(true),
                    "pkg:npm/%40babel/code-frame@7.12.13"
                ),
                ("lodash", "4.17.20", Some(true), "pkg:npm/lodash@4.17.20"),
                // The same package at another version: transitive.
                ("lodash", "3.10.1", Some(false), "pkg:npm/lodash@3.10.1"),
                // An alias is the package it points at.
                ("ms", "2.0.0", Some(false), "pkg:npm/ms@2.0.0"),
            ]
        );
        // Without package.json, nothing says what's direct.
        let parsed = parse("yarn.lock", LOCK, None).unwrap();
        assert!(parsed.dependencies.iter().all(|d| d.direct.is_none()));
    }

    #[test]
    fn berry_and_other_files_are_errors() {
        let berry = "__metadata:\n  version: 6\n\nlodash: [\n";
        assert!(
            parse("yarn.lock", berry, None)
                .unwrap_err()
                .contains("YAML")
        );
        assert!(parse("yarn.lock", "lodash@^4:\n  version \"4\"\n", None).is_err());
    }

    #[test]
    fn reads_yarn_2_and_later() {
        let lock = r#"# This file is generated by running "yarn install" inside your project.

__metadata:
  version: 8
  cacheKey: 10c0

"@types/node@npm:^20":
  version: 20.1.0
  resolution: "@types/node@npm:20.1.0"
  languageName: node
  linkType: hard

"lodash@npm:^4.17.20, lodash@npm:^4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
  languageName: node
  linkType: hard

"lodash@npm:^3":
  version: 3.10.1
  resolution: "lodash@npm:3.10.1"

"ms-alias@npm:ms@^2":
  version: 2.0.0
  resolution: "ms@npm:2.0.0"

"typescript@npm:^5.0.0":
  version: 5.0.4
  resolution: "typescript@npm:5.0.4"

"typescript@patch:typescript@npm%3A^5.0.0#optional!builtin<compat/typescript>":
  version: 5.0.4
  resolution: "typescript@patch:typescript@npm%3A5.0.4#optional!builtin<compat/typescript>::version=5.0.4&hash=b5f058"

"left-pad@git+https://github.com/x/left-pad.git":
  version: 1.3.0
  resolution: "left-pad@git+https://github.com/x/left-pad.git#commit=abc"

"app@workspace:.":
  version: 0.0.0-use.local
  resolution: "app@workspace:."
  dependencies:
    "@types/node": "npm:^20"
    lodash: "npm:^4.17.20"
    ms-alias: "npm:ms@^2"
    typescript: "patch:typescript@npm%3A^5.0.0#optional!builtin<compat/typescript>"
  languageName: unknown
  linkType: soft
"#;
        // Through the module's parse, which merges duplicate entries.
        let parsed =
            super::super::parse(super::super::FileKind::YarnLock, "yarn.lock", lock, None).unwrap();
        let got: Vec<(&str, &str, Option<bool>)> = parsed
            .dependencies
            .iter()
            .map(|d| (d.name.as_str(), d.version.as_str(), d.direct))
            .collect();
        assert_eq!(
            got,
            [
                ("@types/node", "20.1.0", Some(true)),
                ("lodash", "3.10.1", Some(false)),
                ("lodash", "4.17.21", Some(true)),
                ("ms", "2.0.0", Some(true)),
                // Patched and unpatched entries are one package.
                ("typescript", "5.0.4", Some(true)),
            ]
        );
        assert_eq!(parsed.notes.len(), 1, "the git package");
    }

    #[test]
    fn specifiers_name_their_packages() {
        assert_eq!(package_of("a@^1").as_deref(), Some("a"));
        assert_eq!(package_of("@s/a@^1").as_deref(), Some("@s/a"));
        assert_eq!(package_of("a@npm:@s/b@1").as_deref(), Some("@s/b"));
        assert_eq!(package_of("a@npm:b").as_deref(), Some("b"));
        assert_eq!(package_of("a@link:../a"), None);
        assert_eq!(package_of("@s"), None);
        assert_eq!(package_of(""), None);
        assert_eq!(package_of("@"), None);
    }

    proptest! {
        #![proptest_config(crate::test_support::proptest_config(256))]

        #[test]
        fn parser_accepts_any_input_without_panicking(
            body in prop_oneof![any::<String>(), "([a-z@/^:.\"0-9, -]|\n  version |\n)*"]
        ) {
            let _ = parse("yarn.lock", &format!("# yarn lockfile v1\n{body}"), Some(&body));
        }
    }
}
