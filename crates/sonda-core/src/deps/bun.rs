//! Bun's text lockfile, `bun.lock` (Bun 1.2 and later): JSON with
//! trailing commas. `packages` is keyed by install path (`lodash`,
//! `express/debug` for a nested copy), each value an array whose first
//! element is the package and its resolution (`debug@2.6.9`). `workspaces`
//! lists what each workspace declares. Bun's older binary `bun.lockb`
//! isn't read.

use super::{Dependency, Ecosystem, Parsed, purl};
use serde_json::Value;
use std::collections::HashSet;

const WORKSPACE_DEPENDENCIES: &[&str] = &[
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
];

pub(super) fn parse(path: &str, text: &str) -> Result<Parsed, String> {
    let lock: Value =
        serde_json::from_str(&strict_json(text)).map_err(|e| format!("not valid JSON ({e})"))?;
    match lock["lockfileVersion"].as_u64() {
        Some(0 | 1) => {}
        _ => return Err("unknown lockfileVersion".into()),
    }
    let packages = lock["packages"].as_object().ok_or("no \"packages\" map")?;
    // Top-level installs of what a workspace declares, by install name.
    let declared: HashSet<&str> = lock["workspaces"]
        .as_object()
        .into_iter()
        .flat_map(|w| w.values())
        .flat_map(|workspace| {
            WORKSPACE_DEPENDENCIES
                .iter()
                .filter_map(|field| workspace[*field].as_object())
                .flat_map(|deps| deps.keys().map(String::as_str))
        })
        .collect();

    let mut dependencies = Vec::new();
    let mut skipped = 0;
    for (install_path, entry) in packages {
        let Some((name, version)) = entry[0].as_str().and_then(split_at_version) else {
            skipped += 1;
            continue;
        };
        // Workspaces, local, git and tarball packages aren't registry
        // versions (`workspace:`, `file:`, `github:`, `https://`).
        if version.contains(':') || version.contains('/') {
            if !version.starts_with("workspace:") {
                skipped += 1;
            }
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
            direct: Some(declared.contains(install_path.as_str())),
            source: path.to_string(),
            // bun.lock doesn't record licenses.
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

/// `name@1.0.0` -> (`name`, `1.0.0`); a scope's leading `@` isn't the
/// separator.
fn split_at_version(s: &str) -> Option<(&str, &str)> {
    let at = s.get(1..)?.find('@')? + 1;
    let (name, version) = (&s[..at], &s[at + 1..]);
    (!name.is_empty() && !version.is_empty()).then_some((name, version))
}

/// `text` without the trailing commas and comments JSON doesn't allow, and
/// that Bun's lockfile (JSONC) may have. Strings are kept as they are.
fn strict_json(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    // Skips whitespace and comments from `i`; returns where they end.
    let skip_blank = |mut i: usize| {
        loop {
            match (chars.get(i), chars.get(i + 1)) {
                (Some(c), _) if c.is_whitespace() => i += 1,
                (Some('/'), Some('/')) => {
                    while chars.get(i).is_some_and(|&c| c != '\n') {
                        i += 1;
                    }
                }
                (Some('/'), Some('*')) => {
                    i += 2;
                    while i < chars.len() && !(chars[i] == '*' && chars.get(i + 1) == Some(&'/')) {
                        i += 1;
                    }
                    i = (i + 2).min(chars.len());
                }
                _ => return i,
            }
        }
    };
    while i < chars.len() {
        match chars[i] {
            '"' => {
                // Copy the string, escapes included.
                out.push('"');
                i += 1;
                while i < chars.len() {
                    out.push(chars[i]);
                    if chars[i] == '\\' {
                        if let Some(&c) = chars.get(i + 1) {
                            out.push(c);
                        }
                        i += 2;
                        continue;
                    }
                    i += 1;
                    if chars[i - 1] == '"' {
                        break;
                    }
                }
            }
            ',' if matches!(chars.get(skip_blank(i + 1)), Some('}' | ']')) => i += 1,
            '/' if matches!(chars.get(i + 1), Some('/' | '*')) => i = skip_blank(i),
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const LOCK: &str = r#"{
  "lockfileVersion": 1,
  "workspaces": {
    "": {
      "name": "app",
      "dependencies": {
        "lodash": "^4.17.21",
        "ms-alias": "npm:ms@^2",
      },
      "devDependencies": {
        "@types/node": "^20",
      },
    },
    "packages/web": {
      "name": "web",
      "dependencies": {
        "express": "^4.18.0",
      },
    },
  },
  "packages": {
    "@types/node": ["@types/node@20.1.0", "", {}, "sha512-a"],
    "express": ["express@4.18.2", "", { "dependencies": { "debug": "2.6.9" } }, "sha512-b"],
    "express/debug": ["debug@2.6.9", "", {}, "sha512-c"],
    "debug": ["debug@4.3.4", "", {}, "sha512-d"],
    "lodash": ["lodash@4.17.21", "", {}, "sha512-e"],
    "ms-alias": ["ms@2.1.3", "", {}, "sha512-f"],
    "web": ["web@workspace:packages/web"],
    "local": ["local@file:../local", {}],
    "gitdep": ["gitdep@github:user/repo#abc123", {}, "user-repo-abc123"],
    "note": ["note@1.0.0", "", {}, "sha512-// not a comment, ]"],
  }
}
"#;

    #[test]
    fn reads_packages_and_which_are_direct() {
        let parsed =
            super::super::parse(super::super::FileKind::BunLock, "bun.lock", LOCK, None).unwrap();
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
                ("debug", "4.3.4", Some(false), "pkg:npm/debug@4.3.4"),
                // A workspace's dependency is direct too.
                ("express", "4.18.2", Some(true), "pkg:npm/express@4.18.2"),
                ("lodash", "4.17.21", Some(true), "pkg:npm/lodash@4.17.21"),
                // An alias is the package it installs.
                ("ms", "2.1.3", Some(true), "pkg:npm/ms@2.1.3"),
                ("note", "1.0.0", Some(false), "pkg:npm/note@1.0.0"),
            ]
        );
        assert_eq!(parsed.notes.len(), 1, "local and git, not the workspace");
    }

    #[test]
    fn strict_json_drops_trailing_commas_and_comments_only() {
        assert_eq!(strict_json("{\"a\": [1, 2, ], }"), "{\"a\": [1, 2 ] }");
        assert_eq!(
            strict_json("{\"a\": \"x, ] // y\", /* c */ \"b\": 1 // d\n}"),
            "{\"a\": \"x, ] // y\", \"b\": 1 }"
        );
        assert_eq!(strict_json(r#"["a\",", ]"#), r#"["a\"," ]"#);
        assert!(parse("bun.lock", "{\"lockfileVersion\": 9, \"packages\": {}}").is_err());
        assert!(parse("bun.lock", "{").is_err());
    }

    proptest! {
        #![proptest_config(crate::test_support::proptest_config(256))]

        #[test]
        fn parser_accepts_any_input_without_panicking(
            text in prop_oneof![any::<String>(), "([\\[\\]{}\",:/*@a-z0-9 \\\\]|\n)*"]
        ) {
            let _ = strict_json(&text);
            let _ = parse("bun.lock", &text);
        }
    }
}
