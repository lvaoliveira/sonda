//! `Cargo.lock`: every `[[package]]` with its resolved version. Packages
//! without a `source` are the workspace's own crates; their dependencies
//! are the direct ones.

use super::{Dependency, Ecosystem, Parsed, purl};
use std::collections::HashSet;
use toml::Value;

/// crates.io's index, in its git and sparse forms.
const CRATES_IO: &[&str] = &[
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
];

pub(super) fn parse(path: &str, text: &str) -> Result<Parsed, String> {
    let lock: Value =
        toml::from_str(text).map_err(|e| format!("not valid TOML ({})", e.message()))?;
    let packages = lock
        .get("package")
        .and_then(Value::as_array)
        .ok_or("no [[package]] entries")?;
    let str_of = |p: &Value, key: &str| p.get(key).and_then(Value::as_str).map(str::to_string);

    // `dependencies = ["serde", "rand 0.8.5", ...]`: the name comes first.
    let direct: HashSet<String> = packages
        .iter()
        .filter(|p| p.get("source").is_none())
        .filter_map(|p| p.get("dependencies").and_then(Value::as_array))
        .flatten()
        .filter_map(Value::as_str)
        .filter_map(|d| d.split_whitespace().next())
        .map(str::to_string)
        .collect();

    let mut dependencies = Vec::new();
    let mut elsewhere = 0;
    for p in packages {
        let (Some(name), Some(version), Some(source)) =
            (str_of(p, "name"), str_of(p, "version"), str_of(p, "source"))
        else {
            continue;
        };
        if !CRATES_IO.contains(&source.as_str()) {
            elsewhere += 1;
            continue;
        }
        dependencies.push(Dependency {
            ecosystem: Ecosystem::Cargo,
            purl: purl(Ecosystem::Cargo, None, &name, &version),
            direct: Some(direct.contains(&name)),
            name,
            version,
            source: path.to_string(),
            license: None,
        });
    }
    let notes = (elsewhere > 0)
        .then(|| {
            format!("crates from git or registries other than crates.io: {elsewhere} not listed")
        })
        .into_iter()
        .collect();
    Ok(Parsed {
        dependencies,
        notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK: &str = r#"
version = 4

[[package]]
name = "app"
version = "0.1.0"
dependencies = ["serde", "rand 0.8.5"]

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "00"

[[package]]
name = "rand"
version = "0.8.5"
source = "sparse+https://index.crates.io/"
dependencies = ["libc"]

[[package]]
name = "libc"
version = "0.2.150"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "forked"
version = "0.1.0"
source = "git+https://example.com/forked#abc"
"#;

    #[test]
    fn lists_crates_io_packages_and_marks_workspace_dependencies_direct() {
        let parsed = parse("Cargo.lock", LOCK).unwrap();
        let got: Vec<(&str, Option<bool>)> = parsed
            .dependencies
            .iter()
            .map(|d| (d.name.as_str(), d.direct))
            .collect();
        assert_eq!(
            got,
            [
                ("serde", Some(true)),
                ("rand", Some(true)),
                ("libc", Some(false))
            ]
        );
        assert_eq!(parsed.dependencies[0].purl, "pkg:cargo/serde@1.0.200");
        assert_eq!(
            parsed.notes,
            ["crates from git or registries other than crates.io: 1 not listed"]
        );
    }
}
