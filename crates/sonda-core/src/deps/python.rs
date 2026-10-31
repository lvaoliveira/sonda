//! Python: `poetry.lock` (with `pyproject.toml` for which packages are
//! direct), `uv.lock`, pipenv's `Pipfile.lock` (with its `Pipfile`), and
//! pinned `requirements*.txt`.

use super::{Dependency, Ecosystem, Parsed, purl};
use std::collections::HashSet;
use toml::Value;

fn toml(text: &str) -> Result<Value, String> {
    toml::from_str(text).map_err(|e| format!("not valid TOML ({})", e.message()))
}

/// PEP 503's normalized name, which purls for PyPI also use: lowercase,
/// runs of `-`, `_` and `.` as one `-`.
pub(super) fn normalize(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !out.ends_with('-') {
                out.push('-');
            }
        } else {
            out.push(c.to_ascii_lowercase());
        }
    }
    out
}

/// The name a PEP 508 requirement starts with (`requests[socks]>=2` →
/// `requests`).
fn requirement_name(req: &str) -> Option<&str> {
    let req = req.trim_start();
    let end = req
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
        .unwrap_or(req.len());
    (end > 0).then(|| &req[..end])
}

fn dependency(path: &str, name: &str, version: &str, direct: Option<bool>) -> Dependency {
    Dependency {
        ecosystem: Ecosystem::Pypi,
        name: name.to_string(),
        version: version.to_string(),
        purl: purl(Ecosystem::Pypi, None, &normalize(name), version),
        direct,
        source: path.to_string(),
        license: None,
    }
}

fn skipped_note(count: usize, what: &str) -> Vec<String> {
    (count > 0)
        .then(|| format!("{what}: {count} not listed"))
        .into_iter()
        .collect()
}

pub(super) fn poetry(path: &str, text: &str, manifest: Option<&str>) -> Result<Parsed, String> {
    let lock = toml(text)?;
    let packages = lock
        .get("package")
        .and_then(Value::as_array)
        .ok_or("no [[package]] entries")?;
    let direct = manifest
        .and_then(|m| toml(m).ok())
        .map(|m| direct_names(&m));
    let mut dependencies = Vec::new();
    let mut elsewhere = 0;
    for p in packages {
        let (Some(name), Some(version)) = (
            p.get("name").and_then(Value::as_str),
            p.get("version").and_then(Value::as_str),
        ) else {
            continue;
        };
        // Git, path and URL packages aren't on an index; `legacy` (a
        // private index) still serves PyPI-style packages.
        let source = p
            .get("source")
            .and_then(|s| s.get("type"))
            .and_then(Value::as_str);
        if source.is_some_and(|s| s != "legacy") {
            elsewhere += 1;
            continue;
        }
        let is_direct = direct.as_ref().map(|d| d.contains(&normalize(name)));
        dependencies.push(dependency(path, name, version, is_direct));
    }
    Ok(Parsed {
        dependencies,
        notes: skipped_note(elsewhere, "packages from git, a path or a URL"),
    })
}

/// Normalized names a `pyproject.toml` declares, in PEP 621 or Poetry form.
fn direct_names(manifest: &Value) -> HashSet<String> {
    let mut names = HashSet::new();
    let pep621 = manifest.get("project");
    let strings = pep621
        .and_then(|p| p.get("dependencies"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .chain(
            pep621
                .and_then(|p| p.get("optional-dependencies"))
                .and_then(Value::as_table)
                .into_iter()
                .flat_map(|t| t.values())
                .filter_map(Value::as_array)
                .flatten(),
        )
        .chain(
            manifest
                .get("dependency-groups")
                .and_then(Value::as_table)
                .into_iter()
                .flat_map(|t| t.values())
                .filter_map(Value::as_array)
                .flatten(),
        );
    names.extend(
        strings
            .filter_map(Value::as_str)
            .filter_map(requirement_name)
            .map(normalize),
    );
    let poetry = manifest.get("tool").and_then(|t| t.get("poetry"));
    let tables = poetry
        .and_then(|p| p.get("dependencies"))
        .into_iter()
        .chain(poetry.and_then(|p| p.get("dev-dependencies")))
        .chain(
            poetry
                .and_then(|p| p.get("group"))
                .and_then(Value::as_table)
                .into_iter()
                .flat_map(|g| g.values())
                .filter_map(|g| g.get("dependencies")),
        );
    for table in tables.filter_map(Value::as_table) {
        names.extend(
            table
                .keys()
                .filter(|k| *k != "python")
                .map(|k| normalize(k)),
        );
    }
    names
}

/// pipenv's `Pipfile.lock` (JSON): the `default` and `develop` packages,
/// pinned `==version`. `manifest` is the `Pipfile` next to it: its
/// `[packages]` and `[dev-packages]` are the direct ones.
pub(super) fn pipenv(path: &str, text: &str, manifest: Option<&str>) -> Result<Parsed, String> {
    let lock: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("not valid JSON ({e})"))?;
    if !lock["_meta"].is_object() {
        return Err("not a Pipfile.lock (no \"_meta\")".into());
    }
    let direct: Option<HashSet<String>> = manifest.and_then(|m| toml(m).ok()).map(|pipfile| {
        ["packages", "dev-packages"]
            .iter()
            .filter_map(|section| pipfile.get(section).and_then(Value::as_table))
            .flat_map(|table| table.keys().map(|k| normalize(k)))
            .collect()
    });
    let mut dependencies = Vec::new();
    let mut unpinned = 0;
    for section in ["default", "develop"] {
        for (name, entry) in lock[section].as_object().into_iter().flatten() {
            let version = entry["version"].as_str().and_then(|v| {
                v.strip_prefix("===")
                    .or_else(|| v.strip_prefix("=="))
                    .filter(|v| !v.is_empty())
            });
            match version {
                Some(v) => dependencies.push(dependency(
                    path,
                    name,
                    v,
                    direct.as_ref().map(|d| d.contains(&normalize(name))),
                )),
                // git, path and editable packages have no pinned version.
                None => unpinned += 1,
            }
        }
    }
    Ok(Parsed {
        dependencies,
        notes: skipped_note(unpinned, "git, path or editable packages"),
    })
}

pub(super) fn uv(path: &str, text: &str) -> Result<Parsed, String> {
    let lock = toml(text)?;
    let packages = lock
        .get("package")
        .and_then(Value::as_array)
        .ok_or("no [[package]] entries")?;
    let source_kind = |p: &Value| {
        p.get("source")
            .and_then(Value::as_table)
            .and_then(|s| s.keys().next().cloned())
    };
    // The project and its workspace members are `editable` or `virtual`;
    // what they depend on is direct.
    let member = |p: &&Value| matches!(source_kind(p).as_deref(), Some("editable" | "virtual"));
    let names_in = |v: Option<&Value>| -> Vec<String> {
        v.and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|d| d.get("name").and_then(Value::as_str))
            .map(normalize)
            .collect()
    };
    let mut direct = HashSet::new();
    for p in packages.iter().filter(member) {
        direct.extend(names_in(p.get("dependencies")));
        for table in ["optional-dependencies", "dev-dependencies"] {
            for group in p
                .get(table)
                .and_then(Value::as_table)
                .into_iter()
                .flat_map(|t| t.values())
            {
                direct.extend(names_in(Some(group)));
            }
        }
    }

    let mut dependencies = Vec::new();
    let mut elsewhere = 0;
    for p in packages {
        if member(&p) {
            continue;
        }
        let (Some(name), Some(version)) = (
            p.get("name").and_then(Value::as_str),
            p.get("version").and_then(Value::as_str),
        ) else {
            continue;
        };
        if source_kind(p).as_deref() != Some("registry") {
            elsewhere += 1;
            continue;
        }
        let is_direct = direct.contains(&normalize(name));
        dependencies.push(dependency(path, name, version, Some(is_direct)));
    }
    Ok(Parsed {
        dependencies,
        notes: skipped_note(elsewhere, "packages from git, a path or a URL"),
    })
}

/// Pinned lines only (`name==version`, extras and markers allowed).
/// Anything else (ranges, URLs, `-r` includes, options) is not a pin.
pub(super) fn requirements(path: &str, text: &str) -> Parsed {
    let mut dependencies = Vec::new();
    let mut unpinned = 0;
    // Backslash continuations (as pip-compile writes for hashes) join lines.
    let joined = text.replace("\\\r\n", " ").replace("\\\n", " ");
    for line in joined.lines() {
        let line = line.split(" #").next().unwrap_or_default().trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }
        let requirement = line.split(';').next().unwrap_or_default();
        let requirement = requirement.split(" --").next().unwrap_or_default().trim();
        let pinned = requirement
            .split_once("===")
            .or_else(|| requirement.split_once("=="))
            .and_then(|(name_part, version)| {
                let name = requirement_name(name_part)?;
                let rest = name_part[name_part.find(name)? + name.len()..].trim();
                let version = version.trim();
                let plain_version = !version.is_empty()
                    && !version.contains(['*', ',', ' ', '<', '>', '!', '='])
                    && (rest.is_empty() || (rest.starts_with('[') && rest.ends_with(']')));
                plain_version.then_some((name, version))
            });
        match pinned {
            Some((name, version)) => dependencies.push(dependency(path, name, version, None)),
            None => unpinned += 1,
        }
    }
    Parsed {
        dependencies,
        notes: skipped_note(unpinned, "requirements without an exact `==` version"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_pipfile_lock() {
        let lock = r#"{
          "_meta": {"hash": {"sha256": "x"}, "pipfile-spec": 6, "requires": {"python_version": "3.12"}},
          "default": {
            "requests": {"hashes": ["sha256:a"], "index": "pypi", "version": "==2.31.0"},
            "Urllib3": {"version": "==2.0.7", "markers": "python_version >= '3.7'"},
            "mylib": {"editable": true, "path": "."},
            "gitdep": {"git": "https://github.com/x/y.git", "ref": "abc"}
          },
          "develop": {
            "pytest": {"version": "==7.4.0"}
          }
        }"#;
        let pipfile = "[packages]\nrequests = \"*\"\n\n[dev-packages]\nPyTest = \"*\"\n";
        let parsed = pipenv("Pipfile.lock", lock, Some(pipfile)).unwrap();
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
                ("Urllib3", "2.0.7", Some(false), "pkg:pypi/urllib3@2.0.7"),
                ("requests", "2.31.0", Some(true), "pkg:pypi/requests@2.31.0"),
                ("pytest", "7.4.0", Some(true), "pkg:pypi/pytest@7.4.0"),
            ]
        );
        assert_eq!(
            parsed.notes,
            ["git, path or editable packages: 2 not listed"]
        );
        // Without the Pipfile, nothing says what's direct.
        assert!(
            pipenv("p", lock, None)
                .unwrap()
                .dependencies
                .iter()
                .all(|d| d.direct.is_none())
        );
        assert!(pipenv("p", "{}", None).is_err());
        assert!(pipenv("p", "{", None).is_err());
    }

    fn names(p: &Parsed) -> Vec<(&str, &str, Option<bool>)> {
        p.dependencies
            .iter()
            .map(|d| (d.name.as_str(), d.version.as_str(), d.direct))
            .collect()
    }

    #[test]
    fn poetry_uses_pyproject_for_direct_dependencies() {
        let lock = r#"
[[package]]
name = "Requests"
version = "2.31.0"

[[package]]
name = "urllib3"
version = "2.0.7"

[[package]]
name = "pytest"
version = "8.0.0"

[[package]]
name = "mylib"
version = "0.1.0"
[package.source]
type = "git"
url = "https://example.com/mylib.git"
"#;
        let manifest = r#"
[tool.poetry.dependencies]
python = "^3.11"
requests = "^2.31"
[tool.poetry.group.dev.dependencies]
pytest = "^8"
"#;
        let p = poetry("poetry.lock", lock, Some(manifest)).unwrap();
        assert_eq!(
            names(&p),
            [
                ("Requests", "2.31.0", Some(true)),
                ("urllib3", "2.0.7", Some(false)),
                ("pytest", "8.0.0", Some(true)),
            ]
        );
        assert_eq!(p.dependencies[0].purl, "pkg:pypi/requests@2.31.0");
        assert_eq!(
            p.notes,
            ["packages from git, a path or a URL: 1 not listed"]
        );
        // Without a pyproject.toml, directness is unknown.
        assert_eq!(
            poetry("poetry.lock", lock, None).unwrap().dependencies[0].direct,
            None
        );
    }

    #[test]
    fn pep621_names_are_normalized() {
        let manifest: Value = toml::from_str(
            "[project]\ndependencies = [\"Flask_Login>=0.6\", \"requests[socks] ; python_version > '3'\"]\n\
             [project.optional-dependencies]\ntest = [\"pytest\"]\n",
        )
        .unwrap();
        let mut got: Vec<String> = direct_names(&manifest).into_iter().collect();
        got.sort();
        assert_eq!(got, ["flask-login", "pytest", "requests"]);
    }

    #[test]
    fn uv_lists_registry_packages_and_its_project_s_dependencies_as_direct() {
        let lock = r#"
version = 1

[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "httpx" }]
[package.dev-dependencies]
dev = [{ name = "ruff" }]

[[package]]
name = "httpx"
version = "0.27.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "idna" }]

[[package]]
name = "idna"
version = "3.7"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "ruff"
version = "0.4.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "vendored"
version = "1.0"
source = { path = "vendor/vendored" }
"#;
        let p = uv("uv.lock", lock).unwrap();
        assert_eq!(
            names(&p),
            [
                ("httpx", "0.27.0", Some(true)),
                ("idna", "3.7", Some(false)),
                ("ruff", "0.4.0", Some(true)),
            ]
        );
        assert_eq!(p.notes.len(), 1);
    }

    #[test]
    fn requirements_keep_exact_pins_only() {
        let text = "# pinned\nDjango==4.2.7\nrequests[socks]==2.31.0 ; python_version >= \"3.8\"\n\
                    numpy>=1.26\n-r base.txt\n--index-url https://example.com\n\
                    cryptography==41.0.5 \\\n    --hash=sha256:00\nflask\nweird==1.*\n";
        let p = requirements("requirements.txt", text);
        assert_eq!(
            names(&p),
            [
                ("Django", "4.2.7", None),
                ("requests", "2.31.0", None),
                ("cryptography", "41.0.5", None),
            ]
        );
        assert_eq!(
            p.notes,
            ["requirements without an exact `==` version: 3 not listed"]
        );
    }
}
