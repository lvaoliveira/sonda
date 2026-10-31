//! Domain: a project's third-party dependencies, read from its lockfiles
//! (ADR-0009). Pure: the scanner finds and reads the files.
//!
//! Lockfiles come from the analyzed repository, so they are untrusted: the
//! parsers only read data, never run a package manager, and turn anything
//! unexpected into a warning.

mod bun;
mod cargo;
mod npm;
mod pnpm;
mod python;
mod yaml;
mod yarn;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Npm,
    Cargo,
    Pypi,
}

impl Ecosystem {
    pub const ALL: [Ecosystem; 3] = [Ecosystem::Npm, Ecosystem::Cargo, Ecosystem::Pypi];

    pub fn as_str(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Cargo => "cargo",
            Ecosystem::Pypi => "pypi",
        }
    }

    /// The ecosystem `as_str` names.
    pub fn parse(s: &str) -> Option<Ecosystem> {
        Ecosystem::ALL.into_iter().find(|e| e.as_str() == s)
    }
}

/// The name packages are matched by: PEP 503's normalized form for PyPI
/// (`Flask_Login` → `flask-login`), as written elsewhere.
pub fn package_key(ecosystem: Ecosystem, name: &str) -> String {
    match ecosystem {
        Ecosystem::Pypi => python::normalize(name),
        Ecosystem::Npm | Ecosystem::Cargo => name.to_string(),
    }
}

/// One package at one version, as a lockfile pins it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Dependency {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    /// Package URL, the identifier SBOM formats and advisories share.
    pub purl: String,
    /// Whether the project itself declares it; `None` when the lockfile
    /// doesn't say.
    pub direct: Option<bool>,
    /// The lockfile, relative to the project root.
    pub source: String,
    /// As the lockfile records it, usually an SPDX expression.
    pub license: Option<String>,
}

/// Files the scanner hands to this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum FileKind {
    PackageLock,
    CargoLock,
    PoetryLock,
    UvLock,
    Requirements,
    /// `pyproject.toml`: tells which of `poetry.lock`'s packages are direct.
    PyProject,
    /// `pnpm-lock.yaml`.
    PnpmLock,
    /// Bun's text `bun.lock`.
    BunLock,
    /// pipenv's `Pipfile.lock`.
    PipfileLock,
    /// `Pipfile`: tells which of `Pipfile.lock`'s packages are direct.
    Pipfile,
    /// `yarn.lock`: Yarn v1's own format, or Yarn 2+'s YAML.
    YarnLock,
    /// `package.json`: tells which of `yarn.lock`'s packages are direct.
    PackageJson,
    /// A lockfile sonda recognizes but doesn't read yet (ADR-0009's later
    /// phases), reported so an SBOM's gap isn't silent.
    Unsupported,
}

pub(crate) fn file_kind(file_name: &str) -> Option<FileKind> {
    Some(match file_name {
        "package-lock.json" | "npm-shrinkwrap.json" => FileKind::PackageLock,
        "Cargo.lock" => FileKind::CargoLock,
        "poetry.lock" => FileKind::PoetryLock,
        "uv.lock" => FileKind::UvLock,
        "pyproject.toml" => FileKind::PyProject,
        "yarn.lock" => FileKind::YarnLock,
        "pnpm-lock.yaml" => FileKind::PnpmLock,
        "bun.lock" => FileKind::BunLock,
        "Pipfile.lock" => FileKind::PipfileLock,
        "Pipfile" => FileKind::Pipfile,
        "package.json" => FileKind::PackageJson,
        n if n.starts_with("requirements") && n.ends_with(".txt") => FileKind::Requirements,
        "bun.lockb" | "go.sum" | "gradle.lockfile" | "composer.lock" | "Gemfile.lock" => {
            FileKind::Unsupported
        }
        _ => return None,
    })
}

/// The manifest a lockfile of `kind` reads next to it, to tell which of
/// its packages are direct.
pub(crate) fn manifest_for(kind: FileKind) -> Option<FileKind> {
    match kind {
        FileKind::PoetryLock => Some(FileKind::PyProject),
        FileKind::YarnLock => Some(FileKind::PackageJson),
        FileKind::PipfileLock => Some(FileKind::Pipfile),
        _ => None,
    }
}

/// Manifests aren't lockfiles: they're read only next to the lockfile that
/// needs them.
pub(crate) fn is_manifest(kind: FileKind) -> bool {
    matches!(
        kind,
        FileKind::PyProject | FileKind::PackageJson | FileKind::Pipfile
    )
}

/// A parsed lockfile: its dependencies and notes about what it left out.
#[derive(Debug)]
pub(crate) struct Parsed {
    pub(crate) dependencies: Vec<Dependency>,
    pub(crate) notes: Vec<String>,
}

/// Parses the lockfile at `path` (root-relative). `manifest` is the one
/// `manifest_for` names next to it, if any. An error is a warning's text.
pub(crate) fn parse(
    kind: FileKind,
    path: &str,
    text: &str,
    manifest: Option<&str>,
) -> Result<Parsed, String> {
    let mut parsed = match kind {
        FileKind::PackageLock => npm::parse(path, text)?,
        FileKind::CargoLock => cargo::parse(path, text)?,
        FileKind::PoetryLock => python::poetry(path, text, manifest)?,
        FileKind::UvLock => python::uv(path, text)?,
        FileKind::Requirements => python::requirements(path, text),
        FileKind::YarnLock => yarn::parse(path, text, manifest)?,
        FileKind::PnpmLock => pnpm::parse(path, text)?,
        FileKind::BunLock => bun::parse(path, text)?,
        FileKind::PipfileLock => python::pipenv(path, text, manifest)?,
        FileKind::PyProject | FileKind::PackageJson | FileKind::Pipfile => {
            return Ok(Parsed {
                dependencies: Vec::new(),
                notes: Vec::new(),
            });
        }
        // Bun's binary lockfile has a text equivalent sonda reads.
        FileKind::Unsupported if path.ends_with("bun.lockb") => {
            return Err("not read: Bun's binary lockfile isn't; `bun install \
                        --save-text-lockfile` writes bun.lock, which is"
                .into());
        }
        FileKind::Unsupported => {
            return Err(
                "not read: sonda reads package-lock.json, yarn.lock, pnpm-lock.yaml, \
                        bun.lock, Cargo.lock, poetry.lock, uv.lock, Pipfile.lock and \
                        requirements*.txt so far"
                    .into(),
            );
        }
    };
    parsed.dependencies = dedup(parsed.dependencies);
    Ok(parsed)
}

/// One entry per package and version in a lockfile (npm can install the same
/// version at several paths); direct if any of them is.
fn dedup(deps: Vec<Dependency>) -> Vec<Dependency> {
    let mut by_key: BTreeMap<(Ecosystem, String, String), Dependency> = BTreeMap::new();
    for d in deps {
        let key = (d.ecosystem, d.name.clone(), d.version.clone());
        match by_key.get_mut(&key) {
            Some(existing) => {
                existing.direct = match (existing.direct, d.direct) {
                    (Some(a), Some(b)) => Some(a || b),
                    (a, b) => a.or(b),
                };
                if existing.license.is_none() {
                    existing.license = d.license;
                }
            }
            None => {
                by_key.insert(key, d);
            }
        }
    }
    by_key.into_values().collect()
}

/// `pkg:type/namespace/name@version`, percent-encoding each part.
pub(crate) fn purl(
    ecosystem: Ecosystem,
    namespace: Option<&str>,
    name: &str,
    version: &str,
) -> String {
    let mut s = format!("pkg:{}/", ecosystem.as_str());
    if let Some(ns) = namespace {
        s.push_str(&encode(ns));
        s.push('/');
    }
    s.push_str(&encode(name));
    s.push('@');
    s.push_str(&encode(version));
    s
}

fn encode(part: &str) -> String {
    let mut out = String::with_capacity(part.len());
    for b in part.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_lockfiles_by_name() {
        assert_eq!(file_kind("package-lock.json"), Some(FileKind::PackageLock));
        assert_eq!(
            file_kind("requirements-dev.txt"),
            Some(FileKind::Requirements)
        );
        assert_eq!(file_kind("Cargo.toml"), None);
        assert_eq!(file_kind("yarn.lock"), Some(FileKind::YarnLock));
        assert_eq!(file_kind("package.json"), Some(FileKind::PackageJson));
        assert_eq!(file_kind("pnpm-lock.yaml"), Some(FileKind::PnpmLock));
        assert_eq!(file_kind("bun.lockb"), Some(FileKind::Unsupported));
        assert_eq!(file_kind("bun.lock"), Some(FileKind::BunLock));
        assert_eq!(file_kind("Pipfile.lock"), Some(FileKind::PipfileLock));
        assert_eq!(file_kind("Pipfile"), Some(FileKind::Pipfile));
        assert!(
            parse(FileKind::Unsupported, "app/bun.lockb", "", None)
                .unwrap_err()
                .contains("--save-text-lockfile")
        );
    }

    #[test]
    fn purls_are_percent_encoded() {
        assert_eq!(
            purl(Ecosystem::Npm, Some("@babel"), "core", "7.0.0"),
            "pkg:npm/%40babel/core@7.0.0"
        );
        assert_eq!(
            purl(Ecosystem::Pypi, None, "a b", "1.0+local"),
            "pkg:pypi/a%20b@1.0%2Blocal"
        );
    }
}
