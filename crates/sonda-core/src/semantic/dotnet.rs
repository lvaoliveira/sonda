//! The .NET platform's public declarations (ADR-0022): the types and
//! members the reference packs in `data/` declare, extracted by
//! `tools/netref`. Embedded in the binary, since workers never open files
//! (ADR-0004), and decoded once, on first use.
//!
//! Type keys follow the project index's naming (`semantic/cs_index.rs`):
//! namespace, enclosing types without their arity, then the type with its
//! own (`System.Collections.Generic.List`1`). Type references in signatures
//! add arguments in angle brackets, `[]` for arrays, and `!0` / `!!0` for
//! type and method parameters.

use serde::Deserialize;
use std::collections::HashMap;
use std::io::Read;
use std::sync::OnceLock;

/// Deflated JSON, written by `tools/netref`.
const DATA: &[u8] = include_bytes!("../../data/dotnet-8.0.json.z");

#[derive(Deserialize)]
struct Summary {
    types: Vec<PlatformType>,
}

/// A public type of the platform.
#[derive(Deserialize, Debug)]
pub(crate) struct PlatformType {
    #[serde(rename = "n")]
    pub(crate) name: String,
    /// "class", "struct", "interface", "enum" or "delegate".
    #[serde(rename = "k")]
    pub(crate) kind: String,
    #[serde(rename = "b", default)]
    pub(crate) base: Option<String>,
    /// The interfaces it declares, not those its bases do.
    #[serde(rename = "i", default)]
    pub(crate) interfaces: Vec<String>,
    /// "abstract", "sealed", "static", "Flags", "Obsolete".
    #[serde(rename = "a", default)]
    pub(crate) tags: Vec<String>,
    #[serde(rename = "m", default)]
    pub(crate) members: Vec<PlatformMember>,
}

/// A public or protected member of a platform type.
#[derive(Deserialize, Debug)]
pub(crate) struct PlatformMember {
    /// "method", "constructor", "operator", "property", "field", "event".
    #[serde(rename = "k")]
    pub(crate) kind: String,
    #[serde(rename = "n", default)]
    pub(crate) name: String,
    /// The return, property, field or event type.
    #[serde(rename = "t", default)]
    pub(crate) ty: String,
    #[serde(rename = "p", default)]
    pub(crate) params: Vec<PlatformParam>,
    /// The method's own type parameters.
    #[serde(rename = "g", default)]
    pub(crate) generic: u32,
    /// "static", "protected", "virtual", "abstract", "const", "readonly",
    /// "get", "set", "init", "Extension", "Obsolete", and "ns20" when
    /// .NET Standard 2.0 has it too, so every target framework does.
    #[serde(rename = "a", default)]
    pub(crate) tags: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub(crate) struct PlatformParam {
    #[serde(rename = "t")]
    pub(crate) ty: String,
    #[serde(rename = "n", default)]
    #[expect(dead_code, reason = "read by argument-order checks, ADR-0022 step 3")]
    pub(crate) name: String,
    /// "ref", "out", "in", "params", "optional", and `StringSyntax` values
    /// such as "syntax:Regex".
    #[serde(rename = "a", default)]
    pub(crate) tags: Vec<String>,
}

impl PlatformType {
    pub(crate) fn has(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t == tag)
    }
}

impl PlatformMember {
    pub(crate) fn has(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t == tag)
    }
}

/// The platform's types by key.
pub(crate) struct Platform {
    types: HashMap<String, PlatformType>,
    /// The namespaces its types are in, and their enclosing ones.
    namespaces: std::collections::HashSet<String>,
    /// Extension methods by name: (declaring type's key, its index among
    /// that type's members).
    extensions: HashMap<String, Vec<(String, usize)>>,
}

/// The platform, decoded on first use. Empty if the embedded data can't be
/// read, which a test rules out.
pub(crate) fn platform() -> &'static Platform {
    static PLATFORM: OnceLock<Platform> = OnceLock::new();
    PLATFORM.get_or_init(|| {
        Platform::decode(DATA).unwrap_or_else(|| Platform {
            types: HashMap::new(),
            namespaces: std::collections::HashSet::new(),
            extensions: HashMap::new(),
        })
    })
}

impl Platform {
    fn decode(data: &[u8]) -> Option<Platform> {
        let mut json = Vec::new();
        flate2::read::DeflateDecoder::new(data)
            .read_to_end(&mut json)
            .ok()?;
        let summary: Summary = serde_json::from_slice(&json).ok()?;
        let mut namespaces = std::collections::HashSet::new();
        for t in &summary.types {
            let mut ns = t.name.as_str();
            while let Some((outer, _)) = ns.rsplit_once('.') {
                namespaces.insert(outer.to_string());
                ns = outer;
            }
        }
        let mut extensions: HashMap<String, Vec<(String, usize)>> = HashMap::new();
        for t in summary.types.iter().filter(|t| t.has("Extension")) {
            for (i, m) in t.members.iter().enumerate() {
                if m.kind == "method" && m.has("Extension") {
                    extensions
                        .entry(m.name.clone())
                        .or_default()
                        .push((t.name.clone(), i));
                }
            }
        }
        Some(Platform {
            extensions,
            types: summary
                .types
                .into_iter()
                .map(|t| (t.name.clone(), t))
                .collect(),
            namespaces,
        })
    }

    /// The extension methods named `name`, with the type declaring each.
    pub(crate) fn extensions(&self, name: &str) -> Vec<(&PlatformType, &PlatformMember)> {
        self.extensions
            .get(name)
            .into_iter()
            .flatten()
            .filter_map(|(key, i)| {
                let t = self.types.get(key)?;
                Some((t, t.members.get(*i)?))
            })
            .collect()
    }

    /// Whether the platform declares types in this namespace.
    pub(crate) fn has_namespace(&self, namespace: &str) -> bool {
        self.namespaces.contains(namespace)
    }

    /// The type with this key, written with or without its arity when it has
    /// none: `System.IO.Stream` or `System.IO.Stream`0`.
    pub(crate) fn get(&self, key: &str) -> Option<&PlatformType> {
        self.types
            .get(key)
            .or_else(|| self.types.get(key.strip_suffix("`0")?))
    }

    /// A type and its base classes, nearest first, by key; generic
    /// arguments are dropped (`Collection`1<!0>` is `Collection`1`).
    pub(crate) fn base_chain(&self, key: &str) -> Vec<&PlatformType> {
        let mut chain = Vec::new();
        let mut current = self.get(key);
        while let Some(t) = current {
            if chain.len() > 64 {
                break;
            }
            chain.push(t);
            current = t.base.as_deref().and_then(|b| self.get(definition(b)));
        }
        chain
    }

    /// Whether the type implements an interface, through its bases and the
    /// interfaces those extend.
    pub(crate) fn implements(&self, key: &str, interface: &str) -> bool {
        let mut todo: Vec<&str> = vec![key];
        let mut seen: Vec<&str> = Vec::new();
        while let Some(k) = todo.pop() {
            let k = definition(k);
            if k == interface {
                return true;
            }
            if seen.contains(&k) || seen.len() > 256 {
                continue;
            }
            seen.push(k);
            if let Some(t) = self.get(k) {
                todo.extend(t.base.as_deref());
                todo.extend(t.interfaces.iter().map(String::as_str));
            }
        }
        false
    }
}

/// A type reference without its generic arguments, the key of its
/// definition: `System.Collections.Generic.List`1<!0>` is `...List`1`.
pub(crate) fn definition(reference: &str) -> &str {
    reference.split('<').next().unwrap_or(reference)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "timing, run with --release --ignored"]
    fn decoding_is_fast() {
        let start = std::time::Instant::now();
        let p = Platform::decode(DATA).unwrap();
        let took = start.elapsed();
        assert!(p.types.len() > 5000);
        assert!(took.as_millis() < 50, "{took:?}");
    }

    #[test]
    fn embedded_data_decodes() {
        let p = platform();
        assert!(p.types.len() > 5000, "{} types", p.types.len());
        let stream = p.get("System.IO.FileStream").unwrap();
        assert_eq!(stream.kind, "class");
        assert!(p.implements("System.IO.FileStream", "System.IDisposable"));
        assert!(p.implements(
            "System.Collections.Generic.List`1",
            "System.Collections.Generic.IEnumerable`1"
        ));
        assert!(!p.implements("System.String", "System.IDisposable"));
        let chain: Vec<&str> = p
            .base_chain("Microsoft.AspNetCore.Mvc.Controller")
            .iter()
            .map(|t| t.name.as_str())
            .collect();
        assert_eq!(
            chain,
            [
                "Microsoft.AspNetCore.Mvc.Controller",
                "Microsoft.AspNetCore.Mvc.ControllerBase",
                "System.Object"
            ]
        );
        assert!(p.has_namespace("System.Collections.Generic"));
        assert!(p.get("System.Environment.SpecialFolder").is_some());
    }
}
