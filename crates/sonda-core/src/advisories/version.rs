//! Version ordering per ecosystem: SemVer 2.0 for npm and crates.io, PEP 440
//! for PyPI. A version that doesn't parse compares as `None`, never as a
//! guess.

use crate::deps::Ecosystem;
use std::cmp::Ordering;

/// Orders two versions of a package in `ecosystem`; `None` when either
/// doesn't parse.
pub fn compare(ecosystem: Ecosystem, a: &str, b: &str) -> Option<Ordering> {
    match ecosystem {
        Ecosystem::Npm | Ecosystem::Cargo => Some(SemVer::parse(a)?.cmp(&SemVer::parse(b)?)),
        Ecosystem::Pypi => Some(Pep440::parse(a)?.cmp(&Pep440::parse(b)?)),
    }
}

// ------------------------------------------------------------------ SemVer

#[derive(Debug, PartialEq, Eq)]
struct SemVer {
    release: [u64; 3],
    /// Empty for a release, which sorts after its pre-releases.
    pre: Vec<Identifier>,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Identifier {
    // Numeric identifiers sort before alphanumeric ones.
    Numeric(u64),
    Alpha(String),
}

impl SemVer {
    /// `1.2.3`, `1.2.3-rc.1`, `1.2.3+build` (build metadata is ignored, as
    /// SemVer says), with an optional leading `v`. Advisories sometimes
    /// shorten a version (`1.90`); missing parts are 0, as OSV's own tools
    /// read them.
    fn parse(s: &str) -> Option<SemVer> {
        let s = s.trim();
        let s = s.strip_prefix('v').unwrap_or(s);
        let s = s.split_once('+').map_or(s, |(v, _)| v);
        let (core, pre) = match s.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (s, None),
        };
        let parts: Vec<&str> = core.split('.').collect();
        if parts.len() > 3 {
            return None;
        }
        let mut release = [0; 3];
        for (slot, part) in release.iter_mut().zip(&parts) {
            *slot = number(part)?;
        }
        let pre = match pre {
            None => Vec::new(),
            Some(pre) => pre
                .split('.')
                .map(|id| {
                    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                        None
                    } else if id.chars().all(|c| c.is_ascii_digit()) {
                        number(id).map(Identifier::Numeric)
                    } else {
                        Some(Identifier::Alpha(id.to_string()))
                    }
                })
                .collect::<Option<_>>()?,
        };
        Some(SemVer { release, pre })
    }
}

/// Digits only, without the sign or whitespace `str::parse` would accept.
fn number(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

impl Ord for SemVer {
    fn cmp(&self, other: &Self) -> Ordering {
        self.release.cmp(&other.release).then_with(|| {
            match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                // Field by field; a longer list wins a tie.
                (false, false) => self.pre.cmp(&other.pre),
            }
        })
    }
}

impl PartialOrd for SemVer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// ----------------------------------------------------------------- PEP 440

/// A PEP 440 version as its sort key: epoch, release (trailing zeros
/// dropped, so 1.0 == 1.0.0), pre-, post- and dev-release, local label.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Pep440 {
    epoch: u64,
    release: Vec<u64>,
    pre: Pre,
    post: Option<u64>,
    dev: Dev,
    local: Vec<LocalSegment>,
}

/// Unlike SemVer's identifiers, PEP 440's local segments put letters first.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum LocalSegment {
    Alpha(String),
    Numeric(u64),
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Pre {
    /// `1.0.dev1`: a dev release of the final version sorts before all of
    /// its pre-releases.
    DevOnly,
    /// a, b, rc as 0, 1, 2.
    Phase(u8, u64),
    Final,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Dev {
    Dev(u64),
    None,
}

impl Pep440 {
    fn parse(s: &str) -> Option<Pep440> {
        let s = s.trim().to_ascii_lowercase();
        let s = s.strip_prefix('v').unwrap_or(&s);
        let (s, local) = match s.split_once('+') {
            Some((v, local)) => (v, Some(local)),
            None => (s, None),
        };
        let (epoch, rest) = match s.split_once('!') {
            Some((e, rest)) => (number(e)?, rest),
            None => (0, s),
        };
        // The release: digits and dots, up to the first letter or separator.
        let end = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(rest.len());
        let (release_text, mut tail) = rest.split_at(end);
        let release_text = release_text.trim_end_matches('.');
        if end < rest.len() && rest[..end].ends_with('.') {
            // `1.0.post1`, `1.0.dev1`: the dot belongs to the suffix.
            tail = &rest[end - 1..];
        }
        let mut release: Vec<u64> = release_text.split('.').map(number).collect::<Option<_>>()?;
        while release.len() > 1 && release.last() == Some(&0) {
            release.pop();
        }

        let mut pre = None;
        let mut post = None;
        let mut dev = None;
        while !tail.is_empty() {
            // `1.0-1`: a dash and a number alone are a post-release.
            let implicit_post = tail
                .strip_prefix('-')
                .filter(|r| r.starts_with(|c: char| c.is_ascii_digit()));
            let t = tail.trim_start_matches(['.', '-', '_']);
            let (kind, after) = match implicit_post {
                Some(rest) => (Suffix::Post, rest),
                None => suffix_kind(t)?,
            };
            let after = after.trim_start_matches(['.', '-', '_']);
            let digits = after.bytes().take_while(u8::is_ascii_digit).count();
            let n = if digits == 0 {
                0
            } else {
                number(&after[..digits])?
            };
            tail = &after[digits..];
            // In order: pre, post, dev; each at most once.
            if matches!(kind, Suffix::Post) && dev.is_some() {
                return None;
            }
            let slot = match kind {
                Suffix::Pre(phase) if pre.is_none() && post.is_none() && dev.is_none() => {
                    pre = Some((phase, n));
                    continue;
                }
                Suffix::Post => &mut post,
                Suffix::Dev => &mut dev,
                Suffix::Pre(_) => return None,
            };
            if slot.is_some() {
                return None;
            }
            *slot = Some(n);
        }
        let local = match local {
            None => Vec::new(),
            Some(l) => l
                .split(['.', '-', '_'])
                .map(|seg| match number(seg) {
                    Some(n) => Some(LocalSegment::Numeric(n)),
                    None if !seg.is_empty() && seg.chars().all(|c| c.is_ascii_alphanumeric()) => {
                        Some(LocalSegment::Alpha(seg.to_string()))
                    }
                    None => None,
                })
                .collect::<Option<_>>()?,
        };
        Some(Pep440 {
            epoch,
            release,
            pre: match (pre, post, dev) {
                (Some((phase, n)), _, _) => Pre::Phase(phase, n),
                (None, None, Some(_)) => Pre::DevOnly,
                _ => Pre::Final,
            },
            post,
            dev: dev.map_or(Dev::None, Dev::Dev),
            local,
        })
    }
}

enum Suffix {
    Pre(u8),
    Post,
    Dev,
}

/// The suffix `t` starts with, in any of PEP 440's spellings, and the rest.
fn suffix_kind(t: &str) -> Option<(Suffix, &str)> {
    const SPELLINGS: &[(&str, Suffix)] = &[
        ("alpha", Suffix::Pre(0)),
        ("a", Suffix::Pre(0)),
        ("beta", Suffix::Pre(1)),
        ("b", Suffix::Pre(1)),
        ("preview", Suffix::Pre(2)),
        ("pre", Suffix::Pre(2)),
        ("rc", Suffix::Pre(2)),
        ("c", Suffix::Pre(2)),
        ("post", Suffix::Post),
        ("rev", Suffix::Post),
        ("r", Suffix::Post),
        ("dev", Suffix::Dev),
    ];
    SPELLINGS.iter().find_map(|(spelling, kind)| {
        t.strip_prefix(spelling).map(|rest| {
            let kind = match kind {
                Suffix::Pre(p) => Suffix::Pre(*p),
                Suffix::Post => Suffix::Post,
                Suffix::Dev => Suffix::Dev,
            };
            (kind, rest)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ascending(eco: Ecosystem, versions: &[&str]) {
        for pair in versions.windows(2) {
            assert_eq!(
                compare(eco, pair[0], pair[1]),
                Some(Ordering::Less),
                "{} < {}",
                pair[0],
                pair[1]
            );
            assert_eq!(compare(eco, pair[1], pair[0]), Some(Ordering::Greater));
        }
    }

    #[test]
    fn semver_precedence_as_the_spec_lists_it() {
        // semver.org, section 11.
        ascending(
            Ecosystem::Npm,
            &[
                "1.0.0-alpha",
                "1.0.0-alpha.1",
                "1.0.0-alpha.beta",
                "1.0.0-beta",
                "1.0.0-beta.2",
                "1.0.0-beta.11",
                "1.0.0-rc.1",
                "1.0.0",
                "1.0.1",
                "1.1.0",
                "2.0.0",
                "2.10.0",
            ],
        );
        ascending(Ecosystem::Cargo, &["0.0.0-0", "0.0.0", "0.2.1-0", "0.2.1"]);
        assert_eq!(
            compare(Ecosystem::Npm, "1.0.0+build.1", "1.0.0"),
            Some(Ordering::Equal)
        );
        assert_eq!(
            compare(Ecosystem::Npm, "v4.17.21", "4.17.21"),
            Some(Ordering::Equal)
        );
        assert_eq!(
            compare(Ecosystem::Npm, "1.90", "1.90.0"),
            Some(Ordering::Equal)
        );
        assert_eq!(
            compare(Ecosystem::Cargo, "0.9", "0.10.0"),
            Some(Ordering::Less)
        );
        for bad in [
            "",
            "1.0.0.0",
            "1..0",
            "a.b.c",
            "1.0.0-",
            "1.0.0-a..b",
            "-1.0.0",
            "1.0.0-🙂",
        ] {
            assert_eq!(compare(Ecosystem::Npm, bad, "1.0.0"), None, "{bad}");
        }
    }

    #[test]
    fn pep440_ordering_as_the_pep_lists_it() {
        // PEP 440's own examples, in order.
        ascending(
            Ecosystem::Pypi,
            &[
                "1.0.dev456",
                "1.0a1",
                "1.0a2.dev456",
                "1.0a12.dev456",
                "1.0a12",
                "1.0b1.dev456",
                "1.0b2",
                "1.0b2.post345.dev456",
                "1.0b2.post345",
                "1.0rc1.dev456",
                "1.0rc1",
                "1.0",
                "1.0+abc.5",
                "1.0+abc.7",
                "1.0+5",
                "1.0.post456.dev34",
                "1.0.post456",
                "1.0.15",
                "1.1.dev1",
                "1!0.1",
            ],
        );
        let eq = |a, b| {
            assert_eq!(
                compare(Ecosystem::Pypi, a, b),
                Some(Ordering::Equal),
                "{a} == {b}"
            )
        };
        eq("1.0", "1.0.0");
        eq("1.0-alpha.1", "1.0a1");
        eq("1.0c1", "1.0rc1");
        eq("1.0-1", "1.0.post1");
        eq("1.0.dev", "1.0.dev0");
        eq("V2.31.0", "2.31.0");
        for bad in ["", "abc", "1.0junk", "1.0a1a2", "1.0+", "1.0+a b"] {
            assert_eq!(compare(Ecosystem::Pypi, bad, "1.0"), None, "{bad}");
        }
    }
}
