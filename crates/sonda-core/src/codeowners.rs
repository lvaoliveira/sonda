//! Domain: who owns a path, from a repository's CODEOWNERS file, as GitHub
//! reads it. Patterns use gitignore syntax and the last matching line
//! wins. A pattern without owners makes its paths explicitly unowned. As on
//! GitHub, `!` negation is not supported, so such lines are skipped.
//!
//! The file comes from the analyzed repository, so it is untrusted: lines
//! that are too long or patterns that don't parse are skipped, and the rule
//! count is capped.

use ignore::gitignore::{Gitignore, GitignoreBuilder};

/// Where GitHub looks for the file, in order; the first one found wins.
pub const LOCATIONS: &[&str] = &[".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"];
/// The largest file read, as GitHub's own limit (3 MB) is far beyond any
/// real one.
pub const MAX_BYTES: u64 = 128 << 10;
const MAX_RULES: usize = 5_000;
const MAX_LINE: usize = 1_000;

pub struct CodeOwners {
    /// In file order; matching walks them backwards.
    rules: Vec<(Gitignore, Vec<String>)>,
}

impl CodeOwners {
    pub fn parse(text: &str) -> Self {
        let rules = text
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.is_empty()
                    || line.starts_with('#')
                    || line.starts_with('!')
                    || line.len() > MAX_LINE
                {
                    return None;
                }
                let mut parts = line.split_whitespace();
                let pattern = parts.next()?;
                let owners: Vec<String> = parts
                    .take_while(|p| !p.starts_with('#'))
                    .filter(|p| p.contains('@'))
                    .map(str::to_string)
                    .collect();
                let mut builder = GitignoreBuilder::new("");
                builder.add_line(None, pattern).ok()?;
                Some((builder.build().ok()?, owners))
            })
            .take(MAX_RULES)
            .collect();
        Self { rules }
    }

    /// The owners of `path` (relative, `/`-separated): the last matching
    /// line's, which may be empty (explicitly unowned). None if no line
    /// matches.
    pub fn owners(&self, path: &str) -> Option<&[String]> {
        self.rules
            .iter()
            .rev()
            .find(|(glob, _)| glob.matched_path_or_any_parents(path, false).is_ignore())
            .map(|(_, owners)| owners.as_slice())
    }

    /// The owners most of `paths` share, as one display string, e.g.
    /// "@payments" or "@payments +1". None if most paths have no owner.
    pub fn majority<'a>(&self, paths: impl IntoIterator<Item = &'a str>) -> Option<String> {
        let mut counts: Vec<(&[String], usize)> = Vec::new();
        let mut total = 0;
        for path in paths {
            total += 1;
            let owners = self.owners(path).unwrap_or(&[]);
            match counts.iter_mut().find(|(o, _)| *o == owners) {
                Some((_, n)) => *n += 1,
                None => counts.push((owners, 1)),
            }
        }
        // Stable: ties go to the first owners seen, in path order.
        let (owners, n) =
            counts
                .into_iter()
                .fold(None, |best: Option<(&[String], usize)>, c| match best {
                    Some(b) if b.1 >= c.1 => Some(b),
                    _ => Some(c),
                })?;
        if owners.is_empty() || n * 2 < total {
            return None;
        }
        Some(match owners.len() {
            1 => owners[0].clone(),
            k => format!("{} +{}", owners[0], k - 1),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "
# Default owners
*                 @org/everyone
*.js              @web @frontend   # trailing comment
/docs/            @writers
services/checkout/ @checkout
services/checkout/legacy/
!services/neg     @ignored
";

    #[test]
    fn the_last_matching_line_wins() {
        let co = CodeOwners::parse(FILE);
        let o = |p: &str| co.owners(p).map(|o| o.join(" "));
        assert_eq!(o("README.md").as_deref(), Some("@org/everyone"));
        assert_eq!(o("src/app.js").as_deref(), Some("@web @frontend"));
        assert_eq!(o("docs/guide.md").as_deref(), Some("@writers"));
        // Anchored: /docs/ only at the root.
        assert_eq!(o("src/docs/x.md").as_deref(), Some("@org/everyone"));
        // A later directory rule beats the earlier *.js.
        assert_eq!(o("services/checkout/api.js").as_deref(), Some("@checkout"));
        // A pattern without owners makes paths explicitly unowned.
        assert_eq!(o("services/checkout/legacy/old.js").as_deref(), Some(""));
        // Negation is not supported, as on GitHub: the line is skipped.
        assert_eq!(o("services/neg/x.py").as_deref(), Some("@org/everyone"));
        assert_eq!(CodeOwners::parse("").owners("a.js"), None);
    }

    #[test]
    fn a_components_owner_is_its_majority() {
        let co = CodeOwners::parse("services/ @svc\nservices/b.go @svc @ops\n");
        assert_eq!(
            co.majority(["services/a.go", "services/c.go", "services/b.go"])
                .as_deref(),
            Some("@svc")
        );
        assert_eq!(co.majority(["services/b.go"]).as_deref(), Some("@svc +1"));
        // Mostly unowned: no owner rather than a minority's.
        assert_eq!(co.majority(["lib/a.py", "lib/b.py", "services/a.go"]), None);
        assert_eq!(co.majority([]), None);
    }

    #[test]
    fn hostile_files_are_contained() {
        let long = format!("{} @x\n", "a".repeat(5_000));
        let many = "x/ @y\n".repeat(MAX_RULES + 100);
        assert_eq!(CodeOwners::parse(&long).rules.len(), 0);
        assert_eq!(CodeOwners::parse(&many).rules.len(), MAX_RULES);
        // Owners must look like owners: other words after the pattern are not.
        let co = CodeOwners::parse("a.js notanowner @real\n");
        assert_eq!(co.owners("a.js"), Some(&["@real".to_string()][..]));
    }
}
