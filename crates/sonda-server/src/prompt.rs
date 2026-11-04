//! Issues as a prompt for the developer's AI assistant (ADR-0025): what to
//! fix and where, with the code around it, and each rule's explanation and
//! examples once. Markdown, so it reads the same pasted into a chat, an
//! editor or a terminal. The web app copies it; the CLI prints it.

use crate::issues::IssueView;
use std::collections::BTreeMap;
use std::fmt::Write as _;

/// The most issues one prompt carries: enough for a session's work, few
/// enough that each fix gets attention.
pub const MAX_ISSUES: i64 = 50;

/// Lines of code shown before and after an issue's own.
const CONTEXT: usize = 3;

/// Lines of an issue's own code shown at most.
const MAX_ISSUE_LINES: usize = 20;

/// The prompt for `issues` (with their files' contents, when stored), of
/// `total` that matched.
pub fn render(issues: &[(IssueView, Option<String>)], total: i64) -> String {
    let mut out = String::new();
    if issues.is_empty() {
        out.push_str("No sonda issues match, so there's nothing to fix.\n");
        return out;
    }
    let projects: Vec<&str> = {
        let mut p: Vec<&str> = issues.iter().map(|(i, _)| i.project.as_str()).collect();
        p.dedup();
        p
    };
    let n = issues.len();
    let _ = write!(
        out,
        "# Fix {n} sonda {} in {}\n\n",
        if n == 1 { "issue" } else { "issues" },
        projects.join(", ")
    );
    out.push_str(
        "sonda, a static analyzer, found these in the code. Fix each one:\n\n\
         - Change only what the issue needs, and keep the code's behaviour the same.\n\
         - Don't silence a rule with a comment or a configuration change; if an issue \
         shouldn't be fixed, say why instead.\n\
         - Run the project's tests afterwards.\n\
         - To check, run `sonda scan` again: a fixed issue is no longer listed.\n",
    );
    if total > n as i64 {
        let _ = writeln!(
            out,
            "\nThese are {n} of the {total} issues that match. Fix these first; the rest can follow."
        );
    }

    // Issues by file, in the order the list gives them within it.
    let mut files: BTreeMap<&str, Vec<&(IssueView, Option<String>)>> = BTreeMap::new();
    for item in issues {
        files.entry(item.0.file.as_str()).or_default().push(item);
    }
    for (file, items) in &files {
        let _ = write!(out, "\n## `{file}`\n");
        let mut items = items.clone();
        items.sort_by_key(|(i, _)| (i.line, i.id));
        for (issue, source) in items {
            let _ = write!(out, "\n### Line {}: {}\n\n", issue.line, issue.message);
            let _ = writeln!(
                out,
                "`{}` · {} {}{}",
                issue.rule,
                issue.severity,
                issue.category.replace('_', " "),
                if issue.status == "confirmed" {
                    " · confirmed by the team"
                } else {
                    ""
                }
            );
            if let Some(code) = source
                .as_deref()
                .map(|s| excerpt(s, issue.line, issue.end_line))
            {
                let fence = fence_for(&code);
                let _ = write!(
                    out,
                    "\n{fence}{}\n{code}{fence}\n",
                    issue.language.as_deref().unwrap_or("")
                );
            }
        }
    }

    // Each rule once.
    let mut rules: Vec<&str> = issues.iter().map(|(i, _)| i.rule.as_str()).collect();
    rules.sort_unstable();
    rules.dedup();
    out.push_str("\n## The rules\n");
    for id in rules {
        let Some(rule) = sonda_core::rules::find(id) else {
            let _ = write!(
                out,
                "\n### `{id}`\n\nNo description is available for this rule.\n"
            );
            continue;
        };
        let _ = write!(
            out,
            "\n### `{id}`: {}\n\n{}\n",
            rule.name,
            rule.description.trim()
        );
        if let Some(example) = &rule.example {
            let lang = example.lang.name();
            for (label, code) in [("Noncompliant:", example.bad), ("Compliant:", example.good)] {
                let code = format!("{}\n", code.trim_end());
                let fence = fence_for(&code);
                let _ = write!(out, "\n{label}\n\n{fence}{lang}\n{code}{fence}\n");
            }
        }
    }
    out
}

/// The issue's lines with a few around them, numbered, the issue's own
/// marked with `>`.
fn excerpt(source: &str, line: i32, end_line: i32) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let line = (line.max(1) as usize).min(lines.len().max(1));
    let end = (end_line.max(line as i32) as usize)
        .min(line + MAX_ISSUE_LINES - 1)
        .min(lines.len().max(1));
    let first = line.saturating_sub(CONTEXT).max(1);
    let last = (end + CONTEXT).min(lines.len());
    let width = last.to_string().len();
    let mut out = String::new();
    for n in first..=last {
        let mark = if (line..=end).contains(&n) { '>' } else { ' ' };
        let _ = writeln!(out, "{mark} {n:>width$} | {}", lines[n - 1]);
    }
    out
}

/// A code fence longer than any run of backticks in `code`.
fn fence_for(code: &str) -> String {
    let longest = code.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    "`".repeat(longest.max(2) + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issue(id: i64, file: &str, line: i32, rule: &str) -> IssueView {
        IssueView {
            id,
            key: "k".repeat(32),
            project: "shop".into(),
            branch: "main".into(),
            severity: "major".into(),
            category: "code_smell".into(),
            rule: rule.into(),
            message: format!("Message {id}"),
            component: "src".into(),
            file: file.into(),
            line,
            end_line: line,
            language: Some("javascript".into()),
            effort_minutes: 5,
            status: "open".into(),
            assignee: None,
            is_new: false,
            detected_at: "2026-11-04T00:00:00.000Z".into(),
            reason: None,
        }
    }

    #[test]
    fn issues_are_grouped_by_file_with_their_code_and_each_rule_once() {
        let source = (1..=10).map(|n| format!("line {n}\n")).collect::<String>();
        let rule = sonda_core::rules::RULES
            .iter()
            .find(|r| r.example.is_some())
            .unwrap()
            .id;
        let prompt = render(
            &[
                (issue(2, "src/b.js", 5, rule), Some(source.clone())),
                (issue(1, "src/a.js", 9, rule), Some(source.clone())),
                (issue(3, "src/b.js", 2, rule), None),
            ],
            7,
        );
        assert!(
            prompt.starts_with("# Fix 3 sonda issues in shop\n"),
            "{prompt}"
        );
        assert!(prompt.contains("These are 3 of the 7 issues that match"));
        // Files in order, and within one, lines in order.
        let at = |s: &str| {
            prompt
                .find(s)
                .unwrap_or_else(|| panic!("{s:?} not in\n{prompt}"))
        };
        assert!(at("## `src/a.js`") < at("## `src/b.js`"));
        assert!(at("### Line 2: Message 3") < at("### Line 5: Message 2"));
        // The issue's line marked, with three around it, clipped at the file's end.
        assert!(
            prompt.contains(">  9 | line 9\n  10 | line 10\n```\n"),
            "{prompt}"
        );
        assert!(
            prompt.contains("  2 | line 2\n  3 | line 3\n  4 | line 4\n> 5 | line 5\n"),
            "{prompt}"
        );
        // The rule's explanation comes once, after the issues.
        assert_eq!(prompt.matches(&format!("### `{rule}`: ")).count(), 1);
        assert!(at("## The rules") > at("## `src/b.js`"));
        assert!(prompt.contains("Noncompliant:") && prompt.contains("Compliant:"));
        assert!(prompt.contains("Don't silence a rule"));
    }

    #[test]
    fn code_with_backticks_gets_a_longer_fence() {
        assert_eq!(fence_for("plain"), "```");
        assert_eq!(fence_for("a ``` b"), "````");
        let prompt = render(
            &[(
                issue(1, "a.md.js", 1, "nope/unknown"),
                Some("x = ```;\n".into()),
            )],
            1,
        );
        assert!(
            prompt.contains("````javascript\n> 1 | x = ```;\n````"),
            "{prompt}"
        );
        assert!(prompt.contains("No description is available"));
    }

    #[test]
    fn nothing_matching_says_so() {
        assert!(render(&[], 0).contains("nothing to fix"));
    }
}
