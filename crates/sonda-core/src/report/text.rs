use super::Report;
use crate::gate::Status;
use crate::model::Metric;
use std::borrow::Cow;
use std::fmt::Write;

/// Makes text derived from the analyzed repository (paths, identifiers,
/// warnings) safe to print to a terminal: control characters (escape
/// sequences, carriage returns) and Unicode bidi controls ("Trojan Source")
/// are shown as `\u{..}` escapes instead of being interpreted.
pub fn terminal_safe(s: &str) -> Cow<'_, str> {
    if !s.chars().any(needs_escape) {
        return Cow::Borrowed(s);
    }
    Cow::Owned(
        s.chars()
            .map(|c| {
                if needs_escape(c) {
                    c.escape_unicode().to_string()
                } else {
                    c.to_string()
                }
            })
            .collect(),
    )
}

/// Like [`terminal_safe`], but keeps line breaks: for multi-line messages
/// such as errors. Report lines use `terminal_safe`, where a newline in a
/// file name could otherwise forge extra report lines.
pub fn terminal_safe_lines(s: &str) -> String {
    s.split('\n')
        .map(terminal_safe)
        .collect::<Vec<_>>()
        .join("\n")
}

fn needs_escape(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
        )
}

pub fn render(r: &Report) -> String {
    let mut out = String::new();
    let mut current_file = "";
    for i in &r.issues {
        if i.path != current_file {
            current_file = &i.path;
            let _ = writeln!(out, "\n{}", terminal_safe(current_file));
        }
        let new_mark = if r.new_code_reference.is_some() && i.is_new {
            "*"
        } else {
            " "
        };
        let _ = writeln!(
            out,
            "{new_mark}{:>5}:{:<4} {:<9} {:<14} {:<32} {}",
            i.line,
            i.column,
            i.severity.as_str().to_uppercase(),
            i.category.label(),
            i.rule,
            terminal_safe(&i.message)
        );
    }

    if !r.duplications.is_empty() {
        let _ = writeln!(out, "\nDuplicated blocks");
        for d in &r.duplications {
            let _ = writeln!(
                out,
                "  {}:{}-{}  duplicates  {}:{}-{}",
                terminal_safe(d.copy.path),
                d.copy.start_line,
                d.copy.end_line,
                terminal_safe(d.original.path),
                d.original.start_line,
                d.original.end_line
            );
        }
    }

    if let Some(v) = r.vulnerabilities.filter(|v| !v.is_empty()) {
        let _ = writeln!(out, "\nVulnerable dependencies");
        for f in v {
            let fix = f.fixed_in.as_deref().map_or_else(
                || "no fix yet".to_string(),
                |v| format!("fixed in {}", terminal_safe(v)),
            );
            let _ = writeln!(
                out,
                "  {:<9} {} {}  {}  {} ({})",
                f.severity.as_str().to_uppercase(),
                terminal_safe(&f.name),
                terminal_safe(&f.version),
                terminal_safe(&f.advisory),
                terminal_safe(&f.summary),
                fix
            );
        }
    }

    if !r.warnings.is_empty() {
        let _ = writeln!(out, "\nWarnings");
        for w in r.warnings {
            let _ = writeln!(out, "  {}", terminal_safe(w));
        }
    }

    let m = |k: Metric| r.measures.get(&k).copied().flatten();
    let n = |k: Metric| m(k).map_or("n/a".into(), |v| format!("{v}"));
    let pct = |k: Metric| m(k).map_or("n/a".into(), |v| format!("{v:.1}%"));
    let scope = match r.new_code_reference {
        Some(_) => format!("new code = {}, marked *", r.new_code_description),
        None => format!("new code = {}", r.new_code_description),
    };
    let _ = writeln!(out, "\nSummary ({scope})");
    let _ = writeln!(
        out,
        "  Files {} · Lines of code {} · Functions {} · Complexity {}",
        n(Metric::Files),
        n(Metric::Ncloc),
        n(Metric::Functions),
        n(Metric::Complexity)
    );
    let _ = writeln!(
        out,
        "  Bugs {} ({} new) · Vulnerabilities {} ({} new) · Code smells {} ({} new)",
        n(Metric::Bugs),
        n(Metric::NewBugs),
        n(Metric::Vulnerabilities),
        n(Metric::NewVulnerabilities),
        n(Metric::CodeSmells),
        n(Metric::NewCodeSmells)
    );
    let _ = writeln!(
        out,
        "  Duplication {} · Coverage {} (new code {}) · Debt {}",
        pct(Metric::DuplicatedLinesDensity),
        pct(Metric::Coverage),
        pct(Metric::NewCoverage),
        format_minutes(m(Metric::DebtMinutes).unwrap_or(0.0) as u64)
    );
    if !r.dependencies.is_empty() {
        let mut line = dependency_summary(r.dependencies);
        if let Some(v) = r.vulnerabilities {
            let _ = write!(line, " · {} vulnerable", n(Metric::VulnerableDependencies));
            if v.is_empty() {
                line.push_str(" (none known)");
            }
        }
        let _ = writeln!(out, "  {line}");
    }

    let _ = writeln!(
        out,
        "\nQuality gate: {}",
        if r.gate.passed { "PASSED" } else { "FAILED" }
    );
    for c in &r.gate.conditions {
        let (mark, actual) = match c.status {
            Status::Ok => ("✓", format!("{}", c.actual.unwrap_or_default())),
            Status::Error => ("✗", format!("{}", c.actual.unwrap_or_default())),
            Status::NoData => ("–", "no data".into()),
            Status::Ignored => (
                "–",
                format!(
                    "{}, ignored: {}",
                    c.actual.map_or("no data".into(), |v| v.to_string()),
                    c.reason.unwrap_or("not evaluated")
                ),
            ),
        };
        let _ = writeln!(
            out,
            "  {mark} fails if {} {} {} (actual: {actual})",
            c.condition.metric.as_str(),
            c.condition.op.symbol(),
            c.condition.threshold
        );
    }
    out
}

/// Formats technical debt like SonarQube: 8-hour days.
fn format_minutes(total: u64) -> String {
    let (d, h, min) = (total / 480, total % 480 / 60, total % 60);
    match (d, h, min) {
        (0, 0, m) => format!("{m}min"),
        (0, h, 0) => format!("{h}h"),
        (0, h, m) => format!("{h}h {m}min"),
        (d, 0, _) => format!("{d}d"),
        (d, h, _) => format!("{d}d {h}h"),
    }
}

/// `Dependencies 182 (npm 120, cargo 62) from 2 lockfiles · 14 direct`.
fn dependency_summary(deps: &[crate::deps::Dependency]) -> String {
    let mut by_ecosystem: Vec<(&str, usize)> = Vec::new();
    for d in deps {
        match by_ecosystem
            .iter_mut()
            .find(|(e, _)| *e == d.ecosystem.as_str())
        {
            Some((_, n)) => *n += 1,
            None => by_ecosystem.push((d.ecosystem.as_str(), 1)),
        }
    }
    let mut lockfiles: Vec<&str> = deps.iter().map(|d| d.source.as_str()).collect();
    lockfiles.sort_unstable();
    lockfiles.dedup();
    let ecosystems: Vec<String> = by_ecosystem
        .iter()
        .map(|(e, n)| format!("{e} {n}"))
        .collect();
    let mut line = format!(
        "Dependencies {} ({}) from {} {}",
        deps.len(),
        ecosystems.join(", "),
        lockfiles.len(),
        if lockfiles.len() == 1 {
            "lockfile"
        } else {
            "lockfiles"
        }
    );
    let direct = deps.iter().filter(|d| d.direct == Some(true)).count();
    if direct > 0 {
        let _ = write!(line, " · {direct} direct");
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn escapes_terminal_control_and_bidi_characters() {
        assert!(matches!(terminal_safe("src/a.js"), Cow::Borrowed(_)));
        assert_eq!(terminal_safe("a\x1b[2Jb"), "a\\u{1b}[2Jb");
        assert_eq!(terminal_safe("x\ry"), "x\\u{d}y");
        assert_eq!(terminal_safe("ok\u{202E}evil"), "ok\\u{202e}evil");
        assert_eq!(terminal_safe("café"), "café");
    }

    #[test]
    fn multiline_variant_keeps_newlines_only() {
        assert_eq!(terminal_safe_lines("a\nb\x1b[1m"), "a\nb\\u{1b}[1m");
        assert_eq!(terminal_safe("a\nb"), "a\\u{a}b");
    }

    #[test]
    fn formats_debt() {
        assert_eq!(format_minutes(0), "0min");
        assert_eq!(format_minutes(45), "45min");
        assert_eq!(format_minutes(120), "2h");
        assert_eq!(format_minutes(125), "2h 5min");
        assert_eq!(format_minutes(480 * 3 + 90), "3d 1h");
    }

    proptest! {
        #![proptest_config(crate::test_support::proptest_config(512))]

        #[test]
        fn escaped_text_is_inert_and_stable(s in any::<String>()) {
            let safe = terminal_safe(&s);
            prop_assert!(!safe.chars().any(needs_escape));
            prop_assert_eq!(terminal_safe(&safe), safe.clone(), "escaping is idempotent");
            if !s.chars().any(needs_escape) {
                prop_assert_eq!(safe, s.as_str());
            }
        }

        #[test]
        fn multiline_escaping_keeps_exactly_the_newlines(s in any::<String>()) {
            let safe = terminal_safe_lines(&s);
            prop_assert_eq!(safe.matches('\n').count(), s.matches('\n').count());
            prop_assert!(!safe.chars().any(|c| c != '\n' && needs_escape(c)));
        }
    }
}
