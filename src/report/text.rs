use super::Report;
use crate::gate::Status;
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

    if !r.warnings.is_empty() {
        let _ = writeln!(out, "\nWarnings");
        for w in r.warnings {
            let _ = writeln!(out, "  {}", terminal_safe(w));
        }
    }

    let m = |k: &str| r.measures.get(k).copied().flatten();
    let n = |k: &str| m(k).map_or("n/a".into(), |v| format!("{v}"));
    let pct = |k: &str| m(k).map_or("n/a".into(), |v| format!("{v:.1}%"));
    let scope = match r.new_code_reference {
        Some(reference) => format!("new code = changes since {reference}, marked *"),
        None => "no --new-code reference: the whole project counts as new code".into(),
    };
    let _ = writeln!(out, "\nSummary ({scope})");
    let _ = writeln!(
        out,
        "  Files {} · Lines of code {} · Functions {} · Complexity {}",
        n("files"),
        n("ncloc"),
        n("functions"),
        n("complexity")
    );
    let _ = writeln!(
        out,
        "  Bugs {} ({} new) · Vulnerabilities {} ({} new) · Code smells {} ({} new)",
        n("bugs"),
        n("new_bugs"),
        n("vulnerabilities"),
        n("new_vulnerabilities"),
        n("code_smells"),
        n("new_code_smells")
    );
    let _ = writeln!(
        out,
        "  Duplication {} · Coverage {} (new code {}) · Debt {}",
        pct("duplicated_lines_density"),
        pct("coverage"),
        pct("new_coverage"),
        format_minutes(m("debt_minutes").unwrap_or(0.0) as u64)
    );

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
        };
        let _ = writeln!(
            out,
            "  {mark} fails if {} {} {} (actual: {actual})",
            c.condition.metric,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_terminal_control_and_bidi_characters() {
        assert!(matches!(terminal_safe("src/a.js"), Cow::Borrowed(_)));
        assert_eq!(terminal_safe("a\x1b[2Jb"), "a\\u{1b}[2Jb");
        assert_eq!(terminal_safe("x\ry"), "x\\u{d}y");
        assert_eq!(terminal_safe("ok\u{202E}evil"), "ok\\u{202e}evil");
        assert_eq!(terminal_safe("café"), "café");
    }

    #[test]
    fn formats_debt() {
        assert_eq!(format_minutes(0), "0min");
        assert_eq!(format_minutes(45), "45min");
        assert_eq!(format_minutes(120), "2h");
        assert_eq!(format_minutes(125), "2h 5min");
        assert_eq!(format_minutes(480 * 3 + 90), "3d 1h");
    }
}
