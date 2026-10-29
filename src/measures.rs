use crate::model::{Category, Issue, Severity};
use crate::scanner::ScanResult;
use std::collections::BTreeMap;

/// Every metric the quality gate can use. `None` means "no data".
pub type Measures = BTreeMap<&'static str, Option<f64>>;

pub const METRICS: &[&str] = &[
    "files",
    "lines",
    "ncloc",
    "functions",
    "complexity",
    "cognitive_complexity",
    "issues",
    "bugs",
    "vulnerabilities",
    "code_smells",
    "blocker_issues",
    "critical_issues",
    "major_issues",
    "debt_minutes",
    "duplicated_lines",
    "duplicated_lines_density",
    "coverage",
    "new_lines",
    "new_issues",
    "new_bugs",
    "new_vulnerabilities",
    "new_code_smells",
    "new_blocker_issues",
    "new_critical_issues",
    "new_major_issues",
    "new_debt_minutes",
    "new_duplicated_lines",
    "new_duplicated_lines_density",
    "new_coverage",
];

pub fn compute(scan: &ScanResult) -> Measures {
    let mut m = Measures::new();
    let mut put = |k: &'static str, v: Option<f64>| {
        debug_assert!(METRICS.contains(&k), "{k} missing from METRICS");
        m.insert(k, v);
    };
    let sum = |f: fn(&crate::analysis::FileMetrics) -> usize| {
        // Integer sums: an empty f64 sum would be -0.0.
        scan.files.iter().map(|a| f(&a.metrics) as u64).sum::<u64>() as f64
    };
    put("files", Some(scan.files.len() as f64));
    put("lines", Some(sum(|m| m.lines)));
    put("ncloc", Some(sum(|m| m.ncloc)));
    put("functions", Some(sum(|m| m.functions)));
    put("complexity", Some(sum(|m| m.complexity as usize)));
    put(
        "cognitive_complexity",
        Some(sum(|m| m.cognitive_complexity as usize)),
    );

    let issues: Vec<&Issue> = scan.files.iter().flat_map(|f| &f.issues).collect();
    let new_issues: Vec<&Issue> = issues.iter().copied().filter(|i| i.is_new).collect();
    for ((overall, new), (all, fresh)) in ISSUE_METRICS.iter().zip(
        issue_counts(&issues)
            .into_iter()
            .zip(issue_counts(&new_issues)),
    ) {
        put(overall, Some(all));
        put(new, Some(fresh));
    }

    // Duplication and coverage are measured over code lines only.
    let mut code = 0usize;
    let mut dup = 0usize;
    let mut new_code = 0usize;
    let mut new_dup = 0usize;
    let mut coverable = 0usize;
    let mut covered = 0usize;
    let mut new_coverable = 0usize;
    let mut new_covered = 0usize;
    for (idx, f) in scan.files.iter().enumerate() {
        let dup_lines = &scan.duplication.lines[idx];
        let hits = scan.coverage.files.get(&f.path);
        for &line in &f.code_lines {
            let is_new = scan.new_code.is_new(&f.path, line);
            let is_dup = dup_lines.contains(&line);
            code += 1;
            dup += is_dup as usize;
            new_code += is_new as usize;
            new_dup += (is_new && is_dup) as usize;
        }
        // Coverage counts the lines the coverage tool considered executable.
        for (&line, &h) in hits.into_iter().flatten() {
            let is_new = scan.new_code.is_new(&f.path, line);
            coverable += 1;
            covered += (h > 0) as usize;
            new_coverable += is_new as usize;
            new_covered += (is_new && h > 0) as usize;
        }
    }
    let pct =
        |part: usize, whole: usize| (whole > 0).then(|| round1(100.0 * part as f64 / whole as f64));
    put("duplicated_lines", Some(dup as f64));
    put("duplicated_lines_density", pct(dup, code).or(Some(0.0)));
    put("coverage", pct(covered, coverable));
    put("new_lines", Some(new_code as f64));
    put("new_duplicated_lines", Some(new_dup as f64));
    put("new_duplicated_lines_density", pct(new_dup, new_code));
    put("new_coverage", pct(new_covered, new_coverable));
    m
}

/// (overall, new code) metric names, in the order `issue_counts` returns them.
const ISSUE_METRICS: [(&str, &str); 8] = [
    ("issues", "new_issues"),
    ("bugs", "new_bugs"),
    ("vulnerabilities", "new_vulnerabilities"),
    ("code_smells", "new_code_smells"),
    ("blocker_issues", "new_blocker_issues"),
    ("critical_issues", "new_critical_issues"),
    ("major_issues", "new_major_issues"),
    ("debt_minutes", "new_debt_minutes"),
];

fn issue_counts(set: &[&Issue]) -> [f64; 8] {
    let count = |p: fn(&Issue) -> bool| set.iter().filter(|i| p(i)).count() as f64;
    [
        set.len() as f64,
        count(|i| i.category == Category::Bug),
        count(|i| i.category == Category::Vulnerability),
        count(|i| i.category == Category::CodeSmell),
        count(|i| i.severity == Severity::Blocker),
        count(|i| i.severity == Severity::Critical),
        count(|i| i.severity == Severity::Major),
        set.iter().map(|i| i.effort_minutes as u64).sum::<u64>() as f64,
    ]
}

fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}
