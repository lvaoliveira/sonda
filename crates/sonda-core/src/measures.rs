use crate::model::{Category, FileMetrics, Issue, Metric, Severity};
use crate::project::ProjectAnalysis;
use std::collections::BTreeMap;

/// Every project measure, keyed in `Metric` order. `None` means "no data".
pub type Measures = BTreeMap<Metric, Option<f64>>;

pub(crate) fn compute(project: &ProjectAnalysis) -> Measures {
    let mut m = Measures::new();
    let sum = |f: fn(&FileMetrics) -> usize| {
        // Integer sums: an empty f64 sum would be -0.0.
        project
            .files
            .iter()
            .map(|a| f(&a.metrics) as u64)
            .sum::<u64>() as f64
    };
    m.insert(Metric::Files, Some(project.files.len() as f64));
    m.insert(Metric::Lines, Some(sum(|m| m.lines)));
    m.insert(Metric::Ncloc, Some(sum(|m| m.ncloc)));
    m.insert(Metric::Functions, Some(sum(|m| m.functions)));
    m.insert(Metric::Complexity, Some(sum(|m| m.complexity as usize)));
    m.insert(
        Metric::CognitiveComplexity,
        Some(sum(|m| m.cognitive_complexity as usize)),
    );

    // Packages, not findings: one package with two advisories counts once.
    let vulnerable = |severe: bool| {
        project.vulnerabilities.as_ref().map(|v| {
            let mut purls: Vec<&str> = v
                .iter()
                .filter(|f| !severe || f.severity >= crate::model::Severity::Critical)
                .map(|f| f.purl.as_str())
                .collect();
            purls.sort_unstable();
            purls.dedup();
            purls.len() as f64
        })
    };
    m.insert(Metric::VulnerableDependencies, vulnerable(false));
    m.insert(Metric::SevereVulnerableDependencies, vulnerable(true));

    let issues: Vec<&Issue> = project.files.iter().flat_map(|f| &f.issues).collect();
    let new_issues: Vec<&Issue> = issues.iter().copied().filter(|i| i.is_new).collect();
    for ((overall, new), (all, fresh)) in ISSUE_METRICS.iter().zip(
        issue_counts(&issues)
            .into_iter()
            .zip(issue_counts(&new_issues)),
    ) {
        m.insert(*overall, Some(all));
        m.insert(*new, Some(fresh));
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
    for (idx, f) in project.files.iter().enumerate() {
        let dup_lines = &project.duplication.lines[idx];
        let hits = project.coverage.files.get(&f.path);
        for &line in &f.code_lines {
            let is_new = project.new_code.is_new(&f.path, line);
            let is_dup = dup_lines.contains(&line);
            code += 1;
            dup += is_dup as usize;
            new_code += is_new as usize;
            new_dup += (is_new && is_dup) as usize;
        }
        // Coverage counts the lines the coverage tool considered executable.
        for (&line, &h) in hits.into_iter().flatten() {
            let is_new = project.new_code.is_new(&f.path, line);
            coverable += 1;
            covered += (h > 0) as usize;
            new_coverable += is_new as usize;
            new_covered += (is_new && h > 0) as usize;
        }
    }
    let pct =
        |part: usize, whole: usize| (whole > 0).then(|| round1(100.0 * part as f64 / whole as f64));
    m.insert(Metric::DuplicatedLines, Some(dup as f64));
    m.insert(Metric::DuplicatedLinesDensity, pct(dup, code).or(Some(0.0)));
    m.insert(Metric::Coverage, pct(covered, coverable));
    m.insert(Metric::NewLines, Some(new_code as f64));
    m.insert(Metric::NewDuplicatedLines, Some(new_dup as f64));
    m.insert(Metric::NewDuplicatedLinesDensity, pct(new_dup, new_code));
    m.insert(Metric::NewCoverage, pct(new_covered, new_coverable));
    debug_assert_eq!(m.len(), Metric::ALL.len(), "every metric is computed");
    m
}

/// (overall, new code) metrics, in the order `issue_counts` returns them.
const ISSUE_METRICS: [(Metric, Metric); 8] = [
    (Metric::Issues, Metric::NewIssues),
    (Metric::Bugs, Metric::NewBugs),
    (Metric::Vulnerabilities, Metric::NewVulnerabilities),
    (Metric::CodeSmells, Metric::NewCodeSmells),
    (Metric::BlockerIssues, Metric::NewBlockerIssues),
    (Metric::CriticalIssues, Metric::NewCriticalIssues),
    (Metric::MajorIssues, Metric::NewMajorIssues),
    (Metric::DebtMinutes, Metric::NewDebtMinutes),
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
