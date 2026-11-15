//! Decorating pull requests on GitHub (ADR-0021). An upload of a pull
//! request queues its decoration; a background task posts it: a `sonda`
//! check run on the pull request's head commit, with annotations on its new
//! issues, and one summary comment edited in place. A GitHub that's down or
//! refuses never fails the upload: the task retries for a day, and the
//! analysis page shows the state and the last error.

use crate::github::App;
use crate::health::{conditions, gate_state};
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;

/// Annotations on a check run: the rest are counted in the summary.
pub const MAX_ANNOTATIONS: usize = 50;

/// How often the task looks for decorations to post.
pub const INTERVAL: Duration = Duration::from_secs(10);

/// How long a decoration is retried before it's given up.
const RETRY_FOR_HOURS: i32 = 24;

/// Decorations posted at a time; the rest wait for the next round.
const BATCH: i64 = 10;

/// A decoration as the analysis page shows it.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct State {
    /// `pending`, `posted`, `failed`, `not_posted` or `superseded`.
    pub state: String,
    pub attempts: i32,
    /// Why it failed, or why it's not posted.
    pub last_error: Option<String>,
    pub posted_at: Option<String>,
}

pub(crate) async fn state(pool: &PgPool, analysis: i64) -> sqlx::Result<Option<State>> {
    let row: Option<(String, i32, Option<String>, Option<f64>)> = sqlx::query_as(
        "SELECT state, attempts, last_error, extract(epoch FROM posted_at)::float8
         FROM decorations WHERE analysis_id = $1",
    )
    .bind(analysis)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(state, attempts, last_error, posted)| State {
        state,
        attempts,
        last_error,
        posted_at: posted.map(crate::health::rfc3339),
    }))
}

/// An analysis to queue: project, branch, head commit, the upload's
/// repository, and the project's.
type QueueRow = (i64, String, Option<String>, Option<String>, Option<String>);

/// Queues a pull request analysis's decoration, when the server has a
/// GitHub App, or records why it can't be posted. Older queued analyses of
/// the same pull request are superseded: only the latest is posted.
pub(crate) async fn enqueue(pool: &PgPool, analysis: i64) -> sqlx::Result<()> {
    let row: Option<QueueRow> = sqlx::query_as(
        "SELECT a.project_id, a.branch, a.pull_request_head_sha, a.pull_request_repository,
                    p.github_repository
             FROM analyses a JOIN projects p ON p.id = a.project_id
             WHERE a.id = $1 AND a.pull_request IS NOT NULL",
    )
    .bind(analysis)
    .fetch_optional(pool)
    .await?;
    let Some((project, branch, head_sha, repository, bound)) = row else {
        return Ok(());
    };
    let why_not = match (&head_sha, &repository, &bound) {
        (_, _, None) => Some(
            "the project isn't linked to a GitHub repository; an admin sets it in its Settings"
                .to_string(),
        ),
        (None, _, _) | (_, None, _) => Some(
            "the upload didn't say which GitHub repository and commit it's for (only GitHub \
             Actions does)"
                .to_string(),
        ),
        (_, Some(r), Some(b)) if !r.eq_ignore_ascii_case(b) => Some(format!(
            "uploaded from {r}, but the project is linked to {b}"
        )),
        _ => None,
    };
    let mut tx = pool.begin().await?;
    sqlx::query(
        "UPDATE decorations d SET state = 'superseded' FROM analyses a
         WHERE a.id = d.analysis_id AND a.project_id = $1 AND a.branch = $2
           AND d.state = 'pending' AND d.analysis_id <> $3",
    )
    .bind(project)
    .bind(&branch)
    .bind(analysis)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO decorations (analysis_id, state, last_error) VALUES ($1, $2, $3)
         ON CONFLICT (analysis_id) DO UPDATE
             SET state = EXCLUDED.state, last_error = EXCLUDED.last_error, attempts = 0,
                 next_at = now(), queued_at = now()",
    )
    .bind(analysis)
    .bind(if why_not.is_some() {
        "not_posted"
    } else {
        "pending"
    })
    .bind(why_not)
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

/// Queues a pull request analysis's decoration again, after a triage
/// changed what it shows (ADR-0021), so the check and the comment follow the
/// server without a new scan. Only an analysis queued before: one uploaded
/// while no App was configured stays as it was. Returns whether it queued.
pub(crate) async fn requeue(pool: &PgPool, analysis: i64) -> sqlx::Result<bool> {
    let queued: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM decorations WHERE analysis_id = $1)")
            .bind(analysis)
            .fetch_one(pool)
            .await?;
    if queued {
        enqueue(pool, analysis).await?;
    }
    Ok(queued)
}

/// The latest analysis of each of a project's pull requests, with its gate:
/// taken before a change that re-judges gates, for `requeue_changed`.
pub async fn pull_request_gates(pool: &PgPool, project: i64) -> sqlx::Result<Vec<(i64, Value)>> {
    sqlx::query_as(
        "SELECT DISTINCT ON (branch) id, gate FROM analyses
         WHERE project_id = $1 AND pull_request IS NOT NULL
         ORDER BY branch, id DESC",
    )
    .bind(project)
    .fetch_all(pool)
    .await
}

/// Queues again the pull requests whose gate changed since `before`, as a
/// decision on a vulnerable dependency can change it. Those whose gate is
/// the same show nothing new, so GitHub isn't asked again.
pub async fn requeue_changed(
    pool: &PgPool,
    project: i64,
    before: &[(i64, Value)],
) -> sqlx::Result<usize> {
    let mut queued = 0;
    for (analysis, gate) in pull_request_gates(pool, project).await? {
        let changed = before
            .iter()
            .any(|(id, old)| *id == analysis && *old != gate);
        if changed && requeue(pool, analysis).await? {
            queued += 1;
        }
    }
    Ok(queued)
}

/// A new issue as an annotation shows it.
#[derive(sqlx::FromRow, Debug, Clone)]
pub struct NewIssue {
    pub rule: String,
    pub severity: String,
    pub category: String,
    pub message: String,
    pub path: String,
    pub line: i32,
    pub end_line: Option<i32>,
}

/// What a decoration says, built from an analysis.
#[derive(Debug)]
pub struct Content {
    pub project: String,
    pub analysis: i64,
    /// `passed`, `failed` or `partial`.
    pub gate: &'static str,
    pub failing: Vec<String>,
    /// The conditions without data, each with why when that's known.
    pub lacking: Vec<String>,
    pub new_issues: Vec<NewIssue>,
    pub new_coverage: Option<f64>,
    pub new_duplication: Option<f64>,
    /// The analysis page, when SONDA_PUBLIC_URL is set.
    pub url: Option<String>,
}

const SEVERITIES: [&str; 5] = ["blocker", "critical", "major", "minor", "info"];

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

impl Content {
    fn title(&self) -> String {
        match self.gate {
            "failed" => format!(
                "Quality gate failed: {}",
                plural(self.failing.len(), "condition", "conditions")
            ),
            "partial" => format!(
                "Quality gate passed, but {} couldn't be checked",
                plural(self.lacking.len(), "condition", "conditions")
            ),
            _ => "Quality gate passed".into(),
        }
    }

    /// The summary, in GitHub's Markdown: the check run's and the comment's.
    pub fn summary(&self) -> String {
        let mut s = format!("**{}**\n\n", self.title());
        for f in &self.failing {
            s.push_str(&format!("- ✕ {f}\n"));
        }
        for l in &self.lacking {
            s.push_str(&format!("- – {l}\n"));
        }
        if !self.failing.is_empty() || !self.lacking.is_empty() {
            s.push('\n');
        }
        let n = self.new_issues.len();
        if n == 0 {
            s.push_str("No new issues.\n");
        } else {
            let by =
                |f: &dyn Fn(&NewIssue) -> bool| self.new_issues.iter().filter(|i| f(i)).count();
            let types = [
                ("bug", "bug", "bugs"),
                ("vulnerability", "vulnerability", "vulnerabilities"),
                ("code_smell", "code smell", "code smells"),
            ]
            .iter()
            .filter_map(|(c, one, many)| {
                let k = by(&|i| i.category == *c);
                (k > 0).then(|| plural(k, one, many))
            })
            .collect::<Vec<_>>()
            .join(", ");
            let severities = SEVERITIES
                .iter()
                .filter_map(|sev| {
                    let k = by(&|i| i.severity == *sev);
                    (k > 0).then(|| format!("{k} {sev}"))
                })
                .collect::<Vec<_>>()
                .join(", ");
            s.push_str(&format!(
                "**{}**: {types} ({severities}).\n",
                plural(n, "new issue", "new issues")
            ));
            if n > MAX_ANNOTATIONS {
                s.push_str(&format!(
                    "The check annotates the first {MAX_ANNOTATIONS}, most severe first.\n"
                ));
            }
        }
        let measures: Vec<String> = [
            ("Coverage on new code", self.new_coverage),
            ("Duplication on new code", self.new_duplication),
        ]
        .iter()
        .filter_map(|(label, v)| v.map(|v| format!("{label}: {v:.1}%")))
        .collect();
        if !measures.is_empty() {
            s.push_str(&format!("\n{}\n", measures.join(" · ")));
        }
        if let Some(url) = &self.url {
            s.push_str(&format!("\n[See the analysis on sonda]({url})\n"));
        }
        s
    }

    /// The marker that finds sonda's comment for this project again.
    pub fn marker(&self) -> String {
        format!("<!-- sonda:project={} -->", self.project)
    }

    pub fn comment(&self) -> String {
        format!("{}\n### sonda\n\n{}", self.marker(), self.summary())
    }

    /// The check run, on the pull request's head commit.
    pub fn check_run(&self, head_sha: &str) -> Value {
        let annotations: Vec<Value> = self
            .new_issues
            .iter()
            .take(MAX_ANNOTATIONS)
            .map(|i| {
                json!({
                    "path": i.path,
                    "start_line": i.line,
                    "end_line": i.end_line.unwrap_or(i.line).max(i.line),
                    "annotation_level": match i.severity.as_str() {
                        "blocker" | "critical" => "failure",
                        "major" => "warning",
                        _ => "notice",
                    },
                    "title": format!("{} ({})", i.rule, i.severity),
                    "message": i.message,
                })
            })
            .collect();
        let mut run = json!({
            "name": "sonda",
            "head_sha": head_sha,
            "status": "completed",
            "conclusion": match self.gate {
                "failed" => "failure",
                "partial" => "neutral",
                _ => "success",
            },
            "output": {
                "title": self.title(),
                "summary": self.summary(),
                "annotations": annotations,
            },
        });
        if let Some(url) = &self.url {
            run["details_url"] = Value::from(url.as_str());
        }
        run
    }
}

/// What's needed to post an analysis's decoration.
struct Target {
    repository: String,
    number: i64,
    head_sha: String,
}

async fn content(
    pool: &PgPool,
    analysis: i64,
    public_url: Option<&str>,
) -> sqlx::Result<(Target, Content)> {
    let (project_id, project, branch, number, head_sha, repository, gate, passed, measures): (
        i64,
        String,
        String,
        i64,
        String,
        String,
        Value,
        bool,
        Value,
    ) = sqlx::query_as(
        "SELECT a.project_id, p.key, a.branch, a.pull_request, a.pull_request_head_sha,
                p.github_repository, a.gate, a.gate_passed, a.measures
         FROM analyses a JOIN projects p ON p.id = a.project_id WHERE a.id = $1",
    )
    .bind(analysis)
    .fetch_one(pool)
    .await?;
    let new_issues: Vec<NewIssue> = sqlx::query_as(
        "SELECT rule, severity::text AS severity, category::text AS category, message, path,
                line, end_line
         FROM issues
         WHERE project_id = $1 AND branch = $2 AND fixed_analysis_id IS NULL AND is_new
           AND status::text <> ALL($3) AND NOT rule_off(project_id, rule)
         ORDER BY array_position($4::text[], severity::text), path, line",
    )
    .bind(project_id)
    .bind(&branch)
    .bind(crate::issues::DECIDED)
    .bind(SEVERITIES)
    .fetch_all(pool)
    .await?;
    let content = Content {
        url: public_url.map(|u| format!("{}/analyses/{analysis}", u.trim_end_matches('/'))),
        project,
        analysis,
        gate: gate_state(passed, &gate),
        failing: conditions(&gate)
            .into_iter()
            .filter(|c| c.status == "error")
            .map(|c| c.label)
            .collect(),
        lacking: conditions(&gate)
            .into_iter()
            .filter(|c| c.status == "no_data")
            .map(|c| match c.reason {
                Some(r) => format!("{}: no data ({r})", c.label),
                None => format!("{}: no data", c.label),
            })
            .collect(),
        new_issues,
        new_coverage: measures["new_coverage"].as_f64(),
        new_duplication: measures["new_duplicated_lines_density"].as_f64(),
    };
    Ok((
        Target {
            repository,
            number,
            head_sha,
        },
        content,
    ))
}

/// Posts the decorations that are due, at most `BATCH`; returns how many
/// were posted. Claimed with `SKIP LOCKED` and a five-minute lease, so
/// several servers never post the same one at once.
pub async fn post_due(
    pool: &PgPool,
    app: &Arc<App>,
    public_url: Option<&str>,
) -> sqlx::Result<usize> {
    let due: Vec<i64> = sqlx::query_scalar(
        "UPDATE decorations SET next_at = now() + interval '5 minutes', attempts = attempts + 1
         WHERE analysis_id IN (
             SELECT analysis_id FROM decorations WHERE state = 'pending' AND next_at <= now()
             ORDER BY next_at LIMIT $1 FOR UPDATE SKIP LOCKED)
         RETURNING analysis_id",
    )
    .bind(BATCH)
    .fetch_all(pool)
    .await?;
    let mut posted = 0;
    for analysis in due {
        let (target, content) = content(pool, analysis, public_url).await?;
        let app = app.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            app.create_check_run(&target.repository, &content.check_run(&target.head_sha))?;
            app.upsert_comment(
                &target.repository,
                target.number,
                &content.marker(),
                &content.comment(),
            )
        })
        .await
        .unwrap_or_else(|e| Err(anyhow::anyhow!("the posting task failed: {e}")));
        match outcome {
            Ok(()) => {
                sqlx::query(
                    "UPDATE decorations SET state = 'posted', posted_at = now(), last_error = NULL
                     WHERE analysis_id = $1",
                )
                .bind(analysis)
                .execute(pool)
                .await?;
                posted += 1;
            }
            Err(e) => {
                let error = format!("{e:#}");
                tracing::warn!(analysis, error = %error, "decorating a pull request failed");
                // Backoff doubles from a minute, up to an hour; after a day,
                // it's given up.
                sqlx::query(
                    "UPDATE decorations SET last_error = $2,
                         state = CASE WHEN queued_at < now() - make_interval(hours => $3)
                                      THEN 'failed' ELSE 'pending' END,
                         next_at = now() + least(interval '1 hour',
                                                 interval '1 minute' * power(2, attempts - 1))
                     WHERE analysis_id = $1",
                )
                .bind(analysis)
                .bind(&error)
                .bind(RETRY_FOR_HOURS)
                .execute(pool)
                .await?;
            }
        }
    }
    Ok(posted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issue(severity: &str, category: &str, line: i32) -> NewIssue {
        NewIssue {
            rule: "js/no-eval".into(),
            severity: severity.into(),
            category: category.into(),
            message: "Remove this use of eval().".into(),
            path: "src/a.js".into(),
            line,
            end_line: None,
        }
    }

    fn content(gate: &'static str, issues: Vec<NewIssue>) -> Content {
        Content {
            project: "shop".into(),
            analysis: 7,
            gate,
            failing: if gate == "failed" {
                vec!["New vulnerabilities > 0".into()]
            } else {
                vec![]
            },
            lacking: if gate == "partial" {
                vec!["Coverage on new code < 80%: no data (no coverage report)".into()]
            } else {
                vec![]
            },
            new_issues: issues,
            new_coverage: Some(76.84),
            new_duplication: None,
            url: Some("https://sonda.example.com/analyses/7".into()),
        }
    }

    #[test]
    fn the_summary_says_the_gate_the_new_issues_and_where_to_look() {
        let c = content(
            "failed",
            vec![
                issue("critical", "vulnerability", 2),
                issue("minor", "code_smell", 9),
            ],
        );
        let s = c.summary();
        assert!(
            s.starts_with("**Quality gate failed: 1 condition**\n\n- ✕ New vulnerabilities > 0\n"),
            "{s}"
        );
        assert!(
            s.contains("**2 new issues**: 1 vulnerability, 1 code smell (1 critical, 1 minor)."),
            "{s}"
        );
        assert!(s.contains("Coverage on new code: 76.8%"), "{s}");
        assert!(!s.contains("Duplication"), "{s}");
        assert!(
            s.contains("[See the analysis on sonda](https://sonda.example.com/analyses/7)"),
            "{s}"
        );
        assert!(c.comment().starts_with("<!-- sonda:project=shop -->\n"));
        assert_eq!(
            content("passed", vec![]).summary().lines().nth(2),
            Some("No new issues.")
        );
    }

    #[test]
    fn a_partial_gate_says_which_conditions_had_no_data_and_why() {
        let c = content("partial", vec![]);
        assert_eq!(
            c.check_run("abc")["output"]["title"],
            "Quality gate passed, but 1 condition couldn't be checked"
        );
        assert!(
            c.summary().starts_with(
                "**Quality gate passed, but 1 condition couldn't be checked**\n\n\
                 - – Coverage on new code < 80%: no data (no coverage report)\n\nNo new issues.\n"
            ),
            "{}",
            c.summary()
        );
    }

    #[test]
    fn the_check_run_follows_the_gate_and_annotates_at_most_fifty() {
        let c = content(
            "failed",
            (1..=60).map(|l| issue("major", "bug", l)).collect(),
        );
        let run = c.check_run("abc");
        assert_eq!(
            (&run["name"], &run["head_sha"]),
            (&json!("sonda"), &json!("abc"))
        );
        assert_eq!(run["conclusion"], "failure");
        let annotations = run["output"]["annotations"].as_array().unwrap();
        assert_eq!(annotations.len(), MAX_ANNOTATIONS);
        assert_eq!(annotations[0]["annotation_level"], "warning");
        assert_eq!(
            (&annotations[0]["start_line"], &annotations[0]["end_line"]),
            (&json!(1), &json!(1))
        );
        assert!(
            run["output"]["summary"]
                .as_str()
                .unwrap()
                .contains("annotates the first 50")
        );
        assert_eq!(run["details_url"], "https://sonda.example.com/analyses/7");
        assert_eq!(
            content("partial", vec![]).check_run("abc")["conclusion"],
            "neutral"
        );
        assert_eq!(
            content("passed", vec![]).check_run("abc")["conclusion"],
            "success"
        );
    }
}
