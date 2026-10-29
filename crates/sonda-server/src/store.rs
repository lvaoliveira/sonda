//! Infrastructure: stores a validated analysis and tracks its issues across
//! the branch's analyses, in one transaction.

use crate::ingest::Analysis;
use serde::Serialize;
use sqlx::PgPool;

#[derive(Debug, Serialize)]
pub struct Summary {
    pub analysis_id: i64,
    pub issues: IssueCounts,
}

#[derive(Debug, Serialize)]
pub struct IssueCounts {
    /// Present in this analysis.
    pub open: u64,
    /// Seen for the first time.
    pub new: u64,
    /// Seen before, marked fixed, and back now.
    pub reopened: u64,
    /// Present in the previous analysis, gone from this one.
    pub fixed: u64,
}

/// Records `a` as the branch's latest analysis. Issues are matched to the
/// branch's tracked issues by fingerprint:
/// - an unknown fingerprint is a new issue;
/// - a known one is updated to its latest location and message, and
///   reopened if it was fixed, keeping its human status (accepted stays
///   accepted);
/// - a tracked issue missing from this analysis is marked fixed.
///
/// Analyses are ordered by arrival, not by commit date.
pub async fn ingest(pool: &PgPool, a: Analysis) -> Result<Summary, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let project_id: i64 = sqlx::query_scalar(
        "INSERT INTO projects (key) VALUES ($1)
         ON CONFLICT (key) DO UPDATE SET key = EXCLUDED.key
         RETURNING id",
    )
    .bind(&a.meta.project)
    .fetch_one(&mut *tx)
    .await?;
    // One ingestion per branch at a time, so concurrent uploads cannot both
    // see an issue as present (or both mark it fixed). Released at commit.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text || E'\\n' || $2, 0))")
        .bind(project_id)
        .bind(&a.meta.branch)
        .execute(&mut *tx)
        .await?;

    let analysis_id: i64 = sqlx::query_scalar(
        "INSERT INTO analyses (project_id, branch, commit_sha, tool_version,
             new_code_reference, measures, gate, gate_passed, warnings)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         RETURNING id",
    )
    .bind(project_id)
    .bind(&a.meta.branch)
    .bind(&a.meta.commit)
    .bind(&a.tool_version)
    .bind(&a.new_code_reference)
    .bind(&a.measures)
    .bind(&a.gate)
    .bind(a.gate_passed)
    .bind(serde_json::json!(a.warnings))
    .fetch_one(&mut *tx)
    .await?;

    let (shas, contents): (Vec<Vec<u8>>, Vec<String>) = a
        .sources
        .into_iter()
        .map(|(sha, content)| (sha.to_vec(), content))
        .unzip();
    sqlx::query(
        "INSERT INTO sources (sha256, content)
         SELECT * FROM UNNEST($1::bytea[], $2::text[])
         ON CONFLICT (sha256) DO NOTHING",
    )
    .bind(shas)
    .bind(contents)
    .execute(&mut *tx)
    .await?;

    let mut paths = Vec::with_capacity(a.files.len());
    let mut languages = Vec::with_capacity(a.files.len());
    let mut file_shas = Vec::with_capacity(a.files.len());
    let mut metrics = Vec::with_capacity(a.files.len());
    for f in a.files {
        paths.push(f.path);
        languages.push(f.language);
        file_shas.push(f.sha256.to_vec());
        metrics.push(f.metrics);
    }
    sqlx::query(
        "INSERT INTO analysis_files (analysis_id, path, language, sha256, metrics)
         SELECT $1, * FROM UNNEST($2::text[], $3::text[], $4::bytea[], $5::jsonb[])",
    )
    .bind(analysis_id)
    .bind(paths)
    .bind(languages)
    .bind(file_shas)
    .bind(metrics)
    .execute(&mut *tx)
    .await?;

    let n = a.issues.len();
    let mut cols = IssueColumns::with_capacity(n);
    for i in a.issues {
        cols.push(i);
    }
    let reopened: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM issues
         WHERE project_id = $1 AND branch = $2 AND fingerprint = ANY($3)
           AND fixed_analysis_id IS NOT NULL",
    )
    .bind(project_id)
    .bind(&a.meta.branch)
    .bind(&cols.fingerprint)
    .fetch_one(&mut *tx)
    .await?;
    let inserted: Vec<bool> = sqlx::query_scalar(
        "INSERT INTO issues (project_id, branch, fingerprint, rule, severity, category,
             message, path, line, col, end_line, end_col, effort_minutes, is_new,
             first_analysis_id, last_analysis_id)
         SELECT $1, $2, u.*, $3, $3
         FROM UNNEST($4::bytea[], $5::text[], $6::text[], $7::text[], $8::text[],
                     $9::text[], $10::int4[], $11::int4[], $12::int4[], $13::int4[],
                     $14::int4[], $15::bool[]) AS u
         ON CONFLICT (project_id, branch, fingerprint) DO UPDATE SET
             rule = EXCLUDED.rule, severity = EXCLUDED.severity,
             category = EXCLUDED.category, message = EXCLUDED.message,
             path = EXCLUDED.path, line = EXCLUDED.line, col = EXCLUDED.col,
             end_line = EXCLUDED.end_line, end_col = EXCLUDED.end_col,
             effort_minutes = EXCLUDED.effort_minutes, is_new = EXCLUDED.is_new,
             last_analysis_id = EXCLUDED.last_analysis_id,
             fixed_analysis_id = NULL
         RETURNING (xmax = 0)",
    )
    .bind(project_id)
    .bind(&a.meta.branch)
    .bind(analysis_id)
    .bind(cols.fingerprint)
    .bind(cols.rule)
    .bind(cols.severity)
    .bind(cols.category)
    .bind(cols.message)
    .bind(cols.path)
    .bind(cols.line)
    .bind(cols.col)
    .bind(cols.end_line)
    .bind(cols.end_col)
    .bind(cols.effort_minutes)
    .bind(cols.is_new)
    .fetch_all(&mut *tx)
    .await?;
    let fixed = sqlx::query(
        "UPDATE issues SET fixed_analysis_id = $3
         WHERE project_id = $1 AND branch = $2
           AND fixed_analysis_id IS NULL AND last_analysis_id <> $3",
    )
    .bind(project_id)
    .bind(&a.meta.branch)
    .bind(analysis_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    tx.commit().await?;

    Ok(Summary {
        analysis_id,
        issues: IssueCounts {
            open: n as u64,
            // `xmax = 0` is true for a freshly inserted row.
            new: inserted.iter().filter(|&&i| i).count() as u64,
            reopened: reopened as u64,
            fixed,
        },
    })
}

/// Issues as one array per column, for `UNNEST`.
struct IssueColumns {
    fingerprint: Vec<Vec<u8>>,
    rule: Vec<&'static str>,
    severity: Vec<&'static str>,
    category: Vec<&'static str>,
    message: Vec<String>,
    path: Vec<String>,
    line: Vec<i32>,
    col: Vec<i32>,
    end_line: Vec<i32>,
    end_col: Vec<i32>,
    effort_minutes: Vec<i32>,
    is_new: Vec<bool>,
}

impl IssueColumns {
    fn with_capacity(n: usize) -> Self {
        Self {
            fingerprint: Vec::with_capacity(n),
            rule: Vec::with_capacity(n),
            severity: Vec::with_capacity(n),
            category: Vec::with_capacity(n),
            message: Vec::with_capacity(n),
            path: Vec::with_capacity(n),
            line: Vec::with_capacity(n),
            col: Vec::with_capacity(n),
            end_line: Vec::with_capacity(n),
            end_col: Vec::with_capacity(n),
            effort_minutes: Vec::with_capacity(n),
            is_new: Vec::with_capacity(n),
        }
    }

    fn push(&mut self, i: crate::ingest::StoredIssue) {
        self.fingerprint.push(i.fingerprint.to_vec());
        self.rule.push(i.rule);
        self.severity.push(i.severity);
        self.category.push(i.category);
        self.message.push(i.message);
        self.path.push(i.path);
        self.line.push(i.line);
        self.col.push(i.col);
        self.end_line.push(i.end_line);
        self.end_col.push(i.end_col);
        self.effort_minutes.push(i.effort_minutes);
        self.is_new.push(i.is_new);
    }
}
