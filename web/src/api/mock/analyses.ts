import type { AnalysisDetail, AnalysisPage, AnalysisQuery, AnalysisRow, GateState } from '../types'
import { PROJECT_LIST, projectDetail } from './projects'

const NOW = Date.parse('2026-10-30T09:41:00Z')

const MESSAGES = ['Fix refunds rounding for partial captures', 'Bump express to 4.21.2', 'Add retry to the ledger export', 'Split checkout handlers by tender']

/** Two analyses per mock project on main, plus a release branch, newest first. */
const ROWS: AnalysisRow[] = PROJECT_LIST.projects
  .flatMap((p, i) => [
    { offset: i * 2, project: p.key, branch: 'main', gate: p.gate },
    { offset: i * 2 + 1, project: p.key, branch: i % 3 === 0 ? 'release/2.4' : 'main', gate: 'passed' as GateState },
  ])
  .map(({ offset, project, branch, gate }) => ({
    id: 911 + offset,
    project,
    branch,
    sha: offset === 0 ? '9f3c2a1e7b04' : `${(((offset + 1) * 2_654_435_761) >>> 0).toString(16).padStart(8, '0')}a1c3`,
    analyzedAt: new Date(NOW - offset * 2.5 * 3_600_000).toISOString(),
    // One without, as an upload from outside git has.
    message: offset === 3 ? null : MESSAGES[offset % MESSAGES.length],
    toolVersion: '0.1.0',
    gate,
    failing: gate === 'failed' ? ['New vulnerabilities > 0', 'Coverage on new code < 80%'] : [],
    issues: 120 - offset,
    newIssues: gate === 'failed' ? 14 : 0,
    warnings: offset % 4 === 0 ? 2 : 0,
  }))

export function queryAnalyses(q: AnalysisQuery): AnalysisPage {
  const matching = ROWS.filter(
    (r) =>
      (!q.project || r.project === q.project) &&
      (!q.branch || r.branch === q.branch) &&
      (!q.gate || (q.gate === 'failed' ? r.gate === 'failed' : r.gate !== 'failed')),
  )
  return { total: matching.length, offset: q.offset, limit: q.limit, items: matching.slice(q.offset, q.offset + q.limit) }
}

/** Older analyses (a project page's history) that the list doesn't page through. */
function olderRow(id: number): AnalysisRow | null {
  if (id < 900 || id >= 911) return null
  const base = ROWS[0]
  return { ...base, id, sha: (0x9f3c2a1 + (id - 900) * 7919).toString(16), gate: id % 4 === 1 ? 'failed' : 'passed', warnings: 0 }
}

export function analysisDetail(id: number): AnalysisDetail | null {
  const row = ROWS.find((r) => r.id === id) ?? olderRow(id)
  if (!row) return null
  const project = projectDetail(row.project)!
  const same = ROWS.filter((r) => r.project === row.project && r.branch === row.branch)
  const at = same.findIndex((r) => r.id === row.id)
  // The newest analysis continues the older, synthesized history.
  const previous = at < 0 ? olderRow(id - 1) : (same[at + 1] ?? (row.id === ROWS[0].id ? olderRow(910) : null))
  const next = at < 0 ? (olderRow(id + 1) ?? same[same.length - 1] ?? null) : (same[at - 1] ?? null)
  const failing = row.gate === 'failed'
  return {
    id: row.id,
    project: row.project,
    branch: row.branch,
    mainBranch: 'main',
    sha: row.sha,
    message: row.message,
    analyzedAt: row.analyzedAt,
    toolVersion: row.toolVersion,
    newCodeReference: 'origin/main',
    gate: failing ? project.gate : { state: 'passed', conditions: project.gate.conditions.map((c) => ({ ...c, status: 'ok' })) },
    measures: project.measures,
    files: 3_912,
    languages: project.languages.map((l, k) => ({ id: l.id, files: Math.round(2_000 / 2 ** k) })),
    components: project.components.length,
    warnings: row.warnings
      ? [
          'services/fraud-scoring/notebooks/explore.py: contains syntax errors; results may be incomplete',
          'packages/sdk-js/dist/bundle.js: skipped, looks minified (average line over 200 characters; scan.skip_minified = false analyzes it)',
        ]
      : [],
    baseline: previous == null,
    introduced: failing
      ? {
          total: 14,
          bySeverity: { critical: 2, major: 5, minor: 7 },
          items: [
            { id: 1, severity: 'critical', category: 'vulnerability', rule: 'js/no-eval', message: 'Remove this use of eval().', path: 'services/checkout-api/handlers.js', line: 88 },
            { id: 2, severity: 'critical', category: 'vulnerability', rule: 'js/tls-unverified', message: "Remove 'rejectUnauthorized: false'.", path: 'services/checkout-api/client.js', line: 14 },
            { id: 3, severity: 'major', category: 'bug', rule: 'js/eqeqeq', message: "Use '===' or '!==' instead.", path: 'packages/web-checkout/cart.ts', line: 41 },
          ],
        }
      : { total: 0, bySeverity: {}, items: [] },
    fixed: {
      total: 6,
      bySeverity: { major: 2, minor: 4 },
      items: [{ id: 4, severity: 'major', category: 'code_smell', rule: 'js/no-var', message: "Use 'let' or 'const' instead of 'var'.", path: 'services/ledger/index.js', line: 3 }],
    },
    previous: previous && { id: previous.id, sha: previous.sha },
    next: next && { id: next.id, sha: next.sha },
  }
}
