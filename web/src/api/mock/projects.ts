import type { GateState, Level, NewCodePeriod, ProjectDetail, ProjectHistoryPoint, ProjectList, ProjectRow } from '../types'
import { DEPENDENCY_SUMMARY } from './dependencies'

type Row = [key: string, languages: string[], gate: GateState, levels: [Level, Level, Level], coverage: number | null, dup: number, issues: number, ncloc: number, hoursAgo: number]

/** The mock Overview's projects, plus a few healthy ones. */
const ROWS: Row[] = [
  ['payments-platform', ['go', 'rust', 'typescript', 'python'], 'failed', [3, 1, 4], 69.8, 3.4, 131, 412_000, 0.2],
  ['billing-service', ['java'], 'failed', [4, 1, 3], 58.4, 4.1, 214, 188_000, 3],
  ['ml-feature-store', ['python'], 'failed', [3, 4, 2], 41.7, 5.6, 173, 97_000, 2],
  ['mobile-bff', ['typescript'], 'failed', [3, 3, 4], 63.1, 2.2, 71, 54_000, 26],
  ['data-pipeline', ['python'], 'partial', [4, 3, 3], 52.3, 1.9, 64, 120_000, 5],
  ['inventory-service', ['java'], 'passed', [4, 4, 3], 66.0, 1.2, 96, 76_000, 30],
  ['search-indexer', ['rust'], 'passed', [5, 5, 5], 91.0, 0.3, 11, 64_000, 24],
  ['docs-site', ['typescript', 'javascript'], 'partial', [5, 5, 4], null, 0.8, 7, 12_000, 120],
]

const NOW = Date.parse('2026-10-30T09:41:00Z')

function score(levels: Level[], coverage: number | null): number {
  const ratings = levels.reduce((s, l) => s + l, 0) / 15
  return Math.round(coverage == null ? ratings * 100 : ratings * 70 + coverage * 0.3)
}

const projects: ProjectRow[] = ROWS.map(([key, languages, gate, [reliability, security, maintainability], coverage, duplication, issues, ncloc, hoursAgo]) => ({
  key,
  mainBranch: 'main',
  languages,
  gate,
  score: score([reliability, security, maintainability], coverage),
  reliability,
  security,
  maintainability,
  coverage,
  duplication,
  issues,
  ncloc,
  analyzedAt: new Date(NOW - hoursAgo * 3_600_000).toISOString(),
}))

export const PROJECT_LIST: ProjectList = {
  projects,
  languages: ['python', 'java', 'go', 'typescript', 'rust', 'javascript'],
}

/** A plausible project page for any listed project; null for unknown keys. */
export function projectDetail(key: string, branch?: string): ProjectDetail | null {
  const p = projects.find((r) => r.key === key)
  if (!p) return null
  const branches = [
    { name: 'main', gate: p.gate, ago: '12m' },
    { name: 'release/2.4', gate: 'passed' as GateState, ago: '2d' },
  ]
  const on = branch ?? p.mainBranch
  if (!branches.some((b) => b.name === on)) throw new Error(`branch "${on}" has no analyses; analyzed branches: main, release/2.4`)
  // Only the main branch fails; the release branch passes.
  const failing = p.gate === 'failed' && on === 'main'
  const history = Array.from({ length: 12 }, (_, i) => ({
    id: 900 + i,
    sha: (0x9f3c2a1 + i * 7919).toString(16),
    analyzedAt: new Date(NOW - (11 - i) * 86_400_000).toISOString(),
    // payments-platform sends versions; 2.4.0 started a new code period.
    version: p.key === 'payments-platform' ? (i < 7 ? '2.3.0' : '2.4.0') : null,
    gate: (i === 11 ? p.gate : i % 4 === 1 ? 'failed' : 'passed') as GateState,
    issues: p.issues - 11 + i + (i % 3),
    coverage: p.coverage == null ? null : Math.round((p.coverage - 1.5 + i * 0.12) * 10) / 10,
    duplication: Math.round((p.duplication ?? 0) * 10 + (i % 4) - 1) / 10,
    debtMinutes: 9_000 + i * 140,
  }))
  const dirs = p.key === 'payments-platform' ? ['services', 'packages', 'proto', 'tools'] : ['src', 'test', 'scripts']
  return {
    key: p.key,
    mainBranch: p.mainBranch,
    branch: on,
    branches,
    languages: p.languages.map((id, i) => ({ id, ncloc: Math.round(p.ncloc / 2 ** (i + 1)) })),
    analysis: { id: 911, sha: '9f3c2a1e7b04', analyzedAt: p.analyzedAt, toolVersion: '0.1.0', newCodeReference: 'origin/main', version: history[history.length - 1].version },
    gate: {
      state: failing ? 'failed' : on === 'main' ? p.gate : 'passed',
      conditions: [
        { label: 'New bugs > 0', metric: 'new_bugs', actual: 0, status: 'ok' },
        { label: 'New vulnerabilities > 0', metric: 'new_vulnerabilities', actual: failing ? 2 : 0, status: failing ? 'error' : 'ok' },
        { label: 'Coverage on new code < 80%', metric: 'new_coverage', actual: p.coverage == null ? null : 76.8, status: p.coverage == null ? 'no_data' : failing ? 'error' : 'ok' },
        { label: 'Duplication on new code > 3%', metric: 'new_duplicated_lines_density', actual: 1.4, status: 'ok' },
      ],
    },
    score: p.score,
    ratings: {
      reliability: p.reliability,
      security: p.security,
      maintainability: p.maintainability,
      coverage: p.coverage == null ? null : ((p.coverage >= 80 ? 5 : p.coverage >= 70 ? 4 : p.coverage >= 60 ? 3 : p.coverage >= 50 ? 2 : 1) as Level),
    },
    measures: {
      overall: { lines: p.ncloc, issues: p.issues, bugs: 18, vulnerabilities: failing ? 5 : 0, codeSmells: p.issues - 18, coverage: p.coverage, duplication: p.duplication, debtMinutes: 10_540 },
      newCode: { lines: 1_240, issues: 6, bugs: 1, vulnerabilities: failing ? 2 : 0, codeSmells: 3, coverage: p.coverage == null ? null : 76.8, duplication: 1.4, debtMinutes: 95 },
    },
    history,
    components: dirs.map((path, i) => ({
      path,
      languages: p.languages.slice(0, Math.max(1, p.languages.length - i)),
      files: 120 - i * 30,
      ncloc: Math.round(p.ncloc / 2 ** (i + 1)),
      owner: i === 0 ? '@checkout' : i === 1 ? '@web-platform' : null,
      issues: Math.max(0, Math.round(p.issues / 2 ** (i + 1))),
      debtMinutes: 4_000 / (i + 1),
    })),
    // A release branch analyzed before lockfiles were read.
    dependencies: on === p.mainBranch ? DEPENDENCY_SUMMARY : null,
    newCodePeriod: on === p.mainBranch ? newCodePeriod(p.key, history) : null,
  }
}

/** Where each project's new code starts, when an admin moved it. */
const PERIODS = new Map<string, number>()

/** As the server does: an admin's start, else the first analysis of the latest version. */
function newCodePeriod(key: string, history: ProjectHistoryPoint[]): NewCodePeriod {
  const moved = history.find((h) => h.id === PERIODS.get(key))
  const latest = history.findLast((h) => h.version != null)?.version
  const change = history.findLastIndex((h) => h.version != null && h.version !== latest)
  const byVersion = change < 0 ? undefined : history.find((h, i) => i > change && h.version === latest)
  const start = moved ?? byVersion ?? history[0]
  return {
    analysis: start.id,
    sha: start.sha,
    analyzedAt: start.analyzedAt,
    reset: moved !== undefined,
    version: moved ? null : (byVersion?.version ?? null),
    // Projects without coverage keep the scan's (empty) value.
    fromScan: key === 'payments-platform' ? ['new_duplicated_lines_density'] : ['new_coverage', 'new_duplicated_lines_density'],
  }
}

/** As the server does: admins only, and only an analysis of the main branch. */
export function setNewCodePeriod(key: string, analysis: number | null): NewCodePeriod {
  const p = projectDetail(key)
  if (!p) throw new Error('not found')
  if (analysis === null) PERIODS.delete(key)
  else if (p.history.some((h) => h.id === analysis)) PERIODS.set(key, analysis)
  else throw new Error('the new code period starts at an analysis of the project’s main branch')
  return newCodePeriod(key, p.history)
}
