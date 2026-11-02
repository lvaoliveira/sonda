import type { GateConditionInput, GateMetric, GateState, QualityGate } from '../types'
import { PROJECT_LIST } from './projects'

const NOW = Date.parse('2026-10-30T09:41:00Z')
const at = (hours: number) => new Date(NOW - hours * 3_600_000).toISOString()

function evaluations(projects: string[], failEvery: number): QualityGate['evaluations'] {
  return Array.from({ length: 40 }, (_, i) => ({
    analysis: 1_000 - i,
    project: projects[i % projects.length],
    state: (i % failEvery === 0 ? 'failed' : 'passed') as GateState,
    analyzedAt: at(i * 5),
  }))
}

const STRICT = ['payments-platform', 'billing-service']

/** Two gates over the mock projects: the default, and a stricter one. */
export const GATES: QualityGate[] = [
  {
    id: '9b1c2d3e',
    name: 'Default',
    isDefault: true,
    server: null,
    conditions: [
      { label: 'New bugs > 0', metric: 'new_bugs', op: 'gt', threshold: 0, failing: 1, noData: 0 },
      { label: 'New vulnerabilities > 0', metric: 'new_vulnerabilities', op: 'gt', threshold: 0, failing: 2, noData: 0 },
      { label: 'Coverage on new code < 80%', metric: 'new_coverage', op: 'lt', threshold: 80, failing: 2, noData: 1 },
      { label: 'Duplication on new code > 3%', metric: 'new_duplicated_lines_density', op: 'gt', threshold: 3, failing: 0, noData: 0 },
    ],
    projects: PROJECT_LIST.projects.filter((p) => !STRICT.includes(p.key)).map((p) => ({ project: p.key, state: p.gate, analyzedAt: p.analyzedAt })),
    evaluations: evaluations(['ml-feature-store', 'mobile-bff', 'data-pipeline', 'inventory-service'], 4),
    passRate: 75,
    mostCommonFailure: 'Coverage on new code < 80%',
  },
  {
    id: '4f7a0c21',
    name: 'Custom gate 1',
    isDefault: false,
    server: null,
    conditions: [
      { label: 'New vulnerabilities > 0', metric: 'new_vulnerabilities', op: 'gt', threshold: 0, failing: 2, noData: 0 },
      { label: 'New critical issues > 0', metric: 'new_critical_issues', op: 'gt', threshold: 0, failing: 1, noData: 0 },
      { label: 'Coverage on new code < 85%', metric: 'new_coverage', op: 'lt', threshold: 85, failing: 2, noData: 0 },
      { label: 'Coverage < 70%', metric: 'coverage', op: 'lt', threshold: 70, failing: 2, noData: 0 },
      { label: 'Duplication on new code > 3%', metric: 'new_duplicated_lines_density', op: 'gt', threshold: 3, failing: 0, noData: 0 },
      { label: 'New blocker issues > 0', metric: 'new_blocker_issues', op: 'gt', threshold: 0, failing: 0, noData: 0 },
    ],
    projects: PROJECT_LIST.projects.filter((p) => STRICT.includes(p.key)).map((p) => ({ project: p.key, state: p.gate, analyzedAt: p.analyzedAt })),
    evaluations: evaluations(STRICT, 2),
    passRate: 50,
    mostCommonFailure: 'New vulnerabilities > 0',
  },
]

/** As GET /api/gates lists them: sonda-core's metrics. */
const METRIC_IDS = [
  'files', 'lines', 'ncloc', 'functions', 'complexity', 'cognitive_complexity', 'issues', 'bugs', 'vulnerabilities', 'code_smells',
  'blocker_issues', 'critical_issues', 'major_issues', 'debt_minutes', 'duplicated_lines', 'duplicated_lines_density', 'coverage',
  'new_lines', 'new_issues', 'new_bugs', 'new_vulnerabilities', 'new_code_smells', 'new_blocker_issues', 'new_critical_issues',
  'new_major_issues', 'new_debt_minutes', 'new_duplicated_lines', 'new_duplicated_lines_density', 'new_coverage',
  'vulnerable_dependencies', 'severe_vulnerable_dependencies', 'new_vulnerable_dependencies', 'new_severe_vulnerable_dependencies',
]
const NAMED: Record<string, string> = {
  new_coverage: 'Coverage on new code',
  new_duplicated_lines_density: 'Duplication on new code',
  duplicated_lines_density: 'Duplication',
  ncloc: 'Lines of code',
}
export const METRICS: GateMetric[] = METRIC_IDS.map((id) => ({
  id,
  name: NAMED[id] ?? id.charAt(0).toUpperCase() + id.slice(1).replaceAll('_', ' '),
  percent: id.includes('coverage') || id.includes('density'),
}))

/** "Coverage on new code < 90%", as the server labels a condition. */
export function conditionLabel(c: GateConditionInput): string {
  const m = METRICS.find((x) => x.id === c.metric)
  return `${m?.name ?? c.metric} ${c.op === 'gt' ? '>' : '<'} ${c.threshold}${m?.percent ? '%' : ''}`
}
