/**
 * The Sonda API contract the web app is built against.
 *
 * Today it is served by the mock adapter (api/mock), seeded from the design
 * prototypes. The planned `sonda server` will implement the same contract;
 * names follow sonda's own model (src/model.rs) where one exists.
 */

export type Severity = 'blocker' | 'critical' | 'major' | 'minor' | 'info'
export type Category = 'bug' | 'vulnerability' | 'code_smell'
/** Rating as a level from 1 (worst) to 5 (best); shown as pip meters, never letters. */
export type Level = 1 | 2 | 3 | 4 | 5
export type GateState = 'passed' | 'failed' | 'running' | 'partial'
export type IssueStatus = 'open' | 'confirmed' | 'fixed' | 'accepted'
export type Scope = 'all' | 'mine'
export type Range = '7d' | '30d' | '90d'
export type DrillMetric = 'gate' | 'critical' | 'vulns' | 'coverage' | 'dup' | 'debt'

export interface Org {
  name: string
  initials: string
  deployment: string
  projectCount: number
}

export interface User {
  name: string
  handle: string
  initials: string
}

export interface NavCounts {
  projects: number
  components: number
  issues: number
  security: number
}

export interface Shell {
  org: Org
  user: User
  counts: NavCounts
}

// ---------------------------------------------------------------- overview

export interface FocusItem {
  severity: Severity
  tag: string
  title: string
  body: string
  /** Breadcrumb-like trail: project › component · detail. */
  trail: { text: string; emphasis: 'muted' | 'strong' | 'faint' }[]
  cta: string
  drill: DrillMetric
}

export interface HealthDimension {
  label: 'Reliability' | 'Security' | 'Maintainability' | 'Coverage'
  level: Level
  score: number
  note: string
  drill: DrillMetric
}

export interface Kpi {
  metric: DrillMetric
  label: string
  value: string
  unit: string
  delta: string
  /** Whether the change is an improvement. */
  improving: boolean
  sub: string
  series: number[]
}

export interface FlowBucket {
  /** ISO date of the bucket start. */
  date: string
  introduced: number
  resolved: number
  open: number
}

export interface SeverityCount {
  severity: Severity
  open: number
  newThisPeriod: number
}

export interface ProjectHealth {
  name: string
  sub: string
  /** "7 components" for monorepos. */
  badge?: string
  gate: GateState
  reliability: Level
  security: Level
  maintainability: Level
  coverage: number
  newIssues: number
  /** Open issues over the last 30 days. */
  trend: number[]
  components?: ProjectHealth[]
}

export interface GateDay {
  date: string
  passRate: number
}

export interface FailingCondition {
  label: string
  failures: number
}

export interface AnalysisSummary {
  state: GateState
  project: string
  branch: string
  sha: string
  message: string
  note: string
  duration: string
  ago: string
  /** 0–100 while running. */
  progress?: number
}

export interface Overview {
  summary: { projects: number; components: number; lastSounding: string }
  focus: FocusItem[]
  focusTotal: number
  health: { score: number; delta: string; dimensions: HealthDimension[] }
  kpis: Kpi[]
  flow: FlowBucket[]
  severities: SeverityCount[]
  projects: ProjectHealth[]
  projectTotal: number
  gateHistory: { rate: number; delta: number; days: GateDay[]; failing: FailingCondition[] }
  recent: AnalysisSummary[]
}

export interface DrillFile {
  dir: string
  base: string
  value: string
  issue?: { severity: Severity; title: string; line: number }
}

export interface DrillComponent {
  component: string
  project: string
  owner: string
  value: number
  files: DrillFile[]
}

export interface Drill {
  metric: DrillMetric
  title: string
  sub: string
  tone: 'crit' | 'warn' | 'info'
  cta: string
  unit: string
  /** Lower values are worse (coverage). */
  invert?: boolean
  items: DrillComponent[]
}

// ------------------------------------------------------------------ issues

export type TokenRole = 'keyword' | 'string' | 'number' | 'comment' | 'type' | 'punct' | 'plain'

export interface CodeLine {
  number: number
  /** Tokens with a highlight role; the server tokenizes (sonda already parses with tree-sitter). */
  tokens: { text: string; role: TokenRole }[]
}

export interface Issue {
  id: number
  key: string
  severity: Severity
  category: Category
  rule: string
  title: string
  component: string
  componentPath: string
  project: string
  file: string
  line: number
  language: string
  cwe?: string
  effortMinutes: number
  age: string
  detected: string
  status: IssueStatus
  assignee?: string
  isNew: boolean
  message: string
  why: string
  fix: string
  fixCode: string
  related: number[]
  code: { lines: CodeLine[]; highlighted: number[] }
}

export interface IssuePatch {
  status?: IssueStatus
  assignee?: string
}

// ------------------------------------------------------------------- rules

export interface RuleParam {
  key: string
  value: string
  description: string
}

export interface Rule {
  id: string
  name: string
  description: string
  language: string
  category: Category
  severity: Severity
  active: boolean
  openIssues: number
  projects: number
  tags: string[]
  noncompliant: string
  compliant: string
  params: RuleParam[]
}

export interface RuleCatalog {
  total: number
  languageCount: number
  activeCount: number
  profile: string
  languages: { name: string; rules: number }[]
  rules: Rule[]
}

// ------------------------------------------------------------------ client

export interface SondaApi {
  shell(): Promise<Shell>
  overview(scope: Scope, range: Range): Promise<Overview>
  drill(metric: DrillMetric, scope: Scope): Promise<Drill>
  issues(): Promise<Issue[]>
  updateIssue(id: number, patch: IssuePatch): Promise<Issue>
  rules(): Promise<RuleCatalog>
  setRuleActive(id: string, active: boolean): Promise<Rule>
  setRuleParam(id: string, key: string, value: string): Promise<Rule>
}
