/**
 * The Sonda API contract the web app is built against.
 *
 * `api/http` implements it against `sonda server`; `api/mock` implements it
 * in memory for development and tests, seeded from the design prototypes.
 * Names follow sonda's own model (crates/sonda-core/src/model.rs).
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
  /** Null where the server cannot count it yet. */
  projectCount: number | null
}

export interface User {
  name: string
  handle: string
  initials: string
}

/** Null where the server cannot count it yet; the shell then shows nothing. */
export interface NavCounts {
  projects: number | null
  components: number | null
  issues: number | null
  security: number | null
}

export interface Shell {
  org: Org
  user: User
  counts: NavCounts
  /** The name "Assign to me" uses; null until the viewer gives one at sign-in. */
  me: string | null
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
  /** Null without data, e.g. no coverage uploaded. */
  level: Level | null
  score: number | null
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
  /** Null when no coverage is uploaded. */
  coverage: number | null
  newIssues: number
  /** Open issues over the last 30 days. */
  trend: number[]
  components?: ProjectHealth[]
}

export interface GateDay {
  date: string
  /** Null on days without an analysis. */
  passRate: number | null
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
  /** Null where unknown: commit messages and durations are not uploaded. */
  message: string | null
  note: string
  duration: string | null
  ago: string
  /** 0–100 while running. */
  progress?: number
}

export interface Overview {
  /** Whether teams exist, so the "My team" scope means something. */
  teams: boolean
  summary: { projects: number; components: number | null; lastSounding: string }
  focus: FocusItem[]
  focusTotal: number
  /** `delta` is null until the server keeps ratings history. */
  health: { score: number; delta: string | null; dimensions: HealthDimension[] }
  kpis: Kpi[]
  flow: FlowBucket[]
  severities: SeverityCount[]
  projects: ProjectHealth[]
  projectTotal: number
  /** `rate` is null without analyses in the range; `delta` without a previous range. */
  gateHistory: { rate: number | null; delta: number | null; days: GateDay[]; failing: FailingCondition[] }
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
  /** Tokens with a highlight role; the server tokenizes, so the browser needs no highlighter. */
  tokens: { text: string; role: TokenRole }[]
}

/** Status a person can set. `fixed` is decided by analyses, never set. */
export type TriageStatus = Exclude<IssueStatus, 'fixed'>

export type FacetKey = 'severity' | 'category' | 'status' | 'component'

/** Filters and paging for `issues()`. Empty lists match everything. */
export interface IssueQuery {
  severity: Severity[]
  category: Category[]
  status: IssueStatus[]
  /** Top-level directories; `.` is the project root. */
  component: string[]
  /** Any part of the path. */
  file: string
  assignee?: string
  isNew: boolean
  offset: number
  limit: number
}

export interface IssueSummary {
  id: number
  /** The fingerprint: stable across analyses. */
  key: string
  project: string
  branch: string
  severity: Severity
  category: Category
  rule: string
  message: string
  component: string
  file: string
  line: number
  endLine: number
  /** Language id as in reports (`javascript`, `tsx`, ...). */
  language: string | null
  effortMinutes: number
  status: IssueStatus
  assignee: string | null
  isNew: boolean
  /** When the analysis that first saw it arrived (ISO 8601). */
  detectedAt: string
}

export interface IssuePage {
  total: number
  offset: number
  limit: number
  items: IssueSummary[]
  /** Count per value, each facet ignoring its own selection. */
  facets: Record<FacetKey, Record<string, number>>
}

export interface IssueEvent {
  at: string
  field: 'status' | 'assignee'
  oldValue: string | null
  newValue: string | null
}

export interface IssueDetail extends IssueSummary {
  ruleName: string | null
  ruleDescription: string | null
  noncompliant: string | null
  compliant: string | null
  /** The code around the issue, as of the latest analysis that saw it. */
  code: CodeLine[]
  history: IssueEvent[]
}

export interface IssuePatch {
  status?: TriageStatus
  /** `''` unassigns. */
  assignee?: string
}

// ------------------------------------------------------------------- rules

/** A rule of sonda's catalog. Read-only: rules are configured per repository in sonda.toml. */
export interface Rule {
  id: string
  name: string
  description: string
  /** Language ids, as in reports. */
  languages: string[]
  category: Category
  severity: Severity
  effortMinutes: number
  /** Open or confirmed issues on each project's main branch. */
  openIssues: number
  projects: number
  tags: string[]
  noncompliant: string | null
  compliant: string | null
}

export interface RuleCatalog {
  total: number
  languages: { id: string; rules: number }[]
  rules: Rule[]
}

// ----------------------------------------------------------------- session

export interface Session {
  authenticated: boolean
  /** Whether anything can be read before signing in. */
  readsRequireAuth: boolean
}

// ------------------------------------------------------------------ client

export interface SondaApi {
  session(): Promise<Session>
  /** Exchanges the API token for a session cookie; rejects with `AuthError` if wrong. */
  signIn(token: string): Promise<void>
  signOut(): Promise<void>
  shell(): Promise<Shell>
  /** Absent until the server keeps analysis history for it (ADR-0005, phase 3). */
  overview?(scope: Scope, range: Range): Promise<Overview>
  drill?(metric: DrillMetric, scope: Scope): Promise<Drill>
  issues(query: IssueQuery): Promise<IssuePage>
  issue(id: number): Promise<IssueDetail>
  updateIssue(id: number, patch: IssuePatch): Promise<IssueDetail>
  rules(): Promise<RuleCatalog>
}

/** The session is missing or expired: the app shows sign-in again. */
export class AuthError extends Error {
  constructor(message = 'Sign in to continue') {
    super(message)
    this.name = 'AuthError'
  }
}
