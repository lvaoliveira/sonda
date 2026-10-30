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

/** The viewer, as the shell shows them. */
export interface ShellUser {
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
  user: ShellUser
  /** Shows the administration screen. */
  isAdmin: boolean
  counts: NavCounts
  /** The username "Assign to me" uses; null when browsing read-only. */
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
  /** Opens the analysis page. */
  id: number
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
  /** Null where nothing records owners (sonda-server, for now). */
  owner: string | null
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
  /** A project key; all projects when absent. */
  project?: string
  /** A branch; each project's main branch when absent. */
  branch?: string
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
  /** Who made the change: a username, `api-token`, or null before users existed. */
  actor: string | null
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
  /** False for rules a repository must list in `rules.enabled`. */
  onByDefault: boolean
  /** Open or confirmed issues on each project's main branch. */
  openIssues: number
  projects: number
  tags: string[]
  /** CWE ids the rule relates to. */
  cwe: number[]
  /** OWASP Top 10 2025 categories, from the CWE ids. */
  owasp2025: { id: string; title: string }[]
  /** OWASP Top 10 2021 categories, as SonarQube reports them. */
  owasp2021: { id: string; title: string }[]
  noncompliant: string | null
  compliant: string | null
}

export interface RuleCatalog {
  total: number
  languages: { id: string; rules: number }[]
  rules: Rule[]
}

// ----------------------------------------------------------- users, session

export type Role = 'admin' | 'member'

export interface User {
  id: number
  /** Stable; also what issues are assigned to. */
  username: string
  displayName: string
  role: Role
  disabled: boolean
}

/** A user as admins see them. */
export interface UserRow extends User {
  hasPassword: boolean
  createdAt: string
  lastLoginAt: string | null
}

export interface NewUser {
  username: string
  displayName: string
  role: Role
  password: string
}

export interface UserPatch {
  displayName?: string
  role?: Role
  disabled?: boolean
  /** An admin's password reset. */
  password?: string
}

export interface Session {
  /** The signed-in user, or null. */
  user: User | null
  authenticated: boolean
  /** Whether anything can be read before signing in. */
  readsRequireAuth: boolean
}

/** Passwords need at least this many characters (ADR-0006). */
export const MIN_PASSWORD_LENGTH = 12

// ---------------------------------------------------------------- projects

/** A project as of its main branch's latest analysis. */
export interface ProjectRow {
  key: string
  mainBranch: string
  /** Languages by lines of code, most first. */
  languages: string[]
  gate: GateState
  score: number
  reliability: Level
  security: Level
  maintainability: Level
  /** Null without an uploaded coverage report. */
  coverage: number | null
  duplication: number | null
  /** Open and confirmed issues on the main branch. */
  issues: number
  ncloc: number
  analyzedAt: string
}

export interface ProjectList {
  projects: ProjectRow[]
  /** Every language in any project, most code first. */
  languages: string[]
}

export type ConditionStatus = 'ok' | 'error' | 'no_data'

export interface GateCondition {
  /** "New vulnerabilities > 0". */
  label: string
  metric: string
  actual: number | null
  status: ConditionStatus
}

/** Null where the analysis has no value: no coverage uploaded, or no new code. */
export interface MeasureSet {
  lines: number | null
  issues: number | null
  bugs: number | null
  vulnerabilities: number | null
  codeSmells: number | null
  coverage: number | null
  duplication: number | null
  debtMinutes: number | null
}

export interface ProjectHistoryPoint {
  id: number
  sha: string
  analyzedAt: string
  gate: GateState
  issues: number | null
  coverage: number | null
  duplication: number | null
  debtMinutes: number | null
}

/** A project's top-level directory. */
export interface ProjectComponent {
  path: string
  languages: string[]
  files: number
  ncloc: number
  /** From the CODEOWNERS file uploaded with the analysis. */
  owner: string | null
  issues: number
  debtMinutes: number
}

export interface ProjectDetail {
  key: string
  mainBranch: string
  branch: string
  /** The main branch first. */
  branches: { name: string; gate: GateState; ago: string }[]
  languages: { id: string; ncloc: number }[]
  analysis: { id: number; sha: string; analyzedAt: string; toolVersion: string; newCodeReference: string | null }
  gate: { state: GateState; conditions: GateCondition[] }
  score: number
  ratings: { reliability: Level; security: Level; maintainability: Level; coverage: Level | null }
  measures: { overall: MeasureSet; newCode: MeasureSet }
  /** The branch's latest analyses, oldest first. */
  history: ProjectHistoryPoint[]
  components: ProjectComponent[]
  /** From the analysis's lockfiles; null when it recorded none. */
  dependencies: DependencySummary | null
}

// ------------------------------------------------------------ dependencies

export interface DependencySummary {
  total: number
  direct: number
  /** Packages with at least one known vulnerability. */
  vulnerable: number
  /** Most packages first. */
  ecosystems: { id: string; count: number }[]
}

export interface DependencyRow {
  ecosystem: string
  name: string
  version: string
  purl: string
  /** Null when no lockfile says. */
  direct: boolean | null
  license: string | null
  lockfiles: string[]
  /** Known vulnerabilities affecting this version, most severe first. */
  advisories: Advisory[]
  /** Advisories for the package that couldn't be checked against this version. */
  unchecked: string[]
}

/** A known vulnerability, from an OSV record (ADR-0009). */
export interface Advisory {
  id: string
  aliases: string[]
  summary: string
  severity: Severity
  score: number | null
  cwe: number[]
  /** The lowest later version that fixes it; null when none does yet. */
  fixedIn: string | null
  /** The database, for attribution. */
  source: string
  url: string
  /** A person's triage; null while open and unreviewed. */
  review: DependencyReview | null
}

export interface DependencyReview {
  status: 'open' | 'confirmed' | 'accepted'
  /** Required when accepted. */
  reason: string | null
  reviewedBy: string
  reviewedAt: string
}

export interface DependencyReviewPatch {
  ecosystem: string
  name: string
  advisory: string
  status: DependencyReview['status']
  reason?: string
}

/** Known vulnerabilities across every project's main branch; accepted ones left out. */
export interface DependencyPortfolio {
  bySeverity: Partial<Record<Severity, number>>
  vulnerablePackages: number
  projectsAffected: number
  /** Most severe first. */
  top: {
    project: string
    ecosystem: string
    package: string
    version: string
    advisory: string
    summary: string
    severity: Severity
    fixedIn: string | null
    url: string
  }[]
  advisoryData: { importedAt: string; advisories: number } | null
}

export interface PackageVersions {
  ecosystem: string
  name: string
  versions: string[]
}

/** The packages a branch's latest analysis pinned (ADR-0009). */
export interface DependencyList {
  project: string
  branch: string
  mainBranch: string
  analysis: { id: number; sha: string; analyzedAt: string }
  summary: DependencySummary
  lockfiles: { id: string; count: number }[]
  /** Most common first; null is no recorded license. */
  licenses: { license: string | null; count: number }[]
  /** One row per package URL, by ecosystem then name. */
  dependencies: DependencyRow[]
  /** Against the branch's previous analysis; null for its first. */
  changes: {
    previousAnalysis: number
    added: PackageVersions[]
    removed: PackageVersions[]
    updated: { ecosystem: string; name: string; from: string[]; to: string[] }[]
  } | null
  /** When advisories were last imported; null before the first import. */
  advisoryData: { importedAt: string; advisories: number } | null
}

// -------------------------------------------------------------- components

/** A project's component, in the list across projects. */
export interface ComponentListRow extends ProjectComponent {
  project: string
}

export interface ComponentList {
  components: ComponentListRow[]
  /** Every owner of any listed component. */
  owners: string[]
}

export interface ComponentDetail {
  project: string
  branch: string
  mainBranch: string
  /** A top-level directory, or `.` for files at the project's root. */
  path: string
  analyzedAt: string
  languages: { id: string; ncloc: number }[]
  files: number
  ncloc: number
  owner: string | null
  /** Every owner of any of its files, with how many files each owns. */
  owners: { owner: string; files: number }[]
  issues: {
    total: number
    new: number
    bySeverity: Partial<Record<Severity, number>>
    byCategory: Partial<Record<Category, number>>
    debtMinutes: number
  }
  /** The project's components, this one included. */
  siblings: ProjectComponent[]
  /** Open issues at the end of each of the last eight weeks, oldest first. */
  trend: { date: string; open: number }[]
  fileList: { path: string; language: string; ncloc: number; issues: number; debtMinutes: number; worst: Severity | null }[]
}

// ------------------------------------------------------------------- gates

/**
 * A quality gate as projects use it: defined in each repository's
 * sonda.toml, so projects whose latest analysis used the same conditions
 * share one. Read-only on the server.
 */
export interface QualityGate {
  /** Stable for the same conditions. */
  id: string
  name: string
  isDefault: boolean
  conditions: { label: string; metric: string; op: 'gt' | 'lt'; threshold: number; failing: number; noData: number }[]
  projects: { project: string; state: GateState; analyzedAt: string }[]
  /** The latest evaluations on its projects' main branches, newest first (up to 40). */
  evaluations: { analysis: number; project: string; state: GateState; analyzedAt: string }[]
  /** Percent of `evaluations` that passed; partial counts as passing. */
  passRate: number | null
  mostCommonFailure: string | null
}

// ---------------------------------------------------------------- security

export interface SecurityFinding {
  id: number
  severity: Severity
  rule: string
  message: string
  project: string
  branch: string
  component: string
  path: string
  line: number
  firstSeen: string
  ageDays: number
  /** CWE ids of its rule. */
  cwe: number[]
}

/** Vulnerabilities across projects, each project's main branch. */
export interface Security {
  /** Open and confirmed, by severity. */
  openBySeverity: Partial<Record<Severity, number>>
  open: number
  newThisWeek: number
  projectsAffected: number
  status: { open: number; confirmed: number; accepted: number; fixedLast30Days: number }
  /** Most severe first, then oldest. */
  focus: SecurityFinding[]
  /** Twelve weeks, oldest first; `weighted` weighs blocker 10, critical 5, major 2, minor 1. */
  trend: { date: string; open: number; weighted: number; introduced: number; fixed: number }[]
  /** `severe` is blocker and critical. */
  projects: { project: string; severe: number; other: number }[]
  components: { project: string; path: string; count: number; worst: Severity; weighted: number }[]
  rules: { rule: string; count: number }[]
  /** Per OWASP Top 10 edition, newest first: all ten categories in order (a vulnerability counts in every category its rule relates to), and how many have none. */
  owasp: { year: number; categories: { id: string; title: string; count: number; rules: string[] }[]; unmapped: number }[]
  /** Known vulnerabilities in the projects' dependencies (ADR-0009). */
  dependencies: DependencyPortfolio
  /** Medians over vulnerabilities fixed in the last 90 days; null when none was. */
  remediation: { medianDaysSevere: number | null; medianDaysAll: number | null; fixedLast90Days: number }
}

// ---------------------------------------------------------------- analyses

export interface AnalysisQuery {
  project?: string
  branch?: string
  /** `passed` includes partial. */
  gate?: 'failed' | 'passed'
  offset: number
  limit: number
}

export interface AnalysisRow {
  id: number
  project: string
  branch: string
  sha: string
  analyzedAt: string
  toolVersion: string
  gate: GateState
  /** Labels of the conditions that failed. */
  failing: string[]
  issues: number | null
  newIssues: number | null
  warnings: number
}

export interface AnalysisPage {
  total: number
  offset: number
  limit: number
  items: AnalysisRow[]
}

/** An issue an analysis introduced or fixed. */
export interface IssueRef {
  id: number
  severity: Severity
  category: Category
  rule: string
  message: string
  path: string
  line: number
}

export interface AnalysisChanges {
  total: number
  /** Counts for every issue, not only the listed ones. */
  bySeverity: Partial<Record<Severity, number>>
  /** The first 50, most severe first. */
  items: IssueRef[]
}

export interface AnalysisDetail {
  id: number
  project: string
  branch: string
  mainBranch: string
  sha: string
  analyzedAt: string
  toolVersion: string
  newCodeReference: string | null
  gate: { state: GateState; conditions: GateCondition[] }
  measures: { overall: MeasureSet; newCode: MeasureSet }
  files: number
  languages: { id: string; files: number }[]
  components: number
  /** As the CLI reported them: skipped files, syntax errors, timeouts. */
  warnings: string[]
  /** The branch's first analysis: its issues are the baseline, not new. */
  baseline: boolean
  introduced: AnalysisChanges
  fixed: AnalysisChanges
  previous: { id: number; sha: string } | null
  next: { id: number; sha: string } | null
}

// ------------------------------------------------------------------ client

export interface SondaApi {
  session(): Promise<Session>
  /** Starts a session cookie; rejects with `AuthError` on a wrong username or password. */
  signIn(username: string, password: string): Promise<void>
  signOut(): Promise<void>
  /** The signed-in user's own password; needs the current one. */
  changePassword(current: string, next: string): Promise<void>
  /** Admins only. */
  users(): Promise<UserRow[]>
  createUser(user: NewUser): Promise<User>
  updateUser(id: number, patch: UserPatch): Promise<User>
  shell(): Promise<Shell>
  /** Absent until the server keeps analysis history for it (ADR-0005, phase 3). */
  overview?(scope: Scope, range: Range): Promise<Overview>
  drill?(metric: DrillMetric, scope: Scope): Promise<Drill>
  projects(): Promise<ProjectList>
  /** The project on `branch`, or on its main branch. */
  project(key: string, branch?: string): Promise<ProjectDetail>
  /** The default gate first, then by how many projects use each. */
  gates(): Promise<QualityGate[]>
  security(): Promise<Security>
  /** Every project's components, or one project's. */
  components(project?: string): Promise<ComponentList>
  component(project: string, path: string, branch?: string): Promise<ComponentDetail>
  /** The project's dependencies on `branch`, or on its main branch. */
  dependencies(project: string, branch?: string): Promise<DependencyList>
  /** Triages one known vulnerability in one of the project's packages. */
  reviewDependency(project: string, patch: DependencyReviewPatch): Promise<DependencyReview>
  analyses(query: AnalysisQuery): Promise<AnalysisPage>
  analysis(id: number): Promise<AnalysisDetail>
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
