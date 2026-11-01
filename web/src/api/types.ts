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
export type IssueStatus = 'open' | 'confirmed' | 'fixed' | 'accepted' | 'false_positive'
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
  /** About specific issues: the Issues page filtered to them, opened instead of the drawer. */
  link?: string | null
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
  /** How the value itself stands, whatever its trend; neutral without data. */
  tone: 'ok' | 'warn' | 'crit' | 'neutral'
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
  /** Null where unknown: a message needs git, a duration `sonda scan --upload`. */
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
/** Statuses that need a reason, and leave the counts and the gate (ADR-0014). */
export const DECIDED: readonly TriageStatus[] = ['accepted', 'false_positive']

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
  /** Why it was accepted or marked a false positive. */
  reason: string | null
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
  /** Given with a status change. */
  reason: string | null
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
  /** Required with `accepted` and `false_positive`; 1–500 characters. */
  reason?: string
  /** `''` unassigns. */
  assignee?: string
}

// ------------------------------------------------------------------- rules

/** A rule of sonda's catalog. Read-only: rules are configured per repository in sonda.toml. */
/** A rule as the catalog describes it, the same everywhere. */
export interface RuleInfo {
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

/** A catalog rule, across every project. */
export interface Rule extends RuleInfo {
  /** Set when the default profile turns it off (ADR-0016, ADR-0018). */
  serverOff: RuleSettingChange | null
  /** The profiles that set it. */
  inProfiles: { id: number; name: string; on: boolean; severity: Severity | null }[]
  /** In how many projects it's off, by what turned it off; null when on everywhere. */
  offIn: { sondaToml: number; server: number } | null
  /** Open or confirmed issues on each project's main branch. */
  openIssues: number
  projects: number
}

/** Who changed a rule setting on the server, when, and why. */
export interface RuleSettingChange {
  note: string | null
  changedBy: string
  changedAt: string
}

/** What decided a rule's state for a project (ADR-0016). */
export type RuleSetBy = 'default' | 'sonda_toml' | 'profile' | 'project'

/** A rule's state in one project, and what decided it (ADR-0016, ADR-0018). */
export interface ProjectRuleState {
  on: boolean
  setBy: RuleSetBy
  /** The server setting that decided it. */
  change: RuleSettingChange | null
  /** Its severity when the profile or sonda.toml changes it. */
  severity: Severity | null
  /** What changed the severity. */
  severityBy: 'profile' | 'sonda_toml' | null
  /** The server says on, but the latest scan didn't apply its settings and never ran it. */
  conflict: boolean
  /** This project's own setting, over its profile. */
  projectSetting: 'on' | 'off' | null
}

/** A rule for one project: the catalog's description, its state there, and its findings. */
export interface ProjectRule extends RuleInfo {
  state: ProjectRuleState
  /** Open or confirmed findings on the main branch that count. */
  openIssues: number
  /** Open findings the server leaves out, since the rule is off. */
  hiddenIssues: number
}

/** A rule a profile sets (ADR-0018). */
export interface ProfileRuleSetting {
  rule: string
  name: string | null
  on: boolean
  /** Null keeps the catalog's severity. */
  severity: Severity | null
  change: RuleSettingChange
}

/** A rule profile, as lists show it (ADR-0018). */
export interface RuleProfileSummary {
  id: number
  name: string
  /** "sonda way": the catalog's defaults, read-only. */
  builtin: boolean
  isDefault: boolean
  /** Rules it sets. */
  rules: number
  /** Projects using it, by choice or as the default. */
  projects: string[]
}

export interface RuleProfileDetail extends RuleProfileSummary {
  /** The rules it sets, sorted by id. */
  rulesSet: ProfileRuleSetting[]
}

/** sonda.toml's `[rules]`, as an analysis recorded them. */
export interface SondaTomlRules {
  disabled: string[]
  enabled: string[]
  severity: Record<string, Severity>
}

export interface ProjectRules {
  project: string
  mainBranch: string
  /** The rule profile the project uses (ADR-0018). */
  profile: { id: number; name: string; isDefault: boolean; chosen: boolean }
  /** Whether the main branch's latest analysis applied the server's current settings; null without one. */
  profileApplied: boolean | null
  /** From the main branch's latest analysis; null when unknown (an older sonda). */
  sondaToml: SondaTomlRules | null
  /** The languages of the main branch's latest analysis, as in reports. */
  languages: string[]
  /** Every rule for those languages, in catalog order. */
  rules: ProjectRule[]
  /** When the repository changed its settings, newest first. */
  tomlChanges: { analysisId: number; sha: string; at: string; rule: string; change: 'disabled' | 're-enabled' | 'enabled' | 'unset' | 'severity' }[]
}

export type ProjectRuleSetting = 'on' | 'off' | 'inherit'

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
  /** Absent for a service user, such as `ci`: it can't sign in and only owns tokens, so it's a member. */
  password?: string
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
  /** The display name (ADR-0017); null shows the key alone. */
  name: string | null
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

/** `ignored`: coverage or duplication of new code, with fewer than 20 new lines. */
export type ConditionStatus = 'ok' | 'error' | 'no_data' | 'ignored'

export interface GateCondition {
  /** "New vulnerabilities > 0". */
  label: string
  metric: string
  actual: number | null
  status: ConditionStatus
  /** Why an ignored condition is: "fewer than 20 new lines", "no advisory data". */
  reason?: string | null
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
  /** The project's version it was uploaded with (`sonda upload --project-version`). */
  version: string | null
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
  /** The display name (ADR-0017); null shows the key alone. */
  name: string | null
  mainBranch: string
  branch: string
  /** The main branch first. */
  branches: { name: string; gate: GateState; ago: string }[]
  languages: { id: string; ncloc: number }[]
  analysis: { id: number; sha: string; analyzedAt: string; toolVersion: string; newCodeReference: string | null; version: string | null }
  gate: { state: GateState; conditions: GateCondition[] }
  score: number
  ratings: { reliability: Level; security: Level; maintainability: Level; coverage: Level | null }
  measures: { overall: MeasureSet; newCode: MeasureSet }
  /** The branch's latest analyses, oldest first. */
  history: ProjectHistoryPoint[]
  components: ProjectComponent[]
  /** From the analysis's lockfiles; null when it recorded none. */
  dependencies: DependencySummary | null
  /** On the main branch, where new code starts (ADR-0011); null on other branches. */
  newCodePeriod: NewCodePeriod | null
}

/** The main branch's new code period: it starts at this analysis. */
export interface NewCodePeriod {
  analysis: number
  sha: string
  analyzedAt: string
  /** Moved by an admin, rather than following the project's versions. */
  reset: boolean
  /** The version whose first analysis starts the period; null when it's the project's first analysis. */
  version: string | null
  /** New-code measures that keep the scan's values: duplication, and coverage unless the report carried it per file. */
  fromScan: string[]
}

// ---------------------------------------------------------------- coverage

/** Line coverage per file of a branch's latest analysis (`sonda scan --coverage`). */
export interface CoverageList {
  project: string
  branch: string
  analysis: { id: number; sha: string; analyzedAt: string }
  /** The analysis's coverage measure; null without coverage. */
  coverage: number | null
  /** Every analyzed file, by path. */
  files: CoverageFile[]
}

export interface CoverageFile {
  path: string
  language: string
  /** Lines the coverage reports list as run and not run; null when they don't list the file. */
  covered: number | null
  uncovered: number | null
  /** Branches taken at least once, of all; null without branch data. */
  branches: CoverageCounts | null
  /** Functions called at least once, of all; null without function data. */
  functions: CoverageCounts | null
}

export interface CoverageCounts {
  covered: number
  total: number
}

/** One file's source with its covered and uncovered lines. */
export interface FileCoverage {
  project: string
  branch: string
  analysis: { id: number; sha: string; analyzedAt: string }
  path: string
  language: string
  /** Null when the coverage reports don't list the file. */
  covered: number[] | null
  uncovered: number[] | null
  /** Lines with branches, and how many of them ran; null without branch data. */
  branches: { line: number; taken: number; total: number }[] | null
  /** Functions by line, and how often each was called; null without function data. */
  functions: { name: string; line: number; calls: number }[] | null
  lines: CodeLine[]
  /** The file is longer than what `lines` shows. */
  truncated: boolean
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
  status: { open: number; confirmed: number; accepted: number; falsePositive: number; fixedLast30Days: number }
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

/** Filters for the security review queue; each project's main branch without `branch`. */
export interface ReviewQuery {
  project?: string
  branch?: string
  /** Open by default. */
  status?: TriageStatus | 'all'
  severity: Severity[]
  /** An OWASP Top 10 2025 category id, `A01`–`A10`. */
  owasp?: string
  assignee?: string
  isNew: boolean
}

/** How far the review has come: findings by status, and the share no longer open (null without findings). */
export interface ReviewProgress {
  open: number
  confirmed: number
  accepted: number
  falsePositive: number
  reviewed: number | null
}

export interface ReviewFinding {
  id: number
  project: string
  branch: string
  rule: string
  ruleName: string | null
  message: string
  severity: Severity
  file: string
  line: number
  isNew: boolean
  detectedAt: string
  status: TriageStatus
  assignee: string | null
  reason: string | null
  cwe: number[]
  owasp: { id: string; title: string }[]
}

/** Vulnerabilities to decide on (ADR-0014): most severe first, new code first, then oldest. */
export interface SecurityReview {
  /** Every finding in scope, whatever the other filters. */
  progress: ReviewProgress
  newCode: ReviewProgress
  /** Findings matching the filters; `items` holds the first 200. */
  total: number
  items: ReviewFinding[]
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
  /** The commit's subject line, when the upload had one. */
  message: string | null
  /** How long the scan took (`sonda scan --upload`); null for an uploaded report. */
  duration: string | null
  /** `ada (token ci-shop)`, or `api-token` for the shared SONDA_TOKEN. */
  uploadedBy: string
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
  /** The commit's subject line, when the upload had one. */
  message: string | null
  /** How long the scan took (`sonda scan --upload`); null for an uploaded report. */
  duration: string | null
  /** `ada (token ci-shop)`, or `api-token` for the shared SONDA_TOKEN. */
  uploadedBy: string
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

// ------------------------------------------------------------------ tokens

/** As in SonarQube (ADR-0012): a user token acts as its owner; analysis tokens only upload. */
export type TokenType = 'user' | 'project_analysis' | 'global_analysis'

/** A token as lists show it: never its secret. */
export interface ApiToken {
  id: number
  name: string
  type: TokenType
  /** The one project a project analysis token uploads. */
  project: string | null
  /** The secret's first characters. */
  prefix: string
  /** The user it acts as. */
  owner: string
  /** The admin who generated it for its owner; null when the owner did. */
  createdBy: string | null
  createdAt: string
  /** Null for no expiry. */
  expiresAt: string | null
  lastUsedAt: string | null
  revokedAt: string | null
  revokedBy: string | null
  status: 'active' | 'expired' | 'revoked'
}

export interface NewToken {
  name: string
  type: TokenType
  project?: string
  /** Null for no expiry. */
  expiresInDays: 30 | 60 | 90 | null
}

/** A token just generated: its secret, shown this once. */
export interface CreatedToken extends ApiToken {
  token: string
}

// ------------------------------------------------------------------ client

export interface SondaApi {
  session(): Promise<Session>
  /** Starts a session cookie; rejects with `AuthError` on a wrong username or password. */
  signIn(username: string, password: string): Promise<void>
  signOut(): Promise<void>
  /** The signed-in user's own password; needs the current one. */
  changePassword(current: string, next: string): Promise<void>
  /** The signed-in user's tokens, revoked and expired ones included. */
  myTokens(): Promise<ApiToken[]>
  createToken(token: NewToken): Promise<CreatedToken>
  revokeMyToken(id: number): Promise<void>
  /** Admins only: every user's tokens. */
  tokens(): Promise<ApiToken[]>
  revokeToken(id: number): Promise<void>
  /** Admins only: generates a token owned by `user`, such as a `ci` service user. */
  createTokenFor(user: string, token: NewToken): Promise<CreatedToken>
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
  securityReview(query: ReviewQuery): Promise<SecurityReview>
  /** Every project's components, or one project's. */
  components(project?: string): Promise<ComponentList>
  component(project: string, path: string, branch?: string): Promise<ComponentDetail>
  /** The project's dependencies on `branch`, or on its main branch. */
  dependencies(project: string, branch?: string): Promise<DependencyList>
  /** Line coverage per file on `branch`, or on the main branch. */
  coverage(project: string, branch?: string): Promise<CoverageList>
  /** One file's covered and uncovered lines. */
  fileCoverage(project: string, path: string, branch?: string): Promise<FileCoverage>
  /** Admins: starts the main branch's new code at `analysis`, or at the first analysis (null). */
  setNewCodePeriod(project: string, analysis: number | null): Promise<NewCodePeriod>
  projectSettings(project: string): Promise<ProjectSettings>
  /** Admins: the display name (null for the key alone) and the main branch. */
  updateProjectSettings(project: string, patch: ProjectSettingsPatch): Promise<ProjectSettings>
  /** Triages one known vulnerability in one of the project's packages. */
  reviewDependency(project: string, patch: DependencyReviewPatch): Promise<DependencyReview>
  analyses(query: AnalysisQuery): Promise<AnalysisPage>
  analysis(id: number): Promise<AnalysisDetail>
  issues(query: IssueQuery): Promise<IssuePage>
  issue(id: number): Promise<IssueDetail>
  updateIssue(id: number, patch: IssuePatch): Promise<IssueDetail>
  rules(): Promise<RuleCatalog>
  /** Every rule whose state differs from its default for the project, and what set it. */
  /** The rules for the project's languages, each with its state there. */
  projectRules(key: string): Promise<ProjectRules>
  ruleProfiles(): Promise<RuleProfileSummary[]>
  /** Admins: the project's profile, or null for the default. */
  setProjectProfile(key: string, profile: number | null): Promise<void>
  ruleProfile(id: number): Promise<RuleProfileDetail>
  /** Admins: a new profile, empty or a copy of `copyFrom`. */
  createRuleProfile(name: string, copyFrom?: number): Promise<{ id: number; name: string }>
  /** Admins: rename it (not "sonda way"), or make it the default. */
  updateRuleProfile(id: number, patch: { name?: string; isDefault?: true }): Promise<void>
  /** Admins: a profile that isn't the default, built in, or used by a project. */
  deleteRuleProfile(id: number): Promise<void>
  /** Admins: a rule on or off in a profile, with a severity, or `inherit` to leave it at its default. */
  setProfileRule(id: number, rule: string, state: ProjectRuleSetting, severity?: Severity | null, note?: string): Promise<void>
  /** Admins: off for every project, or back on. */
  setRuleOff(rule: string, off: boolean, note?: string): Promise<void>
  /** Admins: on or off for one project, over the global setting, or `inherit` to follow it. */
  setProjectRule(key: string, rule: string, state: ProjectRuleSetting, note?: string): Promise<void>
}

/** The session is missing or expired: the app shows sign-in again. */
export class AuthError extends Error {
  constructor(message = 'Sign in to continue') {
    super(message)
    this.name = 'AuthError'
  }
}

/** A project's settings (ADR-0017): members read them, admins change them. */
export interface ProjectSettings {
  key: string
  name: string | null
  mainBranch: string
  /** Every branch with analyses, the main one first. */
  branches: { name: string; analyses: number; analyzedAt: string; ago: string }[]
  /** Who changed a setting, newest first. */
  changes: ProjectSettingChange[]
}

export interface ProjectSettingChange {
  setting: 'name' | 'main_branch'
  old: string | null
  new: string | null
  by: string
  at: string
}

export interface ProjectSettingsPatch {
  name?: string | null
  mainBranch?: string
}
