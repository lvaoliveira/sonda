import type { Category, IssueQuery, IssueStatus, Severity } from '@/api/types'

/** What the Issues page filters by; the server does the filtering. */
export interface IssueFilter {
  /** A project key and branch, from a project page's links. */
  project?: string
  branch?: string
  severity: Severity[]
  category: Category[]
  status: IssueStatus[]
  component: string[]
  file: string
  mine: boolean
  isNew: boolean
}

/** Open and confirmed issues, as the design selects by default. */
export const DEFAULT_FILTER: IssueFilter = {
  severity: [],
  category: [],
  status: ['open', 'confirmed'],
  component: [],
  file: '',
  mine: false,
  isNew: false,
}

export const PAGE_SIZE = 50

/** The API query for a filter. "Mine" is the name the viewer signed in with. */
export function toQuery(f: IssueFilter, me: string, offset: number, limit = PAGE_SIZE): IssueQuery {
  return {
    project: f.project,
    branch: f.branch,
    severity: f.severity,
    category: f.category,
    status: f.status,
    component: f.component,
    file: f.file,
    assignee: f.mine ? me : undefined,
    isNew: f.isNew,
    offset,
    limit,
  }
}

/** A query as `GET /api/issues` parameters; empty filters are left out. */
export function issueSearchParams(q: IssueQuery): URLSearchParams {
  const p = new URLSearchParams()
  if (q.project) p.set('project', q.project)
  if (q.branch) p.set('branch', q.branch)
  for (const key of ['severity', 'category', 'status', 'component'] as const) {
    if (q[key].length > 0) p.set(key, q[key].join(','))
  }
  if (q.file) p.set('file', q.file)
  if (q.assignee) p.set('assignee', q.assignee)
  if (q.isNew) p.set('new', 'true')
  p.set('offset', String(q.offset))
  p.set('limit', String(q.limit))
  return p
}

const CATEGORIES: Category[] = ['bug', 'vulnerability', 'code_smell']
const SEVERITIES: Severity[] = ['blocker', 'critical', 'major', 'minor', 'info']

const CATEGORY_PLURAL: Record<Category, string> = { bug: 'bugs', vulnerability: 'vulnerabilities', code_smell: 'code smells' }

/**
 * The filters a link carries in its query string, as drill-down links from
 * other screens send them: `project=`, `branch=`, `new`, `me`, `cat=`,
 * `sev=` (comma-separated), `comp=`, `file=`, combinable, and `issue=` to
 * open one of the results. Returns the filter, a description and the issue,
 * or null when there is nothing to apply. On a project's Issues tab,
 * `project` comes from the route instead of the query.
 */
export function filterFromParams(params: URLSearchParams, routeProject?: string): { filter: IssueFilter; description: string; issue: number | null } | null {
  const filter: IssueFilter = { ...DEFAULT_FILTER }
  const parts: string[] = []
  const scope = projectScope(params, routeProject)
  if (scope) {
    Object.assign(filter, scope.filter)
    if (scope.said) parts.push(scope.said)
  }
  if (params.has('new')) {
    filter.isNew = true
    parts.push('new code')
  }
  const cat = params.get('cat')
  if (isCategory(cat)) {
    filter.category = [cat]
    parts.push(CATEGORY_PLURAL[cat])
  }
  const sev = (params.get('sev') ?? '').split(',').filter((s): s is Severity => (SEVERITIES as string[]).includes(s))
  if (sev.length > 0) {
    filter.severity = sev
    parts.push(sev.join(' and '))
  }
  const comp = params.get('comp')
  if (comp) {
    filter.component = [comp]
    parts.push(comp)
  }
  const file = params.get('file')
  if (file) {
    filter.file = file
    parts.push(file)
  }
  if (params.has('me')) {
    filter.mine = true
    parts.push('assigned to you')
  }
  if (parts.length === 0) return null
  return { filter, description: `Showing ${parts.join(' · ')} — from the metric you clicked`, issue: issueParam(params) }
}

function isCategory(value: string | null): value is Category {
  return value !== null && (CATEGORIES as string[]).includes(value)
}

/** The project and branch a link names, and how the description says them. */
function projectScope(params: URLSearchParams, routeProject?: string): { filter: Pick<IssueFilter, 'project' | 'branch'>; said: string } | null {
  const project = routeProject ?? params.get('project')
  if (!project) return null
  const branch = params.get('branch')
  // On the project's own tab, its name is already on the page.
  const said = [routeProject ? null : project, branch && `on ${branch}`].filter(Boolean).join(' ')
  return { filter: branch ? { project, branch } : { project }, said }
}

/** The issue a link opens, when it names a valid one. */
function issueParam(params: URLSearchParams): number | null {
  const issue = Number(params.get('issue'))
  return Number.isInteger(issue) && issue > 0 ? issue : null
}

/**
 * The Issues page with these filters (as `filterFromParams` reads them): a
 * project's own Issues tab, or all projects' without one. `true` sets a
 * flag such as `new`; empty values are left out.
 */
export function issuesUrl(project: string | null | undefined, params: Record<string, string | number | boolean | null | undefined> = {}): string {
  const query = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value === true) query.set(key, '')
    else if (value != null && value !== false && value !== '') query.set(key, String(value))
  }
  const base = project ? `/projects/${encodeURIComponent(project)}/issues` : '/issues'
  const q = query.toString()
  return q ? `${base}?${q}` : base
}
