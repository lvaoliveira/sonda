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

/**
 * Drill-down links from other screens arrive as query parameters:
 * `project=`, `branch=`, `new`, `me`, `cat=`, `sev=` (comma-separated), `comp=`, `file=`,
 * combinable, and `issue=` to open one of the results. Returns the filter, a human description
 * and the issue, or null when there is nothing to apply.
 */
export function filterFromParams(params: URLSearchParams): { filter: IssueFilter; description: string; issue: number | null } | null {
  const filter: IssueFilter = { ...DEFAULT_FILTER }
  const parts: string[] = []
  const project = params.get('project')
  if (project) {
    filter.project = project
    const branch = params.get('branch')
    if (branch) filter.branch = branch
    parts.push(branch ? `${project} on ${branch}` : project)
  }
  if (params.has('new')) {
    filter.isNew = true
    parts.push('new code')
  }
  const cat = params.get('cat')
  if (cat && (CATEGORIES as string[]).includes(cat)) {
    filter.category = [cat as Category]
    parts.push(cat === 'code_smell' ? 'code smells' : `${cat === 'bug' ? 'bugs' : 'vulnerabilities'}`)
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
  const issue = Number(params.get('issue'))
  return { filter, description: `Showing ${parts.join(' · ')} — from the metric you clicked`, issue: Number.isInteger(issue) && issue > 0 ? issue : null }
}
