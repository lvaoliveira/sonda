import type { Category, Issue, IssueStatus, Severity } from '@/api/types'
import { SEVERITY } from './visual'

export interface IssueFilter {
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

type FacetKey = 'severity' | 'category' | 'status' | 'component'

const VALUE: Record<FacetKey, (i: Issue) => string> = {
  severity: (i) => i.severity,
  category: (i) => i.category,
  status: (i) => i.status,
  component: (i) => i.component,
}

/**
 * Whether an issue passes the filter. `ignore` skips one facet, so a facet's
 * counts can exclude its own selection (choosing "Major" must not zero out
 * the other severities' counts).
 */
export function matches(issue: Issue, f: IssueFilter, me: string, ignore?: FacetKey): boolean {
  for (const key of ['severity', 'category', 'status', 'component'] as const) {
    const selected = f[key] as string[]
    if (key !== ignore && selected.length > 0 && !selected.includes(VALUE[key](issue))) return false
  }
  if (f.file && !issue.file.includes(f.file)) return false
  if (f.mine && issue.assignee !== me) return false
  if (f.isNew && !issue.isNew) return false
  return true
}

/** Matching issues, most severe first (stable within a severity). */
export function filterIssues(issues: Issue[], f: IssueFilter, me: string): Issue[] {
  return issues
    .filter((i) => matches(i, f, me))
    .sort((a, b) => SEVERITY[a.severity].rank - SEVERITY[b.severity].rank)
}

export function facetCount(issues: Issue[], f: IssueFilter, me: string, key: FacetKey, value: string): number {
  return issues.filter((i) => matches(i, f, me, key) && VALUE[key](i) === value).length
}

const CATEGORIES: Category[] = ['bug', 'vulnerability', 'code_smell']

/**
 * Drill-down links from other screens arrive as query parameters:
 * `new`, `me`, `cat=`, `comp=`, `file=`, combinable. Returns the filter and
 * a human description, or null when there is nothing to apply.
 */
export function filterFromParams(
  params: URLSearchParams,
  componentLabel: (id: string) => string,
): { filter: IssueFilter; description: string } | null {
  const filter: IssueFilter = { ...DEFAULT_FILTER }
  const parts: string[] = []
  if (params.has('new')) {
    filter.isNew = true
    parts.push('new code')
  }
  const cat = params.get('cat')
  if (cat && (CATEGORIES as string[]).includes(cat)) {
    filter.category = [cat as Category]
    parts.push(cat === 'code_smell' ? 'code smells' : `${cat === 'bug' ? 'bugs' : 'vulnerabilities'}`)
  }
  const comp = params.get('comp')
  if (comp) {
    filter.component = [comp]
    parts.push(componentLabel(comp))
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
  return { filter, description: `Showing ${parts.join(' · ')} — from the metric you clicked` }
}
