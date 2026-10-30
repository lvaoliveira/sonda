import type { FacetKey, IssueDetail, IssuePage, IssueQuery, IssueSummary } from '../types'
import { SEVERITY } from '@/lib/visual'

/**
 * What `GET /api/issues` does, in memory: filter, sort most severe first,
 * page, and count facets, each ignoring its own selection (choosing
 * "Major" must not zero out the other severities' counts).
 */
export function queryIssues(all: IssueDetail[], q: IssueQuery): IssuePage {
  const matching = all
    .filter((i) => matches(i, q))
    .sort((a, b) => SEVERITY[a.severity].rank - SEVERITY[b.severity].rank || a.file.localeCompare(b.file) || a.line - b.line)
  const facets = {} as IssuePage['facets']
  for (const key of FACETS) {
    const counts: Record<string, number> = {}
    for (const i of all.filter((i) => matches(i, q, key))) counts[i[key]] = (counts[i[key]] ?? 0) + 1
    facets[key] = counts
  }
  return {
    total: matching.length,
    offset: q.offset,
    limit: q.limit,
    items: matching.slice(q.offset, q.offset + q.limit).map(summary),
    facets,
  }
}

const FACETS: FacetKey[] = ['severity', 'category', 'status', 'component']

function matches(i: IssueSummary, q: IssueQuery, ignore?: FacetKey): boolean {
  for (const key of FACETS) {
    const selected = q[key] as string[]
    if (key !== ignore && selected.length > 0 && !selected.includes(i[key])) return false
  }
  if (q.project && i.project !== q.project) return false
  if (q.branch && i.branch !== q.branch) return false
  if (q.file && !i.file.includes(q.file)) return false
  if (q.assignee && i.assignee !== q.assignee) return false
  if (q.isNew && !i.isNew) return false
  return true
}

/** The list item: the detail without its rule, code and history. */
export function summary(d: IssueDetail): IssueSummary {
  return {
    id: d.id,
    key: d.key,
    project: d.project,
    branch: d.branch,
    severity: d.severity,
    category: d.category,
    rule: d.rule,
    message: d.message,
    component: d.component,
    file: d.file,
    line: d.line,
    endLine: d.endLine,
    language: d.language,
    effortMinutes: d.effortMinutes,
    status: d.status,
    assignee: d.assignee,
    isNew: d.isNew,
    detectedAt: d.detectedAt,
  }
}
