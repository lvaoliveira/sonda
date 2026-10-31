import type { IssueDetail, ReviewFinding, ReviewProgress, ReviewQuery, RuleCatalog, SecurityReview, TriageStatus } from '../types'
import { SEVERITY_ORDER } from '@/lib/visual'

/** The security review queue over the mock's issues, as the server builds it. */
export function securityReview(issues: IssueDetail[], catalog: RuleCatalog, q: ReviewQuery): SecurityReview {
  const inScope = issues.filter(
    (i) => i.category === 'vulnerability' && i.status !== 'fixed' && (!q.project || i.project === q.project) && i.branch === (q.branch ?? 'main'),
  )
  const progress = (only: IssueDetail[]): ReviewProgress => {
    const n = (s: TriageStatus) => only.filter((i) => i.status === s).length
    const p = { open: n('open'), confirmed: n('confirmed'), accepted: n('accepted'), falsePositive: n('false_positive') }
    const total = only.length
    return { ...p, reviewed: total ? Math.floor((100 * (total - p.open)) / total) : null }
  }
  const status = q.status ?? 'open'
  const items: ReviewFinding[] = inScope
    .filter((i) => (status === 'all' || i.status === status) && (!q.severity.length || q.severity.includes(i.severity)))
    .filter((i) => (!q.assignee || i.assignee === q.assignee) && (!q.isNew || i.isNew))
    .map((i) => {
      const rule = catalog.rules.find((r) => r.id === i.rule)
      return {
        id: i.id,
        project: i.project,
        branch: i.branch,
        rule: i.rule,
        ruleName: rule?.name ?? i.ruleName,
        message: i.message,
        severity: i.severity,
        file: i.file,
        line: i.line,
        isNew: i.isNew,
        detectedAt: i.detectedAt,
        status: i.status as TriageStatus,
        assignee: i.assignee,
        reason: i.reason,
        cwe: rule?.cwe ?? [],
        owasp: rule?.owasp2025 ?? [],
      }
    })
    .filter((f) => !q.owasp || f.owasp.some((o) => o.id === q.owasp))
    .sort(
      (a, b) =>
        SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
        Number(b.isNew) - Number(a.isNew) ||
        a.detectedAt.localeCompare(b.detectedAt) ||
        a.id - b.id,
    )
  return { progress: progress(inScope), newCode: progress(inScope.filter((i) => i.isNew)), total: items.length, items: items.slice(0, 200) }
}
