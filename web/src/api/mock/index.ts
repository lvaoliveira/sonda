import { AuthError, type Drill, type DrillMetric, type IssueDetail, type IssuePatch, type RuleCatalog, type Session, type Shell, type SondaApi } from '../types'
import issuesData from './issues.json'
import { DRILLS, overview } from './overview'
import { queryIssues } from './query'
import rulesData from './rules.json'

export interface MockOptions {
  /** Start signed out, to exercise the sign-in page. */
  signedIn?: boolean
  readsRequireAuth?: boolean
}

/** The token the mock accepts. */
export const MOCK_TOKEN = 'mock-token'

/**
 * In-memory implementation of the contract, seeded from the design
 * prototypes, for development and tests. It behaves like the server where
 * it matters (filtering, paging, facets, triage history), and writes last
 * until the page reloads. `latency` makes loading states visible.
 */
export function createMockApi(latency = 250, options: MockOptions = {}): SondaApi {
  const issues = structuredClone(issuesData) as IssueDetail[]
  const catalog = structuredClone(rulesData) as RuleCatalog
  const session: Session = { authenticated: options.signedIn ?? true, readsRequireAuth: options.readsRequireAuth ?? false }
  const wait = <T>(value: T) => new Promise<T>((resolve) => setTimeout(() => resolve(structuredClone(value)), latency))
  const guard = () => {
    if (!session.authenticated && session.readsRequireAuth) throw new AuthError()
  }

  const shell: Shell = {
    org: { name: 'acme-corp', initials: 'AC', deployment: 'self-hosted', projectCount: 312 },
    user: { name: 'Mara Okafor', handle: '@checkout', initials: 'MO' },
    counts: { projects: 312, components: 611, issues: 1342, security: 23 },
    me: 'Mara Okafor',
  }

  const findIssue = (id: number) => {
    const issue = issues.find((i) => i.id === id)
    if (!issue) throw new Error(`issue ${id} not found`)
    return issue
  }

  const update = (id: number, patch: IssuePatch) => {
    if (!session.authenticated) throw new AuthError()
    const issue = findIssue(id)
    const at = new Date().toISOString()
    if (patch.status !== undefined && patch.status !== issue.status) {
      issue.history.push({ at, field: 'status', oldValue: issue.status, newValue: patch.status })
      issue.status = patch.status
    }
    const assignee = patch.assignee === '' ? null : patch.assignee
    if (assignee !== undefined && assignee !== issue.assignee) {
      issue.history.push({ at, field: 'assignee', oldValue: issue.assignee, newValue: assignee })
      issue.assignee = assignee
    }
    return issue
  }

  return {
    session: () => wait(session),
    signIn: async (token) => {
      await wait(null)
      if (token !== MOCK_TOKEN) throw new AuthError('That token is not valid')
      session.authenticated = true
    },
    signOut: async () => {
      await wait(null)
      session.authenticated = false
    },
    shell: () => wait(shell),
    overview: (scope, range) => wait(overview(scope, range)),
    drill: (metric: DrillMetric) => wait<Drill>(DRILLS[metric]),
    issues: async (query) => {
      guard()
      return wait(queryIssues(issues, query))
    },
    issue: async (id) => {
      guard()
      return wait(findIssue(id))
    },
    updateIssue: async (id, patch) => wait(update(id, patch)),
    rules: async () => {
      guard()
      return wait(catalog)
    },
  }
}
