import { AuthError, type Drill, type DrillMetric, type IssueDetail, type IssuePatch, MIN_PASSWORD_LENGTH, type RuleCatalog, type Session, type Shell, type SondaApi, type User, type UserRow } from '../types'
import { initials } from '@/lib/identity'
import issuesData from './issues.json'
import { DRILLS, overview } from './overview'
import { analysisDetail, queryAnalyses } from './analyses'
import { componentDetail, listComponents } from './components'
import { GATES } from './gates'
import { SECURITY } from './security'
import { dependencyList, reviewDependency } from './dependencies'
import { PROJECT_LIST, projectDetail, setNewCodePeriod } from './projects'
import { queryIssues } from './query'
import rulesData from './rules.json'

export interface MockOptions {
  /** Start signed out, to exercise the sign-in page. */
  signedIn?: boolean
  readsRequireAuth?: boolean
}

/** Every mock user's password. */
export const MOCK_PASSWORD = 'correct horse battery'

const MOCK_USERS: UserRow[] = [
  { id: 1, username: 'mara', displayName: 'Mara Okafor', role: 'admin', disabled: false, hasPassword: true, createdAt: '2026-09-01T09:00:00Z', lastLoginAt: '2026-10-30T08:00:00Z' },
  { id: 2, username: 'dev', displayName: 'Dev Patel', role: 'member', disabled: false, hasPassword: true, createdAt: '2026-09-14T09:00:00Z', lastLoginAt: null },
]

/**
 * In-memory implementation of the contract, seeded from the design
 * prototypes, for development and tests. It behaves like the server where
 * it matters (filtering, paging, facets, triage history), and writes last
 * until the page reloads. `latency` makes loading states visible.
 */
export function createMockApi(latency = 250, options: MockOptions = {}): SondaApi {
  const issues = structuredClone(issuesData) as IssueDetail[]
  const catalog = structuredClone(rulesData) as RuleCatalog
  const users = structuredClone(MOCK_USERS)
  const signedIn = options.signedIn ?? true
  const session: Session = { user: signedIn ? users[0] : null, authenticated: signedIn, readsRequireAuth: options.readsRequireAuth ?? false }
  const asUser = (u: UserRow): User => ({ id: u.id, username: u.username, displayName: u.displayName, role: u.role, disabled: u.disabled })
  const findUser = (id: number) => {
    const user = users.find((u) => u.id === id)
    if (!user) throw new Error('not found')
    return user
  }
  const requireAdmin = () => {
    if (!session.user) throw new AuthError()
    if (session.user.role !== 'admin') throw new Error('admins only')
  }
  const checkPassword = (password: string) => {
    if (password.length < MIN_PASSWORD_LENGTH) throw new Error(`password must have at least ${MIN_PASSWORD_LENGTH} characters`)
  }
  const wait = <T>(value: T) => new Promise<T>((resolve) => setTimeout(() => resolve(structuredClone(value)), latency))
  const guard = () => {
    if (!session.authenticated && session.readsRequireAuth) throw new AuthError()
  }

  const shell = (): Shell => ({
    org: { name: 'acme-corp', initials: 'AC', deployment: 'self-hosted', projectCount: 312 },
    user: session.user
      ? { name: session.user.displayName, handle: `@${session.user.username}`, initials: initials(session.user.displayName) }
      : { name: 'Read-only', handle: 'not signed in', initials: '··' },
    isAdmin: session.user?.role === 'admin',
    counts: { projects: 312, components: 611, issues: 1342, security: 23 },
    me: session.user?.username ?? null,
  })

  const findIssue = (id: number) => {
    const issue = issues.find((i) => i.id === id)
    if (!issue) throw new Error(`issue ${id} not found`)
    return issue
  }

  const update = (id: number, patch: IssuePatch) => {
    if (!session.authenticated) throw new AuthError()
    const issue = findIssue(id)
    const at = new Date().toISOString()
    const actor = session.user?.username ?? null
    if (patch.status !== undefined && patch.status !== issue.status) {
      issue.history.push({ at, actor, field: 'status', oldValue: issue.status, newValue: patch.status })
      issue.status = patch.status
    }
    const assignee = patch.assignee === '' ? null : patch.assignee
    if (assignee !== undefined && assignee !== issue.assignee) {
      issue.history.push({ at, actor, field: 'assignee', oldValue: issue.assignee, newValue: assignee })
      issue.assignee = assignee
    }
    return issue
  }

  return {
    session: () => wait(session),
    signIn: async (username, password) => {
      await wait(null)
      const user = users.find((u) => u.username === username.toLowerCase())
      if (!user || user.disabled || password !== MOCK_PASSWORD) throw new AuthError('Invalid username or password')
      session.user = asUser(user)
      session.authenticated = true
    },
    signOut: async () => {
      await wait(null)
      session.user = null
      session.authenticated = false
    },
    changePassword: async (current, next) => {
      await wait(null)
      if (!session.user) throw new AuthError()
      if (current !== MOCK_PASSWORD) throw new Error('the current password is wrong')
      checkPassword(next)
    },
    users: async () => {
      requireAdmin()
      return wait(users)
    },
    createUser: async (input) => {
      requireAdmin()
      checkPassword(input.password)
      if (users.some((u) => u.username === input.username)) throw new Error(`username "${input.username}" is taken`)
      const user: UserRow = { ...input, id: users.length + 1, disabled: false, hasPassword: true, createdAt: new Date().toISOString(), lastLoginAt: null }
      users.push(user)
      return wait(asUser(user))
    },
    updateUser: async (id, patch) => {
      requireAdmin()
      if (patch.password !== undefined) checkPassword(patch.password)
      const user = findUser(id)
      const activeAdmins = users.filter((u) => u.role === 'admin' && !u.disabled)
      const staysAdmin = (patch.role ?? 'admin') === 'admin' && patch.disabled !== true
      if (activeAdmins.length === 1 && activeAdmins[0].id === id && !staysAdmin) throw new Error('the last active admin cannot be disabled or made a member')
      if (patch.displayName !== undefined) user.displayName = patch.displayName
      if (patch.role !== undefined) user.role = patch.role
      if (patch.disabled !== undefined) user.disabled = patch.disabled
      return wait(asUser(user))
    },
    shell: () => wait(shell()),
    overview: (scope, range) => wait(overview(scope, range)),
    drill: (metric: DrillMetric) => wait<Drill>(DRILLS[metric]),
    gates: async () => {
      guard()
      return wait(GATES)
    },
    security: async () => {
      guard()
      return wait(SECURITY)
    },
    components: async (project) => {
      guard()
      return wait(listComponents(project))
    },
    component: async (project, path, branch) => {
      guard()
      const detail = componentDetail(project, path, branch)
      if (!detail) throw new Error('not found')
      return wait(detail)
    },
    dependencies: async (project, branch) => {
      guard()
      const detail = projectDetail(project, branch)
      if (!detail) throw new Error('not found')
      return wait(dependencyList(detail))
    },
    setNewCodePeriod: async (project, analysis) => {
      guard()
      return wait(setNewCodePeriod(project, analysis))
    },
    reviewDependency: async (_project, patch) => {
      guard()
      return wait(reviewDependency(patch, 'mara'))
    },
    analyses: async (query) => {
      guard()
      return wait(queryAnalyses(query))
    },
    analysis: async (id) => {
      guard()
      const detail = analysisDetail(id)
      if (!detail) throw new Error('not found')
      return wait(detail)
    },
    projects: async () => {
      guard()
      return wait(PROJECT_LIST)
    },
    project: async (key, branch) => {
      guard()
      const detail = projectDetail(key, branch)
      if (!detail) throw new Error('not found')
      return wait(detail)
    },
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
