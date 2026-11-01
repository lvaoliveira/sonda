import { AuthError, DECIDED, type Drill, type DrillMetric, type IssueDetail, type IssuePatch, MIN_PASSWORD_LENGTH, type ProjectSettingChange, type ProjectSettings, type RuleCatalog, type Session, type Shell, type SondaApi, type User, type UserRow } from '../types'
import { initials } from '@/lib/identity'
import issuesData from './issues.json'
import { DRILLS, overview } from './overview'
import { analysisDetail, queryAnalyses } from './analyses'
import { componentDetail, listComponents } from './components'
import { GATES } from './gates'
import { SECURITY } from './security'
import { coverageList, fileCoverage } from './coverage'
import { dependencyList, reviewDependency } from './dependencies'
import { BRANCHES, clearNewCodePeriod, type MockProjectSettings, PROJECT_LIST, projectDetail, setNewCodePeriod } from './projects'
import { queryIssues } from './query'
import { securityReview } from './review'
import { mockRuleSettings } from './ruleSettings'
import { mockTokens } from './tokens'
import rulesData from './rules.json'

export interface MockOptions {
  /** Start signed out, to exercise the sign-in page. */
  signedIn?: boolean
  readsRequireAuth?: boolean
}

/** As the server: admins have to be able to sign in. */
const NO_PASSWORD_ADMIN = "a user without a password can't sign in, so it can't be an admin; set a password first"

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
  const tokens = mockTokens()
  const ruleSettings = mockRuleSettings()
  const projectKeys = PROJECT_LIST.projects.map((p) => p.key)
  // Each project's settings and their changes (ADR-0017), newest first.
  const settings = new Map<string, MockProjectSettings & { changes: ProjectSettingChange[] }>()
  const settingsOf = (key: string) => {
    if (!projectKeys.includes(key)) throw new Error('not found')
    let s = settings.get(key)
    if (!s) settings.set(key, (s = { name: null, mainBranch: 'main', changes: [] }))
    return s
  }
  /** What the project list shows of them. */
  const shown = (key: string) => {
    const s = settings.get(key)
    return s ? { name: s.name, mainBranch: s.mainBranch } : {}
  }
  const settingsView = (key: string): ProjectSettings => {
    const s = settingsOf(key)
    return {
      key,
      name: s.name,
      mainBranch: s.mainBranch,
      branches: [...BRANCHES].sort((a, b) => Number(b.name === s.mainBranch) - Number(a.name === s.mainBranch)),
      changes: s.changes,
    }
  }
  const findRule = (id: string) => {
    if (!catalog.rules.some((r) => r.id === id)) throw new Error(`unknown rule "${id}" (see GET /api/rules)`)
  }
  /** As the server: findings of a rule the server turned off leave lists. */
  const counted = () => issues.filter((i) => !ruleSettings.off(i.rule, i.project))
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
    // As the server: decisions need a reason, and a reason needs a status.
    const reason = patch.reason?.trim() || null
    if (patch.status && DECIDED.includes(patch.status) && !reason) throw new Error(`say why: ${patch.status} needs a reason`)
    if (reason && (!patch.status || patch.status === 'open')) throw new Error('a reason goes with confirmed, accepted or false_positive')
    if (patch.status !== undefined && (patch.status !== issue.status || reason)) {
      issue.history.push({ at, actor, field: 'status', oldValue: issue.status, newValue: patch.status, reason })
      issue.status = patch.status
      issue.reason = reason
    }
    const assignee = patch.assignee === '' ? null : patch.assignee
    if (assignee !== undefined && assignee !== issue.assignee) {
      issue.history.push({ at, actor, field: 'assignee', oldValue: issue.assignee, newValue: assignee, reason: null })
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
    myTokens: async () => {
      if (!session.user) throw new AuthError()
      return wait(tokens.list(session.user.username))
    },
    createToken: async (t) => {
      if (!session.user) throw new AuthError()
      return wait(tokens.create(session.user.username, t))
    },
    revokeMyToken: async (id) => {
      if (!session.user) throw new AuthError()
      tokens.revoke(id, session.user.username, session.user.username)
      await wait(null)
    },
    tokens: async () => {
      requireAdmin()
      return wait(tokens.list())
    },
    revokeToken: async (id) => {
      requireAdmin()
      tokens.revoke(id, session.user!.username)
      await wait(null)
    },
    createTokenFor: async (username, t) => {
      requireAdmin()
      const owner = users.find((u) => u.username === username)
      if (!owner) throw new Error(`no user named "${username}"`)
      if (owner.disabled) throw new Error(`${username} is disabled, so its tokens wouldn't work`)
      return wait(tokens.create(username, t, session.user!.username))
    },
    users: async () => {
      requireAdmin()
      return wait(users)
    },
    createUser: async (input) => {
      requireAdmin()
      const { password, ...fields } = input
      if (password === undefined && input.role === 'admin') throw new Error(NO_PASSWORD_ADMIN)
      if (password !== undefined) checkPassword(password)
      if (users.some((u) => u.username === input.username)) throw new Error(`username "${input.username}" is taken`)
      const user: UserRow = { ...fields, id: users.length + 1, disabled: false, hasPassword: password !== undefined, createdAt: new Date().toISOString(), lastLoginAt: null }
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
      if (patch.role === 'admin' && !user.hasPassword && patch.password === undefined) throw new Error(NO_PASSWORD_ADMIN)
      if (patch.password !== undefined) user.hasPassword = true
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
    securityReview: async (query) => {
      guard()
      return wait(securityReview(issues, catalog, query))
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
    coverage: async (project, branch) => {
      guard()
      const detail = projectDetail(project, branch)
      if (!detail) throw new Error('not found')
      return wait(coverageList(detail))
    },
    fileCoverage: async (project, path, branch) => {
      guard()
      const detail = projectDetail(project, branch)
      if (!detail) throw new Error('not found')
      return wait(fileCoverage(detail, path))
    },
    setNewCodePeriod: async (project, analysis) => {
      guard()
      return wait(setNewCodePeriod(project, analysis))
    },
    projectSettings: async (project) => {
      guard()
      return wait(settingsView(project))
    },
    updateProjectSettings: async (project, patch) => {
      requireAdmin()
      const s = settingsOf(project)
      // As the server does: a trimmed name, null when empty, and a main branch with analyses.
      const name = patch.name === undefined ? s.name : patch.name?.trim() || null
      if (name && name.length > 100) throw new Error('a project name is at most 100 characters')
      const main = patch.mainBranch ?? s.mainBranch
      if (!BRANCHES.some((b) => b.name === main)) throw new Error(`branch "${main}" has no analyses; the main branch must be one that does`)
      const by = session.user!.username
      const at = new Date().toISOString()
      if (name !== s.name) s.changes.unshift({ setting: 'name', old: s.name, new: name, by, at })
      if (main !== s.mainBranch) {
        s.changes.unshift({ setting: 'main_branch', old: s.mainBranch, new: main, by, at })
        clearNewCodePeriod(project)
      }
      Object.assign(s, { name, mainBranch: main })
      return wait(settingsView(project))
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
      return wait({ ...PROJECT_LIST, projects: PROJECT_LIST.projects.map((p) => ({ ...p, ...shown(p.key) })) })
    },
    project: async (key, branch) => {
      guard()
      const detail = projectDetail(key, branch, settings.get(key))
      if (!detail) throw new Error('not found')
      return wait(detail)
    },
    issues: async (query) => {
      guard()
      return wait(queryIssues(counted(), query))
    },
    issue: async (id) => {
      guard()
      return wait(findIssue(id))
    },
    updateIssue: async (id, patch) => wait(update(id, patch)),
    rules: async () => {
      guard()
      return wait({ ...catalog, rules: ruleSettings.withSettings(catalog.rules, projectKeys) })
    },
    projectRules: async (key) => {
      guard()
      const detail = projectDetail(key)
      if (!detail) throw new Error('not found')
      const open = issues.filter((i) => i.status === 'open' || i.status === 'confirmed')
      return wait(ruleSettings.projectRules(key, detail.languages.map((l) => l.id), catalog.rules, open))
    },
    ruleProfiles: async () => {
      guard()
      return wait(ruleSettings.profiles(projectKeys))
    },
    ruleProfile: async (id) => {
      guard()
      return wait(ruleSettings.profileDetail(id, projectKeys, new Map(catalog.rules.map((r) => [r.id, r.name]))))
    },
    createRuleProfile: async (name, copyFrom) => {
      requireAdmin()
      return wait(ruleSettings.createProfile(name, session.user!.username, copyFrom))
    },
    updateRuleProfile: async (id, patch) => {
      requireAdmin()
      ruleSettings.updateProfile(id, patch)
      await wait(null)
    },
    deleteRuleProfile: async (id) => {
      requireAdmin()
      ruleSettings.deleteProfile(id)
      await wait(null)
    },
    setProfileRule: async (id, rule, state, severity, note) => {
      requireAdmin()
      findRule(rule)
      ruleSettings.setProfileRule(id, rule, state, session.user!.username, severity, note)
      await wait(null)
    },
    setProjectProfile: async (key, profile) => {
      requireAdmin()
      if (!projectKeys.includes(key)) throw new Error('not found')
      ruleSettings.setProjectProfile(key, profile)
      await wait(null)
    },
    setRuleOff: async (rule, off, note) => {
      requireAdmin()
      findRule(rule)
      ruleSettings.setGlobal(rule, off, session.user!.username, note)
      await wait(null)
    },
    setProjectRule: async (key, rule, state, note) => {
      requireAdmin()
      findRule(rule)
      if (!projectKeys.includes(key)) throw new Error('not found')
      ruleSettings.setProject(key, rule, state, session.user!.username, note)
      await wait(null)
    },
  }
}
