import { issueSearchParams } from '@/lib/issues'
import { initials } from '@/lib/identity'
import { AuthError, type AnalysisDetail, type ApiToken, type CreatedToken, type AnalysisPage, type ComponentDetail, type ComponentList, type CoverageList, type DependencyList, type FileCoverage, type DependencyReview, type NewCodePeriod, type Drill, type IssueDetail, type IssuePage, type Overview, type ProjectDetail, type ProjectList, type ProjectRules, type QualityGate, type RuleCatalog, type Security, type SecurityReview, type Session, type Shell, type SondaApi, type User, type UserRow } from './types'

/** Fired when a request finds the session missing or expired. */
export const UNAUTHORIZED_EVENT = 'sonda:unauthorized'

/**
 * The contract over `sonda server`'s HTTP API (docs/server.md). The session
 * is a cookie the page cannot read; changes add `Sonda-Csrf`, which the
 * server requires of cookie-authenticated writes.
 */
export function createHttpApi(base = '/api', fetchFn: typeof fetch = (...args) => fetch(...args)): SondaApi {
  async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = {}
    if (body !== undefined) headers['Content-Type'] = 'application/json'
    if (method !== 'GET') headers['Sonda-Csrf'] = '1'
    const response = await fetchFn(base + path, {
      method,
      headers,
      credentials: 'same-origin',
      body: body === undefined ? undefined : JSON.stringify(body),
    })
    if (response.status === 401) {
      // A wrong token at sign-in is the sign-in form's to report.
      if (path !== '/session') window.dispatchEvent(new Event(UNAUTHORIZED_EVENT))
      throw new AuthError(path === '/session' ? 'Invalid username or password' : undefined)
    }
    if (!response.ok) {
      const error = (await response.json().catch(() => null)) as { error?: string } | null
      throw new Error(error?.error ?? `${response.status} ${response.statusText}`)
    }
    return (response.status === 204 ? undefined : await response.json()) as T
  }

  return {
    session: () => call<Session>('GET', '/session'),
    signIn: (username, password) => call<void>('POST', '/session', { username, password }),
    signOut: () => call<void>('DELETE', '/session'),
    changePassword: (current, next) => call<void>('PUT', '/me/password', { current, new: next }),
    myTokens: () => call<ApiToken[]>('GET', '/me/tokens'),
    createToken: (token) => call<CreatedToken>('POST', '/me/tokens', token),
    revokeMyToken: (id) => call<void>('DELETE', `/me/tokens/${id}`),
    tokens: () => call<ApiToken[]>('GET', '/tokens'),
    revokeToken: (id) => call<void>('DELETE', `/tokens/${id}`),
    createTokenFor: (user, token) => call<CreatedToken>('POST', '/tokens', { ...token, user }),
    users: () => call<UserRow[]>('GET', '/users'),
    createUser: (user) => call<User>('POST', '/users', user),
    updateUser: (id, patch) => call<User>('PATCH', `/users/${id}`, patch),
    // Counts the server cannot give yet are null, and the shell omits them.
    shell: async () => {
      const [session, open] = await Promise.all([call<Session>('GET', '/session'), call<IssuePage>('GET', `/issues?status=open,confirmed&limit=1`)])
      const user = session.user
      return {
        org: { name: 'sonda', initials: 'S', deployment: 'self-hosted', projectCount: null },
        user: user ? { name: user.displayName, handle: `@${user.username}`, initials: initials(user.displayName) } : { name: 'Read-only', handle: 'not signed in', initials: '··' },
        isAdmin: user?.role === 'admin',
        counts: { projects: null, components: null, issues: open.total, security: open.facets.category.vulnerability ?? 0 },
        me: user?.username ?? null,
      } satisfies Shell
    },
    // There are no teams yet (`teams: false`), so the scope is always "all".
    overview: (_scope, range) => call<Overview>('GET', `/overview?range=${range}`),
    drill: (metric) => call<Drill>('GET', `/drill/${metric}`),
    gates: async () => (await call<{ gates: QualityGate[] }>('GET', '/gates')).gates,
    security: () => call<Security>('GET', '/security'),
    securityReview: (q) => {
      const p = new URLSearchParams()
      if (q.project) p.set('project', q.project)
      if (q.branch) p.set('branch', q.branch)
      if (q.status) p.set('status', q.status)
      if (q.severity.length) p.set('severity', q.severity.join(','))
      if (q.owasp) p.set('owasp', q.owasp)
      if (q.assignee) p.set('assignee', q.assignee)
      if (q.isNew) p.set('new', 'true')
      return call<SecurityReview>('GET', `/security/review?${p}`)
    },
    components: (project) => call<ComponentList>('GET', `/components${project ? `?project=${encodeURIComponent(project)}` : ''}`),
    component: (project, path, branch) =>
      call<ComponentDetail>(
        'GET',
        `/projects/${encodeURIComponent(project)}/components/${encodeURIComponent(path)}${branch ? `?branch=${encodeURIComponent(branch)}` : ''}`,
      ),
    dependencies: (project, branch) =>
      call<DependencyList>('GET', `/projects/${encodeURIComponent(project)}/dependencies${branch ? `?branch=${encodeURIComponent(branch)}` : ''}`),
    setNewCodePeriod: (project, analysis) => call<NewCodePeriod>('PUT', `/projects/${encodeURIComponent(project)}/new-code`, { analysis }),
    coverage: (project, branch) =>
      call<CoverageList>('GET', `/projects/${encodeURIComponent(project)}/coverage${branch ? `?branch=${encodeURIComponent(branch)}` : ''}`),
    fileCoverage: (project, path, branch) =>
      call<FileCoverage>(
        'GET',
        `/projects/${encodeURIComponent(project)}/coverage/file?path=${encodeURIComponent(path)}${branch ? `&branch=${encodeURIComponent(branch)}` : ''}`,
      ),
    reviewDependency: (project, patch) =>
      call<DependencyReview>('PATCH', `/projects/${encodeURIComponent(project)}/dependencies/reviews`, patch),
    analyses: (q) => {
      const p = new URLSearchParams({ offset: String(q.offset), limit: String(q.limit) })
      if (q.project) p.set('project', q.project)
      if (q.branch) p.set('branch', q.branch)
      if (q.gate) p.set('gate', q.gate)
      return call<AnalysisPage>('GET', `/analyses?${p}`)
    },
    analysis: (id) => call<AnalysisDetail>('GET', `/analyses/${id}`),
    projects: () => call<ProjectList>('GET', '/projects'),
    project: (key, branch) => call<ProjectDetail>('GET', `/projects/${encodeURIComponent(key)}${branch ? `?branch=${encodeURIComponent(branch)}` : ''}`),
    issues: (query) => call<IssuePage>('GET', `/issues?${issueSearchParams(query)}`),
    issue: (id) => call<IssueDetail>('GET', `/issues/${id}`),
    updateIssue: (id, patch) => call<IssueDetail>('PATCH', `/issues/${id}`, patch),
    rules: () => call<RuleCatalog>('GET', '/rules'),
    projectRules: (key) => call<ProjectRules>('GET', `/projects/${encodeURIComponent(key)}/rule-settings`),
    setRuleOff: async (rule, off, note) => {
      await call<unknown>('PUT', '/rule-settings', { rule, off, ...(note ? { note } : {}) })
    },
    setProjectRule: async (key, rule, state, note) => {
      await call<unknown>('PUT', `/projects/${encodeURIComponent(key)}/rule-settings`, { rule, state, ...(note ? { note } : {}) })
    },
  }
}
