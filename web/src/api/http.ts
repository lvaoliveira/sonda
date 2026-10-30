import { issueSearchParams } from '@/lib/issues'
import { initials } from '@/lib/identity'
import { AuthError, type Drill, type IssueDetail, type IssuePage, type Overview, type ProjectDetail, type ProjectList, type RuleCatalog, type Session, type Shell, type SondaApi, type User, type UserRow } from './types'

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
    projects: () => call<ProjectList>('GET', '/projects'),
    project: (key, branch) => call<ProjectDetail>('GET', `/projects/${encodeURIComponent(key)}${branch ? `?branch=${encodeURIComponent(branch)}` : ''}`),
    issues: (query) => call<IssuePage>('GET', `/issues?${issueSearchParams(query)}`),
    issue: (id) => call<IssueDetail>('GET', `/issues/${id}`),
    updateIssue: (id, patch) => call<IssueDetail>('PATCH', `/issues/${id}`, patch),
    rules: () => call<RuleCatalog>('GET', '/rules'),
  }
}
