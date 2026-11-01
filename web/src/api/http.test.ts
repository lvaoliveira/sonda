import { afterEach, describe, expect, it, vi } from 'vitest'
import { DEFAULT_FILTER, toQuery } from '@/lib/issues'
import { createHttpApi, UNAUTHORIZED_EVENT } from './http'
import { AuthError } from './types'

/** A fetch that records requests and answers from `reply`. */
function fakeFetch(reply: (url: string, init: RequestInit) => Response) {
  const calls: { url: string; init: RequestInit }[] = []
  const fn = (async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({ url: String(input), init: init ?? {} })
    return reply(String(input), init ?? {})
  }) as typeof fetch
  return { fn, calls }
}

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
const page = { total: 3, offset: 0, limit: 1, items: [], facets: { severity: {}, category: { vulnerability: 2 }, status: {}, component: {} } }

afterEach(() => localStorage.clear())

describe('the HTTP API client', () => {
  it('reads with the session cookie and no CSRF header', async () => {
    const { fn, calls } = fakeFetch(() => json(page))
    await createHttpApi('/api', fn).issues(toQuery(DEFAULT_FILTER, '', 0))
    expect(calls[0].url).toBe('/api/issues?status=open%2Cconfirmed&offset=0&limit=50')
    expect(calls[0].init.credentials).toBe('same-origin')
    expect(calls[0].init.headers).toEqual({})
  })

  it('sends changes as JSON with the CSRF header', async () => {
    const { fn, calls } = fakeFetch(() => json({ id: 7 }))
    await createHttpApi('/api', fn).updateIssue(7, { status: 'confirmed' })
    expect(calls[0].url).toBe('/api/issues/7')
    expect(calls[0].init.method).toBe('PATCH')
    expect(calls[0].init.headers).toEqual({ 'Content-Type': 'application/json', 'Sonda-Csrf': '1' })
    expect(calls[0].init.body).toBe('{"status":"confirmed"}')
  })

  it('sends an expired session back to sign-in', async () => {
    const onUnauthorized = vi.fn()
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized)
    const { fn } = fakeFetch(() => json({ error: 'missing or invalid token' }, 401))
    await expect(createHttpApi('/api', fn).rules()).rejects.toBeInstanceOf(AuthError)
    expect(onUnauthorized).toHaveBeenCalledOnce()
    // A wrong token at sign-in is the form's to report, not a session expiry.
    await expect(createHttpApi('/api', fn).signIn('ann', 'nope')).rejects.toThrow('Invalid username or password')
    expect(onUnauthorized).toHaveBeenCalledOnce()
    window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized)
  })

  it('asks for the review queue with only the filters set', async () => {
    const { fn, calls } = fakeFetch(() => json({}))
    const api = createHttpApi('/api', fn)
    await api.securityReview({ status: 'open', severity: [], isNew: false })
    await api.securityReview({ project: 'shop', status: 'all', severity: ['blocker', 'critical'], owasp: 'A05', assignee: 'ann', isNew: true })
    expect(calls.map((c) => c.url)).toEqual([
      '/api/security/review?status=open',
      '/api/security/review?project=shop&status=all&severity=blocker%2Ccritical&owasp=A05&assignee=ann&new=true',
    ])
  })

  it('reads and changes rule settings, globally and per project', async () => {
    const { fn, calls } = fakeFetch(() => json({}))
    const api = createHttpApi('/api', fn)
    await api.projectRules('shop')
    await api.setRuleOff('js/no-var', true, 'Too noisy.')
    await api.setProjectRule('shop', 'js/no-var', 'inherit')
    expect(calls.map((c) => [c.init.method ?? 'GET', c.url, c.init.body ?? null])).toEqual([
      ['GET', '/api/projects/shop/rules', null],
      ['PUT', '/api/rule-settings', '{"rule":"js/no-var","off":true,"note":"Too noisy."}'],
      ['PUT', '/api/projects/shop/rule-settings', '{"rule":"js/no-var","state":"inherit"}'],
    ])
  })

  it('asks for the overview of a range; there are no teams to scope by', async () => {
    const { fn, calls } = fakeFetch(() => json({ teams: false }))
    await createHttpApi('/api', fn).overview!('all', '30d')
    await createHttpApi('/api', fn).drill!('vulns', 'all')
    expect(calls.map((c) => c.url)).toEqual(['/api/overview?range=30d', '/api/drill/vulns'])
  })

  it("shows the server's error message", async () => {
    const { fn } = fakeFetch(() => json({ error: 'unknown severity "fatal"' }, 400))
    await expect(createHttpApi('/api', fn).issue(1)).rejects.toThrow('unknown severity "fatal"')
  })

  it('builds the shell from the signed-in user and real counts, leaving unknown ones out', async () => {
    const ann = { id: 2, username: 'ann', displayName: 'Ann Lee', role: 'admin', disabled: false }
    const { fn } = fakeFetch((url) => json(url.endsWith('/session') ? { user: ann, authenticated: true, readsRequireAuth: true } : page))
    const shell = await createHttpApi('/api', fn).shell()
    expect(shell.counts).toEqual({ projects: null, components: null, issues: 3, security: 2 })
    expect(shell.me).toBe('ann')
    expect(shell.user).toEqual({ name: 'Ann Lee', handle: '@ann', initials: 'AL' })
    expect(shell.isAdmin).toBe(true)
    expect(shell.org.projectCount).toBeNull()
  })

  it('signs in with username and password, and manages users', async () => {
    const { fn, calls } = fakeFetch((url, init) => (init.method === 'POST' && url.endsWith('/session') ? new Response(null, { status: 204 }) : json({ id: 3 })))
    const api = createHttpApi('/api', fn)
    await api.signIn('ann', 'correct horse battery')
    await api.changePassword('correct horse battery', 'an even better one')
    await api.createUser({ username: 'bob', displayName: 'Bob', role: 'member', password: 'a long enough one' })
    await api.updateUser(3, { disabled: true })
    expect(calls.map((c) => `${c.init.method} ${c.url} ${c.init.body}`)).toEqual([
      'POST /api/session {"username":"ann","password":"correct horse battery"}',
      'PUT /api/me/password {"current":"correct horse battery","new":"an even better one"}',
      'POST /api/users {"username":"bob","displayName":"Bob","role":"member","password":"a long enough one"}',
      'PATCH /api/users/3 {"disabled":true}',
    ])
    expect(calls.every((c) => (c.init.headers as Record<string, string>)['Sonda-Csrf'] === '1')).toBe(true)
  })
})
