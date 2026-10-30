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
    await expect(createHttpApi('/api', fn).signIn('nope')).rejects.toThrow('That token is not valid')
    expect(onUnauthorized).toHaveBeenCalledOnce()
    window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized)
  })

  it('asks for the overview of a range; there are no teams to scope by', async () => {
    const { fn, calls } = fakeFetch(() => json({ teams: false }))
    await createHttpApi('/api', fn).overview!('all', '30d')
    expect(calls[0].url).toBe('/api/overview?range=30d')
  })

  it("shows the server's error message", async () => {
    const { fn } = fakeFetch(() => json({ error: 'unknown severity "fatal"' }, 400))
    await expect(createHttpApi('/api', fn).issue(1)).rejects.toThrow('unknown severity "fatal"')
  })

  it('builds the shell from real counts, leaving unknown ones out', async () => {
    localStorage.setItem('sonda-name', 'Ann Lee')
    const { fn } = fakeFetch(() => json(page))
    const shell = await createHttpApi('/api', fn).shell()
    expect(shell.counts).toEqual({ projects: null, components: null, issues: 3, security: 2 })
    expect(shell.me).toBe('Ann Lee')
    expect(shell.user.initials).toBe('AL')
    expect(shell.org.projectCount).toBeNull()
  })
})
