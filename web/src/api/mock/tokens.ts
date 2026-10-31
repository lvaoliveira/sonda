import type { ApiToken, CreatedToken, NewToken, TokenType } from '../types'

const PREFIX: Record<TokenType, string> = { user: 'sonda_u_', project_analysis: 'sonda_p_', global_analysis: 'sonda_a_' }
const DAY = 86_400_000

/** Every user's tokens, newest first, as the server keeps them (never their secrets). */
const SEED: ApiToken[] = [
  {
    id: 2,
    name: 'ci-payments',
    type: 'project_analysis',
    project: 'payments-platform',
    prefix: 'sonda_p_k3x9',
    owner: 'mara',
    createdAt: '2026-10-01T09:00:00Z',
    expiresAt: null,
    lastUsedAt: '2026-10-30T08:12:00Z',
    revokedAt: null,
    revokedBy: null,
    status: 'active',
  },
  {
    id: 1,
    name: 'old-script',
    type: 'user',
    project: null,
    prefix: 'sonda_u_2fqa',
    owner: 'devon',
    createdAt: '2026-08-01T09:00:00Z',
    expiresAt: '2026-08-31T09:00:00Z',
    lastUsedAt: null,
    revokedAt: null,
    revokedBy: null,
    status: 'expired',
  },
]

/** One mock server's tokens: each mock API starts from the same seed. */
export function mockTokens() {
  const tokens: ApiToken[] = structuredClone(SEED)

  /** As the server checks it (ADR-0012). */
  function create(owner: string, t: NewToken): CreatedToken {
    const name = t.name.trim()
    if (!name || name.length > 100) throw new Error("a token's name has 1-100 characters, no control characters")
    if (t.type === 'project_analysis' && !t.project?.trim()) throw new Error('a project analysis token needs a project')
    if (t.type !== 'project_analysis' && t.project) throw new Error('only project analysis tokens have a project')
    if (tokens.some((x) => x.owner === owner && x.name === name && x.status !== 'revoked')) throw new Error('you already have a token with this name')
    const secret = PREFIX[t.type] + Array.from({ length: 52 }, (_, i) => 'abcdefghijklmnopqrstuvwxyz234567'[(i * 7 + tokens.length * 13) % 32]).join('')
    const now = Date.now()
    const token: ApiToken = {
      id: Math.max(...tokens.map((x) => x.id)) + 1,
      name,
      type: t.type,
      project: t.type === 'project_analysis' ? t.project!.trim() : null,
      prefix: secret.slice(0, 12),
      owner,
      createdAt: new Date(now).toISOString(),
      expiresAt: t.expiresInDays == null ? null : new Date(now + t.expiresInDays * DAY).toISOString(),
      lastUsedAt: null,
      revokedAt: null,
      revokedBy: null,
      status: 'active',
    }
    tokens.unshift(token)
    return { ...token, token: secret }
  }

  function list(owner?: string): ApiToken[] {
    return tokens.filter((t) => owner === undefined || t.owner === owner)
  }

  /** Revoking is final; an owner can revoke only their own. */
  function revoke(id: number, by: string, owner?: string) {
    const t = tokens.find((x) => x.id === id && (owner === undefined || x.owner === owner))
    if (!t) throw new Error('not found')
    if (t.status === 'revoked') return
    Object.assign(t, { status: 'revoked', revokedAt: new Date().toISOString(), revokedBy: by })
  }

  return { create, list, revoke }
}
