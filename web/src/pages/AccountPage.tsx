import { type FormEvent, useState } from 'react'
import { useApi, useAsync } from '@/api/hooks'
import { type CreatedToken, MIN_PASSWORD_LENGTH, type NewToken, type TokenType } from '@/api/types'
import { AppShell } from '@/components/shell/AppShell'
import { Button } from '@/components/sonda/controls'
import { Card, Mono, PageHeader } from '@/components/sonda/layout'
import { TokenTable } from '@/components/sonda/tokens'
import { TOKEN_TYPE } from '@/lib/visual'

const input = 'h-9 rounded-lg border-0 bg-canvas px-3 text-[13px] edge-strong'

/** The signed-in user's own account: who they are, their password and their tokens. */
export function AccountPage() {
  const api = useApi()
  const shell = useAsync(() => api.shell(), [api])
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [result, setResult] = useState<{ ok: boolean; text: string } | null>(null)
  const [busy, setBusy] = useState(false)

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (next !== confirm) {
      setResult({ ok: false, text: 'The new passwords differ.' })
      return
    }
    setBusy(true)
    try {
      await api.changePassword(current, next)
      setResult({ ok: true, text: 'Password changed. Your other sessions were signed out.' })
      setCurrent('')
      setNext('')
      setConfirm('')
    } catch (err) {
      setResult({ ok: false, text: (err as Error).message })
    }
    setBusy(false)
  }

  const user = shell.state === 'ready' ? shell.data : null
  return (
    <AppShell crumbs={[{ label: 'Account', to: '/account' }]}>
      <PageHeader title="Account" summary={user?.me ? `Signed in as @${user.me}` : 'Not signed in'} />
      {user && !user.me && <p className="m-0 text-[13.5px] text-fg-muted">You're browsing read-only. Sign out and sign in to manage your account.</p>}
      {user?.me && (
        <div className="grid max-w-[880px] grid-cols-[repeat(auto-fit,minmax(min(100%,380px),1fr))] gap-5">
          <Card title="Profile">
            <dl className="m-0 grid grid-cols-[110px_1fr] gap-y-2 text-[13.5px]">
              <dt className="text-fg-faint">Name</dt>
              <dd className="m-0">{user.user.name}</dd>
              <dt className="text-fg-faint">Username</dt>
              <dd className="m-0">
                <Mono className="text-[12px]">{user.me}</Mono>
              </dd>
              <dt className="text-fg-faint">Role</dt>
              <dd className="m-0">{user.isAdmin ? 'Admin' : 'Member'}</dd>
            </dl>
          </Card>
          <Card title="Change password" subtitle={`At least ${MIN_PASSWORD_LENGTH} characters. A long passphrase is best.`}>
            <form onSubmit={submit} className="flex flex-col gap-3">
              <label className="flex flex-col gap-1.5 text-[13px]">
                Current password
                <input type="password" autoComplete="current-password" required value={current} onChange={(e) => setCurrent(e.target.value)} className={input} />
              </label>
              <label className="flex flex-col gap-1.5 text-[13px]">
                New password
                <input type="password" autoComplete="new-password" required minLength={MIN_PASSWORD_LENGTH} value={next} onChange={(e) => setNext(e.target.value)} className={input} />
              </label>
              <label className="flex flex-col gap-1.5 text-[13px]">
                Repeat the new password
                <input type="password" autoComplete="new-password" required value={confirm} onChange={(e) => setConfirm(e.target.value)} className={input} />
              </label>
              {result && (
                <p role={result.ok ? 'status' : 'alert'} className={`m-0 text-[13px] ${result.ok ? 'text-ok' : 'text-crit'}`}>
                  {result.text}
                </p>
              )}
              <Button type="submit" primary className="self-start" disabled={busy || next.length < MIN_PASSWORD_LENGTH || !current}>
                {busy ? 'Changing…' : 'Change password'}
              </Button>
            </form>
          </Card>
          <Tokens />
        </div>
      )}
    </AppShell>
  )
}

const EXPIRY: { value: string; label: string }[] = [
  { value: '30', label: '30 days' },
  { value: '60', label: '60 days' },
  { value: '90', label: '90 days' },
  { value: 'none', label: 'No expiry' },
]

/** Your tokens (ADR-0012): generate one, copy it once, revoke it. */
function Tokens() {
  const api = useApi()
  const [version, setVersion] = useState(0)
  const tokens = useAsync(() => api.myTokens(), [api, version])
  const [name, setName] = useState('')
  const [type, setType] = useState<TokenType>('project_analysis')
  const [project, setProject] = useState('')
  const [expiry, setExpiry] = useState('30')
  const [created, setCreated] = useState<CreatedToken | null>(null)
  const [copied, setCopied] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const generate = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError('')
    setCopied(false)
    const token: NewToken = {
      name,
      type,
      ...(type === 'project_analysis' ? { project } : {}),
      expiresInDays: expiry === 'none' ? null : (Number(expiry) as 30 | 60 | 90),
    }
    try {
      setCreated(await api.createToken(token))
      setName('')
      setProject('')
      setVersion((v) => v + 1)
    } catch (err) {
      setError((err as Error).message)
    }
    setBusy(false)
  }
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(created!.token)
      setCopied(true)
    } catch {
      setError('Could not copy; select the token and copy it.')
    }
  }
  const revoke = async (id: number) => {
    setError('')
    try {
      await api.revokeMyToken(id)
      setVersion((v) => v + 1)
    } catch (err) {
      setError((err as Error).message)
    }
  }

  return (
    <Card id="tokens" title="Tokens" subtitle="For CI and scripts, with sonda upload or sonda scan --upload. A token never has more rights than you." className="col-span-full">
      <form onSubmit={generate} className="flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1.5 text-[13px]">
          Name
          <input required maxLength={100} value={name} onChange={(e) => setName(e.target.value)} placeholder="ci-payments" className={input} />
        </label>
        <label className="flex flex-col gap-1.5 text-[13px]">
          Type
          <select value={type} onChange={(e) => setType(e.target.value as TokenType)} className={input}>
            {(Object.keys(TOKEN_TYPE) as TokenType[]).map((t) => (
              <option key={t} value={t}>
                {TOKEN_TYPE[t].label}
              </option>
            ))}
          </select>
        </label>
        {type === 'project_analysis' && (
          <label className="flex flex-col gap-1.5 text-[13px]">
            Project key
            <input required value={project} onChange={(e) => setProject(e.target.value)} placeholder="payments-platform" className={input} />
          </label>
        )}
        <label className="flex flex-col gap-1.5 text-[13px]">
          Expires in
          <select value={expiry} onChange={(e) => setExpiry(e.target.value)} className={input}>
            {EXPIRY.map((x) => (
              <option key={x.value} value={x.value}>
                {x.label}
              </option>
            ))}
          </select>
        </label>
        <Button type="submit" primary disabled={busy || !name.trim()}>
          {busy ? 'Generating…' : 'Generate'}
        </Button>
      </form>
      <p className="m-0 text-xs text-fg-faint">{TOKEN_TYPE[type].note}</p>
      {created && (
        <div role="status" className="flex flex-col gap-2 rounded-lg bg-panel px-3.5 py-3 edge-strong">
          <span className="text-[13px] font-semibold">Copy “{created.name}” now: it won’t be shown again.</span>
          <div className="flex flex-wrap items-center gap-2">
            <Mono className="min-w-0 flex-1 text-[12px] break-all select-all">{created.token}</Mono>
            <Button onClick={() => void copy()}>{copied ? 'Copied' : 'Copy'}</Button>
            <Button onClick={() => setCreated(null)}>Done</Button>
          </div>
        </div>
      )}
      {error && (
        <p role="alert" className="m-0 text-[13px] text-crit">
          {error}
        </p>
      )}
      {tokens.state === 'ready' && <TokenTable tokens={tokens.data} onRevoke={(t) => void revoke(t.id)} />}
      {tokens.state === 'error' && <p role="alert">Could not load tokens: {tokens.error.message}</p>}
    </Card>
  )
}
