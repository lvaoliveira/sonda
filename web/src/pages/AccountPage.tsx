import { type FormEvent, useState } from 'react'
import { useApi, useAsync } from '@/api/hooks'
import { MIN_PASSWORD_LENGTH } from '@/api/types'
import { AppShell } from '@/components/shell/AppShell'
import { Button } from '@/components/sonda/controls'
import { Card, Mono, PageHeader } from '@/components/sonda/layout'

const input = 'h-9 rounded-lg border-0 bg-canvas px-3 text-[13px] edge-strong'

/** The signed-in user's own account: who they are, and their password. */
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
        </div>
      )}
    </AppShell>
  )
}
