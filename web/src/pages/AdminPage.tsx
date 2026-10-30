import { type FormEvent, useState } from 'react'
import { useApi, useAsync } from '@/api/hooks'
import { MIN_PASSWORD_LENGTH, type NewUser, type Role, type UserPatch, type UserRow } from '@/api/types'
import { AppShell } from '@/components/shell/AppShell'
import { Button } from '@/components/sonda/controls'
import { Card, Mono, PageHeader } from '@/components/sonda/layout'
import { shortDate } from '@/lib/format'

/** Administration: users and roles (ADR-0006). Admins only; the server enforces it too. */
export function AdminPage() {
  const api = useApi()
  const shell = useAsync(() => api.shell(), [api])
  return (
    <AppShell crumbs={[{ label: 'Administration', to: '/admin' }]}>
      {shell.state === 'ready' && !shell.data.isAdmin && (
        <>
          <PageHeader title="Administration" summary="Admins only." />
          <p className="m-0 text-[13.5px] text-fg-muted">Ask an admin to change users or roles.</p>
        </>
      )}
      {shell.state === 'ready' && shell.data.isAdmin && <Users me={shell.data.me} />}
    </AppShell>
  )
}

const input = 'h-9 rounded-lg border-0 bg-canvas px-3 text-[13px] edge-strong'

function Users({ me }: { me: string | null }) {
  const api = useApi()
  const [version, setVersion] = useState(0)
  const users = useAsync(() => api.users(), [api, version])
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const reload = () => setVersion((v) => v + 1)

  const update = async (user: UserRow, patch: UserPatch, done: string) => {
    setError('')
    setNotice('')
    try {
      await api.updateUser(user.id, patch)
      setNotice(done)
      reload()
    } catch (e) {
      setError((e as Error).message)
    }
  }

  const list = users.state === 'ready' ? users.data : []
  const active = list.filter((u) => !u.disabled).length
  return (
    <>
      <PageHeader title="Administration" summary={users.state === 'ready' ? `${list.length} users · ${active} active` : ' '} />
      {(error || notice) && (
        <p role={error ? 'alert' : 'status'} className={`m-0 text-[13px] ${error ? 'text-crit' : 'text-ok'}`}>
          {error || notice}
        </p>
      )}
      {users.state === 'error' && <p role="alert">Could not load users: {users.error.message}</p>}
      <Card title="Users" subtitle="Disabled users can't sign in; they stay in the audit trail.">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px] border-collapse text-[13.5px]">
            <thead>
              <tr className="text-left text-[12px] text-fg-faint">
                <th scope="col" className="py-2 font-normal">User</th>
                <th scope="col" className="py-2 font-normal">Role</th>
                <th scope="col" className="py-2 font-normal">Status</th>
                <th scope="col" className="py-2 font-normal">Last sign-in</th>
                <th scope="col" className="py-2 font-normal">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {list.map((u) => (
                <UserRowView key={u.id} user={u} isMe={u.username === me} update={update} />
              ))}
            </tbody>
          </table>
        </div>
      </Card>
      <CreateUser
        onCreated={(username) => {
          setError('')
          setNotice(`Created ${username}. Share the password with them; they can change it under Account.`)
          reload()
        }}
        onError={setError}
      />
      <p className="m-0 text-[12.5px] text-fg-faint">Single sign-on (OpenID Connect) is planned; see ADR-0006.</p>
    </>
  )
}

function UserRowView({ user, isMe, update }: { user: UserRow; isMe: boolean; update: (u: UserRow, p: UserPatch, done: string) => Promise<void> }) {
  const [resetting, setResetting] = useState(false)
  const [password, setPassword] = useState('')
  const reset = async (e: FormEvent) => {
    e.preventDefault()
    await update(user, { password }, `Reset the password of ${user.username}; they were signed out everywhere.`)
    setResetting(false)
    setPassword('')
  }
  return (
    <>
      <tr className="border-t border-line" style={{ opacity: user.disabled ? 0.6 : 1 }}>
        <td className="py-2.5">
          <span className="flex flex-col leading-[1.3]">
            <span className="font-medium">
              {user.displayName} {isMe && <span className="text-[11px] text-fg-faint">(you)</span>}
            </span>
            <Mono className="text-[11px] text-fg-faint">@{user.username}</Mono>
          </span>
        </td>
        <td className="py-2.5">
          <select
            aria-label={`Role of ${user.username}`}
            value={user.role}
            onChange={(e) => update(user, { role: e.target.value as Role }, `${user.username} is now ${e.target.value === 'admin' ? 'an admin' : 'a member'}.`)}
            className="h-8 rounded-md border-0 bg-canvas px-2 text-[13px] edge"
          >
            <option value="member">Member</option>
            <option value="admin">Admin</option>
          </select>
        </td>
        <td className="py-2.5">{user.disabled ? <span className="text-fg-faint">Disabled</span> : <span className="text-ok">Active</span>}</td>
        <td className="py-2.5 text-fg-muted">{user.lastLoginAt ? shortDate(user.lastLoginAt) : 'Never'}</td>
        <td className="py-2.5 text-right">
          <span className="inline-flex gap-1.5">
            <Button onClick={() => setResetting(!resetting)}>Reset password</Button>
            <Button onClick={() => update(user, { disabled: !user.disabled }, `${user.disabled ? 'Enabled' : 'Disabled'} ${user.username}.`)}>
              {user.disabled ? 'Enable' : 'Disable'}
            </Button>
          </span>
        </td>
      </tr>
      {resetting && (
        <tr>
          <td colSpan={5} className="pb-3">
            <form onSubmit={reset} className="flex flex-wrap items-center gap-2">
              <input
                type="password"
                autoComplete="new-password"
                aria-label={`New password for ${user.username}`}
                placeholder={`New password (at least ${MIN_PASSWORD_LENGTH} characters)`}
                minLength={MIN_PASSWORD_LENGTH}
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className={`${input} w-[320px] max-w-full`}
              />
              <Button type="submit" primary disabled={password.length < MIN_PASSWORD_LENGTH}>
                Set password
              </Button>
            </form>
          </td>
        </tr>
      )}
    </>
  )
}

function CreateUser({ onCreated, onError }: { onCreated: (username: string) => void; onError: (message: string) => void }) {
  const api = useApi()
  const empty: NewUser = { username: '', displayName: '', role: 'member', password: '' }
  const [user, setUser] = useState<NewUser>(empty)
  const [busy, setBusy] = useState(false)
  const set = (patch: Partial<NewUser>) => setUser((u) => ({ ...u, ...patch }))
  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    try {
      await api.createUser({ ...user, username: user.username.trim().toLowerCase(), displayName: user.displayName.trim() })
      onCreated(user.username.trim().toLowerCase())
      setUser(empty)
    } catch (err) {
      onError((err as Error).message)
    }
    setBusy(false)
  }
  return (
    <Card title="Add a user" subtitle="Usernames are lowercase and permanent; they are what issues are assigned to.">
      <form onSubmit={submit} className="grid grid-cols-[repeat(auto-fit,minmax(200px,1fr))] items-end gap-3">
        <label className="flex flex-col gap-1.5 text-[13px]">
          Username
          <input required autoCapitalize="none" spellCheck={false} pattern="[a-z0-9][a-z0-9._\-]{1,63}" value={user.username} onChange={(e) => set({ username: e.target.value })} className={input} />
        </label>
        <label className="flex flex-col gap-1.5 text-[13px]">
          Display name
          <input required maxLength={100} value={user.displayName} onChange={(e) => set({ displayName: e.target.value })} className={input} />
        </label>
        <label className="flex flex-col gap-1.5 text-[13px]">
          Role
          <select value={user.role} onChange={(e) => set({ role: e.target.value as Role })} className={input}>
            <option value="member">Member</option>
            <option value="admin">Admin</option>
          </select>
        </label>
        <label className="flex flex-col gap-1.5 text-[13px]">
          Initial password
          <input
            type="password"
            autoComplete="new-password"
            required
            minLength={MIN_PASSWORD_LENGTH}
            value={user.password}
            onChange={(e) => set({ password: e.target.value })}
            className={input}
          />
        </label>
        <Button type="submit" primary disabled={busy || user.password.length < MIN_PASSWORD_LENGTH}>
          {busy ? 'Adding…' : 'Add user'}
        </Button>
      </form>
    </Card>
  )
}
