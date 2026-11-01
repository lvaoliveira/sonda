import { type FormEvent, useState } from 'react'
import { useApi, useAsync } from '@/api/hooks'
import { type DeletedProject, MIN_PASSWORD_LENGTH, type NewUser, type Role, type UserPatch, type UserRow } from '@/api/types'
import { AppShell } from '@/components/shell/AppShell'
import { Button } from '@/components/sonda/controls'
import { Card, Mono, PageHeader } from '@/components/sonda/layout'
import { TokenGenerator, TokenTable } from '@/components/sonda/tokens'
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
        <div className="relative overflow-x-auto">
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
        onCreated={(username, service) => {
          setError('')
          setNotice(
            service
              ? `Created ${username}, a service user. Generate its CI tokens under Tokens below.`
              : `Created ${username}. Share the password with them; they can change it under Account.`,
          )
          reload()
        }}
        onError={setError}
      />
      <AllTokens owners={list.filter((u) => !u.disabled).map((u) => u.username)} />
      <DeletedProjects />
      <p className="m-0 text-[12.5px] text-fg-faint">Single sign-on (OpenID Connect) is planned; see ADR-0006.</p>
    </>
  )
}

/**
 * Every user's tokens, to revoke (ADR-0012), and generating one for any
 * user, such as a `ci` service user whose tokens outlive a person's account.
 * Nobody can read a secret after it's generated.
 */
function AllTokens({ owners }: { owners: string[] }) {
  const api = useApi()
  const [version, setVersion] = useState(0)
  const tokens = useAsync(() => api.tokens(), [api, version])
  const [error, setError] = useState('')
  const revoke = async (id: number) => {
    setError('')
    try {
      await api.revokeToken(id)
      setVersion((v) => v + 1)
    } catch (err) {
      setError((err as Error).message)
    }
  }
  return (
    <Card
      id="all-tokens"
      title="Tokens"
      subtitle="Everyone's tokens. Users generate their own under Account; generate CI tokens here for a service user such as ci, so pipelines don't stop when a person leaves. Disabling a user stops their tokens."
    >
      <TokenGenerator owners={owners} onGenerate={(token, owner) => api.createTokenFor(owner, token)} onGenerated={() => setVersion((v) => v + 1)} />
      {error && (
        <p role="alert" className="m-0 text-[13px] text-crit">
          {error}
        </p>
      )}
      {tokens.state === 'ready' && <TokenTable tokens={tokens.data} showOwner onRevoke={(t) => void revoke(t.id)} />}
      {tokens.state === 'error' && <p role="alert">Could not load tokens: {tokens.error.message}</p>}
    </Card>
  )
}

/** Deleted projects (ADR-0017): who deleted which key and when; uploads to a key stay refused until it's allowed again. */
function DeletedProjects() {
  const api = useApi()
  const deleted = useAsync(() => api.deletedProjects(), [api])
  const [error, setError] = useState('')
  const allow = async (d: DeletedProject) => {
    setError('')
    try {
      await api.allowDeletedProject(d.id)
      if (deleted.state === 'ready') deleted.reload()
    } catch (err) {
      setError((err as Error).message)
    }
  }
  return (
    <Card
      id="deleted-projects"
      title="Deleted projects"
      subtitle="Uploads to a deleted project's key are refused, so a forgotten pipeline can't bring it back empty. Allow the key again and its next upload starts a new project."
    >
      {error && (
        <p role="alert" className="m-0 text-[13px] text-crit">
          {error}
        </p>
      )}
      {deleted.state === 'error' && <p role="alert">Could not load deleted projects: {deleted.error.message}</p>}
      {deleted.state === 'ready' && deleted.data.length === 0 && <p className="m-0 text-[13px] text-fg-muted">No project has been deleted.</p>}
      {deleted.state === 'ready' && deleted.data.length > 0 && (
        <ul aria-label="Deleted projects" className="m-0 flex list-none flex-col p-0">
          {deleted.data.map((d) => (
            <li key={d.id} className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border-t border-line py-2.5 text-[13px] first:border-t-0">
              <span className="flex min-w-0 flex-col">
                <Mono className="text-[12.5px] text-fg">{d.key}</Mono>
                {d.name && <span className="text-xs text-fg-faint">{d.name}</span>}
              </span>
              <span className="text-fg-muted">
                {d.analyses} {d.analyses === 1 ? 'analysis' : 'analyses'} · deleted by {d.deletedBy}, {shortDate(d.deletedAt)}
              </span>
              {d.allowedAt ? (
                <span className="text-fg-faint">
                  allowed again by {d.allowedBy}, {shortDate(d.allowedAt)}
                </span>
              ) : (
                <>
                  <span className="font-semibold text-warn">Uploads refused</span>
                  <Button onClick={() => void allow(d)} className="ml-auto">
                    Allow the key again
                  </Button>
                </>
              )}
            </li>
          ))}
        </ul>
      )}
    </Card>
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
            {/* Admins have to be able to sign in. */}
            <option value="admin" disabled={!user.hasPassword}>
              Admin
            </option>
          </select>
        </td>
        <td className="py-2.5">
          {user.disabled ? <span className="text-fg-faint">Disabled</span> : <span className="text-ok">Active</span>}
          {!user.hasPassword && <span className="block text-xs text-fg-faint">Service user · can’t sign in</span>}
        </td>
        <td className="py-2.5 text-fg-muted">{user.lastLoginAt ? shortDate(user.lastLoginAt) : 'Never'}</td>
        <td className="py-2.5 text-right">
          <span className="inline-flex gap-1.5">
            <Button onClick={() => setResetting(!resetting)}>{user.hasPassword ? 'Reset password' : 'Set password'}</Button>
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

function CreateUser({ onCreated, onError }: { onCreated: (username: string, service: boolean) => void; onError: (message: string) => void }) {
  const api = useApi()
  const empty = { username: '', displayName: '', role: 'member' as Role, password: '' }
  const [user, setUser] = useState(empty)
  const [service, setService] = useState(false)
  const [busy, setBusy] = useState(false)
  const set = (patch: Partial<typeof empty>) => setUser((u) => ({ ...u, ...patch }))
  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    const { password, ...fields } = user
    const created: NewUser = {
      ...fields,
      username: user.username.trim().toLowerCase(),
      displayName: user.displayName.trim(),
      // A service user has no password and is a member.
      ...(service ? { role: 'member' } : { password }),
    }
    try {
      await api.createUser(created)
      onCreated(user.username.trim().toLowerCase(), service)
      setUser(empty)
      setService(false)
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
          <select value={service ? 'member' : user.role} disabled={service} onChange={(e) => set({ role: e.target.value as Role })} className={input}>
            <option value="member">Member</option>
            <option value="admin">Admin</option>
          </select>
        </label>
        {!service && (
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
        )}
        <label className="flex items-center gap-2 self-center text-[13px]">
          <input type="checkbox" checked={service} onChange={(e) => setService(e.target.checked)} className="accent-brand" />
          <span>
            Service user
            <span className="block text-xs text-fg-faint">No password, can’t sign in: owns CI tokens.</span>
          </span>
        </label>
        <Button type="submit" primary disabled={busy || (!service && user.password.length < MIN_PASSWORD_LENGTH)}>
          {busy ? 'Adding…' : 'Add user'}
        </Button>
      </form>
    </Card>
  )
}
