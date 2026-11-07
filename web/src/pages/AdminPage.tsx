import { type ReactNode, type SubmitEvent, useEffect, useId, useRef, useState } from 'react'
import { Link, Navigate, useLocation } from 'react-router'
import { useApi, useAsync } from '@/api/hooks'
import { type DeletedProject, type GitHubApp, type GitHubAppManifest, MIN_PASSWORD_LENGTH, type NewUser, type Role, type UserPatch, type UserRow } from '@/api/types'
import { AppShell, type Tab, Tabs } from '@/components/shell/AppShell'
import { ExternalButton } from '@/components/sonda/connect'
import { Button, Segmented } from '@/components/sonda/controls'
import { Drawer, DrawerActions, Field } from '@/components/sonda/Drawer'
import { Card, Mono, PageHeader } from '@/components/sonda/layout'
import { GenerateTokenDrawer, TokenTable } from '@/components/sonda/tokens'
import { copyText } from '@/lib/clipboard'
import { shortDate, trimTrailing } from '@/lib/format'
import { generatePassword } from '@/lib/password'

export type AdminTab = 'users' | 'tokens' | 'github' | 'deleted-projects'

/** Administration's sections, each its own route, as a project's pages are. */
const TABS: (Tab & { tab: AdminTab })[] = [
  { tab: 'users', to: '/admin', label: 'Users', end: true },
  { tab: 'tokens', to: '/admin/tokens', label: 'Tokens' },
  { tab: 'github', to: '/admin/github', label: 'GitHub' },
  { tab: 'deleted-projects', to: '/admin/deleted-projects', label: 'Deleted projects' },
]

/** The sections were anchors on one page before they were tabs: old links still land on theirs. */
const MOVED: Record<string, string> = { '#github': '/admin/github', '#all-tokens': '/admin/tokens', '#deleted-projects': '/admin/deleted-projects' }

/** Administration: users and roles (ADR-0006), tokens, the GitHub App and deleted projects. Admins only; the server enforces it too. */
export function AdminPage({ tab = 'users' }: Readonly<{ tab?: AdminTab }>) {
  const api = useApi()
  const shell = useAsync(() => api.shell(), [api])
  const moved = MOVED[useLocation().hash]
  if (moved) return <Navigate to={moved} replace />
  const current = TABS.find((t) => t.tab === tab)!
  const isAdmin = shell.state === 'ready' && shell.data.isAdmin
  return (
    <AppShell
      crumbs={[{ label: 'Administration', to: '/admin' }, ...(isAdmin ? [{ label: current.label, to: current.to }] : [])]}
      tabs={isAdmin && <Tabs label="Administration" tabs={TABS} />}
    >
      {shell.state === 'ready' && !shell.data.isAdmin && (
        <>
          <PageHeader title="Administration" summary="Admins only." />
          <p className="m-0 text-[13.5px] text-fg-muted">Ask an admin to change users or roles.</p>
        </>
      )}
      {isAdmin && tab === 'users' && <Users me={shell.data.me} />}
      {isAdmin && tab === 'tokens' && <AllTokens />}
      {isAdmin && tab === 'github' && <GitHubAppTab />}
      {isAdmin && tab === 'deleted-projects' && <DeletedProjects />}
    </AppShell>
  )
}

const input = 'h-9 rounded-lg border-0 bg-canvas px-3 text-[13px] edge-strong'

function Users({ me }: Readonly<{ me: string | null }>) {
  const api = useApi()
  const [version, setVersion] = useState(0)
  const users = useAsync(() => api.users(), [api, version])
  const [error, setError] = useState('')
  const [notice, setNotice] = useState<ReactNode>('')
  const [adding, setAdding] = useState(false)
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
      <PageHeader title="Users" summary={users.state === 'ready' ? `${list.length} users · ${active} active · disabled users can’t sign in, and stay in the audit trail` : ' '}>
        <Button primary onClick={() => setAdding(true)}>
          Add user
        </Button>
      </PageHeader>
      {(error || notice) && (
        <p role={error ? 'alert' : 'status'} className={`m-0 text-[13px] ${error ? 'text-crit' : 'text-ok'}`}>
          {error || notice}
        </p>
      )}
      {users.state === 'error' && <p role="alert">Could not load users: {users.error.message}</p>}
      <Card>
        <div className="relative overflow-x-auto">
          <table aria-label="Users" className="w-full min-w-[720px] border-collapse text-[13.5px]">
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
      {adding && (
        <AddUserDrawer
          onCreated={(username, service) => {
            setError('')
            setNotice(
              service ? (
                <>
                  Created {username}, a service user. Generate its CI tokens under <Link to="/admin/tokens">Tokens</Link>.
                </>
              ) : (
                `Created ${username}. Share the password with them; they can change it under Account.`
              ),
            )
            reload()
          }}
          onClose={() => setAdding(false)}
        />
      )}
      <p className="m-0 text-[12.5px] text-fg-faint">Single sign-on (OpenID Connect) is planned; see ADR-0006.</p>
    </>
  )
}

/**
 * Every user's tokens, to revoke (ADR-0012), and generating one for any
 * user, such as a `ci` service user whose tokens outlive a person's account.
 * Nobody can read a secret after it's generated.
 */
function AllTokens() {
  const api = useApi()
  const [version, setVersion] = useState(0)
  const tokens = useAsync(() => api.tokens(), [api, version])
  const users = useAsync(() => api.users(), [api])
  const [error, setError] = useState('')
  const [generating, setGenerating] = useState(false)
  const owners = users.state === 'ready' ? users.data.filter((u) => !u.disabled).map((u) => u.username) : []
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
    <>
      <PageHeader
        title="Tokens"
        summary="Everyone’s tokens. Generate CI tokens for a service user such as ci, so pipelines don’t stop when a person leaves."
      >
        <Button primary disabled={users.state !== 'ready'} onClick={() => setGenerating(true)}>
          Generate token
        </Button>
      </PageHeader>
      {error && (
        <p role="alert" className="m-0 text-[13px] text-crit">
          {error}
        </p>
      )}
      <Card>
        <p className="m-0 text-[13px] text-fg-muted">People generate their own tokens under Account. Disabling a user stops every token they own.</p>
        {tokens.state === 'ready' && <TokenTable tokens={tokens.data} showOwner onRevoke={(t) => void revoke(t.id)} />}
        {tokens.state === 'error' && <p role="alert">Could not load tokens: {tokens.error.message}</p>}
      </Card>
      {generating && (
        <GenerateTokenDrawer
          eyebrow="Administration · Tokens"
          owners={owners}
          onGenerate={(token, owner) => api.createTokenFor(owner, token)}
          onGenerated={() => setVersion((v) => v + 1)}
          onClose={() => setGenerating(false)}
        />
      )}
    </>
  )
}

/** A name GitHub will take for a new App: at most 34 characters. */
function proposedAppName(host: string): string {
  return trimTrailing(`sonda-${host.replace(/[^A-Za-z0-9-]+/g, '-')}`.slice(0, 34), '-')
}

/**
 * The GitHub App that decorates pull requests (ADR-0024): one configured on
 * the server, or one created here with GitHub's App manifest flow. GitHub
 * opens its own page filled in, then sends the browser back to
 * /admin/github/created.
 */
function GitHubAppTab() {
  const api = useApi()
  const app = useAsync(() => api.githubApp(), [api])
  const [error, setError] = useState('')
  const disconnect = async () => {
    setError('')
    try {
      await api.disconnectGithubApp()
      if (app.state === 'ready') app.reload()
    } catch (err) {
      setError((err as Error).message)
    }
  }
  return (
    <>
      <PageHeader title="GitHub" summary="The GitHub App posts a sonda check and a summary comment on pull requests, where it’s installed." />
      <Card id="github" title="GitHub App">
        {error && (
          <p role="alert" className="m-0 text-[13px] text-crit">
            {error}
          </p>
        )}
        {app.state === 'error' && <p role="alert">Could not load the GitHub App: {app.error.message}</p>}
        {app.state === 'ready' && <GitHubAppState app={app.data} onDisconnect={() => void disconnect()} />}
      </Card>
    </>
  )
}

function GitHubAppState({ app, onDisconnect }: Readonly<{ app: GitHubApp; onDisconnect: () => void }>) {
  const [confirming, setConfirming] = useState(false)
  const disconnect = confirming ? (
    <span className="flex flex-wrap items-center gap-2 text-[13px]">
      Decorating stops. The App stays on GitHub, where its owner can delete it.
      <Button onClick={onDisconnect}>Disconnect</Button>
      <Button onClick={() => setConfirming(false)}>Cancel</Button>
    </span>
  ) : (
    <Button onClick={() => setConfirming(true)}>Disconnect…</Button>
  )
  switch (app.source) {
    case 'config':
      return (
        <>
          <p className="m-0 text-[13px] text-fg-muted">
            App <Mono className="text-[12.5px] text-fg">{app.id}</Mono> is set in the server's configuration (<Mono className="text-[12px]">SONDA_GITHUB_APP_ID</Mono>), so it's changed
            there, not here.
          </p>
          <Installations installUrl={null} />
        </>
      )
    case 'stored':
      return (
        <>
          <p className="m-0 text-[13px] text-fg-muted">
            <a href={app.htmlUrl!} target="_blank" rel="noreferrer">
              <Mono className="text-[12.5px]">{app.slug}</Mono>
            </a>{' '}
            is connected, created by {app.createdBy} on {shortDate(app.createdAt!)}.
          </p>
          <Installations installUrl={app.installUrl} />
          <div>{disconnect}</div>
        </>
      )
    case 'unreadable':
      return (
        <>
          <output className="block m-0 rounded-[10px] bg-warn-soft px-3.5 py-2.5 text-[13px]">
            <Mono className="text-[12px]">{app.slug}</Mono>'s private key can't be read: <Mono className="text-[12px]">SONDA_SECRET_KEY</Mono> is missing, or isn't the one it was
            stored with. Restore that key and restart the server, or disconnect it and create a new App.
          </output>
          <div>{disconnect}</div>
        </>
      )
    default:
      return app.secretKey ? (
        <CreateGitHubApp />
      ) : (
        <output className="block m-0 rounded-[10px] bg-warn-soft px-3.5 py-2.5 text-[13px]">
          No GitHub App yet. Creating one here needs <Mono className="text-[12px]">SONDA_SECRET_KEY</Mono>, which encrypts its private key: rerun{' '}
          <Mono className="text-[12px]">scripts/setup-server.sh</Mono>, which creates it (see the server docs).
        </output>
      )
  }
}

/** Where the App is installed, asked of GitHub: sonda has no webhook to be told. */
function Installations({ installUrl }: Readonly<{ installUrl: string | null }>) {
  const api = useApi()
  const installed = useAsync(() => api.githubAppInstallations(), [api])
  if (installed.state === 'loading') return <p className="m-0 text-[13px] text-fg-faint">Asking GitHub where it's installed…</p>
  if (installed.state === 'error')
    return (
      <p role="alert" className="m-0 text-[13px] text-crit">
        {installed.error.message}
      </p>
    )
  if (installed.data.length === 0)
    return (
      <>
        <p className="m-0 text-[13px] text-fg-muted">It isn't installed on any repository yet, so it decorates nothing. Install it on each repository whose pull requests it should decorate.</p>
        {installUrl && (
          <div>
            <ExternalButton href={installUrl}>Install it on repositories</ExternalButton>
          </div>
        )}
      </>
    )
  return (
    <>
      <ul aria-label="Installed on" className="m-0 flex list-none flex-col p-0">
        {installed.data.map((i) => (
          <li key={i.account} className="flex flex-wrap items-baseline gap-x-3 gap-y-1 border-t border-line py-2.5 text-[13px] first:border-t-0">
            <span className="font-semibold">{i.account}</span>
            <span className="min-w-0 flex-1 text-fg-muted">
              <InstalledOn repositories={i.repositories} />
            </span>
            <a href={i.settingsUrl} target="_blank" rel="noreferrer">
              Change repositories
            </a>
          </li>
        ))}
      </ul>
      {installUrl && (
        <p className="m-0 text-xs text-fg-faint">
          Pull requests are decorated only in these repositories.{' '}
          <a href={installUrl} target="_blank" rel="noreferrer">
            Install it on another account
          </a>.
        </p>
      )}
    </>
  )
}

/** An installation's repositories: all of them, none, or their names. */
function InstalledOn({ repositories }: Readonly<{ repositories: string[] | null }>) {
  if (repositories === null) return 'all repositories'
  if (repositories.length === 0) return 'no repositories'
  return <Mono className="text-[12.5px]">{repositories.map((r) => r.slice(r.indexOf('/') + 1)).join(', ')}</Mono>
}

function CreateGitHubApp() {
  const api = useApi()
  const [owner, setOwner] = useState<'me' | 'org'>('me')
  const [org, setOrg] = useState('')
  const [name, setName] = useState(() => proposedAppName(location.hostname))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [form, setForm] = useState<GitHubAppManifest | null>(null)
  const formRef = useRef<HTMLFormElement>(null)
  // Posted as a form, not fetched: GitHub's page opens in this tab.
  useEffect(() => {
    if (form) formRef.current?.submit()
  }, [form])
  const submit = async (e: SubmitEvent) => {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      setForm(await api.githubAppManifest(owner === 'org' ? org.trim() : null, name.trim()))
    } catch (err) {
      setError((err as Error).message)
      setBusy(false)
    }
  }
  return (
    <>
      <form onSubmit={submit} className="flex flex-col gap-3">
        <p className="m-0 text-[13px] text-fg-muted">
          No GitHub App yet. sonda can create one: GitHub opens its own page, filled in with the permissions sonda needs (checks and pull requests) and no webhook. Click{' '}
          <strong className="text-fg">Create GitHub App</strong> there, and GitHub brings you back here.
        </p>
        {error && (
          <p role="alert" className="m-0 text-[13px] text-crit">
            {error}
          </p>
        )}
        <div className="flex flex-wrap items-end gap-3">
          <div className="flex flex-col gap-1.5 text-[13px]">
            Owner
            <Segmented
              label="Owner"
              options={[
                { value: 'me', label: 'My account' },
                { value: 'org', label: 'An organization' },
              ]}
              value={owner}
              onChange={setOwner}
            />
          </div>
          {owner === 'org' && (
            <label className="flex flex-col gap-1.5 text-[13px]">
              <span>Organization</span>
              <input required autoCapitalize="none" spellCheck={false} pattern="[A-Za-z0-9][A-Za-z0-9\-]{0,38}" value={org} onChange={(e) => setOrg(e.target.value)} className={input} />
            </label>
          )}
          <label className="flex flex-col gap-1.5 text-[13px]">
            <span>App name</span>
            <input required maxLength={34} value={name} onChange={(e) => setName(e.target.value)} className={input} />
          </label>
          <Button type="submit" primary disabled={busy || !name.trim()}>
            {busy ? 'Opening GitHub…' : 'Create GitHub App'}
          </Button>
        </div>
        <p className="m-0 text-xs text-fg-faint">Names are unique across GitHub; if it's taken, change it on GitHub's page.</p>
      </form>
      {form && (
        <form ref={formRef} method="post" action={form.action} hidden>
          <input type="hidden" name="manifest" value={form.manifest} />
        </form>
      )}
    </>
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
    <>
      <PageHeader
        title="Deleted projects"
        summary="Uploads to a deleted project’s key are refused, so a forgotten pipeline can’t bring it back empty. Allow the key again and its next upload starts a new project."
      />
      <Card>
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
    </>
  )
}

function UserRowView({ user, isMe, update }: Readonly<{ user: UserRow; isMe: boolean; update: (u: UserRow, p: UserPatch, done: string) => Promise<void> }>) {
  const [resetting, setResetting] = useState(false)
  const [password, setPassword] = useState('')
  const reset = async (e: SubmitEvent) => {
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

/**
 * Adds a user, in a drawer. A person gets an initial password, typed or
 * generated; a generated one is shown once more after the user is added, to
 * copy and share. A service user has none: it can't sign in, and owns CI
 * tokens.
 */
function AddUserDrawer({ onCreated, onClose }: Readonly<{ onCreated: (username: string, service: boolean) => void; onClose: () => void }>) {
  const api = useApi()
  const formId = useId()
  const [user, setUser] = useState({ username: '', displayName: '', role: 'member' as Role, password: '' })
  const [service, setService] = useState(false)
  // The password, while it's the one generated here: shown, and offered again once the user is added.
  const [generated, setGenerated] = useState<string | null>(null)
  const [added, setAdded] = useState<{ username: string; password: string } | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [copied, setCopied] = useState(false)
  const set = (patch: Partial<typeof user>) => setUser((u) => ({ ...u, ...patch }))

  const generate = () => {
    const password = generatePassword()
    set({ password })
    setGenerated(password)
  }
  const submit = async (e: SubmitEvent) => {
    e.preventDefault()
    setBusy(true)
    setError('')
    const username = user.username.trim().toLowerCase()
    const { password, ...fields } = user
    const created: NewUser = {
      ...fields,
      username,
      displayName: user.displayName.trim(),
      // A service user has no password and is a member.
      ...(service ? { role: 'member' } : { password }),
    }
    try {
      await api.createUser(created)
      onCreated(username, service)
      if (!service && generated === password) setAdded({ username, password })
      else onClose()
    } catch (err) {
      setError((err as Error).message)
    }
    setBusy(false)
  }
  const copy = async (password: string) => {
    setError('')
    if (await copyText(password)) setCopied(true)
    else setError('Could not copy; select the password and copy it.')
  }

  if (added)
    return (
      <Drawer
        eyebrow="Administration · Users"
        title={`Added ${added.username}`}
        subtitle="Share this password with them, then they can change it under Account. It won’t be shown again."
        onClose={onClose}
        footer={
          <>
            <span className="flex-1" />
            <Button onClick={() => void copy(added.password)}>{copied ? 'Copied' : 'Copy'}</Button>
            <Button primary onClick={onClose}>
              Done
            </Button>
          </>
        }
      >
        <output aria-label={`Password for ${added.username}`} className="block rounded-lg bg-canvas px-3.5 py-3 edge-strong">
          <Mono className="text-[13px] select-all">{added.password}</Mono>
        </output>
        {error && (
          <p role="alert" className="m-0 text-[13px] text-crit">
            {error}
          </p>
        )}
      </Drawer>
    )

  return (
    <Drawer
      eyebrow="Administration · Users"
      title="Add a user"
      subtitle="Usernames are lowercase and permanent: they are what issues are assigned to."
      onClose={onClose}
      footer={
        <DrawerActions
          form={formId}
          submit="Add user"
          busy={busy ? 'Adding…' : undefined}
          disabled={!service && user.password.length < MIN_PASSWORD_LENGTH}
          onCancel={onClose}
        />
      }
    >
      <form id={formId} onSubmit={submit} className="flex flex-col gap-4">
        <Field label="Username">
          <input required autoCapitalize="none" spellCheck={false} pattern="[a-z0-9][a-z0-9._\-]{1,63}" value={user.username} onChange={(e) => set({ username: e.target.value })} className={input} />
        </Field>
        <Field label="Display name">
          <input required maxLength={100} value={user.displayName} onChange={(e) => set({ displayName: e.target.value })} className={input} />
        </Field>
        <label className="flex items-start gap-2 text-[13px]">
          <input type="checkbox" checked={service} onChange={(e) => setService(e.target.checked)} className="mt-0.5 accent-brand" />
          <span>
            Service user <span className="block text-xs text-fg-faint">No password, can’t sign in: owns CI tokens.</span>
          </span>
        </label>
        <Field label="Role">
          <select value={service ? 'member' : user.role} disabled={service} onChange={(e) => set({ role: e.target.value as Role })} className={input}>
            <option value="member">Member</option>
            <option value="admin">Admin</option>
          </select>
        </Field>
        {!service && (
          <div className="flex flex-col gap-1.5 text-[13px]">
            <label htmlFor={`${formId}-password`}>Initial password</label>
            <div className="flex gap-2">
              <input
                id={`${formId}-password`}
                // A generated password is shown, to copy; a typed one isn't.
                type={generated !== null && generated === user.password ? 'text' : 'password'}
                autoComplete="new-password"
                spellCheck={false}
                required
                minLength={MIN_PASSWORD_LENGTH}
                value={user.password}
                onChange={(e) => set({ password: e.target.value })}
                className={`${input} min-w-0 flex-1 font-mono`}
              />
              <Button onClick={generate} className="h-9">
                Generate
              </Button>
            </div>
            <span className="text-xs text-fg-faint">At least {MIN_PASSWORD_LENGTH} characters. They can change it under Account.</span>
          </div>
        )}
        {error && (
          <p role="alert" className="m-0 text-[13px] text-crit">
            {error}
          </p>
        )}
      </form>
    </Drawer>
  )
}
