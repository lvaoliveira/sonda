import { type SubmitEvent, type ReactNode, useCallback, useEffect, useMemo, useState } from 'react'
import { forgetShell, useApi, useAsync } from '@/api/hooks'
import { UNAUTHORIZED_EVENT } from '@/api/http'
import { SessionContext, type SessionActions } from '@/api/session'
import { AuthError } from '@/api/types'
import { Button } from '@/components/sonda/controls'

/**
 * Shows sign-in until the server has a session for this browser, when the
 * server requires one to read. Where reads are open (a server on
 * localhost), the viewer may continue read-only; triage still needs a
 * session.
 */
export function SessionGate({ children }: Readonly<{ children: ReactNode }>) {
  const api = useApi()
  const [check, setCheck] = useState(0)
  const [readOnly, setReadOnly] = useState(false)
  const session = useAsync(() => api.session(), [api, check])
  // Signing in or out, or a session that expired, makes the shell someone
  // else's.
  const recheck = useCallback(() => {
    forgetShell(api)
    setCheck((n) => n + 1)
  }, [api])

  // A request that finds the session expired sends the viewer back here.
  useEffect(() => {
    window.addEventListener(UNAUTHORIZED_EVENT, recheck)
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, recheck)
  }, [recheck])

  const authenticated = session.state === 'ready' && session.data.authenticated
  const signOut = useCallback(() => {
    void api.signOut().finally(() => {
      setReadOnly(false)
      recheck()
    })
  }, [api, recheck])
  const actions = useMemo<SessionActions>(() => ({ signOut: authenticated ? signOut : null }), [authenticated, signOut])

  if (session.state === 'loading') return <div aria-busy="true" className="min-h-screen bg-canvas" />
  if (session.state === 'error') {
    return (
      <Centered>
        <p role="alert" className="m-0">
          Could not reach the server: {session.error.message}
        </p>
        <Button onClick={session.retry}>Retry</Button>
      </Centered>
    )
  }
  const { readsRequireAuth } = session.data
  if (!authenticated && (readsRequireAuth || !readOnly)) {
    return <SignIn canSkip={!readsRequireAuth} onSkip={() => setReadOnly(true)} onSignedIn={recheck} />
  }
  return <SessionContext.Provider value={actions}>{children}</SessionContext.Provider>
}

function SignIn({ canSkip, onSkip, onSignedIn }: Readonly<{ canSkip: boolean; onSkip: () => void; onSignedIn: () => void }>) {
  const api = useApi()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e: SubmitEvent) => {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      await api.signIn(username.trim(), password)
      onSignedIn()
    } catch (err) {
      setError(err instanceof AuthError ? err.message : `Could not sign in: ${(err as Error).message}`)
      setBusy(false)
    }
  }

  return (
    <Centered>
      <h1 className="m-0 text-[22px] font-semibold tracking-[-0.02em]">Sign in to sonda</h1>
      <form onSubmit={submit} className="flex flex-col gap-3">
        <label className="flex flex-col gap-1.5 text-[13px]">
          <span>Username</span>
          <input
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            required
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="h-9 rounded-lg border-0 bg-canvas px-3 text-[13px] edge-strong"
          />
        </label>
        <label className="flex flex-col gap-1.5 text-[13px]">
          <span>Password</span>
          <input
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="h-9 rounded-lg border-0 bg-canvas px-3 text-[13px] edge-strong"
          />
        </label>
        {error && (
          <p role="alert" className="m-0 text-[13px] text-crit">
            {error}
          </p>
        )}
        <div className="flex items-center gap-3">
          <Button type="submit" primary disabled={busy || !username.trim() || !password}>
            {busy ? 'Signing in…' : 'Sign in'}
          </Button>
          {canSkip && (
            <button type="button" onClick={onSkip} className="cursor-pointer border-0 bg-transparent p-0 text-[13px] text-fg-muted hover:text-fg">
              Continue read-only
            </button>
          )}
        </div>
      </form>
      <p className="m-0 text-[12.5px] text-fg-faint">
        First time? The server creates <code className="font-mono">admin</code> with the password in <code className="font-mono">secrets/admin_password</code>.
      </p>
    </Centered>
  )
}

function Centered({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <main className="grid min-h-screen place-items-center bg-canvas px-4">
      <div className="flex w-full max-w-[420px] flex-col gap-4 rounded-[14px] bg-panel p-7 edge">{children}</div>
    </main>
  )
}
