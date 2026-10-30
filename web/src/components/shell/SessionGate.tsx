import { type FormEvent, type ReactNode, useEffect, useState } from 'react'
import { useApi, useAsync } from '@/api/hooks'
import { UNAUTHORIZED_EVENT } from '@/api/http'
import { SessionContext } from '@/api/session'
import { AuthError } from '@/api/types'
import { Button } from '@/components/sonda/controls'
import { storeName, storedName } from '@/lib/identity'

/**
 * Shows sign-in until the server has a session for this browser, when the
 * server requires one to read. Where reads are open (a server on
 * localhost), the viewer may continue read-only; triage still needs a
 * session.
 */
export function SessionGate({ children }: { children: ReactNode }) {
  const api = useApi()
  const [check, setCheck] = useState(0)
  const [readOnly, setReadOnly] = useState(false)
  const session = useAsync(() => api.session(), [api, check])

  // A request that finds the session expired sends the viewer back here.
  useEffect(() => {
    const recheck = () => setCheck((n) => n + 1)
    window.addEventListener(UNAUTHORIZED_EVENT, recheck)
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, recheck)
  }, [])

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
  const { authenticated, readsRequireAuth } = session.data
  if (!authenticated && (readsRequireAuth || !readOnly)) {
    return <SignIn canSkip={!readsRequireAuth} onSkip={() => setReadOnly(true)} onSignedIn={() => setCheck((n) => n + 1)} />
  }
  const signOut = authenticated
    ? () => {
        void api.signOut().finally(() => {
          setReadOnly(false)
          setCheck((n) => n + 1)
        })
      }
    : null
  return <SessionContext.Provider value={{ signOut }}>{children}</SessionContext.Provider>
}

function SignIn({ canSkip, onSkip, onSignedIn }: { canSkip: boolean; onSkip: () => void; onSignedIn: () => void }) {
  const api = useApi()
  const [token, setToken] = useState('')
  const [name, setName] = useState(storedName)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      await api.signIn(token.trim())
      storeName(name.trim())
      onSignedIn()
    } catch (err) {
      setError(err instanceof AuthError ? err.message : `Could not sign in: ${(err as Error).message}`)
      setBusy(false)
    }
  }

  return (
    <Centered>
      <h1 className="m-0 text-[22px] font-semibold tracking-[-0.02em]">Sign in to sonda</h1>
      <p className="m-0 text-[13.5px] text-fg-muted">
        Paste the server's API token (<code className="font-mono text-[12px]">secrets/sonda_token</code> in a Docker setup). This browser keeps a session cookie, never the token.
      </p>
      <form onSubmit={submit} className="flex flex-col gap-3">
        <label className="flex flex-col gap-1.5 text-[13px]">
          API token
          <input
            type="password"
            autoComplete="off"
            required
            value={token}
            onChange={(e) => setToken(e.target.value)}
            className="h-9 rounded-lg border-0 bg-canvas px-3 font-mono text-[13px] edge-strong"
          />
        </label>
        <label className="flex flex-col gap-1.5 text-[13px]">
          <span>
            Your name <span className="text-fg-faint">(optional, for "Assign to me")</span>
          </span>
          <input value={name} onChange={(e) => setName(e.target.value)} maxLength={100} className="h-9 rounded-lg border-0 bg-canvas px-3 text-[13px] edge-strong" />
        </label>
        {error && (
          <p role="alert" className="m-0 text-[13px] text-crit">
            {error}
          </p>
        )}
        <div className="flex items-center gap-3">
          <Button type="submit" primary disabled={busy || !token.trim()}>
            {busy ? 'Signing in…' : 'Sign in'}
          </Button>
          {canSkip && (
            <button type="button" onClick={onSkip} className="cursor-pointer border-0 bg-transparent p-0 text-[13px] text-fg-muted hover:text-fg">
              Continue read-only
            </button>
          )}
        </div>
      </form>
    </Centered>
  )
}

function Centered({ children }: { children: ReactNode }) {
  return (
    <main className="grid min-h-screen place-items-center bg-canvas px-4">
      <div className="flex w-full max-w-[420px] flex-col gap-4 rounded-[14px] bg-panel p-7 edge">{children}</div>
    </main>
  )
}
