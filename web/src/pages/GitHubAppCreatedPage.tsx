import { useEffect, useRef, useState } from 'react'
import { Link, useSearchParams } from 'react-router'
import { useApi } from '@/api/hooks'
import type { GitHubApp } from '@/api/types'
import { AppShell } from '@/components/shell/AppShell'
import { ExternalButton } from '@/components/sonda/connect'
import { Card, Mono, PageHeader } from '@/components/sonda/layout'

const CRUMBS = [
  { label: 'Administration', to: '/admin' },
  { label: 'GitHub App', to: '/admin#github' },
]

/**
 * Where GitHub sends the browser back after creating the App (ADR-0024),
 * with a one-time code. A page rather than an API route: the session cookie
 * is SameSite=Strict, so it doesn't come along on a navigation from
 * github.com, but it does on this page's own request.
 */
export function GitHubAppCreatedPage() {
  const api = useApi()
  const [params] = useSearchParams()
  const code = params.get('code')
  const state = params.get('state')
  const [result, setResult] = useState<{ app: GitHubApp } | { error: string } | null>(null)
  // The code works once: StrictMode's second effect mustn't send it again.
  const sent = useRef(false)
  useEffect(() => {
    if (sent.current || !code || !state) return
    sent.current = true
    api.createGithubApp(code, state).then(
      (app) => setResult({ app }),
      (err: unknown) => setResult({ error: (err as Error).message }),
    )
  }, [api, code, state])

  const startAgain = <Link to="/admin#github">Start again from Administration</Link>
  return (
    <AppShell crumbs={CRUMBS}>
      <PageHeader title="GitHub App" summary="Created on GitHub, connected here." />
      {(!code || !state) && (
        <p role="alert" className="m-0 text-[13px] text-crit">
          GitHub didn't send a code back, so no App was connected. {startAgain}.
        </p>
      )}
      {code && state && !result && (
        <p role="status" className="m-0 text-[13px] text-fg-muted">
          Connecting the App…
        </p>
      )}
      {result && 'error' in result && (
        <p role="alert" className="m-0 text-[13px] text-crit">
          {result.error}. {startAgain}.
        </p>
      )}
      {result && 'app' in result && (
        <Card id="github-connected" title="Connected" subtitle="Its private key is stored encrypted; nobody can read it from sonda.">
          <p className="m-0 text-[13px] text-fg-muted">
            <Mono className="text-[12.5px] text-fg">{result.app.slug}</Mono> now decorates pull requests in the repositories it's installed on. Install it on them next: GitHub
            lets you pick all repositories or some.
          </p>
          <div className="flex flex-wrap items-center gap-3">
            <ExternalButton href={result.app.installUrl!}>Install it on repositories</ExternalButton>
            <Link to="/admin#github">Back to Administration</Link>
          </div>
          <p className="m-0 text-xs text-fg-faint">Then link each project to its repository in the project's Settings, or connect a repository from Projects.</p>
        </Card>
      )}
    </AppShell>
  )
}
