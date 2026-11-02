import { ExternalLink } from 'lucide-react'
import { type FormEvent, type ReactNode, useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router'
import { useApi, useAsync } from '@/api/hooks'
import type { AnalysisRow, ProjectSettings, WaitingProject } from '@/api/types'
import { AppShell } from '@/components/shell/AppShell'
import { Button, Segmented } from '@/components/sonda/controls'
import { Card, Mono, PageHeader } from '@/components/sonda/layout'
import { GateStatus } from '@/components/sonda/status'
import { isRepository, localServer, newFileUrl, newSecretUrl, projectKeyFor, type Runner, SECRET_NAME, serverProblem, WORKFLOW_PATH, workflowYaml } from '@/lib/connect'

import { branchLabel } from '@/lib/format'

/** How often Done checks for the first analysis. */
export const FIRST_ANALYSIS_POLL_MS = 5000

const CRUMBS = [
  { label: 'Projects', to: '/projects' },
  { label: 'Connect a repository', to: '/connect' },
]

/**
 * Connecting a GitHub repository (ADR-0023): creates the project, links the
 * repository and generates its upload token, then hands over to GitHub's own
 * pages, prefilled, for the secret and the workflow. sonda gets no access to
 * the repository for it. `?project=KEY` does it again for a project still
 * waiting for its first analysis, with a new token.
 */
export function ConnectPage() {
  const api = useApi()
  const [params] = useSearchParams()
  const again = params.get('project')
  const data = useAsync(() => Promise.all([api.shell(), api.projects()]), [api])
  return (
    <AppShell crumbs={CRUMBS}>
      {data.state === 'loading' && <div aria-busy="true" className="h-[400px] rounded-xl bg-panel-2 edge" />}
      {data.state === 'error' && <p role="alert">Could not load: {data.error.message}</p>}
      {data.state === 'ready' && !data.data[0].isAdmin && (
        <>
          <PageHeader title="Connect a repository" summary="Admins only." />
          <p className="m-0 text-[13.5px] text-fg-muted">Ask an admin to connect a repository.</p>
        </>
      )}
      {data.state === 'ready' && data.data[0].isAdmin && <Connect waiting={data.data[1].waiting.find((w) => w.key === again) ?? null} />}
    </AppShell>
  )
}

const input = 'h-9 w-full rounded-lg border-0 bg-canvas px-3 text-[13px] edge-strong'

interface Connected {
  token: string
  settings: ProjectSettings
  runner: Runner
  server: string
}

function Connect({ waiting }: { waiting: WaitingProject | null }) {
  const api = useApi()
  const [repository, setRepository] = useState(waiting?.githubRepository ?? '')
  // Follows the repository's name until edited.
  const [key, setKey] = useState<string | null>(waiting?.key ?? null)
  const projectKey = key ?? projectKeyFor(repository)
  const [mainBranch, setMainBranch] = useState('main')
  const [runner, setRunner] = useState<Runner>('self-hosted')
  const [server, setServer] = useState(localServer(window.location))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState<Connected | null>(null)

  const chooseRunner = (r: Runner) => {
    setRunner(r)
    setServer(r === 'self-hosted' ? localServer(window.location) : window.location.protocol === 'https:' ? window.location.origin : '')
  }
  const problem = repository && !isRepository(repository.trim()) ? 'Use owner/name, such as acme/shop.' : server ? serverProblem(server, runner) : null

  const connect = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    const repo = repository.trim()
    try {
      if (!waiting) await api.createProject(projectKey, mainBranch.trim())
      const settings = await api.updateProjectSettings(projectKey, { githubRepository: repo })
      const created = await api.createToken({ name: `GitHub Actions (${repo})`, type: 'project_analysis', project: projectKey, expiresInDays: null })
      setDone({ token: created.token, settings, runner, server: server.replace(/\/+$/, '') })
    } catch (err) {
      setError((err as Error).message)
    }
    setBusy(false)
  }

  if (done) return <Steps done={done} />
  return (
    <>
      <PageHeader
        title="Connect a repository"
        summary={
          waiting ? (
            <>
              <Mono className="text-xs text-fg">{waiting.key}</Mono> is waiting for its first analysis: this generates a new token and shows the steps again.
            </>
          ) : (
            'Analyze a GitHub repository on every push and pull request, with its results posted on each pull request.'
          )
        }
      />
      <Card title="Repository" subtitle="sonda creates the project and its upload token; you add them on GitHub's own pages next. sonda gets no access to the repository.">
        <form onSubmit={(e) => void connect(e)} className="flex max-w-[560px] flex-col gap-4">
          <label className="flex flex-col gap-1.5 text-[13px]">
            GitHub repository
            <input className={input} value={repository} onChange={(e) => setRepository(e.target.value)} placeholder="owner/name" autoComplete="off" required disabled={!!waiting} />
          </label>
          <div className="grid grid-cols-[repeat(auto-fit,minmax(200px,1fr))] gap-4">
            <label className="flex flex-col gap-1.5 text-[13px]">
              Project key
              <input className={`${input} font-mono`} value={projectKey} onChange={(e) => setKey(e.target.value)} autoComplete="off" required disabled={!!waiting} />
            </label>
            {!waiting && (
              <label className="flex flex-col gap-1.5 text-[13px]">
                Main branch
                <input className={`${input} font-mono`} value={mainBranch} onChange={(e) => setMainBranch(e.target.value)} autoComplete="off" required />
              </label>
            )}
          </div>
          <div className="flex flex-col gap-1.5 text-[13px]">
            <span>Where its CI runs</span>
            <Segmented
              label="Where its CI runs"
              value={runner}
              onChange={chooseRunner}
              options={[
                { value: 'self-hosted', label: 'This machine' },
                { value: 'github', label: 'GitHub-hosted' },
              ]}
            />
          </div>
          <label className="flex flex-col gap-1.5 text-[13px]">
            Server address the runner uploads to
            <input className={`${input} font-mono`} value={server} onChange={(e) => setServer(e.target.value)} autoComplete="off" required />
          </label>
          {problem && <p className="m-0 text-[13px] text-warn">{problem}</p>}
          {error && (
            <p role="alert" className="m-0 text-[13px] text-crit">
              {error}
            </p>
          )}
          <div>
            <Button primary type="submit" disabled={busy || !repository || !projectKey || !server || !!problem}>
              {busy ? 'Connecting…' : 'Connect'}
            </Button>
          </div>
        </form>
      </Card>
    </>
  )
}

function Steps({ done }: { done: Connected }) {
  const { settings, token, runner, server } = done
  const [finished, setFinished] = useState(false)
  const repository = settings.githubRepository!
  const yaml = workflowYaml({ project: settings.key, mainBranch: settings.mainBranch, server, runner })
  return (
    <>
      <PageHeader
        title="Connect a repository"
        summary={
          <>
            <Mono className="text-xs text-fg">{settings.key}</Mono> is linked to <Mono className="text-xs text-fg">{repository}</Mono>. Two steps on GitHub finish it.
          </>
        }
      />
      {!settings.githubApp && (
        <p role="status" className="m-0 max-w-[720px] rounded-lg bg-panel-2 px-4 py-3 text-[13px] text-warn edge">
          This server has no GitHub App, so results won't be posted on pull requests; analyses still upload. Setting one up is in docs/server.md.
        </p>
      )}
      <Step n={1} title="Add the upload token as a repository secret">
        <p className="m-0 text-[13px] text-fg-muted">It's shown only now. Paste the name and the token on GitHub's page, then click Add secret.</p>
        <Copyable label="Name" value={SECRET_NAME} />
        <Copyable label="Secret" value={token} />
        <ExternalButton href={newSecretUrl(repository)}>Open the secrets page on GitHub</ExternalButton>
      </Step>
      <Step n={2} title="Add the workflow">
        <p className="m-0 text-[13px] text-fg-muted">
          GitHub opens it filled in. In the commit dialog, create a new branch and start a pull request: that pull request is the first one sonda checks and comments on.
        </p>
        <pre className="m-0 max-h-[320px] overflow-auto rounded-lg bg-canvas p-4 font-mono text-[11.5px] leading-relaxed edge">{yaml}</pre>
        <div className="flex flex-wrap gap-2.5">
          <ExternalButton href={newFileUrl(repository, settings.mainBranch, WORKFLOW_PATH, yaml)}>Create {WORKFLOW_PATH} on GitHub</ExternalButton>
          <CopyButton value={yaml}>Copy the workflow</CopyButton>
        </div>
      </Step>
      {runner === 'self-hosted' && (
        <Step n={3} title="Install the CLI where the runner runs">
          <p className="m-0 text-[13px] text-fg-muted">The workflow runs it from ~/.local/bin. In sonda's checkout on that machine:</p>
          <Copyable label="Command" value="scripts/install-cli.sh" />
        </Step>
      )}
      {finished ? (
        <FirstAnalysis project={settings.key} n={runner === 'self-hosted' ? 4 : 3} />
      ) : (
        <div className="flex flex-wrap items-center gap-3">
          <Button primary onClick={() => setFinished(true)}>
            Done
          </Button>
          <span className="text-[13px] text-fg-muted">sonda then waits for the workflow's first analysis, to confirm it's connected.</span>
        </div>
      )}
    </>
  )
}

/**
 * Checks every few seconds until the project's first analysis arrives,
 * which proves the secret, the workflow and the runner all work.
 */
function FirstAnalysis({ project, n }: { project: string; n: number }) {
  const api = useApi()
  const [first, setFirst] = useState<AnalysisRow | null>(null)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => {
    if (first) return
    let stopped = false
    const check = async () => {
      try {
        const page = await api.analyses({ project, offset: 0, limit: 1 })
        if (stopped) return
        setError(null)
        if (page.items[0]) setFirst(page.items[0])
      } catch (err) {
        if (!stopped) setError((err as Error).message)
      }
    }
    void check()
    const timer = setInterval(() => void check(), FIRST_ANALYSIS_POLL_MS)
    return () => {
      stopped = true
      clearInterval(timer)
    }
  }, [api, project, first])

  if (first)
    return (
      <Card id="connected" title="Connected">
        <div role="status" className="flex max-w-[720px] flex-col gap-3">
          <p className="m-0 flex flex-wrap items-center gap-2 text-[13px]">
            The first analysis arrived, from <Mono className="text-xs text-fg">{branchLabel(first)}</Mono>: <GateStatus state={first.gate} />
          </p>
          <p className="m-0 text-[13px] text-fg-muted">
            {first.pullRequest
              ? 'Its page says whether the check and the comment were posted on the pull request.'
              : 'The project shows on Projects once its main branch is analyzed.'}
          </p>
          <Link
            to={`/analyses/${first.id}`}
            className="inline-flex h-8 w-fit items-center rounded-lg bg-brand px-[13px] text-[13px] font-semibold text-brand-ink no-underline"
          >
            View the analysis
          </Link>
        </div>
      </Card>
    )
  return (
    <Step n={n} title="Waiting for the first analysis">
      <div role="status" className="flex flex-col gap-2.5">
        <div className="h-[3px] w-40 overflow-hidden rounded-sm bg-hover">
          <div className="h-full w-[58%] bg-brand motion-safe:animate-pulse" />
        </div>
        <p className="m-0 text-[13px] text-fg-muted">
          Once the pull request with the workflow runs its CI, its analysis shows here. Checking every {FIRST_ANALYSIS_POLL_MS / 1000} seconds; you can leave this page, and the
          project stays listed on <Link to="/projects">Projects</Link> as waiting.
        </p>
        {error && <p className="m-0 text-[13px] text-crit">Could not check: {error}</p>}
      </div>
    </Step>
  )
}

function Step({ n, title, children }: { n: number; title: string; children: ReactNode }) {
  return (
    <Card id={`step-${n}`} title={`${n}. ${title}`}>
      <div className="flex max-w-[720px] min-w-0 flex-col gap-3">{children}</div>
    </Card>
  )
}

function Copyable({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex min-w-0 flex-wrap items-center gap-2.5">
      <span className="w-16 flex-none text-[13px] text-fg-muted">{label}</span>
      <code aria-label={label} className="min-w-0 flex-1 rounded-md bg-canvas px-2.5 py-1.5 font-mono text-[12px] break-all edge">
        {value}
      </code>
      <CopyButton value={value}>Copy</CopyButton>
    </div>
  )
}

function CopyButton({ value, children }: { value: string; children: ReactNode }) {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle')
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value)
      setState('copied')
    } catch {
      setState('failed')
    }
  }
  return <Button onClick={() => void copy()}>{state === 'copied' ? 'Copied' : state === 'failed' ? 'Select it to copy' : children}</Button>
}

function ExternalButton({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a href={href} target="_blank" rel="noreferrer" className="inline-flex min-h-8 w-fit items-center gap-1.5 rounded-lg bg-brand px-[13px] py-1.5 text-[13px] font-semibold text-brand-ink no-underline">
      {children}
      <ExternalLink size={13} strokeWidth={2} aria-hidden="true" />
    </a>
  )
}
