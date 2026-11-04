import { Check } from 'lucide-react'
import { type SubmitEvent, type ReactNode, useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router'
import { useApi, useAsync } from '@/api/hooks'
import type { AnalysisRow, ProjectSettings, WaitingProject } from '@/api/types'
import { AppShell } from '@/components/shell/AppShell'
import { ExternalButton } from '@/components/sonda/connect'
import { Button, Segmented } from '@/components/sonda/controls'
import { Card, Mono, PageHeader } from '@/components/sonda/layout'
import { GateStatus } from '@/components/sonda/status'
import { localServer, newFileUrl, newSecretUrl, parseRepository, projectKeyFor, type Runner, SECRET_NAME, serverProblem, WORKFLOW_PATH, workflowYaml } from '@/lib/connect'
import { branchLabel, trimTrailing } from '@/lib/format'
import { copyText } from '@/lib/clipboard'

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

function Connect({ waiting }: Readonly<{ waiting: WaitingProject | null }>) {
  const api = useApi()
  const [repository, setRepository] = useState(waiting?.githubRepository ? `https://github.com/${waiting.githubRepository}` : '')
  const repo = parseRepository(repository)
  // Follows the repository's name until edited.
  const [key, setKey] = useState<string | null>(waiting?.key ?? null)
  const projectKey = key ?? projectKeyFor(repo ?? '')
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
  const problem = repository.trim() && !repo ? "Paste the repository's GitHub URL, such as https://github.com/acme/shop." : server ? serverProblem(server, runner) : null

  const connect = async (e: SubmitEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    if (!repo) return
    try {
      if (!waiting) await api.createProject(projectKey, mainBranch.trim())
      const settings = await api.updateProjectSettings(projectKey, { githubRepository: repo })
      const created = await api.createToken({ name: `GitHub Actions (${repo})`, type: 'project_analysis', project: projectKey, expiresInDays: null })
      setDone({ token: created.token, settings, runner, server: trimTrailing(server, '/') })
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
            <span>GitHub repository URL</span>
            <input
              className={input}
              value={repository}
              onChange={(e) => setRepository(e.target.value)}
              placeholder="https://github.com/owner/name"
              autoComplete="off"
              inputMode="url"
              required
              disabled={!!waiting}
            />
          </label>
          <div className="grid grid-cols-[repeat(auto-fit,minmax(200px,1fr))] gap-4">
            <label className="flex flex-col gap-1.5 text-[13px]">
              <span>Project key</span>
              <input className={`${input} font-mono`} value={projectKey} onChange={(e) => setKey(e.target.value)} autoComplete="off" required disabled={!!waiting} />
            </label>
            {!waiting && (
              <label className="flex flex-col gap-1.5 text-[13px]">
                <span>Main branch</span>
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
            <span>Server address the runner uploads to</span>
            <input className={`${input} font-mono`} value={server} onChange={(e) => setServer(e.target.value)} autoComplete="off" required />
          </label>
          {problem && <p className="m-0 text-[13px] text-warn">{problem}</p>}
          {error && (
            <p role="alert" className="m-0 text-[13px] text-crit">
              {error}
            </p>
          )}
          <div>
            <Button primary type="submit" disabled={busy || !repo || !projectKey || !server || !!problem}>
              {busy ? 'Connecting…' : 'Connect'}
            </Button>
          </div>
        </form>
      </Card>
    </>
  )
}

function Steps({ done }: Readonly<{ done: Connected }>) {
  const { settings, token, runner, server } = done
  const [finished, setFinished] = useState(false)
  // One step at a time, in order: the workflow runs CI as soon as it's
  // committed, so the secret (and a runner's CLI) must be there first.
  const [current, setCurrent] = useState(0)
  const repository = settings.githubRepository!
  const yaml = workflowYaml({ project: settings.key, mainBranch: settings.mainBranch, server, runner })
  const steps: { title: string; body: ReactNode; confirm?: string }[] = [
    {
      title: 'Add the upload token as a repository secret',
      confirm: "I've added the secret",
      body: (
        <>
          <p className="m-0 text-[13px] text-fg-muted">It's shown only now. Paste the name and the token on GitHub's page, then click Add secret.</p>
          <Copyable label="Name" value={SECRET_NAME} />
          <Copyable label="Secret" value={token} />
          <ExternalButton href={newSecretUrl(repository)}>Open the secrets page on GitHub</ExternalButton>
        </>
      ),
    },
    ...(runner === 'self-hosted'
      ? [
          {
            title: 'Install the CLI where the runner runs',
            confirm: "It's installed",
            body: (
              <>
                <p className="m-0 text-[13px] text-fg-muted">The workflow runs it from ~/.local/bin. In sonda's checkout on that machine:</p>
                <Copyable label="Command" value="scripts/install-cli.sh" />
              </>
            ),
          },
        ]
      : []),
    {
      title: 'Add the workflow',
      body: (
        <>
          <p className="m-0 text-[13px] text-fg-muted">
            GitHub opens it filled in. In the commit dialog, choose <strong className="text-fg">Create a new branch</strong> and start a pull request, rather than committing to{' '}
            {settings.mainBranch}: that pull request is the first one sonda checks and comments on.
          </p>
          <pre className="m-0 max-h-[320px] overflow-auto rounded-lg bg-canvas p-4 font-mono text-[11.5px] leading-relaxed edge">{yaml}</pre>
          <div className="flex flex-wrap gap-2.5">
            <ExternalButton href={newFileUrl(repository, settings.mainBranch, WORKFLOW_PATH, yaml)}>Create {WORKFLOW_PATH} on GitHub</ExternalButton>
            <CopyButton value={yaml}>Copy the workflow</CopyButton>
          </div>
        </>
      ),
    },
  ]
  return (
    <>
      <PageHeader
        title="Connect a repository"
        summary={
          <>
            <Mono className="text-xs text-fg">{settings.key}</Mono> is linked to <Mono className="text-xs text-fg">{repository}</Mono>. Finish these steps in order.
          </>
        }
      />
      {settings.githubApp ? (
        <InstallApp repository={repository} />
      ) : (
        <p role="status" className="m-0 max-w-[720px] rounded-lg bg-panel-2 px-4 py-3 text-[13px] text-warn edge">
          This server has no GitHub App, so results won't be posted on pull requests; analyses still upload.{' '}
          <Link to="/admin#github">Create one under Administration</Link>.
        </p>
      )}
      {steps.map((step, i) => {
        const state = i < current ? 'done' : i === current ? 'current' : 'locked'
        return (
          <Step key={step.title} n={i + 1} title={step.title} state={state} onReopen={() => setCurrent(i)}>
            {step.body}
            {state === 'current' &&
              (i < steps.length - 1 ? (
                <div>
                  <Button primary onClick={() => setCurrent(i + 1)}>
                    {step.confirm}
                  </Button>
                </div>
              ) : (
                !finished && (
                  <div className="flex flex-wrap items-center gap-3">
                    <Button primary onClick={() => setFinished(true)}>
                      Done
                    </Button>
                    <span className="text-[13px] text-fg-muted">sonda then waits for the workflow's first analysis, to confirm it's connected.</span>
                  </div>
                )
              ))}
          </Step>
        )
      })}
      {finished && <FirstAnalysis project={settings.key} n={steps.length + 1} />}
    </>
  )
}

/**
 * Checks every few seconds until the project's first analysis arrives,
 * which proves the secret, the workflow and the runner all work.
 */
function FirstAnalysis({ project, n }: Readonly<{ project: string; n: number }>) {
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

/** A step: the current one shows everything; a done one only that it's done; a later one only its title. */
function Step({ n, title, state = 'current', onReopen, children }: Readonly<{ n: number; title: string; state?: 'done' | 'current' | 'locked'; onReopen?: () => void; children: ReactNode }>) {
  return (
    <Card
      id={`step-${n}`}
      title={`${n}. ${title}`}
      className={state === 'locked' ? 'opacity-55' : ''}
      aside={
        state === 'done' ? (
          <div className="flex items-center gap-2.5 text-[13px]">
            <span className="flex items-center gap-1 text-ok">
              <Check size={14} strokeWidth={2.5} aria-hidden="true" />
              Done
            </span>
            {onReopen && <Button onClick={onReopen}>Show again</Button>}
          </div>
        ) : state === 'locked' ? (
          <span className="text-[13px] text-fg-muted">After step {n - 1}</span>
        ) : undefined
      }
    >
      {state === 'current' && <div className="flex max-w-[720px] min-w-0 flex-col gap-3">{children}</div>}
    </Card>
  )
}

function Copyable({ label, value }: Readonly<{ label: string; value: string }>) {
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

function CopyButton({ value, children }: Readonly<{ value: string; children: ReactNode }>) {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle')
  const copy = async () => {
    setState((await copyText(value)) ? 'copied' : 'failed')
  }
  return <Button onClick={() => void copy()}>{state === 'copied' ? 'Copied' : state === 'failed' ? 'Select it to copy' : children}</Button>
}

/** Pull requests are decorated only where the App is installed (ADR-0024). */
function InstallApp({ repository }: Readonly<{ repository: string }>) {
  const api = useApi()
  const app = useAsync(() => api.githubApp(), [api])
  const installUrl = app.state === 'ready' ? app.data.installUrl : null
  if (!installUrl) return null
  return (
    <p className="m-0 max-w-[720px] text-[13px] text-fg-muted">
      Pull requests are decorated where the GitHub App is installed. If it isn't on <Mono className="text-xs text-fg">{repository}</Mono> yet,{' '}
      <a href={installUrl} target="_blank" rel="noreferrer">
        install it there
      </a>.
    </p>
  )
}
