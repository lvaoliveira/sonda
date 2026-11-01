import { type FormEvent, useState } from 'react'
import { useNavigate, useParams } from 'react-router'
import { useApi, useAsync } from '@/api/hooks'
import type { ProjectSettingChange, ProjectSettings, ProjectSettingsPatch } from '@/api/types'
import { AppShell } from '@/components/shell/AppShell'
import { Button } from '@/components/sonda/controls'
import { Card, Mono, PageHeader } from '@/components/sonda/layout'
import { formatNumber, shortDate } from '@/lib/format'

/** A project's settings (ADR-0017): admins change them, members read them. */
export function ProjectSettingsPage() {
  const api = useApi()
  const { key = '' } = useParams()
  const projectUrl = `/projects/${encodeURIComponent(key)}`
  const data = useAsync(() => Promise.all([api.projectSettings(key), api.shell()]), [api, key])
  // Each save answers with the settings as they now are, which the crumbs show too.
  const [saved, setSaved] = useState<ProjectSettings | null>(null)
  const settings = saved?.key === key ? saved : data.state === 'ready' ? data.data[0] : null
  return (
    <AppShell
      crumbs={[
        { label: 'Projects', to: '/projects' },
        { label: settings?.name ?? key, to: projectUrl },
        { label: 'Settings', to: `${projectUrl}/settings` },
      ]}
    >
      {data.state === 'loading' && <div aria-busy="true" className="h-[400px] rounded-xl bg-panel-2 edge" />}
      {data.state === 'error' && <p role="alert">Could not load the settings of {key}: {data.error.message}</p>}
      {data.state === 'ready' && settings && (
        <Settings
          settings={settings}
          isAdmin={data.data[1].isAdmin}
          save={async (patch) => setSaved(await api.updateProjectSettings(key, patch))}
        />
      )}
    </AppShell>
  )
}

function Settings({ settings, isAdmin, save }: { settings: ProjectSettings; isAdmin: boolean; save: (patch: ProjectSettingsPatch) => Promise<void> }) {
  return (
    <>
      <PageHeader
        title="Settings"
        summary={
          <>
            {settings.name && <span className="font-semibold text-fg">{settings.name} · </span>}
            <Mono className="text-xs text-fg">{settings.key}</Mono> · {isAdmin ? 'admins change these, and each change is recorded' : 'only admins can change these'}
          </>
        }
      />
      <Card id="general" title="General" subtitle="What the project is called, and which branch the screens count">
        <NameSetting settings={settings} isAdmin={isAdmin} save={save} />
        <MainBranchSetting settings={settings} isAdmin={isAdmin} save={save} />
      </Card>
      <Card id="changes" title="Changes" subtitle="Who changed a setting, newest first">
        {settings.changes.length === 0 ? (
          <p className="m-0 text-[13px] text-fg-muted">No changes yet.</p>
        ) : (
          <ul aria-label="Setting changes" className="m-0 flex list-none flex-col gap-1.5 p-0 text-[13px]">
            {settings.changes.map((c, i) => (
              <li key={`${c.at}-${c.setting}-${i}`} className="flex flex-wrap items-baseline gap-x-2">
                <span>{describe(c)}</span>
                <span className="text-fg-faint">
                  by {c.by}, {shortDate(c.at)}
                </span>
              </li>
            ))}
          </ul>
        )}
      </Card>
      {isAdmin && <DangerZone settings={settings} />}
    </>
  )
}

/** Deleting the project (ADR-0017): permanent, confirmed by typing its key. */
function DangerZone({ settings }: { settings: ProjectSettings }) {
  const api = useApi()
  const navigate = useNavigate()
  const [typed, setTyped] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const analyses = settings.branches.reduce((n, b) => n + b.analyses, 0)
  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await api.deleteProject(settings.key, typed)
      navigate('/projects')
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
      setBusy(false)
    }
  }
  return (
    <Card id="danger" title="Danger zone" subtitle="Deleting the project can't be undone">
      <p className="m-0 text-[13px] text-fg-muted">
        This deletes <Mono className="text-[12px] text-fg">{settings.key}</Mono> and its {formatNumber(analyses)} {analyses === 1 ? 'analysis' : 'analyses'} on{' '}
        {settings.branches.length} {settings.branches.length === 1 ? 'branch' : 'branches'}, with their issues and history, sources, dependencies, reviews and
        settings. Its project analysis tokens are revoked. Uploads to <Mono className="text-[12px]">{settings.key}</Mono> are then refused, so a forgotten pipeline
        can't bring it back, until an admin allows the key again on the Administration page.
      </p>
      <form onSubmit={(e) => void submit(e)} className="flex flex-wrap items-center gap-2">
        <input
          aria-label="Type the project's key to confirm"
          placeholder={`Type ${settings.key} to confirm`}
          autoComplete="off"
          spellCheck={false}
          value={typed}
          onChange={(e) => setTyped(e.target.value)}
          className="h-8 w-[320px] max-w-full rounded-md border-0 bg-canvas px-2 font-mono text-[12.5px] edge"
        />
        <Button type="submit" disabled={busy || typed !== settings.key} className="text-crit">
          Delete this project
        </Button>
      </form>
      <SaveError error={error} />
    </Card>
  )
}

function describe(c: ProjectSettingChange) {
  if (c.setting === 'main_branch') return `Main branch ${c.old ?? '?'} → ${c.new ?? '?'}`
  if (c.new === null) return `Name “${c.old}” removed`
  return c.old === null ? `Named “${c.new}”` : `Renamed “${c.old}” → “${c.new}”`
}

/** A save's state: busy, and its error. */
function useSave(save: (patch: ProjectSettingsPatch) => Promise<void>) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const run = async (patch: ProjectSettingsPatch) => {
    setBusy(true)
    setError(null)
    try {
      await save(patch)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }
  return { busy, error, run }
}

function SaveError({ error }: { error: string | null }) {
  return (
    error && (
      <p role="alert" className="m-0 text-xs text-crit">
        {error}
      </p>
    )
  )
}

type SettingProps = { settings: ProjectSettings; isAdmin: boolean; save: (patch: ProjectSettingsPatch) => Promise<void> }

function NameSetting({ settings, isAdmin, save }: SettingProps) {
  const [name, setName] = useState(settings.name ?? '')
  const { busy, error, run } = useSave(save)
  const changed = name.trim() !== (settings.name ?? '')
  const submit = (e: FormEvent) => {
    e.preventDefault()
    void run({ name: name.trim() || null })
  }
  return (
    <section aria-label="Display name" className="flex flex-col gap-2">
      <h3 className="m-0 font-normal micro-label">Display name</h3>
      <p className="m-0 text-[13px] text-fg-muted">
        Screens show it with the key under it. The key, <Mono className="text-[12px] text-fg">{settings.key}</Mono>, never changes: CI's{' '}
        <Mono className="text-[12px]">--project</Mono>, tokens and links keep using it.
      </p>
      {isAdmin ? (
        <form onSubmit={submit} className="flex flex-wrap items-center gap-2">
          <input
            aria-label="Display name"
            placeholder={`None: screens show ${settings.key}`}
            maxLength={100}
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="h-8 w-[320px] max-w-full rounded-md border-0 bg-canvas px-2 text-[13px] edge"
          />
          <Button type="submit" primary disabled={busy || !changed}>
            Save name
          </Button>
        </form>
      ) : (
        <p className="m-0 text-[13px]">{settings.name ?? <span className="text-fg-muted">None: screens show the key.</span>}</p>
      )}
      <SaveError error={error} />
    </section>
  )
}

function MainBranchSetting({ settings, isAdmin, save }: SettingProps) {
  const [branch, setBranch] = useState(settings.mainBranch)
  const { busy, error, run } = useSave(save)
  const submit = (e: FormEvent) => {
    e.preventDefault()
    void run({ mainBranch: branch })
  }
  return (
    <section aria-label="Main branch" className="flex flex-col gap-2">
      <h3 className="m-0 font-normal micro-label">Main branch</h3>
      <p className="m-0 text-[13px] text-fg-muted">
        What the project's page shows by default, and what the Overview, Projects, Security and Rules pages count. One of the branches with analyses.
      </p>
      {isAdmin ? (
        <form onSubmit={submit} className="flex flex-col items-start gap-2">
          <div className="flex max-w-full flex-wrap items-center gap-2">
            <select
              aria-label="Main branch"
              value={branch}
              onChange={(e) => setBranch(e.target.value)}
              className="h-8 max-w-full rounded-md border-0 bg-canvas px-2 font-mono text-[12.5px] text-fg edge"
            >
              {settings.branches.map((b) => (
                <option key={b.name} value={b.name}>
                  {b.name} · {b.analyses} {b.analyses === 1 ? 'analysis' : 'analyses'} · {b.ago} ago
                </option>
              ))}
            </select>
            <Button type="submit" primary disabled={busy || branch === settings.mainBranch}>
              Make it the main branch
            </Button>
          </div>
          {branch !== settings.mainBranch && (
            <p role="status" className="m-0 rounded-[10px] bg-warn-soft px-3.5 py-2.5 text-[13px]">
              Every screen counts <Mono className="text-[12px]">{branch}</Mono> instead of <Mono className="text-[12px]">{settings.mainBranch}</Mono> at once. New
              code starts over on it, from its first analysis (or its current version's), and a start set on {settings.mainBranch} no longer applies.
            </p>
          )}
        </form>
      ) : (
        <p className="m-0 font-mono text-[13px]">{settings.mainBranch}</p>
      )}
      <SaveError error={error} />
    </section>
  )
}
