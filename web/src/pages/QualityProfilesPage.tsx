import { useCallback, useMemo, useState } from 'react'
import { Link } from 'react-router'
import { useApi, useAsync } from '@/api/hooks'
import type { ProjectRuleSetting, Rule, RuleCatalog, RuleProfileDetail, RuleProfileSummary, Severity } from '@/api/types'
import { AppShell } from '@/components/shell/AppShell'
import { Button } from '@/components/sonda/controls'
import { Card, Mono, PageHeader } from '@/components/sonda/layout'
import { RuleBrowser, type RuleFilter, RuleSearch } from '@/components/sonda/RuleBrowser'
import { formatNumber, shortDate } from '@/lib/format'
import { SEVERITY, SEVERITY_ORDER } from '@/lib/visual'

const input = 'h-8 rounded-md border-0 bg-canvas px-2 text-[13px] text-fg edge'

/** Rule profiles (ADR-0018): named sets of rules, one of them the default, that scans apply. Admins manage them; members read. */
export function QualityProfilesPage() {
  const api = useApi()
  const data = useAsync(() => Promise.all([api.ruleProfiles(), api.rules(), api.shell()]), [api])
  return (
    <AppShell crumbs={[{ label: 'Quality profiles', to: '/quality-profiles' }]}>
      {data.state === 'loading' && <div aria-busy="true" className="h-[600px] rounded-xl bg-panel-2 edge" />}
      {data.state === 'error' && <p role="alert">Could not load the profiles: {data.error.message}</p>}
      {/* A reload keeps the page, and the profile chosen, on screen. */}
      {data.state === 'ready' && <Profiles profiles={data.data[0]} catalog={data.data[1]} isAdmin={data.data[2].isAdmin} reload={data.reload} />}
    </AppShell>
  )
}

function Profiles({ profiles, catalog, isAdmin, reload }: { profiles: RuleProfileSummary[]; catalog: RuleCatalog; isAdmin: boolean; reload: () => void }) {
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const selected = profiles.find((p) => p.id === selectedId) ?? profiles[0]
  const def = profiles.find((p) => p.isDefault)
  return (
    <>
      <PageHeader
        title="Quality profiles"
        summary={
          <>
            {profiles.length} {profiles.length === 1 ? 'profile' : 'profiles'} · the default is <span className="font-semibold text-fg">{def?.name}</span>. Scans that
            upload apply a project's profile; where it sets a rule, it wins over the repository's sonda.toml.
          </>
        }
      />
      {isAdmin && <NewProfile profiles={profiles} onCreated={(id) => (setSelectedId(id), reload())} />}
      <div className="grid grid-cols-1 gap-5 min-[1100px]:grid-cols-[minmax(240px,0.35fr)_minmax(0,1fr)]">
        <ul aria-label="Profiles" className="m-0 flex list-none flex-col gap-px self-start overflow-hidden rounded-xl bg-line p-0" style={{ boxShadow: '0 0 0 1px var(--sd-line)' }}>
          {profiles.map((p) => {
            const on = p.id === selected?.id
            return (
              <li key={p.id}>
                <button
                  type="button"
                  aria-pressed={on}
                  onClick={() => setSelectedId(p.id)}
                  className="flex w-full cursor-pointer flex-col gap-0.5 border-0 bg-panel-2 px-3.5 py-3 text-left text-fg hover:bg-hover"
                  style={{ borderLeft: `3px solid ${on ? 'var(--sd-accent)' : 'transparent'}`, background: on ? 'var(--sd-panel)' : undefined }}
                >
                  <span className="flex flex-wrap items-baseline gap-2 text-[13.5px] font-medium">
                    {p.name}
                    {p.isDefault && <span className="text-xs font-normal text-brand">default</span>}
                    {p.builtin && <span className="text-xs font-normal text-fg-faint">built in</span>}
                  </span>
                  <span className="text-xs text-fg-faint">
                    {p.builtin ? 'the catalog’s defaults' : `${formatNumber(p.rules)} ${p.rules === 1 ? 'rule' : 'rules'} set`} · {p.projects.length}{' '}
                    {p.projects.length === 1 ? 'project' : 'projects'}
                  </span>
                </button>
              </li>
            )
          })}
        </ul>
        {selected && <ProfileView key={selected.id} summary={selected} catalog={catalog} isAdmin={isAdmin} reload={reload} onDeleted={() => setSelectedId(null)} />}
      </div>
    </>
  )
}

/** Admins create a profile, empty or as a copy. */
function NewProfile({ profiles, onCreated }: { profiles: RuleProfileSummary[]; onCreated: (id: number) => void }) {
  const api = useApi()
  const [name, setName] = useState('')
  const [from, setFrom] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  return (
    <form
      className="flex flex-wrap items-end gap-2"
      onSubmit={async (e) => {
        e.preventDefault()
        setBusy(true)
        setError(null)
        try {
          const created = await api.createRuleProfile(name.trim(), from ? Number(from) : undefined)
          setName('')
          setFrom('')
          onCreated(created.id)
        } catch (err) {
          setError(err instanceof Error ? err.message : String(err))
        } finally {
          setBusy(false)
        }
      }}
    >
      <label className="flex flex-col gap-1 text-xs text-fg-muted">
        New profile
        <input aria-label="New profile name" placeholder="Name, such as Strict" maxLength={100} value={name} onChange={(e) => setName(e.target.value)} className={`${input} w-[220px]`} />
      </label>
      <label className="flex flex-col gap-1 text-xs text-fg-muted">
        Starting from
        <select aria-label="Copy from" value={from} onChange={(e) => setFrom(e.target.value)} className={input}>
          <option value="">The catalog’s defaults</option>
          {profiles
            .filter((p) => !p.builtin)
            .map((p) => (
              <option key={p.id} value={p.id}>
                A copy of {p.name}
              </option>
            ))}
        </select>
      </label>
      <Button type="submit" primary disabled={busy || !name.trim()}>
        Create
      </Button>
      {error && (
        <span role="alert" className="basis-full text-xs text-crit">
          {error}
        </span>
      )}
    </form>
  )
}

/** A rule with this profile's setting for it, if any. */
type InProfile = Rule & { setting: RuleProfileDetail['rulesSet'][number] | null }

const SET_FILTER: RuleFilter<InProfile> = {
  label: 'In this profile',
  options: [
    { value: 'set', label: 'Set' },
    { value: 'on', label: 'On' },
    { value: 'off', label: 'Off' },
  ],
  test: (r, v) => (v === 'set' ? r.setting !== null : v === 'on' ? (r.setting?.on ?? r.onByDefault) : !(r.setting?.on ?? r.onByDefault)),
}

function ProfileView({ summary, catalog, isAdmin, reload, onDeleted }: { summary: RuleProfileSummary; catalog: RuleCatalog; isAdmin: boolean; reload: () => void; onDeleted: () => void }) {
  const api = useApi()
  const detail = useAsync(() => api.ruleProfile(summary.id), [api, summary.id])
  const [q, setQ] = useState('')
  const reloadDetail = detail.state === 'ready' ? detail.reload : undefined
  const refresh = useCallback(() => {
    reloadDetail?.()
    reload()
  }, [reload, reloadDetail])
  const rules: InProfile[] = useMemo(() => {
    const set = new Map((detail.state === 'ready' ? detail.data.rulesSet : []).map((r) => [r.rule, r]))
    return catalog.rules.map((r) => ({ ...r, setting: set.get(r.id) ?? null }))
  }, [catalog, detail])
  const count = useCallback((r: InProfile) => r.openIssues, [])
  const order = useCallback((r: InProfile) => (r.setting ? 1_000_000 : 0) + r.openIssues, [])
  const editable = isAdmin && !summary.builtin
  return (
    <div className="flex min-w-0 flex-col gap-5">
      <Card
        id="profile"
        title={summary.name}
        subtitle={
          summary.builtin
            ? 'Built in: the catalog’s defaults. Copy it to make your own.'
            : `${formatNumber(summary.rules)} ${summary.rules === 1 ? 'rule' : 'rules'} set; every other rule keeps its catalog default`
        }
      >
        <p className="m-0 text-[13px] text-fg-muted">
          {summary.isDefault ? 'The default: projects that don’t choose a profile use it. ' : ''}
          {summary.projects.length ? (
            <>
              Used by{' '}
              {summary.projects.map((k, i) => (
                <span key={k}>
                  {i > 0 && ', '}
                  <Link to={`/projects/${encodeURIComponent(k)}/rules`} className="font-mono text-[12px]">
                    {k}
                  </Link>
                </span>
              ))}
              .
            </>
          ) : (
            'No project uses it.'
          )}
        </p>
        {isAdmin && <ProfileActions summary={summary} reload={refresh} onDeleted={onDeleted} />}
      </Card>
      {detail.state === 'error' && <p role="alert">Could not load {summary.name}: {detail.error.message}</p>}
      <RuleSearch q={q} setQ={setQ} />
      <RuleBrowser
        rules={rules}
        total={catalog.total}
        languages={catalog.languages}
        count={count}
        order={order}
        sortLabel="rules it sets first"
        extraFilter={SET_FILTER}
        search={{ q, setQ }}
        listTags={(r) =>
          r.setting && (
            <>
              <span>·</span>
              <span style={{ color: r.setting.on ? 'var(--sd-ok)' : 'var(--sd-faint)' }}>
                {r.setting.on ? 'on' : 'off'} in this profile{r.setting.severity && `, ${r.setting.severity}`}
              </span>
            </>
          )
        }
        summary={(r) => (
          <span className="text-[12.5px] text-fg-muted">
            <Mono className="text-[11.5px] text-fg">{r.openIssues}</Mono> open issues in <Mono className="text-[11.5px] text-fg">{r.projects}</Mono>{' '}
            {r.projects === 1 ? 'project' : 'projects'}, across every profile
          </span>
        )}
        panel={(r) => <InThisProfile key={`${r.id}-${r.setting?.change.changedAt ?? ''}`} profile={summary.id} rule={r} editable={editable} reload={refresh} />}
      />
    </div>
  )
}

/** Admins rename a profile, make it the default, or delete it. */
function ProfileActions({ summary, reload, onDeleted }: { summary: RuleProfileSummary; reload: () => void; onDeleted: () => void }) {
  const api = useApi()
  const [name, setName] = useState(summary.name)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const run = async (action: () => Promise<void>, after: () => void) => {
    setBusy(true)
    setError(null)
    try {
      await action()
      after()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className="flex flex-wrap items-center gap-2 border-t border-line pt-3">
      {!summary.builtin && (
        <>
          <input aria-label="Profile name" maxLength={100} value={name} onChange={(e) => setName(e.target.value)} className={`${input} w-[200px]`} />
          <Button onClick={() => void run(() => api.updateRuleProfile(summary.id, { name: name.trim() }), reload)} disabled={busy || !name.trim() || name.trim() === summary.name}>
            Rename
          </Button>
        </>
      )}
      {!summary.isDefault && (
        <Button onClick={() => void run(() => api.updateRuleProfile(summary.id, { isDefault: true }), reload)} disabled={busy}>
          Make it the default
        </Button>
      )}
      {!summary.builtin && !summary.isDefault && (
        <Button onClick={() => void run(() => api.deleteRuleProfile(summary.id), () => (onDeleted(), reload()))} disabled={busy}>
          Delete
        </Button>
      )}
      {error && (
        <span role="alert" className="basis-full text-xs text-crit">
          {error}
        </span>
      )}
    </div>
  )
}

/** The rule's setting in this profile, and for admins, changing it. */
function InThisProfile({ profile, rule, editable, reload }: { profile: number; rule: InProfile; editable: boolean; reload: () => void }) {
  const api = useApi()
  const s = rule.setting
  const [severity, setSeverity] = useState<Severity | ''>(s?.severity ?? '')
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const set = async (state: ProjectRuleSetting) => {
    setBusy(true)
    setError(null)
    try {
      await api.setProfileRule(profile, rule.id, state, state === 'inherit' ? null : severity || null, note.trim() || undefined)
      setNote('')
      reload()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <section aria-label="In this profile" className="flex flex-col gap-2">
      <h3 className="m-0 font-normal micro-label">In this profile</h3>
      <p className="m-0 text-[13px]">
        {s ? (
          <>
            <span className="font-semibold" style={{ color: s.on ? 'var(--sd-ok)' : 'var(--sd-faint)' }}>
              {s.on ? 'On' : 'Off'}
            </span>
            <span className="text-fg-muted">
              {s.severity && <> · severity {SEVERITY[s.severity].label.toLowerCase()}</>} · by {s.change.changedBy}, {shortDate(s.change.changedAt)}
              {s.change.note && <>: “{s.change.note}”</>}
            </span>
          </>
        ) : (
          <span className="text-fg-muted">Not set: {rule.onByDefault ? 'on' : 'off'}, as the catalog has it.</span>
        )}
      </p>
      {editable && (
        <div className="flex flex-wrap items-center gap-2">
          <select aria-label={`Severity for ${rule.id}`} value={severity} onChange={(e) => setSeverity(e.target.value as Severity | '')} className={input}>
            <option value="">Its own severity ({SEVERITY[rule.severity].label.toLowerCase()})</option>
            {SEVERITY_ORDER.map((sev) => (
              <option key={sev} value={sev}>
                {SEVERITY[sev].label}
              </option>
            ))}
          </select>
          <input aria-label={`Why, for ${rule.id} in this profile`} placeholder="Why (optional)" maxLength={500} value={note} onChange={(e) => setNote(e.target.value)} className={`${input} w-[200px]`} />
          <Button primary onClick={() => void set('on')} disabled={busy}>
            Turn on
          </Button>
          <Button onClick={() => void set('off')} disabled={busy}>
            Turn off
          </Button>
          {s && (
            <Button onClick={() => void set('inherit')} disabled={busy}>
              Leave at default
            </Button>
          )}
        </div>
      )}
      {error && (
        <p role="alert" className="m-0 text-xs text-crit">
          {error}
        </p>
      )}
    </section>
  )
}
