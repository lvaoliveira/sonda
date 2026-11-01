import { useState } from 'react'
import { Link, useParams } from 'react-router'
import { useApi, useAsync } from '@/api/hooks'
import type { ProjectRuleSetting, ProjectRules, ProjectRuleState, Rule } from '@/api/types'
import { AppShell } from '@/components/shell/AppShell'
import { Button } from '@/components/sonda/controls'
import { Card, Mono, PageHeader } from '@/components/sonda/layout'
import { formatNumber, shortDate } from '@/lib/format'
import { SET_BY_LABEL, TOML_CHANGE_LABEL } from '@/lib/visual'

const input = 'h-8 rounded-md border-0 bg-canvas px-2 text-[13px] text-fg edge'

/** A project's settings (ADR-0017). Admins change them; everyone sees them. */
export function ProjectSettingsPage() {
  const api = useApi()
  const { key = '' } = useParams()
  const projectUrl = `/projects/${encodeURIComponent(key)}`
  const data = useAsync(() => Promise.all([api.projectRules(key), api.rules(), api.shell()]), [api, key])
  return (
    <AppShell
      crumbs={[
        { label: 'Projects', to: '/projects' },
        { label: key, to: projectUrl },
        { label: 'Settings', to: `${projectUrl}/settings` },
      ]}
    >
      <PageHeader
        title="Settings"
        summary={
          <>
            <Mono className="text-[13px] text-fg">{key}</Mono>
            {data.state === 'ready' && !data.data[2].isAdmin && <> · read-only: admins change these</>}
          </>
        }
      />
      {data.state === 'loading' && <div aria-busy="true" className="h-[400px] rounded-xl bg-panel-2 edge" />}
      {data.state === 'error' && <p role="alert">Could not load the settings of {key}: {data.error.message}</p>}
      {data.state === 'ready' && <RulesSettings project={key} rules={data.data[0]} catalog={data.data[1].rules} isAdmin={data.data[2].isAdmin} reload={data.reload} />}
    </AppShell>
  )
}

/** Every rule whose state differs from its default here, and what set it (ADR-0016). */
function RulesSettings({ project, rules, catalog, isAdmin, reload }: { project: string; rules: ProjectRules; catalog: Rule[]; isAdmin: boolean; reload: () => void }) {
  const toml = rules.sondaToml
  return (
    <>
      <Card
        id="rules"
        padded={false}
        title="Rules"
        subtitle="The repository's sonda.toml decides which rules the scanner runs; the server decides which findings count. Rules at their default aren't listed."
      >
        <p className="m-0 px-5 pb-3 text-[13px] text-fg-muted">
          {toml ? (
            <>
              <Mono className="text-[12px] text-fg">sonda.toml</Mono> on <Mono className="text-[12px]">{rules.mainBranch}</Mono>, as its latest analysis recorded it:{' '}
              {toml.disabled.length} disabled, {toml.enabled.length} enabled, {Object.keys(toml.severity).length}{' '}
              {Object.keys(toml.severity).length === 1 ? 'severity' : 'severities'} changed.
            </>
          ) : (
            <>
              The repository's <Mono className="text-[12px] text-fg">sonda.toml</Mono> settings are unknown: the latest analysis of{' '}
              <Mono className="text-[12px]">{rules.mainBranch}</Mono> came from an older sonda. They show after its next upload.
            </>
          )}
        </p>
        {rules.rules.length === 0 ? (
          <p className="m-0 border-t border-line px-5 py-4 text-[13px] text-fg-faint">Every rule is at its default for this project.</p>
        ) : (
          <ul aria-label="Rules not at their default" className="m-0 list-none p-0">
            {rules.rules.map((s) => (
              <RuleRow key={s.rule} project={project} s={s} isAdmin={isAdmin} reload={reload} />
            ))}
          </ul>
        )}
        {isAdmin && <TurnOff project={project} catalog={catalog} listed={rules.rules.map((r) => r.rule)} reload={reload} />}
      </Card>
      {rules.tomlChanges.length > 0 && (
        <Card id="toml-changes" title="Changes in sonda.toml" subtitle={`When the repository changed its rule settings, on ${rules.mainBranch}`}>
          <ul className="m-0 flex list-none flex-col gap-1.5 p-0 text-[13px]">
            {rules.tomlChanges.map((c) => (
              <li key={`${c.analysisId}-${c.rule}-${c.change}`} className="flex flex-wrap items-baseline gap-x-2">
                <Link to={`/rules#${encodeURIComponent(c.rule)}`} className="font-mono text-[12px]">
                  {c.rule}
                </Link>
                <span className="text-fg-muted">{TOML_CHANGE_LABEL[c.change]}</span>
                <span className="text-xs text-fg-faint">
                  at{' '}
                  <Link to={`/analyses/${c.analysisId}`} className="font-mono">
                    {c.sha.slice(0, 9)}
                  </Link>{' '}
                  · {shortDate(c.at)}
                </span>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </>
  )
}

function RuleRow({ project, s, isAdmin, reload }: { project: string; s: ProjectRuleState; isAdmin: boolean; reload: () => void }) {
  const api = useApi()
  const current: ProjectRuleSetting = s.projectSetting ?? 'inherit'
  const [setting, setSetting] = useState<ProjectRuleSetting>(current)
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const save = async () => {
    setBusy(true)
    setError(null)
    try {
      await api.setProjectRule(project, s.rule, setting, note.trim() || undefined)
      setNote('')
      reload()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <li aria-label={`Rule ${s.rule}`} className="grid grid-cols-[52px_minmax(0,1fr)] gap-x-3 gap-y-2 border-t border-line px-5 py-3 text-[13.5px] min-[900px]:grid-cols-[52px_minmax(0,1fr)_auto]">
      <span className="text-xs font-semibold" style={{ color: s.on ? 'var(--sd-ok)' : 'var(--sd-faint)' }}>
        {s.on ? 'On' : 'Off'}
      </span>
      <span className="flex min-w-0 flex-col gap-0.5">
        <span>
          <Link to={`/rules#${encodeURIComponent(s.rule)}`} className="font-mono text-[12px]">
            {s.rule}
          </Link>{' '}
          <span className="text-fg-muted">{s.name}</span>
        </span>
        <span className="text-xs text-fg-muted">
          {SET_BY_LABEL[s.setBy]}
          {s.change && (
            <>
              {' '}
              · by {s.change.changedBy}, {shortDate(s.change.changedAt)}
              {s.change.note && <>: “{s.change.note}”</>}
            </>
          )}
          {s.severity && <> · severity {s.severity} in sonda.toml</>}
          {s.hiddenIssues > 0 && <> · {formatNumber(s.hiddenIssues)} open findings left out</>}
        </span>
        {s.conflict && (
          <span role="note" className="text-xs text-warn">
            Off in sonda.toml: the server setting has no effect until the repository turns it back on.
          </span>
        )}
        {error && (
          <span role="alert" className="text-xs text-crit">
            {error}
          </span>
        )}
      </span>
      {isAdmin && (
        <span className="col-start-2 flex flex-wrap items-center gap-1.5 min-[900px]:col-start-3">
          <select aria-label={`Server setting for ${s.rule}`} value={setting} onChange={(e) => setSetting(e.target.value as ProjectRuleSetting)} className={input}>
            <option value="inherit">As for all projects</option>
            <option value="on">On here</option>
            <option value="off">Off here</option>
          </select>
          {setting !== current && (
            <>
              <input aria-label={`Note for ${s.rule}`} placeholder="Why (optional)" maxLength={500} value={note} onChange={(e) => setNote(e.target.value)} className={`${input} w-[200px]`} />
              <Button primary onClick={() => void save()} disabled={busy}>
                Save
              </Button>
            </>
          )}
        </span>
      )}
    </li>
  )
}

/** Admins turn off, for this project only, a rule that's on here. */
function TurnOff({ project, catalog, listed, reload }: { project: string; catalog: Rule[]; listed: string[]; reload: () => void }) {
  const api = useApi()
  const [rule, setRule] = useState('')
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const choices = catalog.filter((r) => !listed.includes(r.id))
  const submit = async () => {
    setBusy(true)
    setError(null)
    try {
      await api.setProjectRule(project, rule.trim(), 'off', note.trim() || undefined)
      setRule('')
      setNote('')
      reload()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <form
      className="flex flex-wrap items-end gap-2 border-t border-line px-5 py-3"
      onSubmit={(e) => {
        e.preventDefault()
        void submit()
      }}
    >
      <label className="flex flex-col gap-1 text-xs text-fg-muted">
        Turn off a rule for this project
        <input list="rule-ids" aria-label="Rule to turn off" placeholder="js/no-var" value={rule} onChange={(e) => setRule(e.target.value)} className={`${input} w-[260px] font-mono`} />
        <datalist id="rule-ids">
          {choices.map((r) => (
            <option key={r.id} value={r.id}>
              {r.name}
            </option>
          ))}
        </datalist>
      </label>
      <input aria-label="Why it's off" placeholder="Why (optional)" maxLength={500} value={note} onChange={(e) => setNote(e.target.value)} className={`${input} w-[240px]`} />
      <Button type="submit" primary disabled={busy || !rule.trim()}>
        Turn off here
      </Button>
      {error && (
        <span role="alert" className="basis-full text-xs text-crit">
          {error}
        </span>
      )}
    </form>
  )
}
