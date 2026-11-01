import { useCallback, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router'
import { useApi, useAsync } from '@/api/hooks'
import type { ProjectRule, ProjectRuleSetting, ProjectRules, RuleProfileSummary } from '@/api/types'
import { AppShell } from '@/components/shell/AppShell'
import { Button } from '@/components/sonda/controls'
import { Card, Mono, PageHeader } from '@/components/sonda/layout'
import { RuleBrowser, type RuleFilter, RuleSearch } from '@/components/sonda/RuleBrowser'
import { formatNumber, shortDate } from '@/lib/format'
import { SET_BY_LABEL, TOML_CHANGE_LABEL, languageLabel } from '@/lib/visual'

/** A project's rules (ADR-0016, ADR-0018): the ones for its languages, each with its state here; admins enable and disable them. */
export function ProjectRulesPage() {
  const api = useApi()
  const { key = '' } = useParams()
  const projectUrl = `/projects/${encodeURIComponent(key)}`
  const data = useAsync(() => Promise.all([api.projectRules(key), api.shell(), api.ruleProfiles()]), [api, key])
  return (
    <AppShell
      crumbs={[
        { label: 'Projects', to: '/projects' },
        { label: key, to: projectUrl },
        { label: 'Rules', to: `${projectUrl}/rules` },
      ]}
    >
      {data.state === 'loading' && <div aria-busy="true" className="h-[600px] rounded-xl bg-panel-2 edge" />}
      {data.state === 'error' && <p role="alert">Could not load the rules of {key}: {data.error.message}</p>}
      {data.state === 'ready' && <Rules rules={data.data[0]} isAdmin={data.data[1].isAdmin} profiles={data.data[2]} reload={data.reload} />}
    </AppShell>
  )
}

const STATE_FILTER: RuleFilter<ProjectRule> = {
  label: 'State',
  options: [
    { value: 'on', label: 'On' },
    { value: 'off', label: 'Off' },
    { value: 'changed', label: 'Not at default' },
  ],
  test: (r, v) => (v === 'on' ? r.state.on : v === 'off' ? !r.state.on : r.state.setBy !== 'default' || r.state.severity !== null),
}

function Rules({ rules, isAdmin, profiles, reload }: { rules: ProjectRules; isAdmin: boolean; profiles: RuleProfileSummary[]; reload: () => void }) {
  const [q, setQ] = useState('')
  const count = useCallback((r: ProjectRule) => r.openIssues + r.hiddenIssues, [])
  const languages = useMemo(
    () => rules.languages.map((id) => ({ id, rules: rules.rules.filter((r) => r.languages.includes(id)).length })),
    [rules],
  )
  const on = rules.rules.filter((r) => r.state.on).length
  return (
    <>
      <PageHeader
        title="Rules"
        summary={
          <>
            {formatNumber(rules.rules.length)} rules for {rules.languages.map(languageLabel).join(', ') || 'no languages yet'} · {formatNumber(on)} on · profile{' '}
            <span className="font-semibold text-fg">{rules.profile.name}</span>
            {!rules.profile.chosen && ' (the default)'}
          </>
        }
      >
        <RuleSearch q={q} setQ={setQ} />
      </PageHeader>
      {isAdmin && <ProfileChoice project={rules.project} current={rules.profile} profiles={profiles} reload={reload} />}
      {rules.profileApplied === false && (
        <p role="status" className="m-0 rounded-[10px] bg-warn-soft px-3.5 py-2.5 text-[13px]">
          The latest scan of <Mono className="text-[12px]">{rules.mainBranch}</Mono> didn't apply these settings. They apply from the next{' '}
          <Mono className="text-[12px]">sonda scan --upload</Mono>; until then, rules turned on here may not have run.
        </p>
      )}
      <RuleBrowser
        rules={rules.rules}
        total={rules.rules.length}
        languages={languages}
        count={count}
        sortLabel="sorted by findings here"
        extraFilter={STATE_FILTER}
        search={{ q, setQ }}
        listTags={(r) => (
          <>
            <span>·</span>
            <span style={{ color: r.state.on ? 'var(--sd-ok)' : 'var(--sd-faint)' }}>{r.state.on ? 'on' : 'off'}</span>
            {r.state.setBy !== 'default' && <span className="text-fg-faint">({shortSetBy(r)})</span>}
          </>
        )}
        summary={(r) => (
          <>
            <span className="text-[12.5px] text-fg-muted">
              <Mono className="text-[11.5px] text-fg">{r.openIssues}</Mono> open issues here
              {r.hiddenIssues > 0 && (
                <>
                  {' '}
                  · <Mono className="text-[11.5px] text-fg">{r.hiddenIssues}</Mono> left out while it's off
                </>
              )}{' '}
              · <Mono className="text-[11.5px] text-fg">{r.effortMinutes}</Mono> min to fix each
            </span>
            <Link to={`/issues?project=${encodeURIComponent(rules.project)}`} className="ml-auto text-[13px]">
              See issues →
            </Link>
          </>
        )}
        panel={(r) => <InThisProject key={r.id} project={rules.project} rule={r} profile={rules.profile.name} isAdmin={isAdmin} reload={reload} />}
      />
      <RepositorySettings rules={rules} />
    </>
  )
}

function shortSetBy(r: ProjectRule): string {
  return { default: 'default', sonda_toml: 'sonda.toml', profile: 'profile', project: 'this project' }[r.state.setBy]
}

/** The rule's state here, and for admins, enabling or disabling it for this project. */
function InThisProject({ project, rule, profile, isAdmin, reload }: { project: string; rule: ProjectRule; profile: string; isAdmin: boolean; reload: () => void }) {
  const api = useApi()
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const s = rule.state
  const set = async (setting: ProjectRuleSetting) => {
    setBusy(true)
    setError(null)
    try {
      await api.setProjectRule(project, rule.id, setting, note.trim() || undefined)
      setNote('')
      reload()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <section aria-label="In this project" className="flex flex-col gap-2">
      <h3 className="m-0 font-normal micro-label">In this project</h3>
      <p className="m-0 text-[13px]">
        <span className="font-semibold" style={{ color: s.on ? 'var(--sd-ok)' : 'var(--sd-faint)' }}>
          {s.on ? 'On' : 'Off'}
        </span>
        <span className="text-fg-muted">
          {' '}
          · {s.setBy === 'profile' ? `${SET_BY_LABEL.profile}, ${profile}` : SET_BY_LABEL[s.setBy]}
          {s.change && (
            <>
              {' '}
              · by {s.change.changedBy}, {shortDate(s.change.changedAt)}
              {s.change.note && <>: “{s.change.note}”</>}
            </>
          )}
          {s.severity && (
            <>
              {' '}
              · severity {s.severity} in {s.severityBy === 'profile' ? 'the profile' : 'sonda.toml'}
            </>
          )}
        </span>
      </p>
      {s.conflict && (
        <p role="note" className="m-0 text-xs text-warn">
          On on the server, but the latest scan didn't apply the server's settings, and the repository's sonda.toml leaves it off: it didn't run.
        </p>
      )}
      {isAdmin && (
        <div className="flex flex-wrap items-center gap-2">
          <input
            aria-label={`Why, for ${rule.id}`}
            placeholder="Why (optional)"
            maxLength={500}
            value={note}
            onChange={(e) => setNote(e.target.value)}
            className="h-8 w-[220px] rounded-md border-0 bg-canvas px-2 text-[13px] edge"
          />
          {(!s.on || s.projectSetting === 'off') && (
            <Button primary onClick={() => void set('on')} disabled={busy || s.projectSetting === 'on'}>
              Enable here
            </Button>
          )}
          {(s.on || s.projectSetting === 'on') && (
            <Button onClick={() => void set('off')} disabled={busy || s.projectSetting === 'off'}>
              Disable here
            </Button>
          )}
          {s.projectSetting && (
            <Button onClick={() => void set('inherit')} disabled={busy}>
              Follow the profile
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

/** Admins choose the project's rule profile, or the default. */
function ProfileChoice({ project, current, profiles, reload }: { project: string; current: ProjectRules['profile']; profiles: RuleProfileSummary[]; reload: () => void }) {
  const api = useApi()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const choose = async (value: string) => {
    setBusy(true)
    setError(null)
    try {
      await api.setProjectProfile(project, value === 'default' ? null : Number(value))
      reload()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }
  const def = profiles.find((p) => p.isDefault)
  return (
    <div className="flex flex-wrap items-center gap-2 text-[13px]">
      <label htmlFor="rule-profile" className="text-fg-muted">
        Rule profile
      </label>
      <select
        id="rule-profile"
        value={current.chosen ? String(current.id) : 'default'}
        disabled={busy}
        onChange={(e) => void choose(e.target.value)}
        className="h-8 rounded-md border-0 bg-canvas px-2 text-[13px] text-fg edge"
      >
        <option value="default">The default{def ? ` (${def.name})` : ''}</option>
        {profiles.map((p) => (
          <option key={p.id} value={p.id}>
            {p.name}
          </option>
        ))}
      </select>
      {error && (
        <span role="alert" className="text-xs text-crit">
          {error}
        </span>
      )}
    </div>
  )
}

/** The repository's own settings, from its sonda.toml, and when they changed. */
function RepositorySettings({ rules }: { rules: ProjectRules }) {
  const toml = rules.sondaToml
  const n = toml ? Object.keys(toml.severity).length : 0
  return (
    <Card id="sonda-toml" title="The repository's sonda.toml" subtitle={`Its [rules] settings, as the latest analysis of ${rules.mainBranch} recorded them`}>
      <p className="m-0 text-[13px] text-fg-muted">
        {toml
          ? `${toml.disabled.length} disabled, ${toml.enabled.length} enabled, ${n} ${n === 1 ? 'severity' : 'severities'} changed. Where the server sets a rule, the server wins in scans that upload.`
          : 'Unknown: the latest analysis came from an older sonda. They show after the next upload.'}
      </p>
      {rules.tomlChanges.length > 0 && (
        <ul aria-label="Changes in sonda.toml" className="m-0 flex list-none flex-col gap-1.5 p-0 text-[13px]">
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
      )}
    </Card>
  )
}
