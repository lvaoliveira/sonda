import { useState } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router'
import { useApi, useAsync } from '@/api/hooks'
import type { MeasureSet, NewCodePeriod, ProjectDetail, ProjectHistoryPoint } from '@/api/types'
import { AppShell } from '@/components/shell/AppShell'
import { Button, Segmented } from '@/components/sonda/controls'
import { Card, MetricGrid, Mono } from '@/components/sonda/layout'
import { HealthBar, PipMeter, Sparkline } from '@/components/sonda/meters'
import { GateConditions } from '@/components/sonda/gate'
import { GateDot, GateStatus } from '@/components/sonda/status'
import { componentLabel, componentUrl, coverageUrl, dependenciesUrl } from '@/lib/links'
import { compactCount, formatAge, formatDebt, formatNumber, shortDate } from '@/lib/format'
import { ECOSYSTEM_LABEL, GATE, coverageColor, languageLabel, scoreColor } from '@/lib/visual'

export function ProjectPage() {
  const api = useApi()
  const { key = '' } = useParams()
  const [params] = useSearchParams()
  const branch = params.get('branch') ?? undefined
  const detail = useAsync(() => api.project(key, branch), [api, key, branch])
  return (
    <AppShell crumbs={[{ label: 'Projects', to: '/projects' }, { label: key, to: `/projects/${encodeURIComponent(key)}` }]}>
      {detail.state === 'loading' && <div aria-busy="true" className="h-[600px] rounded-xl bg-panel-2 edge" />}
      {detail.state === 'error' && (
        <div role="alert" className="flex flex-col items-start gap-2 rounded-xl bg-panel-2 px-5 py-8 edge">
          <span className="font-semibold">Could not load {key}</span>
          <span className="text-[13px] text-fg-muted">{detail.error.message}</span>
          <Link to="/projects" className="text-[13px]">
            All projects →
          </Link>
        </div>
      )}
      {detail.state === 'ready' && <Project p={detail.data} reload={detail.reload} />}
    </AppShell>
  )
}

function Project({ p, reload }: { p: ProjectDetail; reload: () => void }) {
  const navigate = useNavigate()
  const lines = p.languages.reduce((sum, l) => sum + l.ncloc, 0)
  const projectUrl = `/projects/${encodeURIComponent(p.key)}`
  return (
    <>
      <div className="flex flex-col gap-2">
        <h1 className="m-0 text-[30px] leading-[1.1] font-semibold tracking-[-0.035em]">{p.key}</h1>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2 text-[13.5px] text-fg-muted">
          <label className="flex items-center gap-2">
            <span className="sr-only">Branch</span>
            <GateDot state={p.branches.find((b) => b.name === p.branch)?.gate ?? p.gate.state} />
            <select
              value={p.branch}
              onChange={(e) => navigate(e.target.value === p.mainBranch ? projectUrl : `${projectUrl}?branch=${encodeURIComponent(e.target.value)}`)}
              className="h-8 rounded-md bg-canvas px-2 font-mono text-[12.5px] text-fg edge"
            >
              {p.branches.map((b) => (
                <option key={b.name} value={b.name}>
                  {b.name} · {GATE[b.gate].label.toLowerCase()} · {b.ago}
                </option>
              ))}
            </select>
          </label>
          <span>{p.languages.map((l) => languageLabel(l.id)).join(' · ')}</span>
          <span>{compactCount(lines)} lines</span>
          <span>
            Analysis{' '}
            <Link to={`/analyses/${p.analysis.id}`} className="font-mono text-xs">
              {p.analysis.sha.slice(0, 9)}
            </Link>{' '}
            ·{' '}
            <time dateTime={p.analysis.analyzedAt} title={new Date(p.analysis.analyzedAt).toUTCString()}>
              {formatAge(p.analysis.analyzedAt)} ago
            </time>{' '}
            · sonda {p.analysis.toolVersion}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-5 min-[1000px]:grid-cols-[minmax(0,1.4fr)_minmax(320px,1fr)]">
        <Measures p={p} reload={reload} />
        <Gate p={p} />
      </div>
      <History history={p.history} branch={p.branch} />
      <Components p={p} />
      <Dependencies p={p} />
    </>
  )
}

function Dependencies({ p }: { p: ProjectDetail }) {
  const d = p.dependencies
  const url = dependenciesUrl(p.key, p.branch, p.mainBranch)
  return (
    <Card
      id="dependencies"
      title="Dependencies"
      subtitle={d ? 'Packages the lockfiles pin, in this analysis' : 'None recorded in this analysis'}
      aside={
        d && (
          <Link to={url} className="text-[13px]">
            All {formatNumber(d.total)} →
          </Link>
        )
      }
    >
      {d ? (
        <div className="flex flex-wrap items-baseline gap-x-6 gap-y-2 text-[13px] text-fg-muted">
          <span>
            <Mono className="text-[22px] text-fg">{formatNumber(d.total)}</Mono> packages
          </span>
          <span>
            <Mono className="text-fg">{formatNumber(d.direct)}</Mono> direct
          </span>
          {d.vulnerable > 0 && (
            <Link to={url} className="text-[13px]" style={{ color: 'var(--sd-crit)' }}>
              {formatNumber(d.vulnerable)} with known vulnerabilities
            </Link>
          )}
          {d.ecosystems.map((e) => (
            <span key={e.id}>
              {ECOSYSTEM_LABEL[e.id] ?? e.id} <Mono className="text-fg">{formatNumber(e.count)}</Mono>
            </span>
          ))}
        </div>
      ) : (
        <p className="m-0 text-[13px] text-fg-muted">
          sonda reads <Mono className="text-xs">package-lock.json</Mono>, <Mono className="text-xs">yarn.lock</Mono>, <Mono className="text-xs">pnpm-lock.yaml</Mono>,{' '}
          <Mono className="text-xs">bun.lock</Mono>, <Mono className="text-xs">Cargo.lock</Mono>,{' '}
          <Mono className="text-xs">poetry.lock</Mono>,{' '}
          <Mono className="text-xs">uv.lock</Mono>, <Mono className="text-xs">Pipfile.lock</Mono> and pinned <Mono className="text-xs">requirements*.txt</Mono>; analyses uploaded by an older sonda don't include them.
        </p>
      )}
    </Card>
  )
}

function Gate({ p }: { p: ProjectDetail }) {
  const failing = p.gate.conditions.filter((c) => c.status === 'error').length
  const noData = p.gate.conditions.filter((c) => c.status === 'no_data').length
  const ignored = p.gate.conditions.filter((c) => c.status === 'ignored').length
  return (
    <Card
      id="gate"
      title={<GateStatus state={p.gate.state} className="text-base" />}
      subtitle={
        p.gate.conditions.length === 0
          ? 'The gate has no conditions'
          : `${failing} of ${p.gate.conditions.length} conditions failing${noData ? ` · ${noData} without data` : ''}${ignored ? ` · ${ignored} ignored` : ''}`
      }
      aside={<span className="text-xs text-fg-faint">from the repository’s sonda.toml</span>}
    >
      <GateConditions conditions={p.gate.conditions} />
    </Card>
  )
}

type Scope = 'overall' | 'newCode'

function Measures({ p, reload }: { p: ProjectDetail; reload: () => void }) {
  const [scope, setScope] = useState<Scope>('overall')
  const m: MeasureSet = p.measures[scope]
  const issues = (extra: string) =>
    `/issues?project=${encodeURIComponent(p.key)}&branch=${encodeURIComponent(p.branch)}${extra}${scope === 'newCode' ? '&new' : ''}`
  const count = (v: number | null) => (v == null ? '—' : formatNumber(v))
  const pct = (v: number | null) => (v == null ? '—' : `${v.toFixed(1)}%`)
  const period = p.newCodePeriod
  // Without per-line data, the server keeps the scan's own values for these.
  const fromScan = (metric: string) => scope === 'newCode' && period != null && period.fromScan.includes(metric)
  const tiles: { label: string; value: string; sub: string; to?: string; color?: string }[] = [
    { label: 'Bugs', value: count(m.bugs), sub: 'Reliability', to: issues('&cat=bug') },
    { label: 'Vulnerabilities', value: count(m.vulnerabilities), sub: 'Security', to: issues('&cat=vulnerability') },
    { label: 'Code smells', value: count(m.codeSmells), sub: 'Maintainability', to: issues('&cat=code_smell') },
    {
      label: 'Coverage',
      value: pct(m.coverage),
      sub: m.coverage == null ? 'No coverage uploaded' : fromScan('new_coverage') ? 'on lines the scan changed' : scope === 'newCode' ? 'on changed lines' : 'of code lines',
      color: m.coverage == null ? undefined : coverageColor(m.coverage),
      to: coverageUrl(p.key, p.branch, p.mainBranch),
    },
    { label: 'Duplication', value: pct(m.duplication), sub: fromScan('new_duplicated_lines_density') ? 'in lines the scan changed' : 'duplicated lines' },
    { label: 'Debt', value: m.debtMinutes == null ? '—' : formatDebt(m.debtMinutes), sub: 'to fix every issue', to: issues('') },
  ]
  return (
    <Card
      id="measures"
      title="Measures"
      subtitle={
        scope === 'newCode'
          ? period
            ? `${formatNumber(m.lines ?? 0)} new lines since ${shortDate(period.analyzedAt)} (${period.reset ? 'set by an admin' : period.version ? `version ${period.version}` : 'the first analysis'})`
            : `${formatNumber(m.lines ?? 0)} new lines${p.analysis.newCodeReference ? ` since ${p.analysis.newCodeReference}` : ''}`
          : `${formatNumber(m.lines ?? 0)} lines of code`
      }
      aside={
        <Segmented
          label="Measures"
          value={scope}
          onChange={setScope}
          options={[
            { value: 'overall', label: 'Overall' },
            { value: 'newCode', label: 'New code' },
          ]}
        />
      }
    >
      <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
        <span className="flex items-baseline gap-2">
          <span className="font-mono text-[26px] leading-none" style={{ color: scoreColor(p.score) }}>
            {p.score}
          </span>
          <span className="text-xs text-fg-faint">score</span>
        </span>
        <span className="min-w-[160px] flex-1">
          <HealthBar score={p.score} />
        </span>
        <span className="flex gap-4 text-xs text-fg-muted">
          {(['reliability', 'security', 'maintainability'] as const).map((r) => (
            <span key={r} className="flex items-center gap-1.5">
              <PipMeter level={p.ratings[r]} label={r[0].toUpperCase() + r.slice(1)} width={3} />
              {r === 'maintainability' ? 'Mnt' : r === 'reliability' ? 'Rel' : 'Sec'}
            </span>
          ))}
        </span>
      </div>
      <MetricGrid label="Measures" minCell={150}>
        {tiles.map((t) => (
          <div key={t.label} className="flex flex-col gap-1 bg-panel-2 px-4 py-3">
            <span className="text-[12.5px] text-fg-muted">{t.label}</span>
            <span className="font-mono text-[22px] leading-tight" style={{ color: t.color }}>
              {t.to && t.value !== '—' ? (
                <Link to={t.to} className="text-inherit" style={{ color: t.color ?? 'var(--sd-text)' }}>
                  {t.value}
                </Link>
              ) : (
                t.value
              )}
            </span>
            <span className="text-xs text-fg-faint">{t.sub}</span>
          </div>
        ))}
      </MetricGrid>
      {scope === 'newCode' && period && <NewCodeStart p={p} period={period} reload={reload} />}
    </Card>
  )
}

/** Where the main branch's new code starts, and for admins, moving it (ADR-0011). */
function NewCodeStart({ p, period, reload }: { p: ProjectDetail; period: NewCodePeriod; reload: () => void }) {
  const api = useApi()
  const shell = useAsync(() => api.shell(), [api])
  const isAdmin = shell.state === 'ready' && shell.data.isAdmin
  const [choice, setChoice] = useState(String(period.analysis))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const move = async (analysis: number | null) => {
    setBusy(true)
    setError(null)
    try {
      await api.setNewCodePeriod(p.key, analysis)
      reload()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className="mt-3 flex flex-col gap-2 border-t border-line pt-3 text-[13px] text-fg-muted">
      <p className="m-0">
        Issues first seen after analysis{' '}
        <Link to={`/analyses/${period.analysis}`} className="font-mono text-xs">
          {period.sha.slice(0, 9)}
        </Link>{' '}
        ({shortDate(period.analyzedAt)}) are new; what was there then is accepted. Unless an admin sets the start, each new version
        (<code className="text-xs">sonda upload --project-version</code>) starts it again. Coverage and duplication on new code come from the scan.
      </p>
      {isAdmin && (
        <div className="flex flex-wrap items-center gap-2">
          <label htmlFor="new-code-start" className="text-xs">
            Start new code at
          </label>
          <select
            id="new-code-start"
            value={choice}
            onChange={(e) => setChoice(e.target.value)}
            className="h-[30px] rounded-md border-0 bg-canvas px-2 text-[13px] text-fg edge"
          >
            {[...p.history].reverse().map((h) => (
              <option key={h.id} value={h.id}>
                {h.sha.slice(0, 9)} · {h.version ? `${h.version} · ` : ''}
                {shortDate(h.analyzedAt)}
              </option>
            ))}
          </select>
          <Button onClick={() => void move(Number(choice))} disabled={busy || Number(choice) === period.analysis}>
            Start new code here
          </Button>
          {period.reset && (
            <Button onClick={() => void move(null)} disabled={busy}>
              Back to the default start
            </Button>
          )}
          <span className="text-xs text-fg-faint">Accepts the issues present then. Recorded with your name.</span>
        </div>
      )}
      {error && (
        <span role="alert" className="text-xs text-crit">
          {error}
        </span>
      )}
    </div>
  )
}

function History({ history, branch }: { history: ProjectHistoryPoint[]; branch: string }) {
  const series = (pick: (h: ProjectHistoryPoint) => number | null) => history.map(pick).filter((v): v is number => v != null)
  const last = history[history.length - 1]
  const lines: { label: string; values: number[]; value: string; worseUp: boolean }[] = [
    { label: 'Issues', values: series((h) => h.issues), value: last.issues == null ? '—' : formatNumber(last.issues), worseUp: true },
    { label: 'Coverage', values: series((h) => h.coverage), value: last.coverage == null ? '—' : `${last.coverage.toFixed(1)}%`, worseUp: false },
    { label: 'Duplication', values: series((h) => h.duplication), value: last.duplication == null ? '—' : `${last.duplication.toFixed(1)}%`, worseUp: true },
    { label: 'Debt', values: series((h) => h.debtMinutes), value: last.debtMinutes == null ? '—' : formatDebt(last.debtMinutes), worseUp: true },
  ]
  return (
    <Card id="history" title="History" subtitle={`last ${history.length} ${history.length === 1 ? 'analysis' : 'analyses'} · ${branch}`}>
      <div className="grid grid-cols-[repeat(auto-fit,minmax(180px,1fr))] gap-4">
        {lines.map((l) => {
          const first = l.values[0]
          const end = l.values[l.values.length - 1]
          const worse = l.values.length > 1 && (l.worseUp ? end > first : end < first)
          return (
            <div key={l.label} className="flex flex-col gap-1.5">
              <span className="flex items-baseline justify-between text-[12.5px] text-fg-muted">
                {l.label}
                <Mono className="text-[12px] text-fg">{l.value}</Mono>
              </span>
              {l.values.length > 1 ? (
                <Sparkline
                  series={l.values}
                  color={worse ? 'var(--sd-crit)' : 'var(--sd-ok)'}
                  className="block h-8 w-full"
                  label={`${l.label} ${worse ? 'worsening' : 'steady or improving'}: ${first} to ${end}`}
                />
              ) : (
                <span className="text-xs text-fg-faint">{l.values.length ? 'One analysis so far' : 'No data'}</span>
              )}
            </div>
          )
        })}
      </div>
      <div className="flex flex-col gap-1.5">
        <span className="text-[12.5px] text-fg-muted">Gate per analysis</span>
        <ol className="m-0 flex list-none flex-wrap gap-1.5 p-0">
          {history.map((h) => (
            <li key={h.id}>
              <Link
                to={`/analyses/${h.id}`}
                title={`${h.sha.slice(0, 9)} · ${shortDate(h.analyzedAt)} · ${GATE[h.gate].label}`}
                className="flex items-center gap-1.5 rounded-md bg-canvas px-2 py-1 edge hover:bg-hover"
              >
                <GateDot state={h.gate} />
                <Mono className="text-[10.5px] text-fg-muted">{h.sha.slice(0, 7)}</Mono>
              </Link>
            </li>
          ))}
        </ol>
      </div>
    </Card>
  )
}

function Components({ p }: { p: ProjectDetail }) {
  const th = 'border-b border-line px-2 py-2 text-left font-normal'
  const td = 'border-b border-line px-2 py-[10px]'
  const issuesIn = (path: string) =>
    `/issues?project=${encodeURIComponent(p.key)}&branch=${encodeURIComponent(p.branch)}&comp=${encodeURIComponent(path)}`
  return (
    <Card id="components" padded={false} title="Components" subtitle="Top-level directories · owners from the uploaded CODEOWNERS">
      <div className="overflow-x-auto">
        <table className="w-full min-w-[720px] border-collapse text-[13.5px]">
          <thead>
            <tr className="font-mono text-[9.5px] tracking-[.06em] text-fg-faint uppercase">
              <th scope="col" className={`${th} px-5`}>
                Component
              </th>
              <th scope="col" className={th}>
                Owner
              </th>
              <th scope="col" className={`${th} text-right`}>
                Files
              </th>
              <th scope="col" className={`${th} text-right`}>
                Lines
              </th>
              <th scope="col" className={`${th} text-right`}>
                Issues
              </th>
              <th scope="col" className={`${th} pr-5 text-right`}>
                Debt
              </th>
            </tr>
          </thead>
          <tbody>
            {p.components.map((c) => (
              <tr key={c.path} className="hover:bg-hover">
                <td className={`${td} px-5`}>
                  <span className="flex flex-col leading-[1.3]">
                    <Link to={componentUrl(p.key, c.path, p.branch, p.mainBranch)} className="font-mono text-[12.5px] text-fg">
                      {componentLabel(c.path)}
                    </Link>
                    <span className="text-xs text-fg-faint">{c.languages.map(languageLabel).join(', ')}</span>
                  </span>
                </td>
                <td className={`${td} text-[13px] text-fg-muted`}>{c.owner ?? <span className="text-fg-faint">—</span>}</td>
                <td className={`${td} text-right font-mono text-xs text-fg-muted`}>{formatNumber(c.files)}</td>
                <td className={`${td} text-right font-mono text-xs text-fg-muted`}>{compactCount(c.ncloc)}</td>
                <td className={`${td} text-right font-mono text-xs`}>
                  {c.issues ? <Link to={issuesIn(c.path)}>{formatNumber(c.issues)}</Link> : <span className="text-fg-faint">0</span>}
                </td>
                <td className={`${td} pr-5 text-right font-mono text-xs text-fg-muted`}>{c.debtMinutes ? formatDebt(c.debtMinutes) : '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}
