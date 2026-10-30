import { Link } from 'react-router'
import { useApi, useAsync } from '@/api/hooks'
import type { Security } from '@/api/types'
import { AppShell } from '@/components/shell/AppShell'
import { Card, MetricGrid, Mono, PageHeader } from '@/components/sonda/layout'
import { Sparkline } from '@/components/sonda/meters'
import { SeverityGlyph } from '@/components/sonda/status'
import { formatNumber, shortDate } from '@/lib/format'
import { componentLabel, componentUrl, projectUrl } from '@/lib/links'
import { SEVERITY } from '@/lib/visual'

export function SecurityPage() {
  const api = useApi()
  const data = useAsync(() => api.security(), [api])
  return (
    <AppShell crumbs={[{ label: 'Security', to: '/security' }]}>
      {data.state === 'loading' && <div aria-busy="true" className="h-[600px] rounded-xl bg-panel-2 edge" />}
      {data.state === 'error' && <p role="alert">Could not load security: {data.error.message}</p>}
      {data.state === 'ready' && <SecurityView s={data.data} />}
    </AppShell>
  )
}

const VULNS = '/issues?cat=vulnerability'

function SecurityView({ s }: { s: Security }) {
  const tiles = (['blocker', 'critical', 'major', 'minor'] as const).map((sev) => ({ sev, n: s.openBySeverity[sev] ?? 0 }))
  return (
    <>
      <PageHeader
        title="Security"
        summary={
          <>
            {formatNumber(s.open)} open {s.open === 1 ? 'vulnerability' : 'vulnerabilities'} in {s.projectsAffected}{' '}
            {s.projectsAffected === 1 ? 'project' : 'projects'} · each project’s main branch
          </>
        }
      >
        <Link to={VULNS} className="inline-flex h-9 items-center rounded-lg bg-brand px-3.5 text-[13px] font-semibold text-brand-ink">
          Triage vulnerabilities
        </Link>
      </PageHeader>

      <MetricGrid label="Open vulnerabilities" minCell={150}>
        {tiles.map(({ sev, n }) => (
          <Link key={sev} to={`${VULNS}`} className="flex flex-col gap-1 bg-panel-2 px-4 py-3 text-fg hover:bg-hover">
            <span className="flex items-center gap-1.5 text-[12.5px] text-fg-muted">
              <SeverityGlyph severity={sev} />
              {SEVERITY[sev].label}
            </span>
            <span className="font-mono text-[22px] leading-tight" style={{ color: n ? SEVERITY[sev].color : undefined }}>
              {formatNumber(n)}
            </span>
            <span className="text-xs text-fg-faint">open</span>
          </Link>
        ))}
        <div className="flex flex-col gap-1 bg-panel-2 px-4 py-3">
          <span className="text-[12.5px] text-fg-muted">New · 7 days</span>
          <span className="font-mono text-[22px] leading-tight" style={{ color: s.newThisWeek ? 'var(--sd-crit)' : undefined }}>
            {s.newThisWeek ? `+${s.newThisWeek}` : '0'}
          </span>
          <span className="text-xs text-fg-faint">still open</span>
        </div>
        <div className="flex flex-col gap-1 bg-panel-2 px-4 py-3">
          <span className="text-[12.5px] text-fg-muted">Fixed · 30 days</span>
          <span className="font-mono text-[22px] leading-tight" style={{ color: s.status.fixedLast30Days ? 'var(--sd-ok)' : undefined }}>
            {formatNumber(s.status.fixedLast30Days)}
          </span>
          <span className="text-xs text-fg-faint">
            {s.remediation.medianDaysSevere == null ? 'no critical fixed in 90 days' : `critical fixed in ${s.remediation.medianDaysSevere.toFixed(1)} days (median)`}
          </span>
        </div>
      </MetricGrid>

      <div className="grid grid-cols-1 gap-5 min-[1000px]:grid-cols-[minmax(0,1.5fr)_minmax(320px,1fr)]">
        <FixFirst s={s} />
        <Trend s={s} />
      </div>
      <div className="grid grid-cols-1 gap-5 min-[900px]:grid-cols-2">
        <Projects s={s} />
        <Remediation s={s} />
        <Components s={s} />
        <Rules s={s} />
      </div>
    </>
  )
}

function FixFirst({ s }: { s: Security }) {
  return (
    <Card id="focus" padded={false} title="Fix these first" subtitle="Most severe first, then longest open">
      {s.focus.length === 0 ? (
        <p className="m-0 px-5 pb-4 text-[13px] text-fg-faint">No open vulnerabilities.</p>
      ) : (
        <ol className="m-0 list-none p-0">
          {s.focus.map((f) => (
            <li key={f.id} className="grid grid-cols-[16px_minmax(0,1fr)_auto] items-baseline gap-3 border-t border-line px-5 py-2.5 text-[13.5px]">
              <SeverityGlyph severity={f.severity} />
              <span className="flex min-w-0 flex-col gap-0.5">
                <span>{f.message}</span>
                <span className="text-xs text-fg-faint">
                  <Link to={projectUrl(f.project)} className="text-fg-muted">
                    {f.project}
                  </Link>
                  {' › '}
                  <Link
                    to={`/issues?project=${encodeURIComponent(f.project)}&file=${encodeURIComponent(f.path)}&cat=vulnerability`}
                    className="font-mono text-[11.5px]"
                  >
                    {f.path}:{f.line}
                  </Link>{' '}
                  ·{' '}
                  <Link to={`/rules#${encodeURIComponent(f.rule)}`} className="font-mono text-[11px] text-fg-faint">
                    {f.rule}
                  </Link>
                </span>
              </span>
              <span className="text-right text-xs whitespace-nowrap">
                <span style={{ color: SEVERITY[f.severity].color }}>{SEVERITY[f.severity].label}</span>
                <span className="block text-fg-faint">{f.ageDays === 0 ? 'today' : `${f.ageDays}d open`}</span>
              </span>
            </li>
          ))}
        </ol>
      )}
    </Card>
  )
}

function Trend({ s }: { s: Security }) {
  const weighted = s.trend.map((t) => t.weighted)
  const first = weighted[0]
  const last = weighted[weighted.length - 1]
  const change = first ? Math.round(((last - first) / first) * 100) : 0
  const better = last <= first
  const perWeek = (key: 'introduced' | 'fixed') => (s.trend.reduce((sum, t) => sum + t[key], 0) / s.trend.length).toFixed(1)
  return (
    <Card
      id="risk"
      title="Risk · 12 weeks"
      subtitle="Open vulnerabilities weighted by severity: blocker 10, critical 5, major 2, minor 1"
      aside={
        <Mono className="text-[12.5px]">
          <span style={{ color: better ? 'var(--sd-ok)' : 'var(--sd-crit)' }}>
            {change > 0 ? '+' : change < 0 ? '−' : ''}
            {Math.abs(change)}%
          </span>
        </Mono>
      }
    >
      <Sparkline
        series={weighted}
        color={better ? 'var(--sd-ok)' : 'var(--sd-crit)'}
        fill={`color-mix(in oklch, ${better ? 'var(--sd-ok)' : 'var(--sd-crit)'} 10%, transparent)`}
        className="block h-24 w-full"
        label={`Weighted risk ${better ? 'falling or steady' : 'rising'}: ${first} to ${last}`}
      />
      <div className="flex justify-between font-mono text-[9.5px] text-fg-faint">
        <span>{shortDate(s.trend[0].date)}</span>
        <span>{shortDate(s.trend[s.trend.length - 1].date)}</span>
      </div>
      <dl className="m-0 grid grid-cols-3 gap-3 border-t border-line pt-3 text-[12.5px]">
        {[
          ['Weighted now', String(last)],
          ['Found per week', perWeek('introduced')],
          ['Fixed per week', perWeek('fixed')],
        ].map(([k, v]) => (
          <div key={k} className="flex flex-col gap-0.5">
            <dt className="text-fg-muted">{k}</dt>
            <dd className="m-0 font-mono text-[15px]">{v}</dd>
          </div>
        ))}
      </dl>
    </Card>
  )
}

function Bar({ parts, total }: { parts: { n: number; color: string }[]; total: number }) {
  return (
    <span aria-hidden="true" className="flex h-1.5 overflow-hidden rounded-sm bg-pip-off">
      {parts.map((p, i) => (
        <span key={i} style={{ width: `${total ? (p.n / total) * 100 : 0}%`, background: p.color }} />
      ))}
    </span>
  )
}

function Projects({ s }: { s: Security }) {
  const max = Math.max(1, ...s.projects.map((p) => p.severe + p.other))
  return (
    <Card id="projects" title="Affected projects" subtitle="Blocker + critical, then the rest">
      {s.projects.length === 0 && <p className="m-0 text-[13px] text-fg-faint">None.</p>}
      <ul className="m-0 flex list-none flex-col gap-2.5 p-0">
        {s.projects.map((p) => (
          <li key={p.project} className="flex flex-col gap-1">
            <span className="flex items-baseline justify-between text-[13px]">
              <Link to={`/issues?project=${encodeURIComponent(p.project)}&cat=vulnerability`} className="text-fg">
                {p.project}
              </Link>
              <Mono className="text-xs text-fg-muted">
                {p.severe ? <span className="text-crit">{p.severe}</span> : '0'} · {p.other}
              </Mono>
            </span>
            <Bar
              total={max}
              parts={[
                { n: p.severe, color: 'var(--sd-crit)' },
                { n: p.other, color: 'var(--sd-warn)' },
              ]}
            />
          </li>
        ))}
      </ul>
    </Card>
  )
}

function Remediation({ s }: { s: Security }) {
  const rows = [
    { label: 'Open', n: s.status.open, color: 'var(--sd-crit)' },
    { label: 'Confirmed', n: s.status.confirmed, color: 'var(--sd-warn)' },
    { label: 'Fixed · 30 days', n: s.status.fixedLast30Days, color: 'var(--sd-ok)' },
    { label: 'Accepted risk', n: s.status.accepted, color: 'var(--sd-faint)' },
  ]
  const max = Math.max(1, ...rows.map((r) => r.n))
  const r = s.remediation
  return (
    <Card id="remediation" title="Remediation" subtitle={`${formatNumber(r.fixedLast90Days)} fixed in the last 90 days`}>
      <ul className="m-0 flex list-none flex-col gap-2.5 p-0">
        {rows.map((row) => (
          <li key={row.label} className="flex flex-col gap-1">
            <span className="flex justify-between text-[13px]">
              {row.label}
              <Mono className="text-xs text-fg-muted">{row.n}</Mono>
            </span>
            <Bar total={max} parts={[{ n: row.n, color: row.color }]} />
          </li>
        ))}
      </ul>
      <p className="m-0 border-t border-line pt-3 text-[13px] text-fg-muted">
        Median time to fix a blocker or critical:{' '}
        <Mono className="text-fg">{r.medianDaysSevere == null ? '—' : `${r.medianDaysSevere.toFixed(1)} days`}</Mono>
        {r.medianDaysAll != null && <> · any severity {r.medianDaysAll.toFixed(1)} days</>}
      </p>
    </Card>
  )
}

function Components({ s }: { s: Security }) {
  return (
    <Card id="components" title="High-risk components" subtitle="By weighted open vulnerabilities">
      {s.components.length === 0 && <p className="m-0 text-[13px] text-fg-faint">None.</p>}
      <ul className="m-0 flex list-none flex-col p-0">
        {s.components.map((c) => (
          <li key={`${c.project}/${c.path}`} className="flex items-center justify-between gap-3 border-t border-line py-2 text-[13px] first:border-t-0">
            <span className="flex min-w-0 items-baseline gap-2">
              <SeverityGlyph severity={c.worst} />
              <Link to={componentUrl(c.project, c.path)} className="truncate font-mono text-[12.5px] text-fg">
                {c.project}/{componentLabel(c.path)}
              </Link>
            </span>
            <Mono className="text-xs whitespace-nowrap text-fg-muted">
              {c.count} {c.count === 1 ? 'vuln' : 'vulns'}
            </Mono>
          </li>
        ))}
      </ul>
    </Card>
  )
}

function Rules({ s }: { s: Security }) {
  return (
    <Card id="rules" title="Most common rules" subtitle="Open vulnerabilities by rule">
      {s.rules.length === 0 && <p className="m-0 text-[13px] text-fg-faint">None.</p>}
      <ul className="m-0 flex list-none flex-col p-0">
        {s.rules.map((r) => (
          <li key={r.rule} className="flex items-center justify-between gap-3 border-t border-line py-2 text-[13px] first:border-t-0">
            <Link to={`/rules#${encodeURIComponent(r.rule)}`} className="truncate font-mono text-[12.5px] text-fg">
              {r.rule}
            </Link>
            <Mono className="text-xs text-fg-muted">{r.count}</Mono>
          </li>
        ))}
      </ul>
    </Card>
  )
}
