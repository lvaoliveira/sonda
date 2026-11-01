import { ArrowRight } from 'lucide-react'
import { Fragment, type ReactNode, useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { useApi, useAsync } from '@/api/hooks'
import type { Drill, DrillMetric, FlowBucket, Overview, ProjectHealth, Range, Scope, SondaApi } from '@/api/types'
import { AppShell } from '@/components/shell/AppShell'
import { DrillDrawer } from '@/components/sonda/DrillDrawer'
import { Segmented } from '@/components/sonda/controls'
import { Card, MetricGrid, Mono, PageHeader } from '@/components/sonda/layout'
import { CoverageRing, HealthBar, PipMeter, Sparkline } from '@/components/sonda/meters'
import { GateStatus, SeverityGlyph } from '@/components/sonda/status'
import { waffleCells } from '@/lib/charts'
import { formatNumber, shortDate } from '@/lib/format'
import { coverageUrl, fileCoverageUrl } from '@/lib/links'
import { GATE, levelColor, projectScore, scoreColor, SEVERITY } from '@/lib/visual'

/** Where each metric's drill-down leads in the issue explorer. */
const DRILL_LINK: Record<DrillMetric, string> = {
  gate: '/issues?new',
  critical: '/issues',
  vulns: '/issues?cat=vulnerability',
  // Replaced by the lowest covered project's report when there is one.
  coverage: '/projects',
  dup: '/issues?cat=code_smell',
  debt: '/issues?cat=code_smell',
}

export function OverviewPage() {
  const api = useApi()
  return api.overview ? <OverviewScreen load={api.overview} canDrill={!!api.drill} /> : <OverviewNotYet />
}

/** Against a real server: the Overview needs analysis history it does not serve yet. */
function OverviewNotYet() {
  return (
    <AppShell crumbs={[{ label: 'Overview', to: '/' }]}>
      <PageHeader title="Overview" summary="Needs analysis history: the next step (ADR-0005, phase 3)." />
      <div className="flex max-w-[640px] flex-col gap-2 rounded-xl bg-panel-2 px-6 py-5 edge">
        <span className="font-semibold">Trends, ratings and the quality-gate history come next.</span>
        <span className="text-[13px] text-fg-muted">
          The server stores every analysis already; this screen will be built from them rather than show sample numbers. Real data is on <Link to="/issues">Issues</Link> and{' '}
          <Link to="/rules">Rules</Link>.
        </span>
      </div>
    </AppShell>
  )
}

function OverviewScreen({ load, canDrill }: { load: NonNullable<SondaApi['overview']>; canDrill: boolean }) {
  const navigate = useNavigate()
  const [scope, setScope] = useState<Scope>('all')
  const [range, setRange] = useState<Range>('90d')
  const [drill, setDrill] = useState<DrillMetric | null>(null)
  const data = useAsync(() => load(scope, range), [load, scope, range])
  // Offer "My team" only where teams exist; remembered while a range reloads.
  const [teams, setTeams] = useState(false)
  if (data.state === 'ready' && data.data.teams !== teams) setTeams(data.data.teams)
  // Without drill-down data, a metric opens the issues it is about.
  const onDrill = (metric: DrillMetric) => (canDrill ? setDrill(metric) : navigate(DRILL_LINK[metric]))

  return (
    <AppShell crumbs={[{ label: 'Overview', to: '/' }]}>
      <PageHeader
        title="Overview"
        summary={
          data.state === 'ready' ? (
            <>
              {data.data.summary.projects} {data.data.summary.projects === 1 ? 'project' : 'projects'}
              {data.data.summary.components != null && ` · ${data.data.summary.components} components`} · last sounding{' '}
              <Mono className="text-xs text-fg">{data.data.summary.lastSounding}</Mono>
            </>
          ) : (
            ' '
          )
        }
      >
        <div className="flex flex-wrap items-center gap-2.5">
          {teams && (
            <Segmented
              label="Scope"
              value={scope}
              onChange={setScope}
              options={[
                { value: 'all', label: 'All projects' },
                { value: 'mine', label: 'My team' },
              ]}
            />
          )}
          <Segmented label="Time range" mono value={range} onChange={setRange} options={(['7d', '30d', '90d'] as const).map((r) => ({ value: r, label: r }))} />
        </div>
      </PageHeader>

      {data.state === 'loading' && <Loading />}
      {data.state === 'error' && <ErrorState message={data.error.message} retry={data.retry} />}
      {data.state === 'ready' && data.data.summary.projects === 0 && <Empty />}
      {data.state === 'ready' && data.data.summary.projects > 0 && (
        <Live data={data.data} range={range} scopeName={scope === 'all' ? 'all projects' : 'my team'} onDrill={onDrill} active={drill} />
      )}
      {drill && <Drawer metric={drill} scope={scope} onClose={() => setDrill(null)} />}
    </AppShell>
  )
}

function Loading() {
  return (
    <div aria-busy="true" className="flex flex-col gap-4">
      <MetricGrid label="Loading metrics" minCell={170}>
        {Array.from({ length: 6 }, (_, i) => (
          <div key={i} className="box-border flex h-[120px] flex-col gap-3 bg-panel p-[18px]">
            <div className="h-[9px] w-[55%] rounded-[3px] bg-hover" />
            <div className="h-6 w-2/5 rounded bg-hover" />
          </div>
        ))}
      </MetricGrid>
      <div className="flex items-center gap-2.5 text-[13px] text-fg-muted">
        <div className="h-[3px] w-40 overflow-hidden rounded-sm bg-hover">
          <div className="h-full w-[58%] bg-brand" />
        </div>
        Sounding projects…
      </div>
      <div className="h-[300px] rounded-xl bg-panel-2 edge" />
    </div>
  )
}

function Empty() {
  return (
    <div className="grid max-w-[920px] grid-cols-[repeat(auto-fit,minmax(320px,1fr))] overflow-hidden rounded-xl bg-panel-2 edge">
      <div className="flex flex-col gap-3 p-8">
        <span className="font-mono text-[10.5px] tracking-[.08em] text-brand uppercase">No soundings yet</span>
        <h2 className="m-0 text-2xl font-semibold tracking-[-0.03em]">Point Sonda at a repository to map what's beneath it.</h2>
        <p className="m-0 text-fg-muted">Runs locally or in CI and reports bugs, vulnerabilities, code smells, coverage and duplication.</p>
      </div>
      <pre className="m-0 overflow-auto bg-canvas p-8 font-mono text-[11.5px] leading-loose text-fg">
        <span className="text-fg-faint">$</span> cargo install --path .{'\n'}
        <span className="text-fg-faint">$</span> sonda scan . --new-code origin/main{'\n'}
        <span className="text-fg-faint">$</span> sonda scan . --format sarif -o sonda.sarif
      </pre>
    </div>
  )
}

function ErrorState({ message, retry }: { message: string; retry: () => void }) {
  return (
    <div role="alert" className="flex max-w-[720px] gap-3.5 rounded-xl bg-crit-soft px-5 py-[18px]" style={{ boxShadow: 'inset 0 0 0 1px color-mix(in oklch, var(--sd-crit) 35%, transparent)' }}>
      <span aria-hidden="true" className="grid size-6 flex-none place-items-center rounded-full bg-crit text-[13px] font-bold text-canvas">
        !
      </span>
      <div className="flex min-w-0 flex-col gap-2">
        <span className="text-[15px] font-semibold">Lost contact with sonda-api</span>
        <span className="text-[13px] text-fg-muted">{message}</span>
        <div>
          <button type="button" onClick={retry} className="h-8 cursor-pointer rounded-lg border-0 px-3.5 text-[13px] font-semibold" style={{ background: 'var(--sd-text)', color: 'var(--sd-bg)' }}>
            Retry
          </button>
        </div>
      </div>
    </div>
  )
}

function Live({
  data,
  range,
  scopeName,
  onDrill,
  active,
}: {
  data: Overview
  range: Range
  scopeName: string
  onDrill: (m: DrillMetric) => void
  active: DrillMetric | null
}) {
  // Each row pairs a wide card with a narrow one. Side by side when the
  // page area fits both (a container query, so the sidebar counts), else
  // stacked at full width: never a card next to an empty half.
  const twoUp = 'grid grid-cols-1 gap-5 @min-[1000px]:grid-cols-[minmax(0,2fr)_minmax(320px,1fr)]'
  return (
    <div className="@container flex flex-col gap-5">
      <div className={`${twoUp} items-stretch`}>
        <Focus data={data} scopeName={scopeName} onDrill={onDrill} />
        <Health data={data} rangeLong={`vs ${range.replace('d', '')} days ago`} onDrill={onDrill} />
      </div>
      <MetricGrid label="Key metrics">
        {data.kpis.map((k) => {
          const on = active === k.metric
          // The color says how the value stands; the delta, where it's heading.
          const tone = k.tone === 'neutral' ? 'var(--sd-muted)' : `var(--sd-${k.tone})`
          const steady = k.series.length < 2 || k.series[0] === k.series[k.series.length - 1]
          const trend = steady ? 'var(--sd-faint)' : k.improving ? 'var(--sd-ok)' : 'var(--sd-crit)'
          return (
            <button
              key={k.metric}
              type="button"
              onClick={() => onDrill(k.metric)}
              data-tone={k.tone}
              aria-label={`${k.label} ${k.value}${k.unit}, ${k.delta}. Show affected components`}
              className="relative flex min-w-0 cursor-pointer flex-col gap-1.5 overflow-hidden border-0 px-[18px] pt-4 pb-11 text-left hover:bg-hover"
              style={{ background: on ? 'var(--sd-hover)' : 'var(--sd-panel-2)' }}
            >
              <span className="flex w-full items-center justify-between gap-2">
                <span className="text-[13px] text-fg-muted">{k.label}</span>
                <Mono className="text-[10.5px]">
                  <span style={{ color: trend }}>{k.delta}</span>
                </Mono>
              </span>
              <span className="flex items-baseline gap-[5px]">
                <span className="font-mono text-[26px] leading-[1.1] font-light tracking-[-0.05em]">{k.value}</span>
                <span className="text-[13px] text-fg-faint">{k.unit}</span>
              </span>
              <span className="w-full overflow-hidden text-xs text-ellipsis whitespace-nowrap text-fg-faint">{k.sub}</span>
              <Sparkline
                series={k.series}
                color={on ? 'var(--sd-accent)' : tone}
                fill={on ? 'var(--sd-accent-soft)' : `color-mix(in oklch, ${tone} 9%, transparent)`}
                className="absolute right-0 bottom-0 left-0 block h-[34px] w-full"
              />
            </button>
          )
        })}
      </MetricGrid>
      <div className={twoUp}>
        <IssueFlow flow={data.flow} range={range} />
        <Severities data={data} onDrill={onDrill} />
      </div>
      <div className={twoUp}>
        <ProjectTable projects={data.projects} total={data.projectTotal} />
        <GateHistory history={data.gateHistory} />
      </div>
      <Recent data={data} />
    </div>
  )
}

function Focus({ data, scopeName, onDrill }: { data: Overview; scopeName: string; onDrill: (m: DrillMetric) => void }) {
  const navigate = useNavigate()
  const emphasis = { muted: 'var(--sd-muted)', strong: 'var(--sd-text)', faint: 'var(--sd-faint)' }
  return (
    <Card
      id="focus"
      padded={false}
      title="Where to focus"
      subtitle={`Ranked by gate impact, exposure and age · ${scopeName}`}
      aside={
        <Mono className="text-[10.5px] text-fg-faint">
          {data.focus.length} / {data.focusTotal}
        </Mono>
      }
    >
      <div className="flex flex-col gap-1.5 px-2.5 pb-2.5">
        {data.focus.length === 0 && <p className="m-0 px-2.5 py-4 text-[13px] text-fg-muted">Nothing needs attention: every gate passes and no blocker or critical issues were detected.</p>}
        {data.focus.map((f) => {
          const s = SEVERITY[f.severity]
          return (
            <button
              key={f.title}
              type="button"
              onClick={() => (f.link ? navigate(f.link) : onDrill(f.drill))}
              className="grid cursor-pointer grid-cols-[4px_minmax(0,1fr)_auto] items-stretch gap-3.5 rounded-[9px] border-0 bg-panel py-3.5 pr-3.5 pl-2.5 text-left edge hover:bg-hover hover:edge-strong"
            >
              <span aria-hidden="true" className="rounded-sm" style={{ background: s.color }} />
              <span className="flex min-w-0 flex-col gap-1">
                <span className="inline-flex items-center gap-1.5 font-mono text-[10px] tracking-[.04em] uppercase" style={{ color: s.color }}>
                  <span aria-hidden="true">{s.glyph}</span>
                  <span className="sr-only">{s.label}: </span>
                  {f.tag}
                </span>
                <span className="text-[15px] leading-[1.3] font-semibold tracking-[-0.01em]">{f.title}</span>
                <span className="text-[13px] text-fg-muted">{f.body}</span>
                <span className="mt-0.5 flex flex-wrap items-center gap-1.5 font-mono text-[10.5px] text-fg-faint">
                  {f.trail.map((t, i) => (
                    <span key={i} className="flex items-center gap-1.5">
                      {i > 0 && <span>{t.emphasis === 'faint' || f.trail[i - 1].emphasis === t.emphasis ? '·' : '›'}</span>}
                      <span style={{ color: emphasis[t.emphasis] }}>{t.text}</span>
                    </span>
                  ))}
                </span>
              </span>
              <span className="flex h-[30px] items-center gap-1.5 self-center rounded-[7px] bg-hover px-3 text-[12.5px] font-medium whitespace-nowrap">
                {f.cta}
                <ArrowRight size={13} strokeWidth={2} aria-hidden="true" />
              </span>
            </button>
          )
        })}
      </div>
      <div className="flex items-center justify-between px-5 pt-1 pb-3.5 text-[12.5px] text-fg-muted">
        <span>{data.focusTotal - data.focus.length} lower-priority items</span>
        <Link to="/issues" className="font-medium">
          Open issue explorer →
        </Link>
      </div>
    </Card>
  )
}

/** ", driven up by X, held back by Y", from the best and worst dimensions with data. */
function healthDrivers(dimensions: Overview['health']['dimensions']): string {
  const rated = dimensions.filter((d) => d.score != null).sort((a, b) => (b.score ?? 0) - (a.score ?? 0))
  if (rated.length < 2 || rated[0].score === rated[rated.length - 1].score) return ''
  return ` · driven up by ${rated[0].label.toLowerCase()}, held back by ${rated[rated.length - 1].label.toLowerCase()}`
}

function Health({ data, rangeLong, onDrill }: { data: Overview; rangeLong: string; onDrill: (m: DrillMetric) => void }) {
  return (
    <Card id="health" title="Code health" aside={data.health.delta && <span className="text-[12.5px] text-fg-muted">{rangeLong}</span>}>
      <div className="flex flex-col gap-2.5">
        <div className="flex items-baseline gap-2.5">
          <span className="font-mono text-[52px] leading-[.95] font-light tracking-[-0.06em]">{data.health.score}</span>
          {data.health.delta && <Mono className={`text-xs ${data.health.delta.startsWith('+') ? 'text-ok' : 'text-crit'}`}>{data.health.delta}</Mono>}
        </div>
        <HealthBar score={data.health.score} />
        <span className="text-[12.5px] text-fg-muted">Health index out of 100{healthDrivers(data.health.dimensions)}</span>
      </div>
      <div className="flex flex-col gap-0.5">
        {data.health.dimensions.map((d) => (
          <button
            key={d.label}
            type="button"
            onClick={() => onDrill(d.drill)}
            className="-mx-2 grid cursor-pointer grid-cols-[minmax(0,1fr)_auto_34px] items-center gap-3 rounded-lg border-0 bg-transparent p-2 text-left text-[13.5px] hover:bg-hover"
          >
            <span className="flex min-w-0 flex-col leading-[1.35]">
              <span>{d.label}</span>
              <span className="overflow-hidden text-xs text-ellipsis whitespace-nowrap text-fg-faint">{d.note}</span>
            </span>
            {d.level == null ? <span className="text-xs text-fg-faint">No data</span> : <PipMeter level={d.level} label={d.label} />}
            <span className="text-right font-mono text-xs" style={{ color: d.level == null ? 'var(--sd-faint)' : levelColor(d.level) }}>
              {d.score ?? '—'}
            </span>
          </button>
        ))}
      </div>
    </Card>
  )
}

function IssueFlow({ flow, range }: { flow: FlowBucket[]; range: Range }) {
  const [hover, setHover] = useState<number | null>(null)
  // `|| 1` keeps an empty or flat history (no issues yet) from dividing by zero.
  const maxBar = Math.max(...flow.map((d) => Math.max(d.introduced, d.resolved))) * 1.15 || 1
  const opens = flow.map((d) => d.open)
  const oMin = Math.min(...opens) * 0.985
  const oMax = Math.max(...opens) * 1.01
  const oRange = oMax - oMin || 1
  const openLine = flow.map((d, i) => `${(((i + 0.5) / flow.length) * 100).toFixed(2)},${(4 + (1 - (d.open - oMin) / oRange) * 34).toFixed(2)}`).join(' ')
  const gridMax = Math.round(maxBar * 0.62)
  const introduced = flow.reduce((a, d) => a + d.introduced, 0)
  const resolved = flow.reduce((a, d) => a + d.resolved, 0)
  const net = introduced - resolved
  const ticks = [0, Math.floor(flow.length / 3), Math.floor((flow.length * 2) / 3), flow.length - 1]
  const tip = hover != null ? flow[hover] : null
  const pct = hover != null ? (hover + 0.5) / flow.length : 0
  return (
    <Card
      id="trend"
      title="Issue flow"
      subtitle={`Introduced vs. resolved per ${range === '90d' ? 'week' : 'day'} · open backlog`}
      aside={
        <div className="flex flex-wrap gap-7">
          {[
            ['Introduced', formatNumber(introduced), 'var(--sd-text)'],
            ['Resolved', formatNumber(resolved), 'var(--sd-text)'],
            ['Net', `${net > 0 ? '+' : '−'}${formatNumber(Math.abs(net))}`, net > 0 ? 'var(--sd-crit)' : 'var(--sd-ok)'],
          ].map(([k, v, c]) => (
            <span key={k} className="flex flex-col items-end">
              <span className="text-xs text-fg-faint">{k}</span>
              <span className="font-mono text-base font-light tracking-[-0.03em]" style={{ color: c }}>
                {v}
              </span>
            </span>
          ))}
        </div>
      }
    >
      <div
        role="img"
        aria-label={`Issue flow: ${formatNumber(introduced)} introduced and ${formatNumber(resolved)} resolved; ${formatNumber(flow[flow.length - 1].open)} open now`}
        className="relative mt-1 h-[220px]"
        onMouseLeave={() => setHover(null)}
      >
        <div className="pointer-events-none absolute inset-[0_0_22px_38px] flex flex-col justify-between">
          {[gridMax, Math.round((gridMax * 2) / 3), Math.round(gridMax / 3), 0].map((g) => (
            <div key={g} className="relative border-t border-line">
              <span className="absolute -top-2 -left-[38px] font-mono text-[9.5px] text-fg-faint">{g}</span>
            </div>
          ))}
        </div>
        <div className="absolute inset-[0_0_22px_38px] flex items-end" style={{ gap: flow.length > 20 ? 2 : 8 }}>
          {flow.map((d, i) => (
            <div
              key={d.date}
              onMouseEnter={() => setHover(i)}
              className="flex h-full flex-1 items-end justify-center gap-[3px] rounded-md"
              style={{ background: hover === i ? 'var(--sd-hover)' : 'transparent' }}
            >
              <div className="max-w-2.5 flex-1 rounded-[3px_3px_1px_1px] bg-crit" style={{ height: `${((d.introduced / maxBar) * 62).toFixed(1)}%` }} />
              <div className="max-w-2.5 flex-1 rounded-[3px_3px_1px_1px] bg-brand" style={{ height: `${((d.resolved / maxBar) * 62).toFixed(1)}%` }} />
            </div>
          ))}
        </div>
        <svg viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true" className="pointer-events-none absolute top-0 bottom-[22px] left-[38px] h-[calc(100%-22px)] w-[calc(100%-38px)] overflow-visible">
          <polyline points={openLine} fill="none" stroke="var(--sd-text)" strokeWidth="1.5" strokeDasharray="1 4" strokeLinecap="round" vectorEffect="non-scaling-stroke" />
        </svg>
        <div className="absolute right-0 bottom-0 left-[38px] flex justify-between font-mono text-[9.5px] text-fg-faint">
          {ticks.map((i) => (
            <span key={i}>{shortDate(flow[i].date)}</span>
          ))}
        </div>
        {tip && (
          <div
            role="tooltip"
            className="pointer-events-none absolute top-0 z-2 flex min-w-[176px] flex-col gap-[5px] rounded-[10px] bg-panel px-3.5 py-3 text-[12.5px]"
            style={{
              left: `calc(38px + (100% - 38px) * ${pct.toFixed(3)})`,
              transform: `translateX(${pct > 0.7 ? 'calc(-100% - 12px)' : '12px'})`,
              boxShadow: 'var(--sd-shadow), inset 0 0 0 1px var(--sd-line-2)',
            }}
          >
            <span className="font-semibold">{range === '90d' ? `Week of ${shortDate(tip.date)}` : shortDate(tip.date)}</span>
            <TipRow label="Introduced" value={`+${tip.introduced}`} color="var(--sd-crit)" />
            <TipRow label="Resolved" value={`−${tip.resolved}`} color="var(--sd-accent)" />
            <span className="flex justify-between gap-4 border-t border-line pt-[5px]">
              <span className="text-fg-muted">Open</span>
              <Mono className="text-[11.5px]">{formatNumber(tip.open)}</Mono>
            </span>
          </div>
        )}
      </div>
      <div className="flex items-center gap-4 text-xs text-fg-muted">
        <Legend swatch={<span className="size-2 rounded-[2px] bg-crit" />}>Introduced</Legend>
        <Legend swatch={<span className="size-2 rounded-[2px] bg-brand" />}>Resolved</Legend>
        <Legend swatch={<span className="w-4 border-t-2 border-dotted" style={{ borderColor: 'var(--sd-text)' }} />}>Open backlog</Legend>
      </div>
    </Card>
  )
}

function TipRow({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <span className="flex justify-between gap-4">
      <span className="text-fg-muted">{label}</span>
      <Mono className="text-[11.5px]">
        <span style={{ color }}>{value}</span>
      </Mono>
    </span>
  )
}

function Legend({ swatch, children }: { swatch: ReactNode; children: string }) {
  return (
    <span className="flex items-center gap-1.5">
      {swatch}
      {children}
    </span>
  )
}

function Severities({ data, onDrill }: { data: Overview; onDrill: (m: DrillMetric) => void }) {
  const total = data.severities.reduce((a, s) => a + s.open, 0)
  const cells = waffleCells(data.severities)
  return (
    <Card id="sev" title="Open by severity" aside={<Mono className="text-[11.5px] text-fg-muted">{formatNumber(total)}</Mono>}>
      <div aria-hidden="true" className="grid grid-cols-[repeat(20,1fr)] gap-[3px]">
        {cells.map((s, i) => (
          <span key={i} className="aspect-square rounded-[2px]" style={{ background: SEVERITY[s].color }} />
        ))}
      </div>
      <div className="flex flex-col">
        {data.severities.map((s) => (
          <button
            key={s.severity}
            type="button"
            onClick={() => onDrill(s.severity === 'blocker' || s.severity === 'critical' ? 'critical' : 'debt')}
            className="-mx-2 grid cursor-pointer grid-cols-[16px_minmax(0,1fr)_auto_46px] items-center gap-2.5 rounded-lg border-0 bg-transparent px-2 py-[7px] text-left text-[13.5px] hover:bg-hover"
          >
            <SeverityGlyph severity={s.severity} className="text-center text-[11px]" />
            <span>
              {SEVERITY[s.severity].label} {s.newThisPeriod > 0 && <span className="text-xs text-fg-faint">+{s.newThisPeriod}</span>}
            </span>
            <Mono className="text-xs">{formatNumber(s.open)}</Mono>
            <Mono className="text-right text-[10.5px] text-fg-faint">{((s.open / total) * 100).toFixed(1)}%</Mono>
          </button>
        ))}
      </div>
      <span className="text-xs text-fg-faint">Each square ≈ 1% of open issues. Blockers always get one.</span>
    </Card>
  )
}

function ProjectTable({ projects, total }: { projects: ProjectHealth[]; total: number }) {
  // The first monorepo starts expanded, to show that components exist.
  const [expanded, setExpanded] = useState<Record<string, boolean>>(() => {
    const first = projects.find((p) => p.components?.length)
    return first ? { [first.name]: true } : {}
  })
  const th = 'border-y border-line px-2 py-2 text-left font-normal'
  const row = (p: ProjectHealth, child: boolean) => {
    const score = projectScore([p.reliability, p.security, p.maintainability], p.coverage)
    const first = p.trend[0]
    const last = p.trend[p.trend.length - 1]
    const open = !!expanded[p.name]
    const toggle = () => p.components && setExpanded((e) => ({ ...e, [p.name]: !e[p.name] }))
    return (
      <tr
        key={p.name}
        onClick={toggle}
        aria-expanded={p.components ? open : undefined}
        className={`${p.components ? 'cursor-pointer' : ''} hover:bg-hover`}
        style={{ background: child ? 'var(--sd-panel)' : undefined }}
      >
        <td className="border-b border-line px-5 py-[11px]">
          <span className="flex items-center gap-2.5" style={{ paddingLeft: child ? 20 : 0 }}>
            <span aria-hidden="true" className="w-2.5 text-[9px] text-fg-faint">
              {p.components ? (open ? '▾' : '▸') : ''}
            </span>
            <span className="flex min-w-0 flex-col leading-[1.3]">
              <span className="flex items-baseline gap-2">
                {child ? (
                  <span className="font-mono text-xs">{p.name}</span>
                ) : (
                  <Link to={`/projects/${encodeURIComponent(p.name)}`} onClick={(e) => e.stopPropagation()} className="text-sm font-semibold text-fg">
                    {p.name}
                  </Link>
                )}
                {!child && p.badge && <span className="rounded-[10px] bg-hover px-[7px] py-px text-[11px] text-fg-muted">{p.badge}</span>}
              </span>
              <span className="text-xs text-fg-faint">{p.sub}</span>
            </span>
          </span>
        </td>
        <td className="border-b border-line px-2 py-[11px]">
          <GateStatus state={p.gate} />
        </td>
        <td className="border-b border-line px-2 py-[11px] font-mono text-[13px]" style={{ color: scoreColor(score) }}>
          {score}
        </td>
        <td className="border-b border-line px-2 py-[11px]">
          <span className="flex gap-2.5">
            <PipMeter level={p.reliability} label="Reliability" width={3} />
            <PipMeter level={p.security} label="Security" width={3} />
            <PipMeter level={p.maintainability} label="Maintainability" width={3} />
          </span>
        </td>
        <td className="border-b border-line px-2 py-[11px]">
          {p.coverage == null ? <span className="text-xs text-fg-faint" title="No coverage uploaded">—</span> : <CoverageRing pct={p.coverage} />}
        </td>
        <td className="border-b border-line px-2 py-[11px] text-right font-mono text-xs" style={{ color: p.newIssues >= 5 ? 'var(--sd-crit)' : 'var(--sd-muted)' }}>
          {p.newIssues ? `+${p.newIssues}` : '—'}
        </td>
        <td className="border-b border-line py-[11px] pr-5 pl-4">
          <Sparkline
            series={p.trend}
            color={last > first ? 'var(--sd-crit)' : 'var(--sd-ok)'}
            className="block h-[22px] w-[88px]"
            label={`Open issues ${last > first ? 'rising' : 'falling'}: ${first} to ${last}`}
          />
        </td>
      </tr>
    )
  }
  return (
    <Card
      id="cmp"
      padded={false}
      title="Project health"
      subtitle="Lowest scores first · monorepos expand to components"
      aside={
        <Link to="/projects" className="text-[12.5px] font-medium">
          All {total} projects →
        </Link>
      }
    >
      <div className="relative overflow-x-auto">
        <table className="w-full min-w-[780px] border-collapse text-[13.5px]">
          <thead>
            <tr className="font-mono text-[9.5px] tracking-[.06em] text-fg-faint uppercase">
              <th scope="col" className={`${th} px-5`}>
                Project
              </th>
              <th scope="col" className={th}>
                Gate
              </th>
              <th scope="col" className={th}>
                Score
              </th>
              <th scope="col" className={th}>
                <abbr title="Reliability · Security · Maintainability" className="no-underline">
                  Rel · Sec · Mnt
                </abbr>
              </th>
              <th scope="col" className={th}>
                Coverage
              </th>
              <th scope="col" className={`${th} text-right`}>
                New
              </th>
              <th scope="col" className={`${th} pr-5 pl-4`}>
                30d
              </th>
            </tr>
          </thead>
          <tbody>
            {projects.map((p) => (
              <Fragment key={p.name}>
                {row(p, false)}
                {p.components && expanded[p.name] && p.components.map((c) => row(c, true))}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}

function GateHistory({ history }: { history: Overview['gateHistory'] }) {
  const worst = Math.max(...history.failing.map((f) => f.failures))
  return (
    <Card
      id="gate"
      title="Gate history"
      subtitle="Share of main-branch evaluations passing, per day"
      aside={
        <Mono className="text-[11.5px]">
          {history.rate == null ? '—' : `${history.rate}%`}{' '}
          {history.delta != null && <span className={history.delta < 0 ? 'text-crit' : 'text-ok'}>{history.delta < 0 ? `−${-history.delta}` : `+${history.delta}`}</span>}
        </Mono>
      }
    >
      <div className="grid grid-cols-10 gap-1">
        {history.days.map((d) => {
          if (d.passRate == null) {
            return <span key={d.date} title={`${shortDate(d.date)} · no analyses`} className="aspect-square rounded bg-pip-off/40" />
          }
          const bad = d.passRate < 80
          return (
            <span
              key={d.date}
              title={`${shortDate(d.date)} · ${d.passRate}% of evaluations passed`}
              className="grid aspect-square place-items-center rounded font-mono text-[8.5px]"
              style={{
                background: bad
                  ? `color-mix(in oklch, var(--sd-crit) ${Math.min(100, 30 + (80 - d.passRate) * 5)}%, transparent)`
                  : `color-mix(in oklch, var(--sd-accent) ${Math.min(90, 15 + (d.passRate - 78) * 6)}%, transparent)`,
              }}
            >
              {d.passRate}
            </span>
          )
        })}
      </div>
      <div className="flex justify-between font-mono text-[9.5px] text-fg-faint">
        <span>{shortDate(history.days[0].date)}</span>
        <span>{shortDate(history.days[history.days.length - 1].date)}</span>
      </div>
      <div className="flex flex-col gap-0.5 border-t border-line pt-3">
        <span className="mb-1 text-[12.5px] text-fg-muted">Most-failed conditions</span>
        {history.failing.length === 0 && <span className="text-[13px] text-fg-faint">None failed in this range.</span>}
        {history.failing.map((c) => (
          <div key={c.label} className="grid grid-cols-[minmax(0,1fr)_60px_28px] items-center gap-2.5 py-1 text-[13px]">
            <span className="overflow-hidden text-ellipsis whitespace-nowrap">{c.label}</span>
            <span className="h-1 rounded-sm bg-pip-off">
              <span className="block h-full rounded-sm bg-crit" style={{ width: `${((c.failures / worst) * 100).toFixed(0)}%` }} />
            </span>
            <Mono className="text-right text-[11px] text-fg-muted">{c.failures}</Mono>
          </div>
        ))}
      </div>
    </Card>
  )
}

function Recent({ data }: { data: Overview }) {
  return (
    <Card
      id="ra"
      padded={false}
      title={
        <span className="flex items-center gap-3">Recent analyses</span>
      }
      aside={
        <Link to="/analyses" className="text-[12.5px] font-medium">
          All analyses →
        </Link>
      }
    >
      <div className="relative overflow-x-auto">
        {data.recent.map((a) => {
          const g = GATE[a.state]
          const noteColor = a.state === 'failed' ? 'var(--sd-crit)' : a.state === 'partial' ? 'var(--sd-warn)' : a.state === 'running' ? 'var(--sd-info)' : 'var(--sd-muted)'
          return (
            <div
              key={a.sha}
              className="grid min-w-[840px] grid-cols-[22px_minmax(150px,1.2fr)_minmax(220px,2fr)_minmax(170px,1.4fr)_80px_50px] items-center gap-3.5 border-t border-line px-5 py-3 text-[13.5px] hover:bg-hover"
            >
              <span role="img" aria-label={g.label} className="grid size-5 place-items-center rounded-md text-[10px] font-bold" style={{ background: g.soft, color: g.color }}>
                {g.glyph}
              </span>
              <span className="flex min-w-0 flex-col leading-[1.3]">
                <Link to={`/analyses/${a.id}`} className="font-semibold text-fg">
                  {a.project}
                </Link>
                <Mono className="text-[10.5px] text-fg-faint">
                  {a.branch} · {a.sha}
                </Mono>
              </span>
              <span className="overflow-hidden text-ellipsis whitespace-nowrap text-fg-muted">{a.message ?? <span className="text-fg-faint">—</span>}</span>
              <span className="flex min-w-0 flex-col gap-[5px]">
                <span className="overflow-hidden text-[13px] text-ellipsis whitespace-nowrap" style={{ color: noteColor }}>
                  {a.note}
                </span>
                {a.progress != null && (
                  <span
                    role="progressbar"
                    aria-label={`${a.project} analysis progress`}
                    aria-valuenow={a.progress}
                    aria-valuemin={0}
                    aria-valuemax={100}
                    className="h-[3px] overflow-hidden rounded-sm bg-pip-off"
                  >
                    <span className="block h-full rounded-sm bg-info" style={{ width: `${a.progress}%` }} />
                  </span>
                )}
              </span>
              <Mono className="text-[11px] text-fg-muted">{a.duration ?? '—'}</Mono>
              <Mono className="text-right text-[11px] text-fg-faint">{a.ago}</Mono>
            </div>
          )
        })}
      </div>
    </Card>
  )
}

function Drawer({ metric, scope, onClose }: { metric: DrillMetric; scope: Scope; onClose: () => void }) {
  const api = useApi()
  const navigate = useNavigate()
  const drill = useAsync(() => (api.drill ? api.drill(metric, scope) : Promise.reject(new Error('not available'))), [api, metric, scope])
  const [open, setOpen] = useState(0)
  const d: Drill | null = drill.state === 'ready' ? drill.data : null
  const color = d ? `var(--sd-${d.tone})` : 'var(--sd-accent)'
  const max = d ? Math.max(...d.items.map((i) => i.value)) : 1
  // Coverage items are projects, lowest first: the button opens the first's
  // coverage report, and each file its coverage.
  const coverage = metric === 'coverage'
  const first = coverage ? d?.items[0] : undefined
  const cta = first ? { to: coverageUrl(first.component), label: `Open ${first.component}’s coverage report` } : { to: DRILL_LINK[metric], label: d?.cta }
  return (
    <DrillDrawer
      eyebrow={`Sounding · ${scope === 'all' ? 'all projects' : 'my team'}`}
      title={d?.title ?? 'Loading…'}
      subtitle={d?.sub}
      onClose={onClose}
      footer={
        d && (
          <>
            <button
              type="button"
              onClick={() => navigate(cta.to)}
              className="h-[38px] flex-1 cursor-pointer rounded-[9px] border-0 bg-brand px-4 text-left text-[13.5px] font-semibold text-brand-ink"
            >
              {cta.label} →
            </button>
            <button type="button" onClick={onClose} className="h-[38px] cursor-pointer rounded-[9px] border-0 bg-transparent px-4 text-[13.5px] font-medium edge-strong">
              Close
            </button>
          </>
        )
      }
    >
      {drill.state === 'loading' && <div aria-busy="true" className="m-2 h-40 rounded-[10px] bg-hover" />}
      {drill.state === 'error' && <p role="alert">Could not load: {drill.error.message}</p>}
      {d?.items.map((it, i) => {
        const expanded = open === i
        const share = d.invert ? (100 - it.value) / 100 : it.value / max
        return (
          <div key={it.component} className="mb-0.5 flex flex-col rounded-[10px]" style={{ background: expanded ? 'var(--sd-panel-2)' : 'transparent' }}>
            <button
              type="button"
              aria-expanded={expanded}
              onClick={() => setOpen(expanded ? -1 : i)}
              className="grid cursor-pointer grid-cols-[minmax(0,1fr)_90px_52px] items-center gap-3 rounded-[10px] border-0 bg-transparent px-3.5 py-3 text-left hover:bg-hover"
            >
              <span className="flex min-w-0 flex-col leading-[1.35]">
                <Mono className="text-xs">{it.component}</Mono>
                <span className="text-[12.5px] text-fg-faint">
                  {it.project}
                  {it.owner && ` · ${it.owner}`}
                </span>
              </span>
              <span className="h-1 overflow-hidden rounded-sm bg-pip-off">
                <span className="block h-full rounded-sm" style={{ width: `${Math.max(4, share * 100).toFixed(0)}%`, background: color }} />
              </span>
              <Mono className="text-right text-[12.5px]">
                {it.value}
                {d.unit}
              </Mono>
            </button>
            {expanded && (
              <div className="flex flex-col gap-1.5 px-3.5 pb-3.5">
                {it.files.length === 0 && <span className="px-1 text-[12.5px] text-fg-faint">No file-level data for this metric.</span>}
                {it.files.map((f) => (
                  <button
                    key={f.dir + f.base}
                    type="button"
                    title={coverage ? 'Open this file’s coverage' : 'Open this file’s issues'}
                    onClick={() => navigate(coverage ? fileCoverageUrl(it.component, f.dir + f.base) : `/issues?file=${encodeURIComponent(f.dir + f.base)}`)}
                    className="flex cursor-pointer flex-col gap-[5px] rounded-lg border-0 bg-canvas px-3 py-2.5 text-left edge hover:edge-strong"
                  >
                    <span className="flex justify-between gap-2 font-mono text-[11px]">
                      <span className="overflow-hidden text-ellipsis whitespace-nowrap">
                        <span className="text-fg-faint">{f.dir}</span>
                        {f.base}
                      </span>
                      <span className="text-fg-muted">{f.value}</span>
                    </span>
                    {f.issue && (
                      <span className="flex items-baseline gap-2 text-[13px]">
                        <SeverityGlyph severity={f.issue.severity} />
                        <span className="min-w-0 flex-1">{f.issue.title}</span>
                        <Mono className="text-[10px] text-fg-faint">L{f.issue.line}</Mono>
                      </span>
                    )}
                  </button>
                ))}
              </div>
            )}
          </div>
        )
      })}
    </DrillDrawer>
  )
}
