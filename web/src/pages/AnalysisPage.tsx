import { useState } from 'react'
import { Link, useParams } from 'react-router'
import { useApi, useAsync } from '@/api/hooks'
import type { AnalysisChanges, AnalysisDetail, MeasureSet, Severity } from '@/api/types'
import { AppShell } from '@/components/shell/AppShell'
import { Segmented } from '@/components/sonda/controls'
import { GateConditions } from '@/components/sonda/gate'
import { Card, MetricGrid, Mono } from '@/components/sonda/layout'
import { GateStatus, SeverityGlyph } from '@/components/sonda/status'
import { formatDebt, formatNumber } from '@/lib/format'
import { CATEGORY_LABEL, SEVERITY, SEVERITY_ORDER, coverageColor, languageLabel } from '@/lib/visual'

export function AnalysisPage() {
  const api = useApi()
  const { id = '' } = useParams()
  const detail = useAsync(() => api.analysis(Number(id)), [api, id])
  const project = detail.state === 'ready' ? detail.data.project : null
  return (
    <AppShell
      crumbs={[
        { label: 'Analyses', to: '/analyses' },
        ...(project ? [{ label: project, to: `/projects/${encodeURIComponent(project)}` }] : []),
        { label: detail.state === 'ready' ? detail.data.sha.slice(0, 9) : `#${id}`, to: `/analyses/${id}` },
      ]}
    >
      {detail.state === 'loading' && <div aria-busy="true" className="h-[600px] rounded-xl bg-panel-2 edge" />}
      {detail.state === 'error' && (
        <div role="alert" className="flex flex-col items-start gap-2 rounded-xl bg-panel-2 px-5 py-8 edge">
          <span className="font-semibold">Could not load analysis #{id}</span>
          <span className="text-[13px] text-fg-muted">{detail.error.message}</span>
          <Link to="/analyses" className="text-[13px]">
            All analyses →
          </Link>
        </div>
      )}
      {detail.state === 'ready' && <Analysis a={detail.data} />}
    </AppShell>
  )
}

/** "2 critical · 5 major". */
function severitySummary(c: AnalysisChanges): string {
  return SEVERITY_ORDER.filter((s) => c.bySeverity[s])
    .slice(0, 2)
    .map((s) => `${c.bySeverity[s]} ${SEVERITY[s].label.toLowerCase()}`)
    .join(' · ')
}

function Analysis({ a }: { a: AnalysisDetail }) {
  const skipped = a.warnings.filter((w) => w.includes(': skipped')).length
  const projectUrl = `/projects/${encodeURIComponent(a.project)}${a.branch === a.mainBranch ? '' : `?branch=${encodeURIComponent(a.branch)}`}`
  const tiles: { label: string; value: string; sub: string; color?: string; href?: string }[] = [
    { label: 'Files analyzed', value: formatNumber(a.files), sub: skipped ? `${skipped} skipped` : a.languages.map((l) => languageLabel(l.id)).join(', ') },
    a.baseline
      ? { label: 'Baseline', value: formatNumber(a.introduced.total), sub: 'issues found by the first analysis', href: '#introduced' }
      : {
          label: 'New issues',
          value: a.introduced.total ? `+${formatNumber(a.introduced.total)}` : '0',
          sub: severitySummary(a.introduced) || 'since the previous analysis',
          color: a.introduced.total ? 'var(--sd-crit)' : undefined,
          href: '#introduced',
        },
    { label: 'Resolved', value: formatNumber(a.fixed.total), sub: 'since the previous analysis', color: a.fixed.total ? 'var(--sd-ok)' : undefined, href: '#fixed' },
    { label: 'Components', value: formatNumber(a.components), sub: 'top-level directories', href: projectUrl },
    {
      label: 'Warnings',
      value: formatNumber(a.warnings.length),
      sub: a.warnings.length ? 'results may be partial' : 'complete results',
      color: a.warnings.length ? 'var(--sd-warn)' : undefined,
      href: a.warnings.length ? '#warnings' : undefined,
    },
  ]
  const at = new Date(a.analyzedAt)
  return (
    <>
      <div className="flex flex-col gap-2">
        <span className="micro-label">Analysis · {a.project}</span>
        <h1 className="m-0 font-mono text-[26px] leading-[1.15] font-semibold tracking-[-0.02em]">{a.sha.slice(0, 12)}</h1>
        {a.message && <p className="m-0 text-[15px] text-fg">{a.message}</p>}
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 text-[13.5px] text-fg-muted">
          <Link to={projectUrl} className="font-mono text-[12.5px]">
            {a.branch}
          </Link>
          <time dateTime={a.analyzedAt}>
            {at.toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'UTC' })} UTC
          </time>
          <span>sonda {a.toolVersion}</span>
          {a.duration && <span>scanned in {a.duration}</span>}
          {a.newCodeReference && <span>new code since {a.newCodeReference}</span>}
          <span className="ml-auto flex gap-3 text-[13px]">
            {a.previous ? <Link to={`/analyses/${a.previous.id}`}>← {a.previous.sha.slice(0, 7)}</Link> : <span className="text-fg-faint">first on {a.branch}</span>}
            {a.next ? <Link to={`/analyses/${a.next.id}`}>{a.next.sha.slice(0, 7)} →</Link> : <span className="text-fg-faint">latest</span>}
          </span>
        </div>
      </div>

      <MetricGrid label="Summary" minCell={170}>
        {tiles.map((t) => (
          <div key={t.label} className="flex flex-col gap-1 bg-panel-2 px-4 py-3">
            <span className="text-[12.5px] text-fg-muted">{t.label}</span>
            <span className="font-mono text-[22px] leading-tight" style={{ color: t.color }}>
              {t.href ? (
                t.href.startsWith('#') ? (
                  <a href={t.href} style={{ color: t.color ?? 'var(--sd-text)' }}>
                    {t.value}
                  </a>
                ) : (
                  <Link to={t.href} style={{ color: t.color ?? 'var(--sd-text)' }}>
                    {t.value}
                  </Link>
                )
              ) : (
                t.value
              )}
            </span>
            <span className="text-xs text-fg-faint">{t.sub}</span>
          </div>
        ))}
      </MetricGrid>

      <div className="grid grid-cols-1 gap-5 min-[1000px]:grid-cols-[minmax(320px,1fr)_minmax(0,1.4fr)]">
        <Card
          id="result"
          title={<GateStatus state={a.gate.state} className="text-base" />}
          subtitle={`${a.gate.conditions.filter((c) => c.status === 'error').length} of ${a.gate.conditions.length} conditions failing`}
        >
          <GateConditions conditions={a.gate.conditions} />
        </Card>
        <Measures a={a} />
      </div>

      {a.warnings.length > 0 && (
        <Card id="warnings" title="Warnings" subtitle="What the analysis couldn't fully cover; these files' results are missing or partial">
          <ul className="m-0 flex list-none flex-col p-0">
            {a.warnings.map((w) => {
              const [file, ...rest] = w.split(': ')
              return (
                <li key={w} className="flex flex-col gap-0.5 border-t border-line py-2 first:border-t-0">
                  <Mono className="text-[12px] text-fg">{file}</Mono>
                  <span className="text-[13px] text-warn">{rest.join(': ') || w}</span>
                </li>
              )
            })}
          </ul>
        </Card>
      )}

      <ChangeList
        id="introduced"
        title={a.baseline ? 'Baseline issues' : 'Introduced'}
        subtitle={a.baseline ? 'Everything the first analysis of this branch found' : 'First seen in this analysis'}
        changes={a.introduced}
        a={a}
        empty="No new issues."
      />
      {!a.baseline && <ChangeList id="fixed" title="Resolved" subtitle="No longer found by this analysis" changes={a.fixed} a={a} empty="Nothing was resolved." />}
    </>
  )
}

function Measures({ a }: { a: AnalysisDetail }) {
  const [scope, setScope] = useState<'overall' | 'newCode'>('overall')
  const m: MeasureSet = a.measures[scope]
  const count = (v: number | null) => (v == null ? '—' : formatNumber(v))
  const pct = (v: number | null) => (v == null ? '—' : `${v.toFixed(1)}%`)
  const tiles = [
    { label: 'Bugs', value: count(m.bugs) },
    { label: 'Vulnerabilities', value: count(m.vulnerabilities) },
    { label: 'Code smells', value: count(m.codeSmells) },
    { label: 'Coverage', value: pct(m.coverage), color: m.coverage == null ? undefined : coverageColor(m.coverage) },
    { label: 'Duplication', value: pct(m.duplication) },
    { label: 'Debt', value: m.debtMinutes == null ? '—' : formatDebt(m.debtMinutes) },
  ]
  return (
    <Card
      id="measures"
      title="Measures"
      subtitle={scope === 'newCode' ? `${formatNumber(m.lines ?? 0)} new lines` : `${formatNumber(m.lines ?? 0)} lines of code`}
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
      <MetricGrid label="Measures" minCell={180}>
        {tiles.map((t) => (
          <div key={t.label} className="flex flex-col gap-1 bg-panel-2 px-4 py-3">
            <span className="text-[12.5px] text-fg-muted">{t.label}</span>
            <span className="font-mono text-[20px] leading-tight" style={{ color: t.color }}>
              {t.value}
            </span>
          </div>
        ))}
      </MetricGrid>
    </Card>
  )
}

function ChangeList({
  id,
  title,
  subtitle,
  changes,
  a,
  empty,
}: {
  id: string
  title: string
  subtitle: string
  changes: AnalysisChanges
  a: AnalysisDetail
  empty: string
}) {
  const fileIssues = (path: string) =>
    `/issues?project=${encodeURIComponent(a.project)}&branch=${encodeURIComponent(a.branch)}&file=${encodeURIComponent(path)}`
  return (
    <Card
      id={id}
      padded={false}
      title={
        <span className="flex items-baseline gap-2">
          {title} <Mono className="text-[12px] font-normal text-fg-faint">{formatNumber(changes.total)}</Mono>
        </span>
      }
      subtitle={changes.total > changes.items.length ? `${subtitle} · the ${changes.items.length} most severe shown` : subtitle}
    >
      {changes.items.length === 0 ? (
        <p className="m-0 px-5 pb-4 text-[13px] text-fg-faint">{empty}</p>
      ) : (
        <ul className="m-0 list-none p-0">
          {changes.items.map((i) => (
            <li key={i.id} className="grid grid-cols-[16px_minmax(0,1fr)_auto] items-baseline gap-3 border-t border-line px-5 py-2.5 text-[13.5px]">
              <SeverityGlyph severity={i.severity as Severity} />
              <span className="flex min-w-0 flex-col gap-0.5">
                <span>{i.message}</span>
                <span className="text-xs text-fg-faint">
                  <Link to={fileIssues(i.path)} className="font-mono text-[11.5px]">
                    {i.path}:{i.line}
                  </Link>{' '}
                  · {CATEGORY_LABEL[i.category]} ·{' '}
                  <Link to={`/rules#${encodeURIComponent(i.rule)}`} className="font-mono text-[11px] text-fg-faint">
                    {i.rule}
                  </Link>
                </span>
              </span>
              <span className="text-xs" style={{ color: SEVERITY[i.severity].color }}>
                {SEVERITY[i.severity].label}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}
