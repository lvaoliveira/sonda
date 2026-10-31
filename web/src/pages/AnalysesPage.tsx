import { Link, useSearchParams } from 'react-router'
import { useApi, useAsync } from '@/api/hooks'
import type { AnalysisPage, AnalysisQuery } from '@/api/types'
import { AppShell } from '@/components/shell/AppShell'
import { Button, Segmented } from '@/components/sonda/controls'
import { Mono, PageHeader } from '@/components/sonda/layout'
import { formatAge, formatNumber } from '@/lib/format'
import { GATE } from '@/lib/visual'

const PAGE_SIZE = 50

type GateFilter = 'all' | 'failed' | 'passed'

export function AnalysesPage() {
  const api = useApi()
  const [params, setParams] = useSearchParams()
  const project = params.get('project') ?? ''
  const gate = (['failed', 'passed'].includes(params.get('gate') ?? '') ? params.get('gate') : 'all') as GateFilter
  const offset = Math.max(0, Number(params.get('offset')) || 0)
  const query: AnalysisQuery = { project: project || undefined, gate: gate === 'all' ? undefined : gate, offset, limit: PAGE_SIZE }
  const page = useAsync(() => api.analyses(query), [api, project, gate, offset])
  const projects = useAsync(() => api.projects(), [api])
  const set = (changes: Record<string, string | null>) =>
    setParams(
      (p) => {
        for (const [k, v] of Object.entries(changes)) {
          if (v == null || v === '') p.delete(k)
          else p.set(k, v)
        }
        return p
      },
      { replace: true },
    )

  return (
    <AppShell crumbs={[{ label: 'Analyses', to: '/analyses' }]}>
      <PageHeader
        title="Analyses"
        summary={
          page.state === 'ready' ? `${formatNumber(page.data.total)} ${page.data.total === 1 ? 'analysis' : 'analyses'} · newest first · every branch` : 'Loading…'
        }
      />
      <div className="flex flex-wrap items-center gap-4">
        <Segmented
          label="Gate"
          value={gate}
          onChange={(v) => set({ gate: v === 'all' ? null : v, offset: null })}
          options={[
            { value: 'all', label: 'All' },
            { value: 'failed', label: 'Blocking' },
            { value: 'passed', label: 'Passing' },
          ]}
        />
        <label className="flex items-center gap-2 text-[13px] text-fg-muted">
          Project
          <select value={project} onChange={(e) => set({ project: e.target.value, offset: null })} className="h-8 rounded-md bg-canvas px-2 text-[13px] text-fg edge">
            <option value="">All projects</option>
            {projects.state === 'ready' &&
              projects.data.projects.map((p) => (
                <option key={p.key} value={p.key}>
                  {p.key}
                </option>
              ))}
          </select>
        </label>
      </div>
      {page.state === 'loading' && <div aria-busy="true" className="h-[480px] rounded-xl bg-panel-2 edge" />}
      {page.state === 'error' && <p role="alert">Could not load analyses: {page.error.message}</p>}
      {page.state === 'ready' && <AnalysisList page={page.data} onOffset={(o) => set({ offset: o ? String(o) : null })} />}
    </AppShell>
  )
}

function AnalysisList({ page, onOffset }: { page: AnalysisPage; onOffset: (offset: number) => void }) {
  if (page.items.length === 0) {
    return (
      <div className="flex flex-col gap-2 rounded-xl bg-panel-2 px-5 py-8 edge">
        <span className="font-semibold">No analyses match</span>
        <span className="text-[13px] text-fg-muted">
          Analyses appear here when <Mono className="text-xs">sonda upload</Mono> sends a report.
        </span>
      </div>
    )
  }
  const end = page.offset + page.items.length
  return (
    <div className="overflow-hidden rounded-xl bg-panel-2 edge">
      <ol aria-label="Analyses" className="m-0 list-none overflow-x-auto p-0">
        {page.items.map((a) => {
          const g = GATE[a.gate]
          const note =
            a.failing.length > 0
              ? `Gate failed: ${a.failing[0]}${a.failing.length > 1 ? ` (+${a.failing.length - 1})` : ''}`
              : a.newIssues
                ? `${a.newIssues} new ${a.newIssues === 1 ? 'issue' : 'issues'}`
                : 'No new issues'
          return (
            <li
              key={a.id}
              className="grid min-w-[760px] grid-cols-[22px_minmax(180px,1.3fr)_minmax(220px,2fr)_90px_90px_60px] items-center gap-3.5 border-b border-line px-5 py-3 text-[13.5px] last:border-b-0 hover:bg-hover"
            >
              <span role="img" aria-label={g.label} className="grid size-5 place-items-center rounded-md text-[10px] font-bold" style={{ background: g.soft, color: g.color }}>
                {g.glyph}
              </span>
              <span className="flex min-w-0 flex-col leading-[1.3]">
                <Link to={`/analyses/${a.id}`} className="font-semibold text-fg">
                  {a.project}
                </Link>
                <Mono className="text-[10.5px] text-fg-faint">
                  {a.branch} · {a.sha.slice(0, 7)}
                </Mono>
                {a.message && <span className="overflow-hidden text-xs text-ellipsis whitespace-nowrap text-fg-muted">{a.message}</span>}
              </span>
              <span className="overflow-hidden text-ellipsis whitespace-nowrap" style={{ color: a.failing.length ? 'var(--sd-crit)' : 'var(--sd-muted)' }}>
                {note}
              </span>
              <Mono className="text-right text-xs text-fg-muted">{a.issues == null ? '—' : `${formatNumber(a.issues)} issues`}</Mono>
              <span className="text-right text-xs" style={{ color: a.warnings ? 'var(--sd-warn)' : 'var(--sd-faint)' }}>
                {a.warnings ? `${a.warnings} ${a.warnings === 1 ? 'warning' : 'warnings'}` : '—'}
              </span>
              <Mono className="text-right text-xs text-fg-faint">
                <time dateTime={a.analyzedAt} title={new Date(a.analyzedAt).toUTCString()}>
                  {formatAge(a.analyzedAt)}
                </time>
                {a.duration && <span className="block" title="How long the scan took">{a.duration}</span>}
              </Mono>
            </li>
          )
        })}
      </ol>
      <div className="flex items-center justify-between gap-3 border-t border-line px-5 py-2.5 text-[12.5px] text-fg-faint">
        <span>
          {page.offset + 1}–{end} of {formatNumber(page.total)}
        </span>
        <span className="flex gap-2">
          <Button disabled={page.offset === 0} onClick={() => onOffset(Math.max(0, page.offset - page.limit))}>
            Previous
          </Button>
          <Button disabled={end >= page.total} onClick={() => onOffset(end)}>
            Next
          </Button>
        </span>
      </div>
    </div>
  )
}
