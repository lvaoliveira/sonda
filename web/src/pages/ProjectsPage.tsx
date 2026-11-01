import { Search } from 'lucide-react'
import { useMemo } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router'
import { useApi, useAsync } from '@/api/hooks'
import type { GateState, ProjectList, ProjectRow } from '@/api/types'
import { AppShell } from '@/components/shell/AppShell'
import { Chip, Segmented } from '@/components/sonda/controls'
import { Mono, PageHeader } from '@/components/sonda/layout'
import { CoverageRing, PipMeter } from '@/components/sonda/meters'
import { GateStatus } from '@/components/sonda/status'
import { compactCount, formatAge, formatNumber } from '@/lib/format'
import { languageLabel, scoreColor } from '@/lib/visual'

export function ProjectsPage() {
  const api = useApi()
  const list = useAsync(() => api.projects(), [api])
  return (
    <AppShell crumbs={[{ label: 'Projects', to: '/projects' }]}>
      {list.state === 'loading' && <div aria-busy="true" className="h-[600px] rounded-xl bg-panel-2 edge" />}
      {list.state === 'error' && <p role="alert">Could not load projects: {list.error.message}</p>}
      {list.state === 'ready' && <Projects list={list.data} />}
    </AppShell>
  )
}

type GateFilter = 'all' | 'failed' | 'passed'
type Sort = 'score' | 'issues' | 'coverage' | 'recent' | 'name'

const SORTS: { value: Sort; label: string; compare: (a: ProjectRow, b: ProjectRow) => number }[] = [
  { value: 'score', label: 'Lowest score', compare: (a, b) => a.score - b.score },
  { value: 'issues', label: 'Most issues', compare: (a, b) => b.issues - a.issues },
  // Projects without coverage go last: there is nothing to improve yet.
  { value: 'coverage', label: 'Lowest coverage', compare: (a, b) => (a.coverage ?? 101) - (b.coverage ?? 101) },
  { value: 'recent', label: 'Recently analyzed', compare: (a, b) => b.analyzedAt.localeCompare(a.analyzedAt) },
  { value: 'name', label: 'Name', compare: () => 0 },
]

/** Passing includes partial: the gate didn't fail, some condition had no data. */
function matchesGate(gate: GateState, filter: GateFilter): boolean {
  return filter === 'all' || (filter === 'failed' ? gate === 'failed' : gate !== 'failed')
}

function Projects({ list }: { list: ProjectList }) {
  const [params, setParams] = useSearchParams()
  const q = params.get('q') ?? ''
  const gate = (params.get('gate') ?? 'all') as GateFilter
  const lang = params.get('lang') ?? ''
  const sort = (SORTS.find((s) => s.value === params.get('sort'))?.value ?? 'score') as Sort
  const set = (key: string, value: string, fallback: string) =>
    setParams(
      (p) => {
        if (value === fallback) p.delete(key)
        else p.set(key, value)
        return p
      },
      { replace: true },
    )

  const searched = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return list.projects.filter((p) => (!needle || p.key.toLowerCase().includes(needle)) && (!lang || p.languages.includes(lang)))
  }, [list.projects, q, lang])
  const rows = useMemo(() => {
    const compare = SORTS.find((s) => s.value === sort)!.compare
    return searched.filter((p) => matchesGate(p.gate, gate)).sort((a, b) => compare(a, b) || a.key.localeCompare(b.key))
  }, [searched, gate, sort])
  const count = (g: GateFilter) => searched.filter((p) => matchesGate(p.gate, g)).length
  const ncloc = list.projects.reduce((sum, p) => sum + p.ncloc, 0)
  const blocking = list.projects.filter((p) => p.gate === 'failed').length

  return (
    <>
      <PageHeader
        title="Projects"
        summary={
          <>
            {formatNumber(list.projects.length)} {list.projects.length === 1 ? 'project' : 'projects'} · {compactCount(ncloc)} lines of code ·{' '}
            {blocking} blocking on their main branch
          </>
        }
      >
        <label className="flex h-9 w-[300px] max-w-full items-center gap-2 rounded-lg bg-canvas px-3 edge">
          <Search size={14} strokeWidth={2} aria-hidden="true" className="text-fg-faint" />
          <input
            aria-label="Search projects"
            placeholder="Search by name"
            value={q}
            onChange={(e) => set('q', e.target.value, '')}
            className="min-w-0 flex-1 border-0 bg-transparent text-[13.5px] outline-none placeholder:text-fg-faint"
          />
        </label>
      </PageHeader>

      <div className="flex flex-wrap items-center gap-4">
        <Segmented
          label="Gate"
          value={gate}
          onChange={(v) => set('gate', v, 'all')}
          options={[
            { value: 'all', label: `All ${count('all')}` },
            { value: 'failed', label: `Blocking ${count('failed')}` },
            { value: 'passed', label: `Passing ${count('passed')}` },
          ]}
        />
        {list.languages.length > 1 && (
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="mr-1 micro-label">Language</span>
            {list.languages.map((l) => (
              <Chip key={l} on={lang === l} onClick={() => set('lang', lang === l ? '' : l, '')}>
                {languageLabel(l)}
              </Chip>
            ))}
          </div>
        )}
        <label className="ml-auto flex items-center gap-2 text-[13px] text-fg-muted">
          Sort
          <select
            value={sort}
            onChange={(e) => set('sort', e.target.value, 'score')}
            className="h-8 rounded-md bg-canvas px-2 text-[13px] text-fg edge"
          >
            {SORTS.map((s) => (
              <option key={s.value} value={s.value}>
                {s.label}
              </option>
            ))}
          </select>
        </label>
      </div>

      {rows.length === 0 ? (
        <div className="flex flex-col items-start gap-2 rounded-xl bg-panel-2 px-5 py-8 edge">
          <span className="font-semibold">{list.projects.length === 0 ? 'No projects yet' : 'No projects match these filters'}</span>
          <span className="text-[13px] text-fg-muted">
            {list.projects.length === 0 ? (
              <>
                Upload an analysis with <Mono className="text-xs">sonda upload</Mono> and it appears here.
              </>
            ) : (
              'Try another name, or clear the gate and language filters.'
            )}
          </span>
          {list.projects.length > 0 && (
            <button type="button" onClick={() => setParams({}, { replace: true })} className="cursor-pointer border-0 bg-transparent p-0 text-[13px] text-accent">
              Clear filters
            </button>
          )}
        </div>
      ) : (
        <ProjectTable rows={rows} total={list.projects.length} />
      )}
    </>
  )
}

function ProjectTable({ rows, total }: { rows: ProjectRow[]; total: number }) {
  const navigate = useNavigate()
  const th = 'border-b border-line px-2 py-2 text-left font-normal'
  const td = 'border-b border-line px-2 py-[11px]'
  return (
    <div className="overflow-hidden rounded-xl bg-panel-2 edge">
      <div className="relative overflow-x-auto">
        <table className="w-full min-w-[900px] border-collapse text-[13.5px]">
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
                Dup.
              </th>
              <th scope="col" className={`${th} text-right`}>
                Issues
              </th>
              <th scope="col" className={`${th} text-right`}>
                Size
              </th>
              <th scope="col" className={`${th} pr-5 text-right`}>
                Analyzed
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map((p) => (
              <tr key={p.key} onClick={() => navigate(`/projects/${encodeURIComponent(p.key)}`)} className="cursor-pointer hover:bg-hover">
                <td className={`${td} px-5`}>
                  <span className="flex min-w-0 flex-col leading-[1.3]">
                    <Link to={`/projects/${encodeURIComponent(p.key)}`} onClick={(e) => e.stopPropagation()} className="text-sm font-semibold text-fg">
                      {p.key}
                    </Link>
                    <span className="text-xs text-fg-faint">
                      <Mono className="text-[11px]">{p.mainBranch}</Mono>
                      {p.languages.length > 0 && ` · ${p.languages.map(languageLabel).join(', ')}`}
                    </span>
                  </span>
                </td>
                <td className={td}>
                  <GateStatus state={p.gate} />
                </td>
                <td className={`${td} font-mono text-[13px]`} style={{ color: scoreColor(p.score) }}>
                  {p.score}
                </td>
                <td className={td}>
                  <span className="flex gap-2.5">
                    <PipMeter level={p.reliability} label="Reliability" width={3} />
                    <PipMeter level={p.security} label="Security" width={3} />
                    <PipMeter level={p.maintainability} label="Maintainability" width={3} />
                  </span>
                </td>
                <td className={td}>
                  {p.coverage == null ? <span className="text-xs text-fg-faint" title="No coverage uploaded">—</span> : <CoverageRing pct={p.coverage} />}
                </td>
                <td className={`${td} text-right font-mono text-xs text-fg-muted`}>{p.duplication == null ? '—' : `${p.duplication.toFixed(1)}%`}</td>
                <td className={`${td} text-right font-mono text-xs`}>
                  <Link to={`/issues?project=${encodeURIComponent(p.key)}`} onClick={(e) => e.stopPropagation()} className="text-fg-muted">
                    {formatNumber(p.issues)}
                  </Link>
                </td>
                <td className={`${td} text-right font-mono text-xs text-fg-muted`}>{compactCount(p.ncloc)}</td>
                <td className={`${td} pr-5 text-right font-mono text-xs text-fg-faint`}>
                  <time dateTime={p.analyzedAt} title={new Date(p.analyzedAt).toUTCString()}>
                    {formatAge(p.analyzedAt)}
                  </time>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="px-5 py-2.5 text-[12.5px] text-fg-faint">
        Showing {rows.length} of {formatNumber(total)}
      </div>
    </div>
  )
}
