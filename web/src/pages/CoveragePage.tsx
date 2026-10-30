import { useMemo, useRef, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router'
import { useApi, useAsync } from '@/api/hooks'
import type { CoverageFile, CoverageList, FileCoverage } from '@/api/types'
import { AppShell } from '@/components/shell/AppShell'
import { Button, Chip, Segmented } from '@/components/sonda/controls'
import { Card, MetricGrid, Mono, PageHeader } from '@/components/sonda/layout'
import { formatAge, formatNumber } from '@/lib/format'
import { coverageUrl, fileCoverageUrl, projectUrl } from '@/lib/links'
import { ROLE_COLOR, coverageColor } from '@/lib/visual'

/** Rows rendered at once; searching narrows the rest. */
const SHOWN = 500

type Sort = 'uncovered' | 'lowest' | 'name'
const SORTS: { value: Sort; label: string }[] = [
  { value: 'uncovered', label: 'Most uncovered' },
  { value: 'lowest', label: 'Lowest coverage' },
  { value: 'name', label: 'Name' },
]

/** A directory or a file in the current directory, with its subtree's totals. */
interface Entry {
  name: string
  /** The directory (for `dir`) or the file's path. */
  path: string
  dir: boolean
  covered: number
  uncovered: number
  /** Files the coverage reports listed, and didn't. */
  files: number
  withoutData: number
}

const pctOf = (e: { covered: number; uncovered: number }) => (e.covered + e.uncovered === 0 ? null : (100 * e.covered) / (e.covered + e.uncovered))

function Failed({ what, error, back }: { what: string; error: Error; back: { to: string; label: string } }) {
  return (
    <div role="alert" className="flex flex-col items-start gap-2 rounded-xl bg-panel-2 px-5 py-8 edge">
      <span className="font-semibold">Could not load {what}</span>
      <span className="text-[13px] text-fg-muted">{error.message}</span>
      <Link to={back.to} className="text-[13px]">
        {back.label} →
      </Link>
    </div>
  )
}

/** Line coverage by directory and file, as an LCOV HTML report shows it. */
export function CoveragePage() {
  const api = useApi()
  const { key = '' } = useParams()
  const [params] = useSearchParams()
  const branch = params.get('branch') ?? undefined
  const dir = params.get('dir') ?? ''
  const list = useAsync(() => api.coverage(key, branch), [api, key, branch])
  return (
    <AppShell
      crumbs={[
        { label: 'Projects', to: '/projects' },
        { label: key, to: projectUrl(key, branch) },
        { label: 'Coverage', to: coverageUrl(key, branch) },
      ]}
    >
      {list.state === 'loading' && <div aria-busy="true" className="h-[600px] rounded-xl bg-panel-2 edge" />}
      {list.state === 'error' && <Failed what={`${key}’s coverage`} error={list.error} back={{ to: projectUrl(key, branch), label: `Back to ${key}` }} />}
      {list.state === 'ready' && <Coverage c={list.data} branch={branch} dir={dir} />}
    </AppShell>
  )
}

function Coverage({ c, branch, dir }: { c: CoverageList; branch?: string; dir: string }) {
  const [q, setQ] = useState('')
  const [sort, setSort] = useState<Sort>('uncovered')
  const [gapsOnly, setGapsOnly] = useState(false)
  const withData = c.files.filter((f) => f.covered != null)
  const total = withData.reduce((t, f) => ({ covered: t.covered + (f.covered ?? 0), uncovered: t.uncovered + (f.uncovered ?? 0) }), { covered: 0, uncovered: 0 })
  const prefix = dir ? `${dir}/` : ''
  const entries = useMemo(() => {
    const inDir = c.files.filter((f) => f.path.startsWith(prefix))
    const needle = q.trim().toLowerCase()
    // Searching lists matching files from the whole subtree, flat.
    const rows: Entry[] = needle
      ? inDir.filter((f) => f.path.toLowerCase().includes(needle)).map((f) => fileEntry(f, f.path.slice(prefix.length)))
      : group(inDir, prefix)
    const filtered = gapsOnly ? rows.filter((e) => e.uncovered > 0) : rows
    const name = (a: Entry, b: Entry) => Number(b.dir) - Number(a.dir) || a.name.localeCompare(b.name)
    // Entries without data sort last: there's nothing to improve there yet.
    const low = (e: Entry) => pctOf(e) ?? 101
    return filtered.sort((a, b) =>
      sort === 'name' ? name(a, b) : sort === 'lowest' ? low(a) - low(b) || b.uncovered - a.uncovered || name(a, b) : b.uncovered - a.uncovered || low(a) - low(b) || name(a, b),
    )
  }, [c.files, prefix, q, sort, gapsOnly])
  const here = group(c.files.filter((f) => f.path.startsWith(prefix)), '').reduce(
    (t, e) => ({ covered: t.covered + e.covered, uncovered: t.uncovered + e.uncovered }),
    { covered: 0, uncovered: 0 },
  )
  const th = 'border-b border-line px-2 py-2 text-left font-normal'
  const td = 'border-b border-line px-2 py-[7px]'
  const parts = dir ? dir.split('/') : []
  return (
    <>
      <PageHeader
        title="Coverage"
        summary={
          <>
            {c.project} · {c.branch} · line coverage from analysis{' '}
            <Link to={`/analyses/${c.analysis.id}`} className="font-mono text-xs">
              {c.analysis.sha.slice(0, 9)}
            </Link>
            , {formatAge(c.analysis.analyzedAt)} ago
          </>
        }
      />
      {withData.length === 0 ? (
        <div className="flex flex-col gap-2 rounded-xl bg-panel-2 px-5 py-8 edge">
          <span className="font-semibold">No coverage per file in this analysis</span>
          <span className="text-[13px] text-fg-muted">
            Run the tests with an LCOV reporter (Istanbul, c8 and vitest’s <Mono className="text-xs">--coverage</Mono>, coverage.py’s{' '}
            <Mono className="text-xs">coverage lcov</Mono>, llvm-cov or lcov), scan with <Mono className="text-xs">sonda scan --coverage lcov.info</Mono> and upload the
            report. Reports from older sonda versions carry coverage per project only.
          </span>
        </div>
      ) : (
        <>
          <MetricGrid label="Coverage totals" minCell={170}>
            <Tile label="Line coverage" value={c.coverage == null ? '—' : `${c.coverage.toFixed(1)}%`} note="of the lines the coverage reports list" color={c.coverage == null ? undefined : coverageColor(c.coverage)} />
            <Tile label="Covered lines" value={formatNumber(total.covered)} note={`of ${formatNumber(total.covered + total.uncovered)} coverable`} />
            <Tile label="Uncovered lines" value={formatNumber(total.uncovered)} note={`in ${withData.filter((f) => (f.uncovered ?? 0) > 0).length} files`} color={total.uncovered > 0 ? 'var(--sd-crit)' : undefined} />
            <Tile label="Files without data" value={formatNumber(c.files.length - withData.length)} note={`of ${formatNumber(c.files.length)} analyzed`} />
          </MetricGrid>

          <Card
            id="files"
            padded={false}
            title={
              <nav aria-label="Directory" className="flex flex-wrap items-baseline gap-1 font-mono text-[14px]">
                {parts.length === 0 ? (
                  <span>All files</span>
                ) : (
                  <Link to={coverageUrl(c.project, branch)}>All files</Link>
                )}
                {parts.map((part, i) => {
                  const to = parts.slice(0, i + 1).join('/')
                  return (
                    <span key={to} className="flex gap-1">
                      <span className="text-fg-faint">/</span>
                      {i === parts.length - 1 ? <span>{part}</span> : <Link to={coverageUrl(c.project, branch, undefined, to)}>{part}</Link>}
                    </span>
                  )
                })}
              </nav>
            }
            subtitle={
              dir
                ? `${pctOf(here) == null ? 'No data' : `${pctOf(here)!.toFixed(1)}%`} · ${formatNumber(here.uncovered)} uncovered lines in this directory`
                : 'Directories add up their files; open one, or a file to see its lines'
            }
          >
            <div className="flex flex-wrap items-center gap-2.5 px-5 pb-3">
              <input
                type="search"
                aria-label="Search files"
                placeholder={dir ? `Search files under ${dir}/` : 'Search files'}
                value={q}
                onChange={(e) => setQ(e.target.value)}
                className="h-[30px] min-w-0 flex-1 rounded-md border-0 bg-canvas px-2.5 text-[13px] edge"
              />
              <Chip on={gapsOnly} onClick={() => setGapsOnly(!gapsOnly)}>
                With uncovered lines
              </Chip>
              <Segmented label="Sort" options={SORTS} value={sort} onChange={setSort} />
            </div>
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-[13px]">
                <thead className="text-xs text-fg-muted">
                  <tr>
                    <th className={`${th} pl-5`}>{q.trim() ? 'File' : 'Name'}</th>
                    <th className={`${th} w-[180px]`}>Coverage</th>
                    <th className={`${th} text-right`}>Covered</th>
                    <th className={`${th} text-right`}>Coverable</th>
                    <th className={`${th} pr-5 text-right`}>Uncovered</th>
                  </tr>
                </thead>
                <tbody>
                  {entries.slice(0, SHOWN).map((e) => {
                    const pct = pctOf(e)
                    const noData = e.files === 0
                    return (
                      <tr key={e.path}>
                        <td className={`${td} pl-5`}>
                          <Link
                            to={e.dir ? coverageUrl(c.project, branch, undefined, e.path) : fileCoverageUrl(c.project, e.path, branch)}
                            className="font-mono text-[12.5px]"
                          >
                            {e.name}
                            {e.dir && '/'}
                          </Link>
                          {e.dir && e.withoutData > 0 && <span className="ml-2 text-xs text-fg-faint">{e.withoutData} without data</span>}
                        </td>
                        <td className={td}>{noData ? <span className="text-xs text-fg-faint">no data</span> : <Bar pct={pct} />}</td>
                        <td className={`${td} text-right font-mono`}>{noData ? '—' : formatNumber(e.covered)}</td>
                        <td className={`${td} text-right font-mono`}>{noData ? '—' : formatNumber(e.covered + e.uncovered)}</td>
                        <td className={`${td} pr-5 text-right font-mono`} style={{ color: e.uncovered > 0 ? 'var(--sd-crit)' : undefined }}>
                          {noData ? '—' : formatNumber(e.uncovered)}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
              {entries.length === 0 && <p className="m-0 px-5 py-4 text-[13px] text-fg-faint">Nothing matches.</p>}
              {entries.length > SHOWN && (
                <p className="m-0 px-5 py-3 text-xs text-fg-faint">
                  Showing {SHOWN} of {formatNumber(entries.length)}; search to narrow them.
                </p>
              )}
            </div>
          </Card>
        </>
      )}
    </>
  )
}

function fileEntry(f: CoverageFile, name: string): Entry {
  return { name, path: f.path, dir: false, covered: f.covered ?? 0, uncovered: f.uncovered ?? 0, files: f.covered == null ? 0 : 1, withoutData: f.covered == null ? 1 : 0 }
}

/** The files under `prefix`, as its direct subdirectories (with totals) and files. */
function group(files: CoverageFile[], prefix: string): Entry[] {
  const dirs = new Map<string, Entry>()
  const rows: Entry[] = []
  for (const f of files) {
    const rest = f.path.slice(prefix.length)
    const slash = rest.indexOf('/')
    if (slash < 0) {
      rows.push(fileEntry(f, rest))
      continue
    }
    const name = rest.slice(0, slash)
    const e = dirs.get(name) ?? { name, path: prefix + name, dir: true, covered: 0, uncovered: 0, files: 0, withoutData: 0 }
    const one = fileEntry(f, name)
    e.covered += one.covered
    e.uncovered += one.uncovered
    e.files += one.files
    e.withoutData += one.withoutData
    dirs.set(name, e)
  }
  return [...dirs.values(), ...rows]
}

function Bar({ pct }: { pct: number | null }) {
  if (pct == null) return <span className="text-xs text-fg-faint">nothing coverable</span>
  return (
    <span className="flex items-center gap-2">
      <span aria-hidden="true" className="h-1.5 w-[100px] flex-none overflow-hidden rounded-full bg-canvas edge">
        <span className="block h-full" style={{ width: `${pct}%`, background: coverageColor(pct) }} />
      </span>
      <Mono className="text-xs">{pct.toFixed(1)}%</Mono>
    </span>
  )
}

function Tile({ label, value, note, color }: { label: string; value: string; note: string; color?: string }) {
  return (
    <div className="flex flex-col gap-1 bg-panel-2 px-4 py-3">
      <span className="text-[12.5px] text-fg-muted">{label}</span>
      <span className="font-mono text-[22px] leading-tight" style={{ color }}>
        {value}
      </span>
      <span className="text-xs text-fg-faint">{note}</span>
    </div>
  )
}

/** One file's source: uncovered lines in red, covered ones marked green. */
export function FileCoveragePage() {
  const api = useApi()
  const { key = '' } = useParams()
  const [params] = useSearchParams()
  const branch = params.get('branch') ?? undefined
  const path = params.get('path') ?? ''
  const dir = path.includes('/') ? path.slice(0, path.lastIndexOf('/')) : ''
  const file = useAsync(() => api.fileCoverage(key, path, branch), [api, key, path, branch])
  return (
    <AppShell
      crumbs={[
        { label: 'Projects', to: '/projects' },
        { label: key, to: projectUrl(key, branch) },
        { label: 'Coverage', to: coverageUrl(key, branch, undefined, dir) },
        { label: path.slice(path.lastIndexOf('/') + 1), to: fileCoverageUrl(key, path, branch) },
      ]}
    >
      {file.state === 'loading' && <div aria-busy="true" className="h-[600px] rounded-xl bg-panel-2 edge" />}
      {file.state === 'error' && <Failed what={path} error={file.error} back={{ to: coverageUrl(key, branch, undefined, dir), label: 'Back to coverage' }} />}
      {file.state === 'ready' && <FileView f={file.data} />}
    </AppShell>
  )
}

function FileView({ f }: { f: FileCoverage }) {
  const covered = useMemo(() => new Set(f.covered ?? []), [f.covered])
  const uncovered = useMemo(() => new Set(f.uncovered ?? []), [f.uncovered])
  // The first line of each block of uncovered lines, to step through them.
  // Only a covered line ends a block; comments and blank lines don't.
  const gaps = useMemo(
    () =>
      (f.uncovered ?? []).filter((n, i, all) => {
        if (i === 0) return true
        for (let l = all[i - 1] + 1; l < n; l++) if (covered.has(l)) return true
        return false
      }),
    [f.uncovered, covered],
  )
  const [at, setAt] = useState(-1)
  const source = useRef<HTMLDivElement>(null)
  const go = (i: number) => {
    setAt(i)
    source.current?.querySelector(`[data-line="${gaps[i]}"]`)?.scrollIntoView({ block: 'center', behavior: 'smooth' })
  }
  const n = covered.size + uncovered.size
  const pct = n === 0 ? null : (100 * covered.size) / n
  return (
    <>
      <PageHeader
        title={f.path.slice(f.path.lastIndexOf('/') + 1)}
        summary={
          <>
            <Mono className="text-xs">{f.path}</Mono> · {f.branch} ·{' '}
            {f.covered == null
              ? 'not in the coverage reports'
              : pct == null
                ? 'no coverable lines'
                : `${pct.toFixed(1)}% · ${formatNumber(covered.size)} of ${formatNumber(n)} lines covered`}
          </>
        }
      >
        {gaps.length > 0 && (
          <div className="flex items-center gap-2">
            <span className="text-[13px] text-fg-muted">
              {gaps.length} uncovered {gaps.length === 1 ? 'block' : 'blocks'}
              {at >= 0 && ` · ${at + 1} of ${gaps.length}`}
            </span>
            <Button onClick={() => go(at <= 0 ? gaps.length - 1 : at - 1)}>Previous uncovered</Button>
            <Button primary onClick={() => go(at >= gaps.length - 1 ? 0 : at + 1)}>
              Next uncovered
            </Button>
          </div>
        )}
      </PageHeader>
      {f.covered == null && (
        <p role="note" className="m-0 rounded-xl bg-panel-2 px-4 py-3 text-[13px] text-fg-muted edge">
          The coverage reports don’t list this file, so its tests never loaded it, or the reporter excludes it (Istanbul and c8 list only loaded files unless told
          to include all).
        </p>
      )}
      <Card padded={false}>
        <div className="flex flex-wrap gap-4 border-b border-line px-5 py-2.5 text-xs text-fg-muted">
          <Legend color="var(--sd-ok)" glyph="✓" label="Covered: run by the tests" />
          <Legend color="var(--sd-crit)" glyph="✗" label="Uncovered: never run" />
          <span>Unmarked lines aren’t coverable (comments, declarations, blank lines).</span>
        </div>
        <div ref={source} role="region" aria-label="Source code with coverage" className="overflow-auto bg-canvas py-2 font-mono text-[11.5px] leading-[1.85]">
          {f.lines.map((line) => {
            const state = uncovered.has(line.number) ? 'uncovered' : covered.has(line.number) ? 'covered' : undefined
            const color = state === 'uncovered' ? 'var(--sd-crit)' : state === 'covered' ? 'var(--sd-ok)' : 'transparent'
            return (
              <div
                key={line.number}
                data-line={line.number}
                data-coverage={state}
                className="flex"
                style={{
                  background: state === 'uncovered' ? 'color-mix(in oklch, var(--sd-crit) 13%, transparent)' : 'transparent',
                  boxShadow: `inset 3px 0 0 ${color}`,
                }}
              >
                <span className="w-[66px] flex-none pr-2 text-right select-none" style={{ color: state === 'uncovered' ? 'var(--sd-crit)' : 'var(--sd-faint)' }}>
                  {line.number}
                </span>
                <span
                  className="w-5 flex-none text-center select-none"
                  style={{ color }}
                  aria-label={state}
                >
                  {state === 'uncovered' ? '✗' : state === 'covered' ? '✓' : ''}
                </span>
                <span className="pr-5 whitespace-pre">
                  {line.tokens.map((t, i) => (
                    <span key={i} style={{ color: ROLE_COLOR[t.role] }}>
                      {t.text}
                    </span>
                  ))}
                </span>
              </div>
            )
          })}
          {f.lines.length === 0 && <p className="m-0 px-5 py-2 font-sans text-[13px] text-fg-faint">This file’s language can’t be shown.</p>}
        </div>
        {f.truncated && <p className="m-0 border-t border-line px-5 py-3 text-xs text-fg-faint">The file is longer; only its first {formatNumber(f.lines.length)} lines are shown.</p>}
      </Card>
    </>
  )
}

function Legend({ color, glyph, label }: { color: string; glyph: string; label: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <span aria-hidden="true" style={{ color }}>
        {glyph}
      </span>
      {label}
    </span>
  )
}
