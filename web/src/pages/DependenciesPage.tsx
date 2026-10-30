import { useMemo, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router'
import { useApi, useAsync } from '@/api/hooks'
import type { DependencyList } from '@/api/types'
import { AppShell } from '@/components/shell/AppShell'
import { Chip, Segmented } from '@/components/sonda/controls'
import { Card, MetricGrid, Mono, PageHeader } from '@/components/sonda/layout'
import { formatAge, formatNumber } from '@/lib/format'
import { dependenciesUrl, projectUrl } from '@/lib/links'
import { ECOSYSTEM_LABEL } from '@/lib/visual'

/** Rows rendered at once; searching narrows the rest. */
const SHOWN = 500

export function DependenciesPage() {
  const api = useApi()
  const { key = '' } = useParams()
  const [params] = useSearchParams()
  const branch = params.get('branch') ?? undefined
  const list = useAsync(() => api.dependencies(key, branch), [api, key, branch])
  return (
    <AppShell
      crumbs={[
        { label: 'Projects', to: '/projects' },
        { label: key, to: projectUrl(key, branch) },
        { label: 'Dependencies', to: dependenciesUrl(key, branch) },
      ]}
    >
      {list.state === 'loading' && <div aria-busy="true" className="h-[600px] rounded-xl bg-panel-2 edge" />}
      {list.state === 'error' && (
        <div role="alert" className="flex flex-col items-start gap-2 rounded-xl bg-panel-2 px-5 py-8 edge">
          <span className="font-semibold">Could not load {key}’s dependencies</span>
          <span className="text-[13px] text-fg-muted">{list.error.message}</span>
          <Link to={projectUrl(key, branch)} className="text-[13px]">
            Back to {key} →
          </Link>
        </div>
      )}
      {list.state === 'ready' && <Dependencies d={list.data} />}
    </AppShell>
  )
}

function Dependencies({ d }: { d: DependencyList }) {
  const [q, setQ] = useState('')
  const [ecosystem, setEcosystem] = useState('all')
  const [directOnly, setDirectOnly] = useState(false)
  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return d.dependencies.filter(
      (r) =>
        (ecosystem === 'all' || r.ecosystem === ecosystem) &&
        (!directOnly || r.direct === true) &&
        (!needle || `${r.name} ${r.version} ${r.license ?? ''} ${r.lockfiles.join(' ')}`.toLowerCase().includes(needle)),
    )
  }, [d.dependencies, q, ecosystem, directOnly])
  const s = d.summary
  const th = 'border-b border-line px-2 py-2 text-left font-normal'
  const td = 'border-b border-line px-2 py-[9px]'
  return (
    <>
      <PageHeader
        title="Dependencies"
        summary={
          <>
            {d.project} · {d.branch} · from the lockfiles in analysis{' '}
            <Link to={`/analyses/${d.analysis.id}`} className="font-mono text-xs">
              {d.analysis.sha.slice(0, 9)}
            </Link>
            , {formatAge(d.analysis.analyzedAt)} ago
          </>
        }
      />
      {s.total === 0 ? (
        <div className="flex flex-col gap-2 rounded-xl bg-panel-2 px-5 py-8 edge">
          <span className="font-semibold">No dependencies recorded</span>
          <span className="text-[13px] text-fg-muted">
            This analysis has no lockfiles sonda reads (package-lock.json, Cargo.lock, poetry.lock, uv.lock, pinned requirements*.txt), or was uploaded by an older sonda.
          </span>
        </div>
      ) : (
        <>
          <MetricGrid label="Dependency counts" minCell={150}>
            <Tile label="Packages" value={s.total} note={`in ${d.lockfiles.length} ${d.lockfiles.length === 1 ? 'lockfile' : 'lockfiles'}`} />
            <Tile label="Direct" value={s.direct} note="declared by the project" />
            {s.ecosystems.map((e) => (
              <Tile key={e.id} label={ECOSYSTEM_LABEL[e.id] ?? e.id} value={e.count} note="packages" />
            ))}
          </MetricGrid>

          <div className="grid grid-cols-1 gap-5 min-[900px]:grid-cols-3">
            <Changes d={d} />
            <Card id="licenses" title="Licenses" subtitle="As the lockfiles record them">
              <ul className="m-0 flex list-none flex-col p-0">
                {d.licenses.map((l) => (
                  <li key={l.license ?? ''} className="flex items-center justify-between gap-3 border-t border-line py-1.5 text-[13px] first:border-t-0">
                    {l.license ? <Mono className="truncate text-[12px]">{l.license}</Mono> : <span className="text-fg-faint">not recorded</span>}
                    <Mono className="text-xs text-fg-muted">{formatNumber(l.count)}</Mono>
                  </li>
                ))}
              </ul>
            </Card>
            <Card id="lockfiles" title="Lockfiles" subtitle="Packages each pins">
              <ul className="m-0 flex list-none flex-col p-0">
                {d.lockfiles.map((l) => (
                  <li key={l.id} className="flex items-center justify-between gap-3 border-t border-line py-1.5 text-[13px] first:border-t-0">
                    <Mono className="truncate text-[12px]">{l.id}</Mono>
                    <Mono className="text-xs text-fg-muted">{formatNumber(l.count)}</Mono>
                  </li>
                ))}
              </ul>
            </Card>
          </div>

          <Card id="packages" padded={false} title="Packages" subtitle={`${formatNumber(rows.length)} of ${formatNumber(s.total)}`}>
            <div className="flex flex-wrap items-center gap-2.5 px-5 pb-3">
              <input
                type="search"
                aria-label="Search packages"
                placeholder="Search by name, version, license or lockfile"
                value={q}
                onChange={(e) => setQ(e.target.value)}
                className="h-[30px] min-w-0 flex-1 rounded-md border-0 bg-canvas px-2.5 text-[13px] edge"
              />
              {s.ecosystems.length > 1 && (
                <Segmented
                  label="Ecosystem"
                  value={ecosystem}
                  onChange={setEcosystem}
                  options={[{ value: 'all', label: 'All' }, ...s.ecosystems.map((e) => ({ value: e.id, label: ECOSYSTEM_LABEL[e.id] ?? e.id }))]}
                />
              )}
              <Chip on={directOnly} onClick={() => setDirectOnly(!directOnly)}>
                Direct only
              </Chip>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[640px] border-collapse text-[13px]">
                <thead>
                  <tr className="font-mono text-[9.5px] tracking-[.06em] text-fg-faint uppercase">
                    <th scope="col" className={`${th} pl-5`}>
                      Package
                    </th>
                    <th scope="col" className={th}>
                      Version
                    </th>
                    <th scope="col" className={th}>
                      Dependency
                    </th>
                    <th scope="col" className={th}>
                      License
                    </th>
                    <th scope="col" className={`${th} pr-5`}>
                      Lockfile
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {rows.slice(0, SHOWN).map((r) => (
                    <tr key={r.purl}>
                      <td className={`${td} pl-5`}>
                        <span className="block font-medium">{r.name}</span>
                        <span className="block truncate font-mono text-[10.5px] text-fg-faint" title={r.purl}>
                          {r.purl}
                        </span>
                      </td>
                      <td className={`${td} font-mono text-[12px]`}>{r.version}</td>
                      <td className={`${td} text-fg-muted`}>{r.direct === true ? 'direct' : r.direct === false ? 'transitive' : '—'}</td>
                      <td className={`${td} font-mono text-[12px] text-fg-muted`}>{r.license ?? '—'}</td>
                      <td className={`${td} pr-5 font-mono text-[11.5px] text-fg-muted`}>{r.lockfiles.join(', ')}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {rows.length === 0 && <p className="m-0 px-5 py-4 text-[13px] text-fg-faint">No packages match.</p>}
            {rows.length > SHOWN && (
              <p className="m-0 px-5 py-3 text-xs text-fg-faint">
                Showing the first {SHOWN} of {formatNumber(rows.length)}; search to narrow them.
              </p>
            )}
          </Card>
        </>
      )}
    </>
  )
}

function Tile({ label, value, note }: { label: string; value: number; note: string }) {
  return (
    <div className="flex flex-col gap-1 bg-panel-2 px-4 py-3">
      <span className="text-[12.5px] text-fg-muted">{label}</span>
      <span className="font-mono text-[22px] leading-tight">{formatNumber(value)}</span>
      <span className="text-xs text-fg-faint">{note}</span>
    </div>
  )
}

function Changes({ d }: { d: DependencyList }) {
  const c = d.changes
  const total = c ? c.added.length + c.removed.length + c.updated.length : 0
  return (
    <Card id="changes" title="Changed" subtitle={c ? 'Since the previous analysis on this branch' : 'First analysis on this branch'}>
      {!c || total === 0 ? (
        <p className="m-0 text-[13px] text-fg-faint">{c ? 'No package changed.' : 'Nothing to compare with yet.'}</p>
      ) : (
        <ul className="m-0 flex list-none flex-col gap-1 p-0 text-[13px]">
          {c.updated.map((u) => (
            <li key={`u${u.ecosystem}${u.name}`}>
              <span className="text-fg-muted">updated</span> {u.name}{' '}
              <Mono className="text-[11.5px] text-fg-muted">
                {u.from.join(', ')} → {u.to.join(', ')}
              </Mono>
            </li>
          ))}
          {c.added.map((a) => (
            <li key={`a${a.ecosystem}${a.name}`}>
              <span style={{ color: 'var(--sd-ok)' }}>added</span> {a.name} <Mono className="text-[11.5px] text-fg-muted">{a.versions.join(', ')}</Mono>
            </li>
          ))}
          {c.removed.map((r) => (
            <li key={`r${r.ecosystem}${r.name}`}>
              <span style={{ color: 'var(--sd-crit)' }}>removed</span> {r.name} <Mono className="text-[11.5px] text-fg-muted">{r.versions.join(', ')}</Mono>
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}
