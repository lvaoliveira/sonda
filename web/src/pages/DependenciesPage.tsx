import { useMemo, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router'
import { useApi, useAsync } from '@/api/hooks'
import type { DependencyList, DependencyReview, DependencyRow } from '@/api/types'
import { AppShell } from '@/components/shell/AppShell'
import { Button, Chip, Segmented } from '@/components/sonda/controls'
import { Card, MetricGrid, Mono, PageHeader } from '@/components/sonda/layout'
import { SeverityGlyph } from '@/components/sonda/status'
import { formatAge, formatNumber } from '@/lib/format'
import { dependenciesUrl, projectUrl } from '@/lib/links'
import { ECOSYSTEM_LABEL, SEVERITY, SEVERITY_ORDER } from '@/lib/visual'

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

function Dependencies({ d: loaded }: { d: DependencyList }) {
  // Reviews update this copy in place, so the page doesn't reload.
  const [d, setD] = useState(loaded)
  const onReview = (name: string, advisory: string, review: DependencyReview) =>
    setD((old) => ({
      ...old,
      dependencies: old.dependencies.map((r) =>
        r.name !== name ? r : { ...r, advisories: r.advisories.map((a) => (a.id === advisory ? { ...a, review } : a)) },
      ),
    }))
  const vulnerable = d.dependencies.filter((r) => r.advisories.some((a) => a.review?.status !== 'accepted')).length
  const [q, setQ] = useState('')
  const [ecosystem, setEcosystem] = useState('all')
  const [directOnly, setDirectOnly] = useState(false)
  const [vulnerableOnly, setVulnerableOnly] = useState(false)
  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return d.dependencies.filter(
      (r) =>
        (ecosystem === 'all' || r.ecosystem === ecosystem) &&
        (!directOnly || r.direct === true) &&
        (!vulnerableOnly || r.advisories.length > 0) &&
        (!needle || `${r.name} ${r.version} ${r.license ?? ''} ${r.lockfiles.join(' ')}`.toLowerCase().includes(needle)),
    )
  }, [d.dependencies, q, ecosystem, directOnly, vulnerableOnly])
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
            This analysis has no lockfiles sonda reads (package-lock.json, yarn.lock, pnpm-lock.yaml, Cargo.lock, poetry.lock, uv.lock, pinned requirements*.txt), or was uploaded by an older sonda.
          </span>
        </div>
      ) : (
        <>
          <AdvisoryData d={d} />
          <MetricGrid label="Dependency counts" minCell={150}>
            <Tile label="Packages" value={s.total} note={`in ${d.lockfiles.length} ${d.lockfiles.length === 1 ? 'lockfile' : 'lockfiles'}`} />
            <Tile label="Vulnerable" value={vulnerable} note="with an open known vulnerability" alarm />
            <Tile label="Direct" value={s.direct} note="declared by the project" />
            {s.ecosystems.map((e) => (
              <Tile key={e.id} label={ECOSYSTEM_LABEL[e.id] ?? e.id} value={e.count} note="packages" />
            ))}
          </MetricGrid>

          <Vulnerabilities d={d} onReview={onReview} />
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
              <Chip on={vulnerableOnly} onClick={() => setVulnerableOnly(!vulnerableOnly)}>
                Vulnerable only
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
                        <span className="flex items-center gap-1.5 font-medium">
                          {r.advisories[0] && <SeverityGlyph severity={r.advisories[0].severity} />}
                          {r.name}
                          {r.advisories.length > 0 && (
                            <span className="text-xs font-normal" style={{ color: SEVERITY[r.advisories[0].severity].color }}>
                              {r.advisories.length} {r.advisories.length === 1 ? 'vulnerability' : 'vulnerabilities'}
                            </span>
                          )}
                        </span>
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

function Tile({ label, value, note, alarm = false }: { label: string; value: number; note: string; alarm?: boolean }) {
  return (
    <div className="flex flex-col gap-1 bg-panel-2 px-4 py-3">
      <span className="text-[12.5px] text-fg-muted">{label}</span>
      <span className="font-mono text-[22px] leading-tight" style={{ color: alarm && value > 0 ? 'var(--sd-crit)' : undefined }}>
        {formatNumber(value)}
      </span>
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

/** Where vulnerability data comes from, and whether there is any. */
function AdvisoryData({ d }: { d: DependencyList }) {
  if (!d.advisoryData) {
    return (
      <p role="note" className="m-0 rounded-xl bg-panel-2 px-4 py-3 text-[13px] text-fg-muted edge">
        No advisory data imported yet, so no package can be shown as vulnerable. An administrator imports OSV records with{' '}
        <Mono className="text-xs text-fg">sonda-server advisories import</Mono> (see docs/server.md).
      </p>
    )
  }
  return (
    <p className="m-0 text-xs text-fg-faint">
      Checked against {formatNumber(d.advisoryData.advisories)} advisories imported {formatAge(d.advisoryData.importedAt)} ago, from the GitHub, RustSec, PyPA and Go
      advisory databases via <a href="https://osv.dev">OSV</a>.
    </p>
  )
}

/** Every known vulnerability in the project's packages, most severe first; accepted ones last. */
function Vulnerabilities({ d, onReview }: { d: DependencyList; onReview: (name: string, advisory: string, review: DependencyReview) => void }) {
  const accepted = (a: DependencyRow['advisories'][number]) => a.review?.status === 'accepted'
  const rows: { dep: DependencyRow; a: DependencyRow['advisories'][number] }[] = d.dependencies
    .flatMap((dep) => dep.advisories.map((a) => ({ dep, a })))
    .sort(
      (x, y) =>
        Number(accepted(x.a)) - Number(accepted(y.a)) ||
        SEVERITY_ORDER.indexOf(x.a.severity) - SEVERITY_ORDER.indexOf(y.a.severity) ||
        x.dep.name.localeCompare(y.dep.name),
    )
  const unchecked = d.dependencies.filter((r) => r.unchecked.length > 0)
  if (rows.length === 0 && unchecked.length === 0) return null
  return (
    <Card id="vulnerabilities" padded={false} title="Vulnerabilities" subtitle="Known vulnerabilities in the pinned versions, most severe first; accepted ones last">
      <ul className="m-0 list-none p-0">
        {rows.map(({ dep, a }) => (
          <Finding key={`${dep.purl}${a.id}`} project={d.project} dep={dep} a={a} onReview={(r) => onReview(dep.name, a.id, r)} />
        ))}
      </ul>
      {unchecked.length > 0 && (
        <p className="m-0 border-t border-line px-5 py-3 text-xs text-fg-faint">
          Couldn’t check {unchecked.length} {unchecked.length === 1 ? 'package' : 'packages'} against some advisories (versions that don’t parse):{' '}
          {unchecked.map((r) => `${r.name} ${r.version}`).join(', ')}.
        </p>
      )}
    </Card>
  )
}

const REVIEW_LABEL = { open: 'Open', confirmed: 'Confirmed', accepted: 'Accepted' } as const

function Finding({
  project,
  dep,
  a,
  onReview,
}: {
  project: string
  dep: DependencyRow
  a: DependencyRow['advisories'][number]
  onReview: (r: DependencyReview) => void
}) {
  const api = useApi()
  const [accepting, setAccepting] = useState(false)
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const status = a.review?.status ?? 'open'
  const set = async (next: DependencyReview['status'], why?: string) => {
    setBusy(true)
    setError(null)
    try {
      onReview(await api.reviewDependency(project, { ecosystem: dep.ecosystem, name: dep.name, advisory: a.id, status: next, reason: why }))
      setAccepting(false)
      setReason('')
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <li
      aria-label={`${a.id} in ${dep.name} ${dep.version}`}
      className="grid grid-cols-[16px_minmax(0,1fr)_auto] items-baseline gap-3 border-t border-line px-5 py-2.5 text-[13.5px]"
      style={{ opacity: status === 'accepted' ? 0.65 : 1 }}
    >
      <SeverityGlyph severity={a.severity} />
      <span className="flex min-w-0 flex-col gap-1">
        <span>{a.summary}</span>
        <span className="text-xs text-fg-faint">
          <Mono className="text-[11.5px] text-fg-muted">
            {dep.name} {dep.version}
          </Mono>{' '}
          ·{' '}
          <a href={a.url} target="_blank" rel="noreferrer" className="font-mono text-[11.5px]">
            {a.id}
          </a>
          {a.aliases
            .filter((x) => x.startsWith('CVE-'))
            .map((cve) => (
              <span key={cve}> · {cve}</span>
            ))}
          {a.score != null && <span> · CVSS {a.score.toFixed(1)}</span>}
          <span> · {a.source}</span>
        </span>
        {a.review && a.review.status !== 'open' && (
          <span className="text-xs text-fg-muted">
            {REVIEW_LABEL[a.review.status]} by {a.review.reviewedBy}, {formatAge(a.review.reviewedAt)} ago
            {a.review.reason && <>: “{a.review.reason}”</>}
          </span>
        )}
        {accepting && (
          <form
            className="flex flex-col gap-1.5"
            onSubmit={(e) => {
              e.preventDefault()
              void set('accepted', reason)
            }}
          >
            <label className="text-xs text-fg-muted" htmlFor={`reason-${dep.purl}-${a.id}`}>
              Why is this acceptable? Shown to everyone with the finding.
            </label>
            <textarea
              id={`reason-${dep.purl}-${a.id}`}
              value={reason}
              maxLength={500}
              rows={2}
              onChange={(e) => setReason(e.target.value)}
              className="rounded-md border-0 bg-canvas px-2.5 py-1.5 text-[13px] edge"
            />
            <span className="flex gap-2">
              <Button primary type="submit" disabled={busy || !reason.trim()}>
                Accept
              </Button>
              <Button onClick={() => setAccepting(false)} disabled={busy}>
                Cancel
              </Button>
            </span>
          </form>
        )}
        {error && (
          <span role="alert" className="text-xs text-crit">
            {error}
          </span>
        )}
      </span>
      <span className="flex flex-col items-end gap-1.5 text-right text-xs whitespace-nowrap">
        <span>
          <span style={{ color: SEVERITY[a.severity].color }}>{SEVERITY[a.severity].label}</span>
          <span className="text-fg-muted"> · {a.fixedIn ? `fixed in ${a.fixedIn}` : 'no fix yet'}</span>
        </span>
        <span className="flex gap-1.5">
          {status === 'open' && (
            <Button onClick={() => void set('confirmed')} disabled={busy}>
              Confirm
            </Button>
          )}
          {status !== 'accepted' && !accepting && (
            <Button onClick={() => setAccepting(true)} disabled={busy}>
              Accept…
            </Button>
          )}
          {status !== 'open' && (
            <Button onClick={() => void set('open')} disabled={busy}>
              Reopen
            </Button>
          )}
        </span>
      </span>
    </li>
  )
}
