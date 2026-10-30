import { Search } from 'lucide-react'
import { useMemo } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router'
import { useApi, useAsync } from '@/api/hooks'
import type { ComponentList } from '@/api/types'
import { AppShell } from '@/components/shell/AppShell'
import { Mono, PageHeader } from '@/components/sonda/layout'
import { compactCount, formatDebt, formatNumber } from '@/lib/format'
import { componentLabel, componentUrl, projectUrl } from '@/lib/links'
import { languageLabel } from '@/lib/visual'

export function ComponentsPage() {
  const api = useApi()
  const list = useAsync(() => api.components(), [api])
  return (
    <AppShell crumbs={[{ label: 'Components', to: '/components' }]}>
      {list.state === 'loading' && <div aria-busy="true" className="h-[600px] rounded-xl bg-panel-2 edge" />}
      {list.state === 'error' && <p role="alert">Could not load components: {list.error.message}</p>}
      {list.state === 'ready' && <Components list={list.data} />}
    </AppShell>
  )
}

function Components({ list }: { list: ComponentList }) {
  const navigate = useNavigate()
  const [params, setParams] = useSearchParams()
  const q = params.get('q') ?? ''
  const project = params.get('project') ?? ''
  const owner = params.get('owner') ?? ''
  const set = (key: string, value: string) =>
    setParams(
      (p) => {
        if (value) p.set(key, value)
        else p.delete(key)
        return p
      },
      { replace: true },
    )
  const projects = useMemo(() => [...new Set(list.components.map((c) => c.project))].sort(), [list.components])
  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return list.components
      .filter(
        (c) =>
          (!needle || `${c.project}/${c.path}`.toLowerCase().includes(needle)) &&
          (!project || c.project === project) &&
          (!owner || (owner === '-' ? c.owner == null : c.owner === owner)),
      )
      .sort((a, b) => b.issues - a.issues || b.ncloc - a.ncloc || a.project.localeCompare(b.project) || a.path.localeCompare(b.path))
  }, [list.components, q, project, owner])

  const th = 'border-b border-line px-2 py-2 text-left font-normal'
  const td = 'border-b border-line px-2 py-[10px]'
  return (
    <>
      <PageHeader
        title="Components"
        summary={
          <>
            {formatNumber(list.components.length)} components in {projects.length} {projects.length === 1 ? 'project' : 'projects'} · each project’s top-level
            directories, on its main branch
          </>
        }
      >
        <label className="flex h-9 w-[300px] max-w-full items-center gap-2 rounded-lg bg-canvas px-3 edge">
          <Search size={14} strokeWidth={2} aria-hidden="true" className="text-fg-faint" />
          <input
            aria-label="Search components"
            placeholder="Search by project or path"
            value={q}
            onChange={(e) => set('q', e.target.value)}
            className="min-w-0 flex-1 border-0 bg-transparent text-[13.5px] outline-none placeholder:text-fg-faint"
          />
        </label>
      </PageHeader>
      <div className="flex flex-wrap items-center gap-4 text-[13px] text-fg-muted">
        <label className="flex items-center gap-2">
          Project
          <select aria-label="Project" value={project} onChange={(e) => set('project', e.target.value)} className="h-8 rounded-md bg-canvas px-2 text-[13px] text-fg edge">
            <option value="">All projects</option>
            {projects.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
        </label>
        <label className="flex items-center gap-2">
          Owner
          <select aria-label="Owner" value={owner} onChange={(e) => set('owner', e.target.value)} className="h-8 rounded-md bg-canvas px-2 text-[13px] text-fg edge">
            <option value="">Anyone</option>
            {list.owners.map((o) => (
              <option key={o} value={o}>
                {o}
              </option>
            ))}
            <option value="-">No owner</option>
          </select>
        </label>
      </div>

      {rows.length === 0 ? (
        <div className="flex flex-col gap-2 rounded-xl bg-panel-2 px-5 py-8 edge">
          <span className="font-semibold">{list.components.length === 0 ? 'No components yet' : 'No components match these filters'}</span>
          <span className="text-[13px] text-fg-muted">
            {list.components.length === 0 ? 'Components appear once a project has been analyzed.' : 'Try another search, project or owner.'}
          </span>
        </div>
      ) : (
        <div className="overflow-hidden rounded-xl bg-panel-2 edge">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[820px] border-collapse text-[13.5px]">
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
                {rows.map((c) => {
                  const url = componentUrl(c.project, c.path)
                  return (
                    <tr key={`${c.project}/${c.path}`} onClick={() => navigate(url)} className="cursor-pointer hover:bg-hover">
                      <td className={`${td} px-5`}>
                        <span className="flex flex-col leading-[1.3]">
                          <Link to={url} onClick={(e) => e.stopPropagation()} className="font-mono text-[12.5px] text-fg">
                            {componentLabel(c.path)}
                          </Link>
                          <span className="text-xs text-fg-faint">
                            <Link to={projectUrl(c.project)} onClick={(e) => e.stopPropagation()} className="text-fg-muted">
                              {c.project}
                            </Link>
                            {c.languages.length > 0 && ` · ${c.languages.map(languageLabel).join(', ')}`}
                          </span>
                        </span>
                      </td>
                      <td className={`${td} text-[13px] text-fg-muted`}>{c.owner ?? <span className="text-fg-faint">—</span>}</td>
                      <td className={`${td} text-right font-mono text-xs text-fg-muted`}>{formatNumber(c.files)}</td>
                      <td className={`${td} text-right font-mono text-xs text-fg-muted`}>{compactCount(c.ncloc)}</td>
                      <td className={`${td} text-right font-mono text-xs`}>
                        <Mono className={c.issues ? 'text-fg' : 'text-fg-faint'}>{formatNumber(c.issues)}</Mono>
                      </td>
                      <td className={`${td} pr-5 text-right font-mono text-xs text-fg-muted`}>{c.debtMinutes ? formatDebt(c.debtMinutes) : '—'}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
          <div className="px-5 py-2.5 text-[12.5px] text-fg-faint">
            Showing {rows.length} of {formatNumber(list.components.length)}
          </div>
        </div>
      )}
    </>
  )
}
