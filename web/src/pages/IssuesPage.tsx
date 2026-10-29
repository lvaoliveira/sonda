import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router'
import { useApi, useAsync } from '@/api/hooks'
import type { Issue, IssuePatch, IssueStatus } from '@/api/types'
import { AppShell } from '@/components/shell/AppShell'
import { CodeViewer } from '@/components/sonda/CodeViewer'
import { Button, Toast, type ToastMessage } from '@/components/sonda/controls'
import { Mono, PageHeader } from '@/components/sonda/layout'
import { SeverityGlyph, SeverityPill } from '@/components/sonda/status'
import { formatEffort } from '@/lib/format'
import { DEFAULT_FILTER, facetCount, filterFromParams, filterIssues, type IssueFilter } from '@/lib/issues'
import { CATEGORY_LABEL, SEVERITY, STATUS_COLOR, STATUS_LABEL } from '@/lib/visual'

const ME = 'Mara Okafor'

export function IssuesPage() {
  const api = useApi()
  const issues = useAsync(() => api.issues(), [api])
  return (
    <AppShell crumbs={[{ label: 'acme-corp', to: '/' }, { label: 'Issues', to: '/issues' }]}>
      {issues.state === 'loading' && <IssuesSkeleton />}
      {issues.state === 'error' && <p role="alert">Could not load issues: {issues.error.message}</p>}
      {issues.state === 'ready' && <Issues initial={issues.data} />}
    </AppShell>
  )
}

function IssuesSkeleton() {
  return (
    <>
      <PageHeader title="Issues" summary="Loading…" />
      <div aria-busy="true" className="grid min-h-[520px] grid-cols-[minmax(0,1fr)_minmax(0,1.3fr)] gap-px overflow-hidden rounded-xl bg-line">
        <div className="flex flex-col gap-3 bg-panel-2 p-4">
          {Array.from({ length: 6 }, (_, i) => (
            <div key={i} className="h-[52px] rounded-lg bg-hover" />
          ))}
        </div>
        <div className="flex flex-col gap-3 bg-panel-2 p-4">
          <div className="h-6 w-3/5 rounded bg-hover" />
          <div className="h-[220px] rounded-lg bg-hover" />
        </div>
      </div>
    </>
  )
}

function useWide(min: number) {
  const query = `(min-width: ${min}px)`
  const [wide, setWide] = useState(() => window.matchMedia(query).matches)
  useEffect(() => {
    const mq = window.matchMedia(query)
    const onChange = () => setWide(mq.matches)
    mq.addEventListener('change', onChange)
    return () => mq.removeEventListener('change', onChange)
  }, [query])
  return wide
}

function Issues({ initial }: { initial: Issue[] }) {
  const api = useApi()
  const [params, setParams] = useSearchParams()
  const [issues, setIssues] = useState(initial)
  const components = useMemo(() => new Map(initial.map((i) => [i.component, i.componentPath])), [initial])
  const drill = useMemo(() => filterFromParams(params, (id) => components.get(id) ?? id), [params, components])
  const [filter, setFilter] = useState<IssueFilter>(drill?.filter ?? DEFAULT_FILTER)
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const [checked, setChecked] = useState<number[]>([])
  const [toast, setToast] = useState<ToastMessage | null>(null)
  const clearToast = useCallback(() => setToast(null), [])
  const wide = useWide(1280)
  // Facets follow the window width until toggled; crossing the breakpoint resets them.
  const [facets, setFacets] = useState({ wide, show: wide })
  if (facets.wide !== wide) setFacets({ wide, show: wide })
  const showFacets = facets.show
  const setShowFacets = (show: boolean) => setFacets({ wide, show })
  // A new drill-down link (from another screen) replaces the current filter.
  const [appliedDrill, setAppliedDrill] = useState(drill)
  if (drill !== appliedDrill) {
    setAppliedDrill(drill)
    if (drill) {
      setFilter(drill.filter)
      setSelectedId(null)
    }
  }

  const list = useMemo(() => filterIssues(issues, filter, ME), [issues, filter])
  const selected = list.find((i) => i.id === selectedId) ?? list[0]

  const changeFilter = (patch: Partial<IssueFilter>) => {
    setFilter((f) => ({ ...f, ...patch }))
    setSelectedId(null)
    if (drill) setParams({})
  }
  const toggleIn = <K extends 'severity' | 'category' | 'status' | 'component'>(key: K, value: IssueFilter[K][number]) => {
    const current = filter[key] as string[]
    changeFilter({ [key]: current.includes(value) ? current.filter((v) => v !== value) : [...current, value] })
  }

  const apply = useCallback(
    async (ids: number[], patch: IssuePatch, message: string) => {
      const before = issues.filter((i) => ids.includes(i.id)).map((i) => ({ id: i.id, status: i.status, assignee: i.assignee }))
      const updated = await Promise.all(ids.map((id) => api.updateIssue(id, patch)))
      setIssues((all) => all.map((i) => updated.find((u) => u.id === i.id) ?? i))
      setToast({
        text: message,
        undo: async () => {
          const restored = await Promise.all(before.map((b) => api.updateIssue(b.id, { status: b.status, assignee: b.assignee })))
          setIssues((all) => all.map((i) => restored.find((r) => r.id === i.id) ?? i))
        },
      })
    },
    [api, issues],
  )
  const setStatus = (ids: number[], status: IssueStatus) => apply(ids, { status }, `Marked ${STATUS_LABEL[status].toLowerCase()}`)
  const assignToMe = (ids: number[]) => apply(ids, { assignee: ME }, 'Assigned to you')

  // j/k move, a assigns to me, c confirms (not while typing).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (/INPUT|SELECT|TEXTAREA/.test((e.target as HTMLElement).tagName) || e.metaKey || e.ctrlKey || !selected) return
      const at = Math.max(0, list.findIndex((i) => i.id === selected.id))
      if (e.key === 'j') setSelectedId(list[Math.min(list.length - 1, at + 1)].id)
      if (e.key === 'k') setSelectedId(list[Math.max(0, at - 1)].id)
      if (e.key === 'a') assignToMe([selected.id])
      if (e.key === 'c') setStatus([selected.id], 'confirmed')
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  })

  const effort = list.reduce((sum, i) => sum + i.effortMinutes, 0)
  const columns = showFacets ? (wide ? '240px minmax(0,1fr) minmax(0,1.35fr)' : '220px minmax(0,1fr) minmax(0,1.2fr)') : 'minmax(0,1fr) minmax(0,1.35fr)'

  return (
    <>
      <PageHeader title="Issues" summary="1,342 open across 312 projects · showing the payments & billing slice">
        <div className="flex items-center gap-2">
          <Button onClick={() => setShowFacets(!showFacets)}>{showFacets ? 'Hide filters' : 'Filters'}</Button>
          <span className="text-xs text-fg-faint">
            <Key>j</Key> <Key>k</Key> move · <Key>a</Key> assign · <Key>c</Key> confirm
          </span>
        </div>
      </PageHeader>

      {drill && (
        <div role="status" className="flex items-center gap-2.5 rounded-[10px] bg-brand-soft px-3.5 py-2.5 text-[13px]">
          <span className="font-mono text-[10px] tracking-[.06em] text-brand uppercase">Drill-down</span>
          <span className="flex-1">{drill.description}</span>
          <button type="button" onClick={() => changeFilter(DEFAULT_FILTER)} className="cursor-pointer border-0 bg-transparent p-0 text-[12.5px] text-brand">
            Clear
          </button>
        </div>
      )}

      <div className="grid min-h-[calc(100vh-220px)] gap-px overflow-hidden rounded-xl bg-line" style={{ gridTemplateColumns: columns, boxShadow: '0 0 0 1px var(--sd-line)' }}>
        {showFacets && <Facets issues={issues} filter={filter} toggleIn={toggleIn} changeFilter={changeFilter} components={components} />}

        <section aria-label="Issue list" className="flex min-w-0 flex-col bg-panel-2">
          <div className="flex min-h-12 flex-wrap items-center gap-2.5 border-b border-line px-3.5">
            <span className="font-semibold">
              {list.length} {list.length === 1 ? 'issue' : 'issues'}
            </span>
            <Mono className="text-[10.5px] text-fg-faint">~{formatEffort(effort)} effort</Mono>
            <span className="flex-1" />
            {checked.length > 0 && (
              <span className="flex items-center gap-1.5 text-[12.5px]">
                <span className="text-fg-muted">{checked.length} selected</span>
                <button type="button" onClick={() => assignToMe(checked)} className="h-[26px] cursor-pointer rounded-md border-0 bg-brand px-2.5 text-xs font-semibold text-brand-ink">
                  Assign to me
                </button>
                <button type="button" onClick={() => setStatus(checked, 'confirmed')} className="h-[26px] cursor-pointer rounded-md border-0 bg-transparent px-2.5 text-xs edge-strong">
                  Confirm
                </button>
              </span>
            )}
          </div>
          {list.length === 0 && (
            <div className="flex flex-col gap-1.5 px-[18px] py-10">
              <span className="text-base font-semibold">Nothing matches</span>
              <span className="text-[13px] text-fg-muted">Either very good news or a filter that's too narrow.</span>
              <Button className="mt-2 self-start" onClick={() => changeFilter(DEFAULT_FILTER)}>
                Reset filters
              </Button>
            </div>
          )}
          <div role="listbox" aria-label="Issues" className="flex flex-col overflow-auto">
            {list.map((issue) => {
              const on = issue.id === selected?.id
              return (
                <div
                  key={issue.id}
                  role="option"
                  aria-selected={on}
                  onClick={() => setSelectedId(issue.id)}
                  className="grid cursor-pointer grid-cols-[16px_14px_minmax(0,1fr)] items-start gap-2.5 border-b border-line py-3 pr-3.5 pl-[11px] hover:bg-hover"
                  style={{ borderLeft: `3px solid ${on ? 'var(--sd-accent)' : 'transparent'}`, background: on ? 'var(--sd-panel)' : undefined }}
                >
                  <input
                    type="checkbox"
                    aria-label={`Select ${issue.key}`}
                    checked={checked.includes(issue.id)}
                    onClick={(e) => e.stopPropagation()}
                    onChange={() => setChecked((c) => (c.includes(issue.id) ? c.filter((x) => x !== issue.id) : [...c, issue.id]))}
                    className="m-0 mt-[3px] accent-brand"
                  />
                  <SeverityGlyph severity={issue.severity} className="pt-[3px] text-[10px]" />
                  <span className="flex min-w-0 flex-col gap-1">
                    <span className="text-[13.5px] leading-[1.35] font-medium">{issue.title}</span>
                    <Mono className="overflow-hidden text-[10.5px] text-ellipsis whitespace-nowrap text-fg-faint">
                      {issue.file}:{issue.line}
                    </Mono>
                    <span className="flex flex-wrap items-center gap-2 text-xs text-fg-faint">
                      <span style={{ color: STATUS_COLOR[issue.status] }}>{STATUS_LABEL[issue.status]}</span>
                      <span>·</span>
                      <span>{CATEGORY_LABEL[issue.category]}</span>
                      <span>·</span>
                      <span>{formatEffort(issue.effortMinutes)}</span>
                      <span>·</span>
                      <span>{issue.age}</span>
                      {issue.isNew && <Tag accent>NEW</Tag>}
                      {issue.assignee === ME && <Tag>YOU</Tag>}
                    </span>
                  </span>
                </div>
              )
            })}
          </div>
        </section>

        {selected && (
          <IssueDetail
            issue={selected}
            all={issues}
            onStatus={(s) => setStatus([selected.id], s)}
            onAssign={() => assignToMe([selected.id])}
            onEditor={() => setToast({ text: `Opening ${selected.file.split('/').pop()}:${selected.line} in VS Code` })}
            onRelated={(id) => {
              changeFilter({ ...DEFAULT_FILTER, status: [] })
              setSelectedId(id)
            }}
          />
        )}
      </div>
      <Toast toast={toast} onDone={clearToast} />
    </>
  )
}

function Facets({
  issues,
  filter,
  toggleIn,
  changeFilter,
  components,
}: {
  issues: Issue[]
  filter: IssueFilter
  toggleIn: <K extends 'severity' | 'category' | 'status' | 'component'>(key: K, value: IssueFilter[K][number]) => void
  changeFilter: (patch: Partial<IssueFilter>) => void
  components: Map<string, string>
}) {
  const groups: { label: string; key: 'severity' | 'category' | 'status' | 'component'; options: { value: string; label: string; mono?: boolean }[] }[] = [
    { label: 'Severity', key: 'severity', options: (['blocker', 'critical', 'major', 'minor'] as const).map((s) => ({ value: s, label: SEVERITY[s].label })) },
    { label: 'Category', key: 'category', options: (['vulnerability', 'bug', 'code_smell'] as const).map((c) => ({ value: c, label: CATEGORY_LABEL[c] })) },
    { label: 'Status', key: 'status', options: (['open', 'confirmed', 'fixed', 'accepted'] as const).map((s) => ({ value: s, label: STATUS_LABEL[s] })) },
    { label: 'Component', key: 'component', options: [...components].map(([id, path]) => ({ value: id, label: path, mono: true })) },
  ]
  const toggles = [
    { label: 'Assigned to me', key: 'mine' as const, n: issues.filter((i) => i.assignee === ME).length },
    { label: 'New code only', key: 'isNew' as const, n: issues.filter((i) => i.isNew).length },
  ]
  const saved: [string, Partial<IssueFilter>][] = [
    ['My open issues', { mine: true }],
    ['Security on main', { category: ['vulnerability'] }],
    ['Introduced this week', { isNew: true }],
  ]
  return (
    <aside aria-label="Filters" className="flex flex-col gap-[18px] overflow-auto bg-panel-2 p-4">
      <div className="flex flex-col gap-1">
        {toggles.map((t) => {
          const on = filter[t.key]
          return (
            <button
              key={t.key}
              type="button"
              aria-pressed={on}
              onClick={() => changeFilter({ [t.key]: !on })}
              className="flex h-8 cursor-pointer items-center justify-between rounded-[7px] border-0 px-2.5 text-[13px]"
              style={{
                background: on ? 'var(--sd-accent-soft)' : 'transparent',
                color: on ? 'var(--sd-accent)' : 'var(--sd-text)',
                boxShadow: `inset 0 0 0 1px ${on ? 'var(--sd-accent)' : 'var(--sd-line-2)'}`,
              }}
            >
              <span>{t.label}</span>
              <Mono className="text-[10.5px]">{t.n}</Mono>
            </button>
          )
        })}
      </div>
      {groups.map((g) => (
        <fieldset key={g.key} className="m-0 flex flex-col gap-px border-0 p-0">
          <legend className="pb-2 micro-label">{g.label}</legend>
          {g.options.map((o) => {
            const on = (filter[g.key] as string[]).includes(o.value)
            return (
              <label key={o.value} className="flex cursor-pointer items-center gap-[9px] rounded-md px-1.5 py-[5px] text-[13px] hover:bg-hover" style={{ background: on ? 'var(--sd-hover)' : undefined }}>
                <input type="checkbox" checked={on} onChange={() => toggleIn(g.key, o.value as never)} className="m-0 accent-brand" />
                {g.key === 'severity' && <SeverityGlyph severity={o.value as keyof typeof SEVERITY} className="w-2.5 text-[10px]" />}
                <span className={`min-w-0 flex-1 overflow-hidden text-ellipsis whitespace-nowrap ${o.mono ? 'font-mono text-[11px]' : ''}`}>{o.label}</span>
                <Mono className="text-[10px] text-fg-faint">{facetCount(issues, filter, ME, g.key, o.value)}</Mono>
              </label>
            )
          })}
        </fieldset>
      ))}
      <div className="flex flex-col gap-0.5 border-t border-line pt-3">
        <span className="pb-1.5 micro-label">Saved views</span>
        {saved.map(([label, patch]) => (
          <button
            key={label}
            type="button"
            onClick={() => changeFilter({ ...DEFAULT_FILTER, ...patch })}
            className="cursor-pointer rounded-md border-0 bg-transparent px-1.5 py-[5px] text-left text-[13px] text-fg-muted hover:bg-hover hover:text-fg"
          >
            {label}
          </button>
        ))}
      </div>
    </aside>
  )
}

function IssueDetail({
  issue,
  all,
  onStatus,
  onAssign,
  onEditor,
  onRelated,
}: {
  issue: Issue
  all: Issue[]
  onStatus: (s: IssueStatus) => void
  onAssign: () => void
  onEditor: () => void
  onRelated: (id: number) => void
}) {
  const mine = issue.assignee === ME
  const meta: { k: string; v: string; mono?: boolean; color?: string }[] = [
    { k: 'Location', v: `${issue.file.split('/').pop()}:${issue.line}`, mono: true },
    { k: 'Component', v: issue.componentPath, mono: true },
    { k: 'Effort', v: formatEffort(issue.effortMinutes), mono: true },
    { k: 'Detected', v: issue.detected + (issue.isNew ? ' · new code' : '') },
    { k: 'Status', v: STATUS_LABEL[issue.status], color: STATUS_COLOR[issue.status] },
    { k: 'Assignee', v: issue.assignee ?? 'Unassigned', color: issue.assignee ? undefined : 'var(--sd-faint)' },
  ]
  const related = issue.related.map((id) => all.find((i) => i.id === id)).filter((i): i is Issue => !!i)
  return (
    <article aria-label="Issue detail" className="flex min-w-0 flex-col overflow-auto bg-panel">
      <div className="flex flex-col gap-3 border-b border-line px-5 py-[18px]">
        <div className="flex flex-wrap items-center gap-2.5 text-[12.5px]">
          <SeverityPill severity={issue.severity} />
          <span className="inline-flex h-6 items-center rounded-xl bg-hover px-2.5">{CATEGORY_LABEL[issue.category]}</span>
          {issue.cwe && <Mono className="text-[10.5px] text-fg-muted">{issue.cwe}</Mono>}
          <Mono className="text-[10.5px] text-fg-faint">{issue.key}</Mono>
          <Link to={`/rules#${encodeURIComponent(issue.rule)}`} className="font-mono text-[10.5px]">
            {issue.rule}
          </Link>
        </div>
        <h2 className="m-0 text-[21px] leading-[1.25] font-semibold tracking-[-0.02em]">{issue.title}</h2>
        <div className="grid grid-cols-[repeat(auto-fit,minmax(130px,1fr))] gap-px overflow-hidden rounded-[9px] bg-line" style={{ boxShadow: '0 0 0 1px var(--sd-line)' }}>
          {meta.map((m) => (
            <div key={m.k} className="flex flex-col gap-0.5 bg-panel-2 px-2.5 py-2">
              <span className="text-[11px] text-fg-faint">{m.k}</span>
              <span className={`overflow-hidden text-ellipsis whitespace-nowrap ${m.mono ? 'font-mono text-[11px]' : 'text-[13px]'}`} style={{ color: m.color ?? 'var(--sd-text)' }}>
                {m.v}
              </span>
            </div>
          ))}
        </div>
        <div className="flex flex-wrap gap-1.5">
          <Button primary={!mine} disabled={mine} onClick={onAssign}>
            {mine ? 'Assigned to you' : 'Assign to me'}
          </Button>
          <Button disabled={issue.status === 'confirmed'} onClick={() => onStatus('confirmed')}>
            Confirm
          </Button>
          <Button disabled={issue.status === 'fixed'} onClick={() => onStatus('fixed')}>
            Resolve as fixed
          </Button>
          <Button disabled={issue.status === 'accepted'} onClick={() => onStatus('accepted')}>
            Accept risk
          </Button>
          <Button onClick={onEditor}>Open in editor</Button>
        </div>
      </div>
      <div className="flex flex-col border-b border-line">
        <div className="flex justify-between gap-2 border-b border-line bg-panel-2 px-5 py-[9px] font-mono text-[10.5px]">
          <span className="overflow-hidden text-ellipsis whitespace-nowrap text-fg-muted">{issue.file}</span>
          <span className="text-fg-faint">{issue.language}</span>
        </div>
        <CodeViewer lines={issue.code.lines} highlighted={issue.code.highlighted} severity={issue.severity} noteLine={issue.line} note={issue.message} />
      </div>
      <div className="flex flex-col gap-5 px-5 pt-[18px] pb-7">
        <section className="flex flex-col gap-1.5">
          <h3 className="m-0 font-normal micro-label">Why it matters</h3>
          <p className="m-0 max-w-[68ch] text-sm">{issue.why}</p>
        </section>
        <section className="flex flex-col gap-2">
          <h3 className="m-0 font-normal micro-label">How to fix</h3>
          <p className="m-0 max-w-[68ch] text-sm">{issue.fix}</p>
          <pre className="m-0 overflow-auto rounded-lg bg-canvas px-3.5 py-3 font-mono text-[11.5px] leading-[1.8]" style={{ boxShadow: 'inset 3px 0 0 var(--sd-ok), inset 0 0 0 1px var(--sd-line)' }}>
            {issue.fixCode}
          </pre>
        </section>
        {related.length > 0 && (
          <section className="flex flex-col gap-0.5">
            <h3 className="m-0 mb-1.5 font-normal micro-label">Related issues</h3>
            {related.map((r) => (
              <button
                key={r.id}
                type="button"
                onClick={() => onRelated(r.id)}
                className="grid cursor-pointer grid-cols-[14px_minmax(0,1fr)_auto] items-baseline gap-2.5 border-0 border-t border-solid border-line bg-transparent py-2 text-left text-[13.5px] hover:text-brand"
              >
                <SeverityGlyph severity={r.severity} />
                <span>{r.title}</span>
                <Mono className="text-[10px] text-fg-faint">{r.key}</Mono>
              </button>
            ))}
          </section>
        )}
      </div>
    </article>
  )
}

function Key({ children }: { children: string }) {
  return <span className="rounded bg-hover px-[5px] py-0.5 font-mono text-[10px]">{children}</span>
}

function Tag({ children, accent = false }: { children: string; accent?: boolean }) {
  return (
    <span
      className="rounded-lg px-1.5 py-px font-mono text-[9px] tracking-[.06em]"
      style={{ background: accent ? 'var(--sd-accent-soft)' : 'var(--sd-hover)', color: accent ? 'var(--sd-accent)' : 'var(--sd-muted)' }}
    >
      {children}
    </span>
  )
}
