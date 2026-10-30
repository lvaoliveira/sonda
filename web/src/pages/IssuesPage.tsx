import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router'
import { useApi, useAsync } from '@/api/hooks'
import type { FacetKey, IssueDetail, IssuePage, IssuePatch, IssueSummary, TriageStatus } from '@/api/types'
import { AppShell } from '@/components/shell/AppShell'
import { CodeViewer } from '@/components/sonda/CodeViewer'
import { Button, Toast, type ToastMessage } from '@/components/sonda/controls'
import { Mono, PageHeader } from '@/components/sonda/layout'
import { SeverityGlyph, SeverityPill } from '@/components/sonda/status'
import { formatAge, formatEffort, formatNumber, shortDate } from '@/lib/format'
import { DEFAULT_FILTER, filterFromParams, type IssueFilter, PAGE_SIZE, toQuery } from '@/lib/issues'
import { CATEGORY_LABEL, languageLabel, SEVERITY, SEVERITY_ORDER, STATUS_COLOR, STATUS_LABEL } from '@/lib/visual'

export function IssuesPage() {
  const api = useApi()
  const shell = useAsync(() => api.shell(), [api])
  return (
    <AppShell crumbs={[{ label: 'Issues', to: '/issues' }]}>
      {shell.state === 'error' && <p role="alert">Could not load issues: {shell.error.message}</p>}
      {shell.state === 'loading' && <IssuesSkeleton />}
      {shell.state === 'ready' && <Issues me={shell.data.me} />}
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

/** Triage changes made on this page, laid over the server's list until it reloads. */
type Overrides = Record<number, Pick<IssueSummary, 'status' | 'assignee'>>

function Issues({ me }: { me: string | null }) {
  const api = useApi()
  const [params, setParams] = useSearchParams()
  const drill = useMemo(() => filterFromParams(params), [params])
  const [filter, setFilter] = useState<IssueFilter>(drill?.filter ?? DEFAULT_FILTER)
  const [offset, setOffset] = useState(0)
  const [selectedId, setSelectedId] = useState<number | null>(drill?.issue ?? null)
  const [checked, setChecked] = useState<number[]>([])
  const [overrides, setOverrides] = useState<Overrides>({})
  const [detailVersion, setDetailVersion] = useState(0)
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
      setOffset(0)
      setSelectedId(drill.issue)
    }
  }

  const loaded = useAsync(() => api.issues(toQuery(filter, me ?? '', offset)), [api, filter, offset, me])
  // Keep showing the last page while the next one loads, instead of flashing a skeleton.
  const [page, setPage] = useState<IssuePage | null>(null)
  if (loaded.state === 'ready' && loaded.data !== page) setPage(loaded.data)
  const items = useMemo(() => (page?.items ?? []).map((i) => ({ ...i, ...overrides[i.id] })), [page, overrides])
  const selected = items.find((i) => i.id === selectedId) ?? items[0]

  const changeFilter = (patch: Partial<IssueFilter>) => {
    setFilter((f) => ({ ...f, ...patch }))
    setOffset(0)
    setSelectedId(null)
    setChecked([])
    if (drill) setParams({})
  }
  const toggleIn = (key: FacetKey, value: string) => {
    const current = filter[key] as string[]
    changeFilter({ [key]: current.includes(value) ? current.filter((v) => v !== value) : [...current, value] })
  }

  const remember = (updated: IssueDetail[]) => {
    setOverrides((o) => ({ ...o, ...Object.fromEntries(updated.map((u) => [u.id, { status: u.status, assignee: u.assignee }])) }))
    setDetailVersion((v) => v + 1)
  }
  const apply = async (ids: number[], patch: IssuePatch, message: string) => {
    const before = items.filter((i) => ids.includes(i.id))
    try {
      remember(await Promise.all(ids.map((id) => api.updateIssue(id, patch))))
    } catch (e) {
      setToast({ text: `Not saved: ${(e as Error).message}` })
      return
    }
    setToast({
      text: message,
      undo: async () => {
        const restore = (b: IssueSummary): IssuePatch => ({
          // "Fixed" is not a triage status: scans set it, and undo leaves it.
          ...(b.status !== 'fixed' && { status: b.status }),
          assignee: b.assignee ?? '',
        })
        remember(await Promise.all(before.map((b) => api.updateIssue(b.id, restore(b)))))
      },
    })
  }
  const setStatus = (ids: number[], status: TriageStatus) => apply(ids, { status }, `Marked ${STATUS_LABEL[status].toLowerCase()}`)
  const assignToMe = (ids: number[]) => me && apply(ids, { assignee: me }, 'Assigned to you')

  // j/k move, a assigns to me, c confirms (not while typing).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (/INPUT|SELECT|TEXTAREA/.test((e.target as HTMLElement).tagName) || e.metaKey || e.ctrlKey || !selected) return
      const at = Math.max(0, items.findIndex((i) => i.id === selected.id))
      if (e.key === 'j') setSelectedId(items[Math.min(items.length - 1, at + 1)].id)
      if (e.key === 'k') setSelectedId(items[Math.max(0, at - 1)].id)
      if (e.key === 'a') assignToMe([selected.id])
      if (e.key === 'c') setStatus([selected.id], 'confirmed')
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  })

  if (!page) {
    return loaded.state === 'error' ? <p role="alert">Could not load issues: {loaded.error.message}</p> : <IssuesSkeleton />
  }
  const columns = showFacets ? (wide ? '240px minmax(0,1fr) minmax(0,1.35fr)' : '220px minmax(0,1fr) minmax(0,1.2fr)') : 'minmax(0,1fr) minmax(0,1.35fr)'
  const last = Math.min(page.offset + page.limit, page.total)

  return (
    <>
      <PageHeader
        title="Issues"
        summary={`${formatNumber(page.total)} ${page.total === 1 ? 'issue matches' : 'issues match'} · ${
          filter.project ? `${filter.project} on ${filter.branch ?? 'its main branch'}` : "each project's main branch"
        }`}
      >
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
      {loaded.state === 'error' && <p role="alert">Could not load issues: {loaded.error.message}</p>}

      <div className="grid min-h-[calc(100vh-220px)] gap-px overflow-hidden rounded-xl bg-line" style={{ gridTemplateColumns: columns, boxShadow: '0 0 0 1px var(--sd-line)' }}>
        {showFacets && <Facets page={page} filter={filter} me={me} toggleIn={toggleIn} changeFilter={changeFilter} />}

        <section aria-label="Issue list" aria-busy={loaded.state === 'loading'} className="flex min-w-0 flex-col bg-panel-2">
          <div className="flex min-h-12 flex-wrap items-center gap-2.5 border-b border-line px-3.5">
            <span className="font-semibold">
              {page.total === 0 ? 'No issues' : `${formatNumber(page.offset + 1)}–${formatNumber(last)} of ${formatNumber(page.total)}`}
            </span>
            <span className="flex-1" />
            {checked.length > 0 && (
              <span className="flex items-center gap-1.5 text-[12.5px]">
                <span className="text-fg-muted">{checked.length} selected</span>
                {me && (
                  <button type="button" onClick={() => assignToMe(checked)} className="h-[26px] cursor-pointer rounded-md border-0 bg-brand px-2.5 text-xs font-semibold text-brand-ink">
                    Assign to me
                  </button>
                )}
                <button type="button" onClick={() => setStatus(checked, 'confirmed')} className="h-[26px] cursor-pointer rounded-md border-0 bg-transparent px-2.5 text-xs edge-strong">
                  Confirm
                </button>
              </span>
            )}
          </div>
          {items.length === 0 && (
            <div className="flex flex-col gap-1.5 px-[18px] py-10">
              <span className="text-base font-semibold">Nothing matches</span>
              <span className="text-[13px] text-fg-muted">Either very good news or a filter that's too narrow.</span>
              <Button className="mt-2 self-start" onClick={() => changeFilter(DEFAULT_FILTER)}>
                Reset filters
              </Button>
            </div>
          )}
          <div role="listbox" aria-label="Issues" className="flex flex-1 flex-col overflow-auto">
            {items.map((issue) => {
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
                    aria-label={`Select ${issue.file}:${issue.line}`}
                    checked={checked.includes(issue.id)}
                    onClick={(e) => e.stopPropagation()}
                    onChange={() => setChecked((c) => (c.includes(issue.id) ? c.filter((x) => x !== issue.id) : [...c, issue.id]))}
                    className="m-0 mt-[3px] accent-brand"
                  />
                  <SeverityGlyph severity={issue.severity} className="pt-[3px] text-[10px]" />
                  <span className="flex min-w-0 flex-col gap-1">
                    <span className="text-[13.5px] leading-[1.35] font-medium">{issue.message}</span>
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
                      <span>{formatAge(issue.detectedAt)}</span>
                      {issue.isNew && <Tag accent>NEW</Tag>}
                      {me && issue.assignee === me && <Tag>YOU</Tag>}
                    </span>
                  </span>
                </div>
              )
            })}
          </div>
          {page.total > page.limit && (
            <nav aria-label="Pages" className="flex items-center justify-between gap-2 border-t border-line px-3.5 py-2.5">
              <Button disabled={page.offset === 0} onClick={() => setOffset(Math.max(0, page.offset - PAGE_SIZE))}>
                Previous
              </Button>
              <Button disabled={last >= page.total} onClick={() => setOffset(page.offset + PAGE_SIZE)}>
                Next
              </Button>
            </nav>
          )}
        </section>

        {selected && (
          <IssueView
            id={selected.id}
            version={detailVersion}
            me={me}
            onStatus={(s) => setStatus([selected.id], s)}
            onAssign={() => assignToMe([selected.id])}
          />
        )}
      </div>
      <Toast toast={toast} onDone={clearToast} />
    </>
  )
}

const FACET_OPTIONS: Record<Exclude<FacetKey, 'component'>, { value: string; label: string }[]> = {
  severity: SEVERITY_ORDER.map((s) => ({ value: s, label: SEVERITY[s].label })),
  category: (['vulnerability', 'bug', 'code_smell'] as const).map((c) => ({ value: c, label: CATEGORY_LABEL[c] })),
  status: (['open', 'confirmed', 'accepted', 'fixed'] as const).map((s) => ({ value: s, label: STATUS_LABEL[s] })),
}

function Facets({
  page,
  filter,
  me,
  toggleIn,
  changeFilter,
}: {
  page: IssuePage
  filter: IssueFilter
  me: string | null
  toggleIn: (key: FacetKey, value: string) => void
  changeFilter: (patch: Partial<IssueFilter>) => void
}) {
  // Components come from the data; a selected one stays listed even at zero.
  const components = [...new Set([...Object.keys(page.facets.component), ...filter.component])].sort()
  const groups: { label: string; key: FacetKey; options: { value: string; label: string; mono?: boolean }[] }[] = [
    { label: 'Severity', key: 'severity', options: FACET_OPTIONS.severity },
    { label: 'Category', key: 'category', options: FACET_OPTIONS.category },
    { label: 'Status', key: 'status', options: FACET_OPTIONS.status },
    { label: 'Component', key: 'component', options: components.map((c) => ({ value: c, label: c === '.' ? '(root)' : c, mono: true })) },
  ]
  const toggles = [
    { label: 'Assigned to me', key: 'mine' as const, disabled: !me, title: me ? undefined : 'Sign in with a name to use this' },
    { label: 'New code only', key: 'isNew' as const, disabled: false, title: undefined },
  ]
  const saved: [string, Partial<IssueFilter>, boolean][] = [
    ['My open issues', { mine: true }, !me],
    ['Vulnerabilities', { category: ['vulnerability'] }, false],
    ['On new code', { isNew: true }, false],
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
              disabled={t.disabled}
              title={t.title}
              onClick={() => changeFilter({ [t.key]: !on })}
              className="flex h-8 cursor-pointer items-center rounded-[7px] border-0 px-2.5 text-[13px] disabled:cursor-default disabled:opacity-45"
              style={{
                background: on ? 'var(--sd-accent-soft)' : 'transparent',
                color: on ? 'var(--sd-accent)' : 'var(--sd-text)',
                boxShadow: `inset 0 0 0 1px ${on ? 'var(--sd-accent)' : 'var(--sd-line-2)'}`,
              }}
            >
              {t.label}
            </button>
          )
        })}
      </div>
      {groups.map((g) => (
        <fieldset key={g.key} className="m-0 flex flex-col gap-px border-0 p-0">
          <legend className="pb-2 micro-label">{g.label}</legend>
          {g.options.length === 0 && <span className="px-1.5 text-[12.5px] text-fg-faint">None</span>}
          {g.options.map((o) => {
            const on = (filter[g.key] as string[]).includes(o.value)
            return (
              <label key={o.value} className="flex cursor-pointer items-center gap-[9px] rounded-md px-1.5 py-[5px] text-[13px] hover:bg-hover" style={{ background: on ? 'var(--sd-hover)' : undefined }}>
                <input type="checkbox" checked={on} onChange={() => toggleIn(g.key, o.value)} className="m-0 accent-brand" />
                {g.key === 'severity' && <SeverityGlyph severity={o.value as keyof typeof SEVERITY} className="w-2.5 text-[10px]" />}
                <span className={`min-w-0 flex-1 overflow-hidden text-ellipsis whitespace-nowrap ${o.mono ? 'font-mono text-[11px]' : ''}`}>{o.label}</span>
                <Mono className="text-[10px] text-fg-faint">{page.facets[g.key][o.value] ?? 0}</Mono>
              </label>
            )
          })}
        </fieldset>
      ))}
      <div className="flex flex-col gap-0.5 border-t border-line pt-3">
        <span className="pb-1.5 micro-label">Saved views</span>
        {saved.map(([label, patch, disabled]) => (
          <button
            key={label}
            type="button"
            disabled={disabled}
            onClick={() => changeFilter({ ...DEFAULT_FILTER, ...patch })}
            className="cursor-pointer rounded-md border-0 bg-transparent px-1.5 py-[5px] text-left text-[13px] text-fg-muted hover:bg-hover hover:text-fg disabled:cursor-default disabled:opacity-45"
          >
            {label}
          </button>
        ))}
      </div>
    </aside>
  )
}

/** One issue, loaded on demand: its code, rule and history. */
function IssueView({
  id,
  version,
  me,
  onStatus,
  onAssign,
}: {
  id: number
  version: number
  me: string | null
  onStatus: (s: TriageStatus) => void
  onAssign: () => void
}) {
  const api = useApi()
  const detail = useAsync(() => api.issue(id), [api, id, version])
  // Keep the issue on screen while a change reloads it.
  const [shown, setShown] = useState<IssueDetail | null>(null)
  if (detail.state === 'ready' && detail.data !== shown) setShown(detail.data)
  const issue = shown?.id === id ? shown : null
  if (!issue) {
    return (
      <article aria-label="Issue detail" aria-busy={detail.state === 'loading'} className="flex min-w-0 flex-col gap-3 bg-panel p-5">
        {detail.state === 'error' ? <p role="alert">Could not load the issue: {detail.error.message}</p> : <div className="h-6 w-3/5 rounded bg-hover" />}
      </article>
    )
  }
  const mine = me !== null && issue.assignee === me
  const meta: { k: string; v: string; mono?: boolean; color?: string }[] = [
    { k: 'Location', v: `${issue.file.split('/').pop()}:${issue.line}`, mono: true },
    { k: 'Project', v: `${issue.project} · ${issue.branch}`, mono: true },
    { k: 'Effort', v: formatEffort(issue.effortMinutes), mono: true },
    { k: 'Detected', v: shortDate(issue.detectedAt) + (issue.isNew ? ' · new code' : '') },
    { k: 'Status', v: STATUS_LABEL[issue.status], color: STATUS_COLOR[issue.status] },
    { k: 'Assignee', v: issue.assignee ?? 'Unassigned', color: issue.assignee ? undefined : 'var(--sd-faint)' },
  ]
  const highlighted = Array.from({ length: issue.endLine - issue.line + 1 }, (_, i) => issue.line + i)
  return (
    <article aria-label="Issue detail" className="flex min-w-0 flex-col overflow-auto bg-panel">
      <div className="flex flex-col gap-3 border-b border-line px-5 py-[18px]">
        <div className="flex flex-wrap items-center gap-2.5 text-[12.5px]">
          <SeverityPill severity={issue.severity} />
          <span className="inline-flex h-6 items-center rounded-xl bg-hover px-2.5">{CATEGORY_LABEL[issue.category]}</span>
          <Mono className="text-[10.5px] text-fg-faint">{issue.key.slice(0, 8)}</Mono>
          <Link to={`/rules#${encodeURIComponent(issue.rule)}`} className="font-mono text-[10.5px]">
            {issue.rule}
          </Link>
        </div>
        <h2 className="m-0 text-[21px] leading-[1.25] font-semibold tracking-[-0.02em]">{issue.message}</h2>
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
          <Button primary={!mine && !!me} disabled={mine || !me} onClick={onAssign}>
            {mine ? 'Assigned to you' : me ? 'Assign to me' : 'Assign to me (sign in with a name)'}
          </Button>
          <Button disabled={issue.status === 'confirmed'} onClick={() => onStatus('confirmed')}>
            Confirm
          </Button>
          <Button disabled={issue.status === 'accepted'} onClick={() => onStatus('accepted')}>
            Accept risk
          </Button>
          {(issue.status === 'confirmed' || issue.status === 'accepted') && <Button onClick={() => onStatus('open')}>Reopen</Button>}
        </div>
      </div>
      <div className="flex flex-col border-b border-line">
        <div className="flex justify-between gap-2 border-b border-line bg-panel-2 px-5 py-[9px] font-mono text-[10.5px]">
          <span className="overflow-hidden text-ellipsis whitespace-nowrap text-fg-muted">{issue.file}</span>
          <span className="text-fg-faint">{issue.language ? languageLabel(issue.language) : ''}</span>
        </div>
        {issue.code.length > 0 ? (
          <CodeViewer lines={issue.code} highlighted={highlighted} severity={issue.severity} noteLine={issue.endLine} note={issue.message} />
        ) : (
          <p className="m-0 px-5 py-4 text-[13px] text-fg-faint">The source of this file is not available.</p>
        )}
      </div>
      <div className="flex flex-col gap-5 px-5 pt-[18px] pb-7">
        {issue.ruleDescription && (
          <section className="flex flex-col gap-1.5">
            <h3 className="m-0 font-normal micro-label">Why it matters</h3>
            {issue.ruleName && <p className="m-0 text-sm font-medium">{issue.ruleName}</p>}
            <p className="m-0 max-w-[68ch] text-sm">{issue.ruleDescription}</p>
          </section>
        )}
        {issue.compliant && (
          <section className="flex flex-col gap-2">
            <h3 className="m-0 font-normal micro-label">Compliant example</h3>
            <pre className="m-0 overflow-auto rounded-lg bg-canvas px-3.5 py-3 font-mono text-[11.5px] leading-[1.8]" style={{ boxShadow: 'inset 3px 0 0 var(--sd-ok), inset 0 0 0 1px var(--sd-line)' }}>
              {issue.compliant}
            </pre>
          </section>
        )}
        <section className="flex flex-col gap-0.5">
          <h3 className="m-0 mb-1.5 font-normal micro-label">History</h3>
          {issue.history.length === 0 && <span className="text-[13px] text-fg-faint">No triage changes yet.</span>}
          {issue.history.map((e, i) => (
            <div key={i} className="flex flex-wrap items-baseline gap-2 border-t border-line py-2 text-[13px]">
              <span className="capitalize">{e.field}</span>
              <span className="text-fg-muted">
                {e.oldValue ?? 'none'} → {e.newValue ?? 'none'}
              </span>
              <span className="ml-auto text-[12px] text-fg-faint">
                {e.actor && <>{e.actor === 'api-token' ? 'API token' : `@${e.actor}`} · </>}
                {shortDate(e.at)}
              </span>
            </div>
          ))}
        </section>
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
