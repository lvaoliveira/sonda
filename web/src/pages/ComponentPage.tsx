import { useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router'
import { useApi, useAsync } from '@/api/hooks'
import type { ComponentDetail } from '@/api/types'
import { AppShell } from '@/components/shell/AppShell'
import { Segmented } from '@/components/sonda/controls'
import { Card, MetricGrid, Mono } from '@/components/sonda/layout'
import { Sparkline } from '@/components/sonda/meters'
import { SeverityGlyph } from '@/components/sonda/status'
import { compactCount, formatDebt, formatNumber, shortDate } from '@/lib/format'
import { componentLabel, componentUrl, projectUrl } from '@/lib/links'
import { SEVERITY, SEVERITY_ORDER, languageLabel } from '@/lib/visual'

export function ComponentPage() {
  const api = useApi()
  const { key = '', component = '' } = useParams()
  const [params] = useSearchParams()
  const branch = params.get('branch') ?? undefined
  const detail = useAsync(() => api.component(key, component, branch), [api, key, component, branch])
  return (
    <AppShell
      crumbs={[
        { label: 'Projects', to: '/projects' },
        { label: key, to: projectUrl(key, branch) },
        { label: componentLabel(component), to: componentUrl(key, component, branch) },
      ]}
    >
      {detail.state === 'loading' && <div aria-busy="true" className="h-[600px] rounded-xl bg-panel-2 edge" />}
      {detail.state === 'error' && (
        <div role="alert" className="flex flex-col items-start gap-2 rounded-xl bg-panel-2 px-5 py-8 edge">
          <span className="font-semibold">
            Could not load {componentLabel(component)} in {key}
          </span>
          <span className="text-[13px] text-fg-muted">{detail.error.message}</span>
          <Link to={projectUrl(key, branch)} className="text-[13px]">
            Back to {key} →
          </Link>
        </div>
      )}
      {detail.state === 'ready' && <Component c={detail.data} />}
    </AppShell>
  )
}

function Component({ c }: { c: ComponentDetail }) {
  const issues = (extra: string) =>
    `/issues?project=${encodeURIComponent(c.project)}&branch=${encodeURIComponent(c.branch)}&comp=${encodeURIComponent(c.path)}${extra}`
  const severities = SEVERITY_ORDER.filter((s) => c.issues.bySeverity[s])
    .slice(0, 2)
    .map((s) => `${c.issues.bySeverity[s]} ${SEVERITY[s].label.toLowerCase()}`)
    .join(' · ')
  const tiles: { label: string; value: number | string; sub: string; to?: string }[] = [
    { label: 'Open issues', value: c.issues.total, sub: severities || 'none open', to: issues('') },
    { label: 'On new code', value: c.issues.new, sub: 'issues in changed lines', to: issues('&new') },
    { label: 'Bugs', value: c.issues.byCategory.bug ?? 0, sub: 'Reliability', to: issues('&cat=bug') },
    { label: 'Vulnerabilities', value: c.issues.byCategory.vulnerability ?? 0, sub: 'Security', to: issues('&cat=vulnerability') },
    { label: 'Code smells', value: c.issues.byCategory.code_smell ?? 0, sub: 'Maintainability', to: issues('&cat=code_smell') },
    { label: 'Debt', value: c.issues.debtMinutes ? formatDebt(c.issues.debtMinutes) : '0', sub: 'to fix every issue' },
  ]
  return (
    <div className="grid grid-cols-1 gap-5 min-[1100px]:grid-cols-[220px_minmax(0,1fr)]">
      <nav aria-label={`${c.project} components`} className="flex flex-col gap-0.5 self-start rounded-xl bg-panel-2 p-2 edge">
        <Link to={projectUrl(c.project, c.branch, c.mainBranch)} className="px-2.5 py-1.5 text-[12.5px] text-fg-muted">
          ← {c.project}
        </Link>
        {c.siblings.map((s) => {
          const on = s.path === c.path
          return (
            <Link
              key={s.path}
              to={componentUrl(c.project, s.path, c.branch, c.mainBranch)}
              aria-current={on ? 'page' : undefined}
              className="flex items-center justify-between gap-2 rounded-md px-2.5 py-1.5 text-[12.5px] hover:bg-hover"
              style={{ background: on ? 'var(--sd-panel)' : undefined, color: on ? 'var(--sd-text)' : 'var(--sd-muted)' }}
            >
              <Mono className="truncate">{componentLabel(s.path)}</Mono>
              <Mono className="text-[10.5px] text-fg-faint">{s.issues}</Mono>
            </Link>
          )
        })}
      </nav>

      <div className="flex min-w-0 flex-col gap-5">
        <div className="flex flex-col gap-2">
          <span className="micro-label">Component · {c.project}</span>
          <h1 className="m-0 font-mono text-[26px] leading-[1.15] font-semibold tracking-[-0.02em]">{componentLabel(c.path)}</h1>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 text-[13.5px] text-fg-muted">
            <Mono className="text-[12.5px] text-fg">{c.branch}</Mono>
            <span>{c.languages.map((l) => languageLabel(l.id)).join(' · ')}</span>
            <span>
              {compactCount(c.ncloc)} lines · {formatNumber(c.files)} {c.files === 1 ? 'file' : 'files'}
            </span>
            <span>
              Owner <span className="text-fg">{c.owner ?? 'none in CODEOWNERS'}</span>
            </span>
          </div>
        </div>

        <MetricGrid label="Issues" minCell={220}>
          {tiles.map((t) => (
            <div key={t.label} className="flex flex-col gap-1 bg-panel-2 px-4 py-3">
              <span className="text-[12.5px] text-fg-muted">{t.label}</span>
              <span className="font-mono text-[22px] leading-tight">
                {t.to && t.value !== 0 ? (
                  <Link to={t.to} className="text-fg">
                    {typeof t.value === 'number' ? formatNumber(t.value) : t.value}
                  </Link>
                ) : typeof t.value === 'number' ? (
                  formatNumber(t.value)
                ) : (
                  t.value
                )}
              </span>
              <span className="text-xs text-fg-faint">{t.sub}</span>
            </div>
          ))}
        </MetricGrid>

        <div className="grid grid-cols-1 gap-5 min-[900px]:grid-cols-[minmax(0,1.3fr)_minmax(260px,1fr)]">
          <Trend c={c} />
          <Owners c={c} />
        </div>
        <Files c={c} />
      </div>
    </div>
  )
}

function Trend({ c }: { c: ComponentDetail }) {
  const series = c.trend.map((t) => t.open)
  const first = series[0]
  const last = series[series.length - 1]
  const change = last - first
  const worse = change > 0
  return (
    <Card
      id="trend"
      title="Open issues · 8 weeks"
      subtitle={`${change > 0 ? '+' : change < 0 ? '−' : ''}${Math.abs(change)} since ${shortDate(c.trend[0].date)}`}
      aside={<Mono className="text-[13px]">{formatNumber(last)}</Mono>}
    >
      <Sparkline
        series={series}
        color={worse ? 'var(--sd-crit)' : 'var(--sd-ok)'}
        fill={`color-mix(in oklch, ${worse ? 'var(--sd-crit)' : 'var(--sd-ok)'} 10%, transparent)`}
        className="block h-20 w-full"
        label={`Open issues ${worse ? 'rising' : 'falling or steady'}: ${first} to ${last}`}
      />
      <div className="flex justify-between font-mono text-[9.5px] text-fg-faint">
        <span>{shortDate(c.trend[0].date)}</span>
        <span>{shortDate(c.trend[c.trend.length - 1].date)}</span>
      </div>
    </Card>
  )
}

function Owners({ c }: { c: ComponentDetail }) {
  return (
    <Card id="owners" title="Owners" subtitle="From the CODEOWNERS file uploaded with the analysis">
      {c.owners.length === 0 ? (
        <p className="m-0 text-[13px] text-fg-faint">No CODEOWNERS line matches these files.</p>
      ) : (
        <ul className="m-0 flex list-none flex-col p-0">
          {c.owners.map((o) => (
            <li key={o.owner} className="flex items-center justify-between border-t border-line py-2 text-[13.5px] first:border-t-0">
              <span>{o.owner}</span>
              <Mono className="text-xs text-fg-muted">
                {o.files} of {c.files} files
              </Mono>
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}

type FileSort = 'issues' | 'lines' | 'path'

function Files({ c }: { c: ComponentDetail }) {
  const [sort, setSort] = useState<FileSort>('issues')
  const files = [...c.fileList].sort((a, b) =>
    sort === 'issues' ? b.issues - a.issues || a.path.localeCompare(b.path) : sort === 'lines' ? b.ncloc - a.ncloc || a.path.localeCompare(b.path) : a.path.localeCompare(b.path),
  )
  const th = 'border-b border-line px-2 py-2 text-left font-normal'
  const td = 'border-b border-line px-2 py-[9px]'
  const prefix = c.path === '.' ? '' : `${c.path}/`
  return (
    <Card
      id="files"
      padded={false}
      title="Files"
      subtitle="Click a file to see its issues"
      aside={
        <Segmented
          label="Sort files"
          value={sort}
          onChange={setSort}
          options={[
            { value: 'issues', label: 'Issues' },
            { value: 'lines', label: 'Lines' },
            { value: 'path', label: 'Path' },
          ]}
        />
      }
    >
      <div className="overflow-x-auto">
        <table className="w-full min-w-[600px] border-collapse text-[13.5px]">
          <thead>
            <tr className="font-mono text-[9.5px] tracking-[.06em] text-fg-faint uppercase">
              <th scope="col" className={`${th} px-5`}>
                Path
              </th>
              <th scope="col" className={`${th} text-right`}>
                Issues
              </th>
              <th scope="col" className={`${th} text-right`}>
                Debt
              </th>
              <th scope="col" className={`${th} pr-5 text-right`}>
                Lines
              </th>
            </tr>
          </thead>
          <tbody>
            {files.map((f) => {
              const rel = f.path.startsWith(prefix) ? f.path.slice(prefix.length) : f.path
              const slash = rel.lastIndexOf('/')
              const to = `/issues?project=${encodeURIComponent(c.project)}&branch=${encodeURIComponent(c.branch)}&file=${encodeURIComponent(f.path)}`
              return (
                <tr key={f.path} className="hover:bg-hover">
                  <td className={`${td} px-5`}>
                    <span className="flex items-baseline gap-2">
                      {f.worst ? <SeverityGlyph severity={f.worst} /> : <span className="w-[10px]" />}
                      <Link to={to} className="min-w-0 truncate font-mono text-[12px] text-fg">
                        <span className="text-fg-faint">{slash >= 0 ? rel.slice(0, slash + 1) : ''}</span>
                        {slash >= 0 ? rel.slice(slash + 1) : rel}
                      </Link>
                    </span>
                  </td>
                  <td className={`${td} text-right font-mono text-xs`}>{f.issues ? formatNumber(f.issues) : <span className="text-fg-faint">0</span>}</td>
                  <td className={`${td} text-right font-mono text-xs text-fg-muted`}>{f.debtMinutes ? formatDebt(f.debtMinutes) : '—'}</td>
                  <td className={`${td} pr-5 text-right font-mono text-xs text-fg-muted`}>{formatNumber(f.ncloc)}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </Card>
  )
}
