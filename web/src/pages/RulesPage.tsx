import { Search } from 'lucide-react'
import { useMemo, useState } from 'react'
import { Link, useLocation } from 'react-router'
import { useApi, useAsync } from '@/api/hooks'
import type { Category, Rule, RuleCatalog } from '@/api/types'
import { AppShell } from '@/components/shell/AppShell'
import { Chip } from '@/components/sonda/controls'
import { Mono, PageHeader } from '@/components/sonda/layout'
import { SeverityGlyph, SeverityPill } from '@/components/sonda/status'
import { formatNumber } from '@/lib/format'
import { cweUrl } from '@/lib/links'
import { CATEGORY_LABEL, languageLabel } from '@/lib/visual'

export function RulesPage() {
  const api = useApi()
  const catalog = useAsync(() => api.rules(), [api])
  return (
    <AppShell crumbs={[{ label: 'Rules', to: '/rules' }]}>
      {catalog.state === 'loading' && <div aria-busy="true" className="h-[600px] rounded-xl bg-panel-2 edge" />}
      {catalog.state === 'error' && <p role="alert">Could not load rules: {catalog.error.message}</p>}
      {catalog.state === 'ready' && <Rules catalog={catalog.data} />}
    </AppShell>
  )
}

/** Read-only: rules are configured per repository in sonda.toml, not on the server. */
function Rules({ catalog }: { catalog: RuleCatalog }) {
  const location = useLocation()
  const rules = catalog.rules
  const [q, setQ] = useState('')
  const [lang, setLang] = useState('')
  const [cat, setCat] = useState<Category | ''>('')
  const [selected, setSelected] = useState(() => decodeURIComponent(location.hash.slice(1)))

  const list = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return rules
      .filter(
        (r) =>
          (!needle || `${r.id} ${r.name} ${r.tags.join(' ')}`.toLowerCase().includes(needle)) &&
          (!lang || r.languages.includes(lang)) &&
          (!cat || r.category === cat),
      )
      .sort((a, b) => b.openIssues - a.openIssues)
  }, [rules, q, lang, cat])
  const rule = list.find((r) => r.id === selected) ?? list[0]

  return (
    <>
      <PageHeader
        title="Rules"
        summary={
          <>
            {formatNumber(catalog.total)} rules across {catalog.languages.length} languages · configured per repository in{' '}
            <Mono className="text-xs text-fg">sonda.toml</Mono>
          </>
        }
      >
        <label className="flex h-9 w-[340px] max-w-full items-center gap-2 rounded-lg bg-canvas px-3 edge">
          <Search size={14} strokeWidth={2} aria-hidden="true" className="text-fg-faint" />
          <input
            aria-label="Search rules"
            placeholder="Search by name, id, tag or CWE"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            className="min-w-0 flex-1 border-0 bg-transparent text-[13.5px] outline-none placeholder:text-fg-faint"
          />
        </label>
      </PageHeader>

      <div className="flex flex-wrap items-center gap-4">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="mr-1 micro-label">Language</span>
          {catalog.languages.map((l) => (
            <Chip key={l.id} on={lang === l.id} onClick={() => setLang(lang === l.id ? '' : l.id)}>
              {languageLabel(l.id)} <span className="font-mono text-[10px] text-fg-faint">{l.rules}</span>
            </Chip>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="mr-1 micro-label">Type</span>
          {(['bug', 'vulnerability', 'code_smell'] as const).map((c) => (
            <Chip key={c} on={cat === c} onClick={() => setCat(cat === c ? '' : c)}>
              {CATEGORY_LABEL[c]}
            </Chip>
          ))}
        </div>
      </div>

      <div
        className="grid min-h-[600px] grid-cols-1 gap-px overflow-hidden rounded-xl bg-line min-[1100px]:grid-cols-[minmax(320px,0.85fr)_minmax(0,1.4fr)]"
        style={{ boxShadow: '0 0 0 1px var(--sd-line)' }}
      >
        <div role="listbox" aria-label="Rules" className="flex max-h-[820px] flex-col overflow-auto bg-panel-2">
          <div className="flex justify-between border-b border-line px-3.5 py-2.5 text-[12.5px] text-fg-faint">
            <span>
              {list.length} of {formatNumber(catalog.total)} shown
            </span>
            <span>sorted by open issues</span>
          </div>
          {list.length === 0 && (
            <div className="flex flex-col gap-1.5 px-4 py-8">
              <span className="font-semibold">No rules match “{q}”</span>
              <span className="text-[13px] text-fg-muted">Try a CWE id like cwe-89, or a tag like owasp-a03.</span>
            </div>
          )}
          {list.map((r) => {
            const on = r.id === rule?.id
            return (
              <div
                key={r.id}
                role="option"
                aria-selected={on}
                tabIndex={0}
                onClick={() => setSelected(r.id)}
                onKeyDown={(e) => e.key === 'Enter' && setSelected(r.id)}
                className="flex cursor-pointer flex-col gap-1 border-b border-line py-3 pr-3.5 pl-[11px] hover:bg-hover"
                style={{
                  borderLeft: `3px solid ${on ? 'var(--sd-accent)' : 'transparent'}`,
                  background: on ? 'var(--sd-panel)' : undefined,
                }}
              >
                <span className="flex items-baseline gap-2.5">
                  <SeverityGlyph severity={r.severity} />
                  <span className="min-w-0 flex-1 text-[13.5px] leading-[1.35] font-medium">{r.name}</span>
                  <span className="font-mono text-[10.5px] text-fg-faint">{r.openIssues}</span>
                </span>
                <span className="flex flex-wrap gap-2 pl-5 text-xs text-fg-faint">
                  <span className="font-mono text-[10.5px]">{r.id}</span>
                  <span>·</span>
                  <span>
                    {CATEGORY_LABEL[r.category]} · {r.languages.map(languageLabel).join(', ')}
                  </span>
                  {!r.onByDefault && (
                    <>
                      <span>·</span>
                      <span>off by default</span>
                    </>
                  )}
                </span>
              </div>
            )
          })}
        </div>
        {rule && <RuleDetail rule={rule} />}
      </div>
    </>
  )
}

function RuleDetail({ rule }: { rule: Rule }) {
  return (
    <article className="flex min-w-0 flex-col gap-5 overflow-auto bg-panel px-[22px] py-5">
      <div className="flex flex-col gap-2.5">
        <div className="flex flex-wrap items-center gap-2.5 text-[12.5px]">
          <SeverityPill severity={rule.severity} />
          <span className="inline-flex h-6 items-center rounded-xl bg-hover px-2.5">{CATEGORY_LABEL[rule.category]}</span>
          <span className="text-fg-muted">{rule.languages.map(languageLabel).join(', ')}</span>
          {!rule.onByDefault && <span className="inline-flex h-6 items-center rounded-xl bg-hover px-2.5 text-fg-muted">Off by default</span>}
          <Mono className="text-[10.5px] text-fg-faint">{rule.id}</Mono>
        </div>
        <h2 className="m-0 text-[22px] leading-[1.25] font-semibold tracking-[-0.025em]">{rule.name}</h2>
        <p className="m-0 max-w-[70ch] text-sm text-fg-muted">{rule.description}</p>
        {(rule.cwe.length > 0 || rule.owasp.length > 0) && (
          <p className="m-0 flex flex-wrap items-baseline gap-x-3 gap-y-1 text-[13px] text-fg-muted">
            <span className="micro-label">Standards</span>
            {rule.cwe.map((c) => (
              <a key={c} href={cweUrl(c)} target="_blank" rel="noreferrer" className="font-mono text-[12px]">
                CWE-{c}
              </a>
            ))}
            {rule.owasp.map((o) => (
              <span key={o.id}>
                OWASP {o.id}:2021 {o.title}
              </span>
            ))}
          </p>
        )}
        <div className="flex flex-wrap gap-1.5">
          {rule.tags.map((t) => (
            <Mono key={t} className="rounded-[10px] bg-hover px-2 py-0.5 text-[10.5px] text-fg-muted">
              {t}
            </Mono>
          ))}
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-3.5 rounded-[10px] bg-panel-2 px-3.5 py-3 edge">
        <span className="text-[12.5px] text-fg-muted">
          <Mono className="text-[11.5px] text-fg">{rule.openIssues}</Mono> open issues in <Mono className="text-[11.5px] text-fg">{rule.projects}</Mono>{' '}
          {rule.projects === 1 ? 'project' : 'projects'} · <Mono className="text-[11.5px] text-fg">{rule.effortMinutes}</Mono> min to fix each
        </span>
        <Link to="/issues" className="ml-auto text-[13px]">
          See issues →
        </Link>
      </div>

      {(rule.noncompliant || rule.compliant) && (
        <div className="grid grid-cols-[repeat(auto-fit,minmax(min(100%,300px),1fr))] gap-3">
          {rule.noncompliant && <CodeSample tone="crit" mark="✕" label="Noncompliant" code={rule.noncompliant} />}
          {rule.compliant && <CodeSample tone="ok" mark="✓" label="Compliant" code={rule.compliant} />}
        </div>
      )}

      <section className="flex flex-col gap-2">
        <h3 className="m-0 font-normal micro-label">Configure</h3>
        <p className="m-0 text-[13px] text-fg-muted">
          Rules are configured per repository, in its sonda.toml. To turn this one {rule.onByDefault ? 'off' : 'on (it is off by default)'}, or change its
          severity:
        </p>
        <pre className="m-0 overflow-auto rounded-lg bg-canvas px-3.5 py-3 font-mono text-[11.5px] leading-[1.8] edge">
          {`[rules]\n${rule.onByDefault ? 'disabled' : 'enabled'} = ["${rule.id}"]\n\n[rules.severity]\n"${rule.id}" = "major"`}
        </pre>
      </section>
    </article>
  )
}

function CodeSample({ tone, mark, label, code }: { tone: 'crit' | 'ok'; mark: string; label: string; code: string }) {
  return (
    <div className="flex flex-col overflow-hidden rounded-[10px] edge">
      <div className="flex items-center gap-2 px-3 py-2 text-[12.5px] font-semibold" style={{ background: `var(--sd-${tone}-soft)`, color: `var(--sd-${tone})` }}>
        <span aria-hidden="true">{mark}</span>
        {label}
      </div>
      <pre className="m-0 flex-1 overflow-auto bg-canvas px-3.5 py-3 font-mono text-[11.5px] leading-[1.8]">{code}</pre>
    </div>
  )
}
