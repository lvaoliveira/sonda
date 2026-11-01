import { useCallback, useState } from 'react'
import { Link } from 'react-router'
import { useApi, useAsync } from '@/api/hooks'
import type { Rule, RuleCatalog } from '@/api/types'
import { AppShell } from '@/components/shell/AppShell'
import { Button } from '@/components/sonda/controls'
import { Mono, PageHeader } from '@/components/sonda/layout'
import { RuleBrowser, RuleSearch } from '@/components/sonda/RuleBrowser'
import { formatNumber, shortDate } from '@/lib/format'

export function RulesPage() {
  const api = useApi()
  const catalog = useAsync(() => api.rules(), [api])
  const shell = useAsync(() => api.shell(), [api])
  const isAdmin = shell.state === 'ready' && shell.data.isAdmin
  return (
    <AppShell crumbs={[{ label: 'Rules', to: '/rules' }]}>
      {catalog.state === 'loading' && <div aria-busy="true" className="h-[600px] rounded-xl bg-panel-2 edge" />}
      {catalog.state === 'error' && <p role="alert">Could not load rules: {catalog.error.message}</p>}
      {catalog.state === 'ready' && <Rules catalog={catalog.data} isAdmin={isAdmin} reload={catalog.reload} />}
    </AppShell>
  )
}

/** The catalog, with where each rule is off; admins turn rules off for every project (ADR-0016). */
function Rules({ catalog, isAdmin, reload }: { catalog: RuleCatalog; isAdmin: boolean; reload: () => void }) {
  const [q, setQ] = useState('')
  const count = useCallback((r: Rule) => r.openIssues, [])
  return (
    <>
      <PageHeader
        title="Rules"
        summary={
          <>
            {formatNumber(catalog.total)} rules across {catalog.languages.length} languages · each project's rules are on its{' '}
            <Mono className="text-xs text-fg">Rules</Mono> page
          </>
        }
      >
        <RuleSearch q={q} setQ={setQ} />
      </PageHeader>
      <RuleBrowser
        rules={catalog.rules}
        total={catalog.total}
        languages={catalog.languages}
        count={count}
        sortLabel="sorted by open issues"
        search={{ q, setQ }}
        listTags={(r) =>
          r.serverOff && (
            <>
              <span>·</span>
              <span className="text-warn">off in the default profile</span>
            </>
          )
        }
        summary={(r) => (
          <>
            <span className="text-[12.5px] text-fg-muted">
              <Mono className="text-[11.5px] text-fg">{r.openIssues}</Mono> open issues in <Mono className="text-[11.5px] text-fg">{r.projects}</Mono>{' '}
              {r.projects === 1 ? 'project' : 'projects'} · <Mono className="text-[11.5px] text-fg">{r.effortMinutes}</Mono> min to fix each
            </span>
            <Link to="/issues" className="ml-auto text-[13px]">
              See issues →
            </Link>
          </>
        )}
        panel={(r) => <WhereOff key={r.id} rule={r} isAdmin={isAdmin} reload={reload} />}
      />
    </>
  )
}

/** Where the rule is off, and for admins, turning it off in the default profile (ADR-0016, ADR-0018). */
function WhereOff({ rule, isAdmin, reload }: { rule: Rule; isAdmin: boolean; reload: () => void }) {
  const api = useApi()
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const set = async (off: boolean) => {
    setBusy(true)
    setError(null)
    try {
      await api.setRuleOff(rule.id, off, note.trim() || undefined)
      setNote('')
      reload()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }
  const off = rule.offIn
  return (
    <section aria-label="Where it's off" className="flex flex-col gap-2">
      <h3 className="m-0 font-normal micro-label">Where it's off</h3>
      {rule.serverOff && (
        <p className="m-0 text-[13px]">
          <span className="font-semibold text-warn">Off in the default profile</span>
          <span className="text-fg-muted">
            {' '}
            · by {rule.serverOff.changedBy}, {shortDate(rule.serverOff.changedAt)}
            {rule.serverOff.note && <>: “{rule.serverOff.note}”</>}. A project can turn it back on in its rules.
          </span>
        </p>
      )}
      <p className="m-0 text-[13px] text-fg-muted">
        {off
          ? `Off in ${formatNumber(off.sondaToml + off.server)} ${off.sondaToml + off.server === 1 ? 'project' : 'projects'}: ${off.sondaToml} by their sonda.toml, ${off.server} on the server.`
          : rule.onByDefault
            ? 'On in every project.'
            : 'Off by default, and no project turns it on.'}
      </p>
      {rule.inProfiles.length > 0 && (
        <p className="m-0 text-[13px] text-fg-muted">
          In profiles:{' '}
          {rule.inProfiles.map((p, i) => (
            <span key={p.id}>
              {i > 0 && ', '}
              {p.name} ({p.on ? 'on' : 'off'}
              {p.severity && `, ${p.severity}`})
            </span>
          ))}
        </p>
      )}
      {isAdmin && (
        <div className="flex flex-wrap items-center gap-2">
          {!rule.serverOff && (
            <input
              aria-label="Why it's off"
              placeholder="Why (optional)"
              maxLength={500}
              value={note}
              onChange={(e) => setNote(e.target.value)}
              className="h-8 w-[260px] rounded-md border-0 bg-canvas px-2 text-[13px] edge"
            />
          )}
          <Button onClick={() => void set(!rule.serverOff)} disabled={busy}>
            {rule.serverOff ? 'Turn back on in the default profile' : 'Turn off in the default profile'}
          </Button>
        </div>
      )}
      {error && (
        <p role="alert" className="m-0 text-xs text-crit">
          {error}
        </p>
      )}
    </section>
  )
}
