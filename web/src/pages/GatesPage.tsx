import { useState } from 'react'
import { Link, useLocation } from 'react-router'
import { useApi, useAsync } from '@/api/hooks'
import type { QualityGate } from '@/api/types'
import { AppShell } from '@/components/shell/AppShell'
import { Card, Mono, PageHeader } from '@/components/sonda/layout'
import { GateDot, GateStatus } from '@/components/sonda/status'
import { formatAge, shortDate } from '@/lib/format'
import { projectUrl } from '@/lib/links'
import { GATE } from '@/lib/visual'

export function GatesPage() {
  const api = useApi()
  const gates = useAsync(() => api.gates(), [api])
  return (
    <AppShell crumbs={[{ label: 'Quality gates', to: '/gates' }]}>
      {gates.state === 'loading' && <div aria-busy="true" className="h-[600px] rounded-xl bg-panel-2 edge" />}
      {gates.state === 'error' && <p role="alert">Could not load quality gates: {gates.error.message}</p>}
      {gates.state === 'ready' && <Gates gates={gates.data} />}
    </AppShell>
  )
}

function Gates({ gates }: { gates: QualityGate[] }) {
  const location = useLocation()
  const [selected, setSelected] = useState(() => location.hash.slice(1))
  const gate = gates.find((g) => g.id === selected) ?? gates[0]
  const select = (id: string) => {
    setSelected(id)
    window.history.replaceState(null, '', `#${id}`)
  }
  return (
    <>
      <PageHeader
        title="Quality gates"
        summary={
          <>
            The conditions every analysis must meet · defined per repository in <Mono className="text-xs text-fg">sonda.toml</Mono>; projects using the same
            conditions share a gate
          </>
        }
      />
      {gates.length === 0 ? (
        <div className="flex flex-col gap-2 rounded-xl bg-panel-2 px-5 py-8 edge">
          <span className="font-semibold">No gates yet</span>
          <span className="text-[13px] text-fg-muted">Gates appear once a project has been analyzed.</span>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-5 min-[1100px]:grid-cols-[300px_minmax(0,1fr)]">
          <ul aria-label="Gates" className="m-0 flex list-none flex-col gap-2 self-start p-0">
            {gates.map((g) => {
              const on = g.id === gate.id
              const failing = g.projects.filter((p) => p.state === 'failed').length
              return (
                <li key={g.id}>
                  <button
                    type="button"
                    aria-pressed={on}
                    onClick={() => select(g.id)}
                    className="flex w-full cursor-pointer flex-col gap-1 rounded-xl border-0 bg-panel-2 px-4 py-3 text-left edge hover:bg-hover"
                    style={{ boxShadow: on ? 'inset 3px 0 0 var(--sd-accent), 0 0 0 1px var(--sd-line)' : undefined }}
                  >
                    <span className="flex items-center gap-2 text-[14px] font-semibold text-fg">
                      {g.name}
                      {g.isDefault && <span className="rounded-[10px] bg-hover px-[7px] py-px text-[11px] font-normal text-fg-muted">sonda default</span>}
                    </span>
                    <span className="text-xs text-fg-muted">
                      {g.conditions.length} {g.conditions.length === 1 ? 'condition' : 'conditions'} · {g.projects.length}{' '}
                      {g.projects.length === 1 ? 'project' : 'projects'}
                      {failing > 0 && <span className="text-crit"> · {failing} blocking</span>}
                    </span>
                    <span className="font-mono text-[11px] text-fg-faint">{g.passRate == null ? 'no evaluations' : `${g.passRate}% of the last ${g.evaluations.length} passed`}</span>
                  </button>
                </li>
              )
            })}
          </ul>
          <GateDetail gate={gate} />
        </div>
      )}
    </>
  )
}

function GateDetail({ gate }: { gate: QualityGate }) {
  const total = gate.projects.length
  const th = 'border-b border-line px-2 py-2 text-left font-normal'
  const td = 'border-b border-line px-2 py-[10px]'
  return (
    <div className="flex min-w-0 flex-col gap-5">
      <Card id="conditions" padded={false} title={gate.name} subtitle={gate.isDefault ? 'sonda’s default gate: what sonda init writes' : 'Set in these projects’ sonda.toml'}>
        <div className="relative overflow-x-auto">
          <table className="w-full min-w-[560px] border-collapse text-[13.5px]">
            <thead>
              <tr className="font-mono text-[9.5px] tracking-[.06em] text-fg-faint uppercase">
                <th scope="col" className={`${th} px-5`}>
                  Condition
                </th>
                <th scope="col" className={th}>
                  Fails when
                </th>
                <th scope="col" className={`${th} pr-5 text-right`}>
                  Failing now
                </th>
              </tr>
            </thead>
            <tbody>
              {gate.conditions.map((c) => (
                <tr key={c.metric}>
                  <td className={`${td} px-5`}>{c.label}</td>
                  <td className={`${td} font-mono text-xs text-fg-muted`}>
                    {c.metric} {c.op === 'gt' ? '>' : '<'} {c.threshold}
                  </td>
                  <td className={`${td} pr-5 text-right text-[13px]`}>
                    <span style={{ color: c.failing ? 'var(--sd-crit)' : 'var(--sd-ok)' }}>
                      {c.failing} of {total}
                    </span>
                    {c.noData > 0 && <span className="block text-xs text-fg-faint">{c.noData} without data</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <div className="grid grid-cols-1 gap-5 min-[900px]:grid-cols-2">
        <Card id="assigned" title="Assigned to" subtitle={`${total} ${total === 1 ? 'project' : 'projects'}, as of their latest main-branch analysis`}>
          <ul className="m-0 flex list-none flex-col p-0">
            {gate.projects.map((p) => (
              <li key={p.project} className="flex items-center justify-between gap-3 border-t border-line py-2 text-[13.5px] first:border-t-0">
                <Link to={projectUrl(p.project)} className="text-fg">
                  {p.project}
                </Link>
                <span className="flex items-center gap-3">
                  <GateStatus state={p.state} className="text-[12.5px]" />
                  <Mono className="w-8 text-right text-[11px] text-fg-faint">{formatAge(p.analyzedAt)}</Mono>
                </span>
              </li>
            ))}
          </ul>
        </Card>
        <Card
          id="evaluations"
          title={`Last ${gate.evaluations.length} evaluations`}
          subtitle={gate.passRate == null ? 'No evaluations yet' : `${gate.passRate}% passed`}
        >
          <ol aria-label="Evaluations, newest first" className="m-0 flex list-none flex-wrap gap-1.5 p-0">
            {gate.evaluations.map((e) => (
              <li key={e.analysis}>
                <Link
                  to={`/analyses/${e.analysis}`}
                  title={`${e.project} · ${shortDate(e.analyzedAt)} · ${GATE[e.state].label}`}
                  className="grid size-6 place-items-center rounded-md bg-canvas edge hover:bg-hover"
                >
                  <GateDot state={e.state} />
                </Link>
              </li>
            ))}
          </ol>
          {gate.mostCommonFailure && (
            <p className="m-0 border-t border-line pt-3 text-[13px] text-fg-muted">
              Most common failure: <span className="text-fg">{gate.mostCommonFailure}</span>
            </p>
          )}
        </Card>
      </div>

      <Card id="toml" title="Configure" subtitle="Gates are read-only here: each repository sets its gate in sonda.toml">
        <pre className="m-0 overflow-auto rounded-lg bg-canvas px-3.5 py-3 font-mono text-[11.5px] leading-[1.8] edge">
          {gate.conditions.map((c) => `[[gate.conditions]]\nmetric = "${c.metric}"\nop = "${c.op}"\nthreshold = ${c.threshold}\n`).join('\n')}
        </pre>
      </Card>
    </div>
  )
}
