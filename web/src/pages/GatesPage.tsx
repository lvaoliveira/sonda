import { X } from 'lucide-react'
import { type SubmitEvent, useId, useState } from 'react'
import { Link, useLocation } from 'react-router'
import { useApi, useAsync } from '@/api/hooks'
import type { GateConditionInput, GateList, GateMetric, QualityGate } from '@/api/types'
import { AppShell } from '@/components/shell/AppShell'
import { Button } from '@/components/sonda/controls'
import { Drawer, DrawerActions } from '@/components/sonda/Drawer'
import { Card, Mono, PageHeader } from '@/components/sonda/layout'
import { GateDot, GateStatus } from '@/components/sonda/status'
import { countOf, formatAge, shortDate } from '@/lib/format'
import { projectUrl } from '@/lib/links'
import { GATE } from '@/lib/visual'

export function GatesPage() {
  const api = useApi()
  const data = useAsync(() => Promise.all([api.gates(), api.shell()]), [api])
  return (
    <AppShell crumbs={[{ label: 'Quality gates', to: '/gates' }]}>
      {data.state === 'loading' && <div aria-busy="true" className="h-[600px] rounded-xl bg-panel-2 edge" />}
      {data.state === 'error' && <p role="alert">Could not load quality gates: {data.error.message}</p>}
      {data.state === 'ready' && <Gates list={data.data[0]} isAdmin={data.data[1].isAdmin} reload={data.reload} />}
    </AppShell>
  )
}

/** The gate open in the editor's drawer, if any: a new one (copying `from`), or one being edited. */
type Editing = { gate: QualityGate | null; from: QualityGate | null } | null

function Gates({ list, isAdmin, reload }: Readonly<{ list: GateList; isAdmin: boolean; reload: () => void }>) {
  const { gates, metrics } = list
  const location = useLocation()
  const [selected, setSelected] = useState(() => location.hash.slice(1))
  const [editing, setEditing] = useState<Editing>(null)
  const gate = gates.find((g) => g.id === selected) ?? gates[0]
  const select = (id: string) => {
    setSelected(id)
    setEditing(null)
    window.history.replaceState(null, '', `#${id}`)
  }
  const saved = (id: number) => {
    setEditing(null)
    setSelected(`server-${id}`)
    window.history.replaceState(null, '', `#server-${id}`)
    reload()
  }
  return (
    <>
      <PageHeader
        title="Quality gates"
        summary={
          <>
            The conditions every analysis must meet · from each repository's <Mono className="text-xs text-fg">sonda.toml</Mono>, where projects using the same
            conditions share a gate, or a gate on the server that a project's settings choose
          </>
        }
      >
        {isAdmin && (
          <Button primary onClick={() => setEditing({ gate: null, from: gate ?? null })}>
            New gate
          </Button>
        )}
      </PageHeader>
      {gates.length === 0 ? (
        <div className="flex flex-col gap-2 rounded-xl bg-panel-2 px-5 py-8 edge">
          <span className="font-semibold">No gates yet</span>
          <span className="text-[13px] text-fg-muted">Gates appear once a project has been analyzed, or an admin creates one.</span>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-5 min-[1100px]:grid-cols-[300px_minmax(0,1fr)]">
          <ul aria-label="Gates" className="m-0 flex list-none flex-col gap-2 self-start p-0">
            {gates.map((g) => {
              const on = g.id === gate?.id
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
                      {g.server && <span className="rounded-[10px] bg-hover px-[7px] py-px text-[11px] font-normal text-fg-muted">server</span>}
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
          {gate && (
            <GateDetail
              gate={gate}
              isAdmin={isAdmin}
              onEdit={() => setEditing({ gate, from: gate })}
              onDeleted={() => {
                setSelected('')
                reload()
              }}
            />
          )}
        </div>
      )}
      {editing && (
        <GateEditor
          key={editing.gate?.id ?? 'new'}
          gate={editing.gate}
          from={editing.from}
          gates={gates}
          metrics={metrics}
          onSaved={saved}
          onCancel={() => setEditing(null)}
        />
      )}
    </>
  )
}

function GateDetail({ gate, isAdmin, onEdit, onDeleted }: Readonly<{ gate: QualityGate; isAdmin: boolean; onEdit: () => void; onDeleted: () => void }>) {
  const api = useApi()
  const [error, setError] = useState<string | null>(null)
  const total = gate.projects.length
  const th = 'border-b border-line px-2 py-2 text-left font-normal'
  const td = 'border-b border-line px-2 py-[10px]'
  const remove = async (id: number) => {
    setError(null)
    try {
      await api.deleteQualityGate(id)
      onDeleted()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }
  const subtitle = gateOrigin(gate)
  return (
    <div className="flex min-w-0 flex-col gap-5">
      <Card
        id="conditions"
        padded={false}
        title={gate.name}
        subtitle={subtitle}
        aside={
          isAdmin &&
          gate.server && (
            <span className="flex gap-2">
              <Button onClick={onEdit}>Edit</Button>
              <Button onClick={() => void remove(gate.server!.id)} className="text-crit">
                Delete
              </Button>
            </span>
          )
        }
      >
        {error && (
          <p role="alert" className="m-0 px-5 pb-3 text-[13px] text-crit">
            {error}
          </p>
        )}
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
                <tr key={`${c.metric}-${c.op}-${c.threshold}`}>
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
          {total === 0 && (
            <p className="m-0 text-[13px] text-fg-muted">
              {gate.server ? 'No project uses it yet: choose it in a project’s Settings.' : 'No project uses it now.'}
            </p>
          )}
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

      <Card
        id="toml"
        title="Configure"
        subtitle={
          gate.server
            ? 'A project uses it once its Settings choose it; it then wins over the repository’s sonda.toml'
            : 'A repository sets its gate in sonda.toml, unless its project’s Settings choose a server gate'
        }
      >
        <pre className="m-0 overflow-auto rounded-lg bg-canvas px-3.5 py-3 font-mono text-[11.5px] leading-[1.8] edge">
          {gate.conditions.map((c) => `[[gate.conditions]]\nmetric = "${c.metric}"\nop = "${c.op}"\nthreshold = ${c.threshold}\n`).join('\n')}
        </pre>
      </Card>
    </div>
  )
}

/** Where a gate is defined. */
function gateOrigin(gate: QualityGate): string {
  if (gate.server) return `On the server · changed by ${gate.server.changedBy}, ${shortDate(gate.server.changedAt)}`
  return gate.isDefault ? 'sonda’s default gate: what sonda init writes' : 'Set in these projects’ sonda.toml'
}

const NEW_CONDITION: GateConditionInput = { metric: 'new_bugs', op: 'gt', threshold: 0 }

/** A condition being edited, with a key that stays with it when another is removed. */
type ConditionRow = GateConditionInput & { key: number }
let conditionKeys = 0
const conditionRow = (c: GateConditionInput): ConditionRow => ({ ...c, key: conditionKeys++ })

/** Creating a server gate, or editing one (ADR-0017), in a drawer: a name and sonda.toml's conditions. */
function GateEditor({
  gate,
  from,
  gates,
  metrics,
  onSaved,
  onCancel,
}: Readonly<{
  gate: QualityGate | null
  from: QualityGate | null
  gates: QualityGate[]
  metrics: GateMetric[]
  onSaved: (id: number) => void
  onCancel: () => void
}>) {
  const api = useApi()
  const formId = useId()
  const conditionsOf = (g: QualityGate | null): ConditionRow[] =>
    (g ? g.conditions : [NEW_CONDITION]).map(({ metric, op, threshold }) => conditionRow({ metric, op, threshold }))
  const [name, setName] = useState(gate?.name ?? '')
  const [conditions, setConditions] = useState(() => conditionsOf(from))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const set = (i: number, patch: Partial<GateConditionInput>) => setConditions((cs) => cs.map((c, j) => (j === i ? { ...c, ...patch } : c)))
  const remove = (key: number) => setConditions((cs) => cs.filter((c) => c.key !== key))
  const submit = async (e: SubmitEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const inputs = conditions.map(({ metric, op, threshold }) => ({ metric, op, threshold }))
      const saved = gate?.server ? await api.updateQualityGate(gate.server.id, name, inputs) : await api.createQualityGate(name, inputs)
      onSaved(saved.id)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
      setBusy(false)
    }
  }
  const control = 'h-8 rounded-md border-0 bg-canvas px-2 text-[13px] text-fg edge'
  return (
    <Drawer
      eyebrow="Quality gates"
      title={gate ? `Edit ${gate.name}` : 'New gate'}
      subtitle={gate ? `Its ${countOf(gate.projects.length, 'project is', 'projects are')} judged again when you save` : 'A gate on the server, which projects choose in their Settings'}
      width={680}
      onClose={onCancel}
      footer={<DrawerActions form={formId} submit={gate ? 'Save' : 'Create'} busy={busy ? 'Saving…' : undefined} disabled={!name.trim()} onCancel={onCancel} />}
    >
      <form id={formId} onSubmit={(e) => void submit(e)} className="flex flex-col gap-4">
        <div className="flex flex-wrap items-center gap-2">
          <input aria-label="Gate name" placeholder="Name, such as Strict" maxLength={100} value={name} onChange={(e) => setName(e.target.value)} className={`${control} w-[260px] max-w-full`} />
          {!gate && (
            <label className="flex items-center gap-2 text-[13px] text-fg-muted">
              <span>Start from</span>
              <select
                aria-label="Start from"
                value={from?.id ?? ''}
                onChange={(e) => setConditions(conditionsOf(gates.find((g) => g.id === e.target.value) ?? null))}
                className={`${control} max-w-[220px]`}
              >
                <option value="">One condition</option>
                {gates.map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.name}
                  </option>
                ))}
              </select>
            </label>
          )}
        </div>
        <ul aria-label="Conditions" className="m-0 flex list-none flex-col p-0">
          {conditions.map((c, i) => {
            const metric = metrics.find((m) => m.id === c.metric)
            return (
              <li key={c.key} className="flex flex-wrap items-center gap-2 border-t border-line py-2.5 text-[13px] first:border-t-0 first:pt-0">
                <span className="text-fg-muted">Fails when</span>
                <select aria-label={`Metric ${i + 1}`} value={c.metric} onChange={(e) => set(i, { metric: e.target.value })} className={`${control} w-[220px] max-w-full`}>
                  {metrics.map((m) => (
                    <option key={m.id} value={m.id}>
                      {m.name}
                    </option>
                  ))}
                </select>
                <select aria-label={`Operator ${i + 1}`} value={c.op} onChange={(e) => set(i, { op: e.target.value as 'gt' | 'lt' })} className={control}>
                  <option value="gt">is greater than</option>
                  <option value="lt">is less than</option>
                </select>
                <input
                  aria-label={`Threshold ${i + 1}`}
                  type="number"
                  step="any"
                  required
                  value={Number.isNaN(c.threshold) ? '' : c.threshold}
                  onChange={(e) => set(i, { threshold: e.target.value === '' ? Number.NaN : Number(e.target.value) })}
                  className={`${control} w-24 font-mono`}
                />
                {metric?.percent && <span className="text-fg-muted">%</span>}
                <button
                  type="button"
                  aria-label={`Remove condition ${i + 1}`}
                  title="Remove"
                  onClick={() => remove(c.key)}
                  disabled={conditions.length === 1}
                  className="grid size-8 cursor-pointer place-items-center rounded-lg border-0 bg-transparent text-fg-muted edge-strong disabled:cursor-default disabled:opacity-45"
                >
                  <X size={14} strokeWidth={2} aria-hidden="true" />
                </button>
              </li>
            )
          })}
        </ul>
        <div>
          <Button onClick={() => setConditions((cs) => [...cs, conditionRow(NEW_CONDITION)])}>Add a condition</Button>
        </div>
        {error && (
          <p role="alert" className="m-0 text-[13px] text-crit">
            {error}
          </p>
        )}
      </form>
    </Drawer>
  )
}
