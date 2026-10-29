import type { GateState, Severity } from '@/api/types'
import { GATE, SEVERITY } from '@/lib/visual'

/** Gate status: a shaped dot plus a word, never a filled pill. */
export function GateStatus({ state, className = 'text-[13px]' }: { state: GateState; className?: string }) {
  const g = GATE[state]
  return (
    <span className={`inline-flex items-center gap-[7px] whitespace-nowrap ${className}`} style={{ color: g.color }}>
      <span aria-hidden="true" className="size-2 shrink-0" style={{ borderRadius: g.radius, background: g.dot, boxShadow: g.ring }} />
      {g.label}
    </span>
  )
}

/** Just the dot, for dense places (trees, chips); always paired with a text label nearby. */
export function GateDot({ state }: { state: GateState }) {
  const g = GATE[state]
  return (
    <span
      role="img"
      aria-label={g.label}
      className="inline-block size-2 shrink-0"
      style={{ borderRadius: g.radius, background: g.dot, boxShadow: g.ring }}
    />
  )
}

/** The severity glyph; screen readers get the label. */
export function SeverityGlyph({ severity, className = 'text-[10px]' }: { severity: Severity; className?: string }) {
  const s = SEVERITY[severity]
  return (
    <span role="img" aria-label={s.label} className={className} style={{ color: s.color }}>
      {s.glyph}
    </span>
  )
}

/** Severity as a soft pill with glyph and label (detail panes). */
export function SeverityPill({ severity }: { severity: Severity }) {
  const s = SEVERITY[severity]
  return (
    <span
      className="inline-flex h-6 items-center gap-1.5 rounded-xl px-2.5 font-semibold"
      style={{ background: s.soft, color: s.color }}
    >
      <span aria-hidden="true" className="text-[10px]">
        {s.glyph}
      </span>
      {s.label}
    </span>
  )
}
