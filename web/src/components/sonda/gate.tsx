import type { GateCondition } from '@/api/types'
import { Mono } from './layout'

const CONDITION_MARK: Record<GateCondition['status'], { glyph: string; color: string; label: string }> = {
  ok: { glyph: '✓', color: 'var(--sd-ok)', label: 'Passing' },
  error: { glyph: '✕', color: 'var(--sd-crit)', label: 'Failing' },
  no_data: { glyph: '–', color: 'var(--sd-faint)', label: 'No data' },
  ignored: { glyph: '–', color: 'var(--sd-faint)', label: 'Ignored' },
}

/** A gate's conditions: a glyph and a word for the status, the condition, and its actual value. */
export function GateConditions({ conditions }: { conditions: GateCondition[] }) {
  return (
    <ul className="m-0 flex list-none flex-col p-0">
      {conditions.map((c) => {
        const m = CONDITION_MARK[c.status]
        const unit = /coverage|density/.test(c.metric) ? '%' : ''
        return (
          <li key={c.metric} className="grid grid-cols-[18px_minmax(0,1fr)_auto] items-center gap-2.5 border-t border-line py-2 text-[13.5px] first:border-t-0">
            <span role="img" aria-label={m.label} className="text-center text-xs font-bold" style={{ color: m.color }}>
              {m.glyph}
            </span>
            <span>
              {c.label}
              {c.status === 'ignored' && <span className="text-xs text-fg-faint"> · ignored: fewer than 20 new lines</span>}
            </span>
            <Mono className="text-xs">
              <span style={{ color: m.color }}>{c.actual == null ? 'no data' : `${Number.isInteger(c.actual) ? c.actual : c.actual.toFixed(1)}${unit}`}</span>
            </Mono>
          </li>
        )
      })}
    </ul>
  )
}
