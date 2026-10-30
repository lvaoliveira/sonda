import type { CodeLine, Severity } from '@/api/types'
import { ROLE_COLOR, SEVERITY } from '@/lib/visual'

/**
 * Source excerpt with line numbers. Highlighted lines are tinted with the
 * severity color and an inset bar; the annotation card sits under `noteLine`.
 */
export function CodeViewer({
  lines,
  highlighted,
  severity,
  noteLine,
  note,
}: {
  lines: CodeLine[]
  highlighted: number[]
  severity: Severity
  noteLine: number
  note: string
}) {
  const s = SEVERITY[severity]
  return (
    <div role="region" aria-label="Source code" className="overflow-auto bg-canvas py-2 font-mono text-[11.5px] leading-[1.85]">
      {lines.map((line) => {
        const hot = highlighted.includes(line.number)
        return (
          <div key={line.number} className="flex flex-col">
            <div
              className="flex"
              data-highlighted={hot || undefined}
              style={{
                background: hot ? `color-mix(in oklch, ${s.color} 11%, transparent)` : 'transparent',
                boxShadow: `inset 3px 0 0 ${hot ? s.color : 'transparent'}`,
              }}
            >
              <span className="w-[66px] flex-none pr-3.5 text-right select-none" style={{ color: hot ? s.color : 'var(--sd-faint)' }}>
                {line.number}
              </span>
              <span className="pr-5 whitespace-pre">
                {line.tokens.map((t, i) => (
                  <span key={i} style={{ color: ROLE_COLOR[t.role] }}>
                    {t.text}
                  </span>
                ))}
              </span>
            </div>
            {line.number === noteLine && (
              <div className="mx-5 mt-1.5 mb-2 ml-[66px] flex gap-2.5 rounded-lg bg-panel-2 px-3 py-2.5 font-sans text-[13px] leading-[1.45] whitespace-normal edge-strong">
                <span aria-hidden="true" className="pt-[3px] text-[10px]" style={{ color: s.color }}>
                  {s.glyph}
                </span>
                <span>{note}</span>
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}
