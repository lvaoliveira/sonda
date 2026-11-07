import type { ReactNode } from 'react'
import { Drawer } from './Drawer'

const DEPTH = ['org', 'project', 'component', 'file', 'issue']

/** A drill step's label: the current one stands out, the ones passed less so. */
function stepColor(step: number, depth: number): string {
  if (step === depth) return 'var(--sd-accent)'
  return step < depth ? 'var(--sd-muted)' : 'var(--sd-faint)'
}

/** The Overview's drill-down: a `Drawer` that shows how deep it is, from org to issue. */
export function DrillDrawer({
  eyebrow,
  title,
  subtitle,
  depth = 2,
  footer,
  onClose,
  children,
}: Readonly<{
  eyebrow: string
  title: string
  subtitle?: string
  /** Index into org → project → component → file → issue. */
  depth?: number
  footer?: ReactNode
  onClose: () => void
  children: ReactNode
}>) {
  return (
    <Drawer
      eyebrow={eyebrow}
      title={title}
      subtitle={subtitle}
      footer={footer}
      padded={false}
      onClose={onClose}
      header={
        <ol aria-label="Drill-down depth" className="m-0 mt-1.5 flex list-none gap-1 p-0">
          {DEPTH.map((d, i) => (
            <li key={d} aria-current={i === depth ? 'step' : undefined} className="flex flex-1 flex-col gap-[5px]">
              <span className="h-[3px] rounded-sm" style={{ background: i <= depth ? 'var(--sd-accent)' : 'var(--sd-pip-off)' }} />
              <span className="font-mono text-[9.5px]" style={{ color: stepColor(i, depth), fontWeight: i === depth ? 500 : 400 }}>
                {d}
              </span>
            </li>
          ))}
        </ol>
      }
    >
      {children}
    </Drawer>
  )
}
