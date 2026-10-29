import type { ReactNode } from 'react'

/** A section card inside the sheet: panel-2, radius 12, inset hairline. */
export function Card({
  title,
  subtitle,
  aside,
  children,
  className = '',
  padded = true,
  id,
}: {
  title?: ReactNode
  subtitle?: ReactNode
  aside?: ReactNode
  children: ReactNode
  className?: string
  padded?: boolean
  id?: string
}) {
  const headingId = id ? `${id}-h` : undefined
  return (
    <section
      aria-labelledby={headingId}
      className={`flex min-w-0 flex-col rounded-xl bg-panel-2 edge ${padded ? 'gap-4 px-5 py-[18px]' : 'overflow-hidden'} ${className}`}
    >
      {title && (
        <div className={`flex flex-wrap items-start justify-between gap-3 ${padded ? '' : 'px-5 pt-4 pb-3'}`}>
          <div className="flex flex-col gap-0.5">
            <h2 id={headingId} className="m-0 text-base font-semibold tracking-[-0.01em]">
              {title}
            </h2>
            {subtitle && <span className="text-[13px] text-fg-muted">{subtitle}</span>}
          </div>
          {aside}
        </div>
      )}
      {children}
    </section>
  )
}

/**
 * Seamless metric grid: the container is the hairline color and cells sit
 * on panel-2 with a 1px gap, so the gaps draw the dividers.
 */
export function MetricGrid({ label, minCell = 180, children }: { label: string; minCell?: number; children: ReactNode }) {
  return (
    <section
      aria-label={label}
      className="grid gap-px overflow-hidden rounded-xl bg-line"
      style={{ gridTemplateColumns: `repeat(auto-fit, minmax(${minCell}px, 1fr))`, boxShadow: '0 0 0 1px var(--sd-line)' }}
    >
      {children}
    </section>
  )
}

export function PageHeader({ title, summary, children }: { title: string; summary: ReactNode; children?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-4">
      <div className="flex flex-col gap-1.5">
        <h1 className="m-0 text-[30px] leading-[1.1] font-semibold tracking-[-0.035em]">{title}</h1>
        <div className="text-[13.5px] text-fg-muted">{summary}</div>
      </div>
      {children}
    </div>
  )
}

export function Mono({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <span className={`font-mono ${className}`}>{children}</span>
}
