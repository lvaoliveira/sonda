import { X } from 'lucide-react'
import { type ReactNode, useEffect, useRef, useState } from 'react'

const DEPTH = ['org', 'project', 'component', 'file', 'issue']

/** A drill step's label: the current one stands out, the ones passed less so. */
function stepColor(step: number, depth: number): string {
  if (step === depth) return 'var(--sd-accent)'
  return step < depth ? 'var(--sd-muted)' : 'var(--sd-faint)'
}

/**
 * The floating drill-down panel: 480px, inset 10px, blurred backdrop. A modal
 * dialog, so the page behind is inert; closes on Escape or a backdrop click,
 * and returns focus to whatever opened it.
 */
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
  const dialog = useRef<HTMLDialogElement>(null)
  // What had focus when the drawer opened, read once: by the time an effect
  // runs again (StrictMode runs them twice), focus is inside the dialog.
  const [opener] = useState(() => document.activeElement as HTMLElement | null)

  useEffect(() => {
    // Opened once: an open dialog's showModal() throws in older browsers.
    if (dialog.current && !dialog.current.open) dialog.current.showModal()
    return () => opener?.focus()
  }, [opener])

  return (
    // The dialog covers the window, transparent: the backdrop below and the
    // panel are inside it, since a modal dialog makes everything else inert.
    <dialog
      ref={dialog}
      aria-labelledby="drill-title"
      onClose={onClose}
      className="m-0 size-full max-h-none max-w-none overflow-hidden bg-transparent p-0 text-fg backdrop:bg-transparent"
    >
      <div
        aria-hidden="true"
        onClick={onClose}
        className="fixed inset-0 backdrop-blur-[2px]"
        style={{ background: 'color-mix(in srgb, var(--sd-bg) 55%, transparent)' }}
      />
      <section
        className="fixed top-2.5 right-2.5 bottom-2.5 flex w-[480px] max-w-[calc(100vw-20px)] flex-col overflow-hidden rounded-[14px] bg-panel"
        style={{ boxShadow: 'var(--sd-shadow), inset 0 0 0 1px var(--sd-line-2)' }}
      >
        <div className="flex flex-col gap-2 border-b border-line px-[22px] py-[18px]">
          <div className="flex items-center justify-between">
            <span className="font-mono text-[10px] tracking-[.06em] text-brand uppercase">{eyebrow}</span>
            <button
              type="button"
              onClick={onClose}
              aria-label="Close"
              className="grid size-[30px] cursor-pointer place-items-center rounded-lg border-0 bg-transparent text-fg-muted hover:bg-hover hover:text-fg"
            >
              <X size={15} aria-hidden="true" />
            </button>
          </div>
          <h2 id="drill-title" className="m-0 text-xl font-semibold tracking-[-0.025em]">
            {title}
          </h2>
          {subtitle && <span className="text-[13.5px] text-fg-muted">{subtitle}</span>}
          <ol aria-label="Drill-down depth" className="m-0 mt-1.5 flex list-none gap-1 p-0">
            {DEPTH.map((d, i) => (
              <li key={d} aria-current={i === depth ? 'step' : undefined} className="flex flex-1 flex-col gap-[5px]">
                <span className="h-[3px] rounded-sm" style={{ background: i <= depth ? 'var(--sd-accent)' : 'var(--sd-pip-off)' }} />
                <span
                  className="font-mono text-[9.5px]"
                  style={{ color: stepColor(i, depth), fontWeight: i === depth ? 500 : 400 }}
                >
                  {d}
                </span>
              </li>
            ))}
          </ol>
        </div>
        <div className="flex flex-1 flex-col overflow-auto p-2">{children}</div>
        {footer && <div className="flex gap-2 border-t border-line px-[18px] py-3.5">{footer}</div>}
      </section>
    </dialog>
  )
}
