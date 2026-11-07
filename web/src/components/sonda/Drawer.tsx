import { X } from 'lucide-react'
import { type ReactNode, useEffect, useId, useRef, useState } from 'react'
import { Button } from './controls'

/**
 * The floating side panel: inset 10px from the window's right edge, over a
 * blurred backdrop. A modal dialog, so the page behind is inert; it closes
 * on Escape, a backdrop click or its close button, and returns focus to
 * whatever opened it.
 *
 * Every "new item" form opens in one (a user, a token, a gate, a profile),
 * and so does the Overview's drill-down. A form puts its submit button in
 * `footer`, tied to the form by `form={id}`.
 */
export function Drawer({
  eyebrow,
  title,
  subtitle,
  header,
  footer,
  width = 480,
  padded = true,
  onClose,
  children,
}: Readonly<{
  /** A small label above the title: where this drawer belongs. */
  eyebrow: string
  title: string
  subtitle?: ReactNode
  /** More of the header, under the subtitle. */
  header?: ReactNode
  footer?: ReactNode
  width?: number
  /** Pads the body for a form; lists that run to the edges turn it off. */
  padded?: boolean
  onClose: () => void
  children: ReactNode
}>) {
  const dialog = useRef<HTMLDialogElement>(null)
  const titleId = useId()
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
      aria-labelledby={titleId}
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
        className="fixed top-2.5 right-2.5 bottom-2.5 flex max-w-[calc(100vw-20px)] flex-col overflow-hidden rounded-[14px] bg-panel"
        style={{ width, boxShadow: 'var(--sd-shadow), inset 0 0 0 1px var(--sd-line-2)' }}
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
          <h2 id={titleId} className="m-0 text-xl font-semibold tracking-[-0.025em]">
            {title}
          </h2>
          {subtitle && <span className="text-[13.5px] text-fg-muted">{subtitle}</span>}
          {header}
        </div>
        <div className={`flex flex-1 flex-col overflow-auto ${padded ? 'gap-4 px-[22px] py-[18px]' : 'p-2'}`}>{children}</div>
        {footer && <div className="flex flex-wrap items-center gap-2 border-t border-line px-[18px] py-3.5">{footer}</div>}
      </section>
    </dialog>
  )
}

/** A form field in a drawer: its label above the control, full width. */
export function Field({ label, hint, children }: Readonly<{ label: string; hint?: ReactNode; children: ReactNode }>) {
  return (
    <label className="flex flex-col gap-1.5 text-[13px]">
      <span>{label}</span>
      {children}
      {hint && <span className="text-xs text-fg-faint">{hint}</span>}
    </label>
  )
}

/** The usual footer of a form drawer: Cancel, then the form's submit button on the right. */
export function DrawerActions({ form, submit, busy, disabled, onCancel }: Readonly<{ form: string; submit: string; busy?: string; disabled?: boolean; onCancel: () => void }>) {
  return (
    <>
      <span className="flex-1" />
      <Button onClick={onCancel}>Cancel</Button>
      <Button type="submit" form={form} primary disabled={disabled || busy !== undefined}>
        {busy ?? submit}
      </Button>
    </>
  )
}
