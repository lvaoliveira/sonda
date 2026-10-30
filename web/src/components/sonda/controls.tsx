import { type ReactNode, useEffect } from 'react'

/** A segmented control (scope, range, tabs); the selected segment is raised. */
export function Segmented<T extends string>({
  label,
  options,
  value,
  onChange,
  mono = false,
}: {
  label: string
  options: { value: T; label: string }[]
  value: T
  onChange: (value: T) => void
  mono?: boolean
}) {
  return (
    <div role="group" aria-label={label} className="flex rounded-[9px] bg-canvas p-[3px] edge">
      {options.map((o) => {
        const on = o.value === value
        return (
          <button
            key={o.value}
            type="button"
            aria-pressed={on}
            onClick={() => onChange(o.value)}
            className={`h-7 cursor-pointer rounded-md border-0 font-medium ${mono ? 'px-2.5 font-mono text-[11px]' : 'px-3 text-[13px]'}`}
            style={{
              background: on ? 'var(--sd-panel)' : 'transparent',
              color: on ? 'var(--sd-text)' : 'var(--sd-muted)',
              boxShadow: on ? 'inset 0 0 0 1px var(--sd-line-2), 0 1px 2px rgba(0,0,0,.2)' : 'none',
            }}
          >
            {o.label}
          </button>
        )
      })}
    </div>
  )
}

/** A filter chip: accent-tinted when pressed. */
export function Chip({ on, onClick, children }: { on: boolean; onClick: () => void; children: ReactNode }) {
  return (
    <button
      type="button"
      aria-pressed={on}
      onClick={onClick}
      className="h-[30px] cursor-pointer rounded-[15px] border-0 px-[11px] text-[12.5px]"
      style={{
        background: on ? 'var(--sd-accent-soft)' : 'transparent',
        color: on ? 'var(--sd-accent)' : 'var(--sd-muted)',
        boxShadow: `inset 0 0 0 1px ${on ? 'var(--sd-accent)' : 'var(--sd-line-2)'}`,
      }}
    >
      {children}
    </button>
  )
}

export function Button({
  primary = false,
  disabled = false,
  onClick,
  children,
  className = '',
  type = 'button',
}: {
  primary?: boolean
  disabled?: boolean
  onClick?: () => void
  children: ReactNode
  className?: string
  type?: 'button' | 'submit'
}) {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={`h-8 cursor-pointer rounded-lg border-0 px-[13px] text-[13px] disabled:cursor-default disabled:opacity-45 ${
        primary ? 'bg-brand font-semibold text-brand-ink' : 'bg-transparent font-medium edge-strong'
      } ${className}`}
    >
      {children}
    </button>
  )
}

export interface ToastMessage {
  text: string
  undo?: () => void
}

/** A bottom-center toast with optional Undo; disappears after 4 seconds. */
export function Toast({ toast, onDone }: { toast: ToastMessage | null; onDone: () => void }) {
  useEffect(() => {
    if (!toast) return
    const timer = setTimeout(onDone, 4000)
    return () => clearTimeout(timer)
  }, [toast, onDone])
  if (!toast) return null
  return (
    <div
      role="status"
      aria-live="polite"
      className="fixed bottom-6 left-1/2 z-30 flex -translate-x-1/2 items-center gap-3 rounded-[10px] px-4 py-2.5 text-[13px] shadow-float"
      style={{ background: 'var(--sd-text)', color: 'var(--sd-bg)' }}
    >
      <span>{toast.text}</span>
      {toast.undo && (
        <button
          type="button"
          onClick={() => {
            toast.undo?.()
            onDone()
          }}
          className="cursor-pointer border-0 bg-transparent p-0 font-semibold text-inherit underline"
        >
          Undo
        </button>
      )}
    </div>
  )
}
