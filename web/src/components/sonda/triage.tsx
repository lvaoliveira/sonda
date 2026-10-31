import { useId, useState } from 'react'
import { Button } from './controls'

/** Asks why before a decision that takes a finding out of the counts: accepting it, or marking it a false positive. */
export function ReasonForm({
  verb,
  prompt,
  onSubmit,
  onCancel,
}: {
  verb: string
  prompt: string
  /** Resolves true once saved. */
  onSubmit: (reason: string) => Promise<boolean>
  onCancel: () => void
}) {
  const id = useId()
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  return (
    <form
      className="flex flex-col gap-1.5"
      onSubmit={async (e) => {
        e.preventDefault()
        setBusy(true)
        const saved = await onSubmit(reason.trim())
        setBusy(false)
        if (saved) setReason('')
      }}
    >
      <label className="text-xs text-fg-muted" htmlFor={id}>
        {prompt} Shown to everyone with the finding.
      </label>
      <textarea
        id={id}
        autoFocus
        value={reason}
        maxLength={500}
        rows={2}
        onChange={(e) => setReason(e.target.value)}
        className="rounded-md border-0 bg-canvas px-2.5 py-1.5 text-[13px] edge"
      />
      <span className="flex gap-2">
        <Button primary type="submit" disabled={busy || !reason.trim()}>
          {verb}
        </Button>
        <Button onClick={onCancel} disabled={busy}>
          Cancel
        </Button>
      </span>
    </form>
  )
}
