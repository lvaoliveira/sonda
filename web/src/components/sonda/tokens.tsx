import { type SubmitEvent, useId, useState } from 'react'
import type { ApiToken, CreatedToken, NewToken, TokenType } from '@/api/types'
import { formatAge, shortDate } from '@/lib/format'
import { TOKEN_TYPE } from '@/lib/visual'
import { copyText } from '@/lib/clipboard'
import { Button } from './controls'
import { Drawer, DrawerActions, Field } from './Drawer'
import { Mono } from './layout'

const input = 'h-9 rounded-lg border-0 bg-canvas px-3 text-[13px] edge-strong'

const EXPIRY: { value: string; label: string }[] = [
  { value: '30', label: '30 days' },
  { value: '60', label: '60 days' },
  { value: '90', label: '90 days' },
  { value: 'none', label: 'No expiry' },
]

/**
 * A drawer that generates a token, then shows its secret once, with a Copy
 * button. With `owners`, an admin picks whom it belongs to; otherwise it's
 * the viewer's.
 */
export function GenerateTokenDrawer({
  eyebrow,
  owners,
  onGenerate,
  onGenerated,
  onClose,
}: Readonly<{
  eyebrow: string
  owners?: string[]
  onGenerate: (token: NewToken, owner: string) => Promise<CreatedToken>
  onGenerated: () => void
  onClose: () => void
}>) {
  const formId = useId()
  const [name, setName] = useState('')
  const [owner, setOwner] = useState('')
  const [type, setType] = useState<TokenType>('project_analysis')
  const [project, setProject] = useState('')
  const [expiry, setExpiry] = useState('30')
  const [created, setCreated] = useState<CreatedToken | null>(null)
  const [copied, setCopied] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const generate = async (e: SubmitEvent) => {
    e.preventDefault()
    setBusy(true)
    setError('')
    const token: NewToken = {
      name,
      type,
      ...(type === 'project_analysis' ? { project } : {}),
      expiresInDays: expiry === 'none' ? null : (Number(expiry) as 30 | 60 | 90),
    }
    try {
      setCreated(await onGenerate(token, owner))
      onGenerated()
    } catch (err) {
      setError((err as Error).message)
    }
    setBusy(false)
  }
  const copy = async () => {
    setError('')
    if (await copyText(created!.token)) setCopied(true)
    else setError('Could not copy; select the token and copy it.')
  }

  if (created) {
    const forWhom = created.createdBy ? `For ${created.owner}. ` : ''
    return (
      <Drawer
        eyebrow={eyebrow}
        title={`Copy “${created.name}”`}
        subtitle={`${forWhom}It won’t be shown again.`}
        onClose={onClose}
        footer={
          <>
            <span className="flex-1" />
            <Button onClick={() => void copy()}>{copied ? 'Copied' : 'Copy'}</Button>
            <Button primary onClick={onClose}>
              Done
            </Button>
          </>
        }
      >
        <output aria-label="New token" className="block rounded-lg bg-canvas px-3.5 py-3 edge-strong">
          <Mono className="text-[12px] break-all select-all">{created.token}</Mono>
        </output>
        <p className="m-0 text-xs text-fg-faint">{TOKEN_TYPE[created.type].note}</p>
        {error && (
          <p role="alert" className="m-0 text-[13px] text-crit">
            {error}
          </p>
        )}
      </Drawer>
    )
  }

  return (
    <Drawer
      eyebrow={eyebrow}
      title="Generate a token"
      subtitle="Its secret is shown once, when it's generated."
      onClose={onClose}
      footer={
        <DrawerActions form={formId} submit="Generate" busy={busy ? 'Generating…' : undefined} disabled={!name.trim() || (owners !== undefined && !owner)} onCancel={onClose} />
      }
    >
      <form id={formId} onSubmit={generate} className="flex flex-col gap-4">
        {owners && (
          <Field label="Owner">
            <select required value={owner} onChange={(e) => setOwner(e.target.value)} className={input}>
              <option value="">Choose a user</option>
              {owners.map((o) => (
                <option key={o} value={o}>
                  {o}
                </option>
              ))}
            </select>
          </Field>
        )}
        <Field label="Name">
          <input required maxLength={100} value={name} onChange={(e) => setName(e.target.value)} placeholder="ci-payments" className={input} />
        </Field>
        <Field label="Type" hint={TOKEN_TYPE[type].note}>
          <select value={type} onChange={(e) => setType(e.target.value as TokenType)} className={input}>
            {(Object.keys(TOKEN_TYPE) as TokenType[]).map((t) => (
              <option key={t} value={t}>
                {TOKEN_TYPE[t].label}
              </option>
            ))}
          </select>
        </Field>
        {type === 'project_analysis' && (
          <Field label="Project key">
            <input required value={project} onChange={(e) => setProject(e.target.value)} placeholder="payments-platform" className={input} />
          </Field>
        )}
        <Field label="Expires in">
          <select value={expiry} onChange={(e) => setExpiry(e.target.value)} className={input}>
            {EXPIRY.map((x) => (
              <option key={x.value} value={x.value}>
                {x.label}
              </option>
            ))}
          </select>
        </Field>
        {error && (
          <p role="alert" className="m-0 text-[13px] text-crit">
            {error}
          </p>
        )}
      </form>
    </Drawer>
  )
}

const STATUS = {
  active: { label: 'Active', color: 'var(--sd-ok)' },
  expired: { label: 'Expired', color: 'var(--sd-faint)' },
  revoked: { label: 'Revoked', color: 'var(--sd-faint)' },
} as const

/** Tokens without their secrets; active ones can be revoked. */
export function TokenTable({ tokens, showOwner = false, onRevoke }: Readonly<{ tokens: ApiToken[]; showOwner?: boolean; onRevoke: (t: ApiToken) => void }>) {
  if (tokens.length === 0) return <p className="m-0 text-[13px] text-fg-faint">No tokens yet.</p>
  const th = 'border-b border-line px-2 py-2 text-left font-normal'
  const td = 'border-b border-line px-2 py-2 align-top'
  return (
    <div className="relative overflow-x-auto">
      <table className="w-full border-collapse text-[13px]">
        <thead className="text-xs text-fg-muted">
          <tr>
            <th className={th}>Name</th>
            {showOwner && <th className={th}>Owner</th>}
            <th className={th}>Type</th>
            <th className={th}>Token</th>
            <th className={th}>Last used</th>
            <th className={th}>Expires</th>
            <th className={th}>Status</th>
            <th className={th} />
          </tr>
        </thead>
        <tbody>
          {tokens.map((t) => {
            const s = STATUS[t.status]
            return (
              <tr key={t.id} aria-label={`Token ${t.name}`} style={{ opacity: t.status === 'active' ? 1 : 0.65 }}>
                <td className={td}>
                  {t.name}
                  {t.createdBy && <span className="block text-xs text-fg-faint">generated by {t.createdBy}</span>}
                </td>
                {showOwner && <td className={td}>{t.owner}</td>}
                <td className={td}>
                  {TOKEN_TYPE[t.type].label}
                  {t.project && <Mono className="block text-[11.5px] text-fg-muted">{t.project}</Mono>}
                </td>
                <td className={td}>
                  <Mono className="text-[11.5px] text-fg-muted">{t.prefix}…</Mono>
                </td>
                <td className={`${td} text-fg-muted`}>{t.lastUsedAt ? `${formatAge(t.lastUsedAt)} ago` : 'Never'}</td>
                <td className={`${td} text-fg-muted`}>{t.expiresAt ? shortDate(t.expiresAt) : 'No expiry'}</td>
                <td className={td}>
                  <span style={{ color: s.color }}>{s.label}</span>
                  {t.revokedBy && <span className="block text-xs text-fg-faint">by {t.revokedBy}</span>}
                </td>
                <td className={`${td} text-right`}>
                  {t.status === 'active' && <Button onClick={() => onRevoke(t)}>Revoke</Button>}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
