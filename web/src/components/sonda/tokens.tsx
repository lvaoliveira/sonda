import type { ApiToken } from '@/api/types'
import { formatAge, shortDate } from '@/lib/format'
import { TOKEN_TYPE } from '@/lib/visual'
import { Button } from './controls'
import { Mono } from './layout'

const STATUS = {
  active: { label: 'Active', color: 'var(--sd-ok)' },
  expired: { label: 'Expired', color: 'var(--sd-faint)' },
  revoked: { label: 'Revoked', color: 'var(--sd-faint)' },
} as const

/** Tokens without their secrets; active ones can be revoked. */
export function TokenTable({ tokens, showOwner = false, onRevoke }: { tokens: ApiToken[]; showOwner?: boolean; onRevoke: (t: ApiToken) => void }) {
  if (tokens.length === 0) return <p className="m-0 text-[13px] text-fg-faint">No tokens yet.</p>
  const th = 'border-b border-line px-2 py-2 text-left font-normal'
  const td = 'border-b border-line px-2 py-2 align-top'
  return (
    <div className="overflow-x-auto">
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
                <td className={td}>{t.name}</td>
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
