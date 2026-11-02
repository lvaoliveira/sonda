import { Link } from 'react-router'
import type { WaitingProject } from '@/api/types'
import { Mono } from '@/components/sonda/layout'

/** Admins' way to connect a repository (ADR-0023). */
export function ConnectLink({ primary = false }: { primary?: boolean }) {
  return (
    <Link
      to="/connect"
      className={`inline-flex h-8 w-fit items-center rounded-lg px-[13px] text-[13px] no-underline ${primary ? 'bg-brand font-semibold text-brand-ink' : 'font-medium text-fg edge-strong'}`}
    >
      Connect a repository
    </Link>
  )
}

/** Projects created ahead of their first analysis, with their steps again for admins. */
export function WaitingProjects({ waiting, isAdmin }: { waiting: WaitingProject[]; isAdmin: boolean }) {
  if (waiting.length === 0) return null
  return (
    <section aria-label="Waiting for a first analysis" className="flex flex-col gap-2 rounded-xl bg-panel-2 px-5 py-4 edge">
      <span className="micro-label">Waiting for a first analysis</span>
      <ul className="m-0 flex list-none flex-col gap-1.5 p-0">
        {waiting.map((w) => (
          <li key={w.key} className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[13px]">
            <Mono className="text-fg">{w.name ?? w.key}</Mono>
            {w.githubRepository && <span className="text-fg-muted">{w.githubRepository}</span>}
            {isAdmin && <Link to={`/connect?project=${encodeURIComponent(w.key)}`}>Show the steps again</Link>}
          </li>
        ))}
      </ul>
    </section>
  )
}
