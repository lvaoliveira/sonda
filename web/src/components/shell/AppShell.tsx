import {
  Activity,
  BookOpen,
  CircleCheck,
  CircleDot,
  Folder,
  LayoutGrid,
  type LucideIcon,
  Package,
  Search,
  Shield,
  SlidersHorizontal,
} from 'lucide-react'
import type { ReactNode } from 'react'
import { Link, NavLink } from 'react-router'
import { useApi, useAsync } from '@/api/hooks'
import type { NavCounts } from '@/api/types'
import { compactCount } from '@/lib/format'
import { useTheme } from '@/lib/theme'

interface NavItem {
  to: string
  label: string
  icon: LucideIcon
  count?: (c: NavCounts) => number
  hot?: boolean
}

const NAV: (NavItem | 'Configure')[] = [
  { to: '/', label: 'Overview', icon: LayoutGrid },
  { to: '/projects', label: 'Projects', icon: Folder, count: (c) => c.projects },
  { to: '/components', label: 'Components', icon: Package, count: (c) => c.components },
  { to: '/issues', label: 'Issues', icon: CircleDot, count: (c) => c.issues },
  { to: '/security', label: 'Security', icon: Shield, count: (c) => c.security, hot: true },
  { to: '/analyses', label: 'Analyses', icon: Activity },
  'Configure',
  { to: '/gates', label: 'Quality gates', icon: CircleCheck },
  { to: '/rules', label: 'Rules', icon: BookOpen },
  { to: '/admin', label: 'Administration', icon: SlidersHorizontal },
]

/** Two sonar arcs over a plumb line with a teal dot. */
export function Logo() {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" aria-hidden="true">
      <path d="M3 9a9 9 0 0 1 18 0" fill="none" stroke="var(--sd-text)" strokeWidth="1.6" opacity=".3" />
      <path d="M7 9a5 5 0 0 1 10 0" fill="none" stroke="var(--sd-text)" strokeWidth="1.6" opacity=".65" />
      <path d="M12 9v9" stroke="var(--sd-accent)" strokeWidth="1.6" />
      <circle cx="12" cy="20" r="2.4" fill="var(--sd-accent)" />
    </svg>
  )
}

export interface Crumb {
  label: string
  to?: string
  mono?: boolean
}

export function AppShell({ crumbs, children }: { crumbs: Crumb[]; children: ReactNode }) {
  const api = useApi()
  const shell = useAsync(() => api.shell(), [api])
  const [theme, toggleTheme] = useTheme()
  const data = shell.state === 'ready' ? shell.data : null

  return (
    <div className="flex min-h-screen bg-canvas text-fg">
      <aside aria-label="Primary" className="sticky top-0 flex h-screen w-[228px] flex-none flex-col bg-canvas">
        <Link to="/" className="flex h-[60px] items-center gap-2.5 px-[18px] text-fg hover:text-fg">
          <Logo />
          <span className="text-[17px] font-semibold tracking-[-0.03em]">sonda</span>
        </Link>
        <div className="mx-3 mb-2.5 flex items-center gap-2.5 rounded-lg bg-panel px-2.5 py-2 edge">
          <span className="grid size-[22px] place-items-center rounded-md text-[10px] font-bold" style={{ background: 'var(--sd-text)', color: 'var(--sd-bg)' }}>
            {data?.org.initials ?? '··'}
          </span>
          <span className="flex min-w-0 flex-1 flex-col leading-[1.2]">
            <span className="text-[13px] font-semibold">{data?.org.name ?? ' '}</span>
            <span className="text-[11px] text-fg-faint">
              {data ? `${data.org.deployment} · ${data.org.projectCount} projects` : ' '}
            </span>
          </span>
        </div>
        <nav className="flex flex-1 flex-col gap-0.5 overflow-auto px-3 py-1">
          {NAV.map((item) =>
            item === 'Configure' ? (
              <div key={item} className="px-2.5 pt-4 pb-1.5 font-mono text-[10px] tracking-[.08em] text-fg-faint uppercase">
                {item}
              </div>
            ) : (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === '/'}
                className={({ isActive }) =>
                  `group flex h-[34px] items-center gap-2.5 rounded-lg px-2.5 text-sm hover:bg-hover hover:text-fg ${
                    isActive ? 'bg-panel font-semibold text-fg' : 'text-fg-muted'
                  }`
                }
              >
                {({ isActive }) => (
                  <>
                    <item.icon size={16} strokeWidth={1.6} aria-hidden="true" className="flex-none" style={{ color: isActive ? 'var(--sd-accent)' : 'currentColor' }} />
                    <span className="flex-1">{item.label}</span>
                    {item.count && data && (
                      <span className="font-mono text-[10.5px]" style={{ color: item.hot ? 'var(--sd-crit)' : 'var(--sd-faint)' }}>
                        {compactCount(item.count(data.counts))}
                      </span>
                    )}
                  </>
                )}
              </NavLink>
            ),
          )}
        </nav>
        <div className="m-3 flex items-center gap-2.5 rounded-lg bg-panel p-2.5 edge">
          <span className="grid size-7 place-items-center rounded-full bg-brand-soft text-[11px] font-semibold text-brand">{data?.user.initials ?? '··'}</span>
          <span className="flex min-w-0 flex-1 flex-col leading-[1.25]">
            <span className="text-[13px] font-semibold">{data?.user.name ?? ' '}</span>
            <span className="text-[11.5px] text-fg-faint">{data?.user.handle ?? ' '}</span>
          </span>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col py-2.5 pr-2.5">
        <div className="flex min-w-0 flex-1 flex-col rounded-[14px] bg-panel edge">
          <header className="sticky top-0 z-5 flex h-14 items-center gap-3 rounded-t-[14px] border-b border-line bg-panel px-6">
            <nav aria-label="Breadcrumb" className="flex min-w-0 flex-1 items-center gap-2 overflow-hidden text-[13.5px] whitespace-nowrap">
              {crumbs.map((c, i) => {
                const last = i === crumbs.length - 1
                return (
                  <span key={i} className="flex items-center gap-2" style={{ minWidth: last ? 0 : '4.5em', flex: last ? '0 1 auto' : '0 4 auto' }}>
                    {i > 0 && (
                      <span aria-hidden="true" className="text-line-strong">
                        /
                      </span>
                    )}
                    <Link
                      to={c.to ?? '#'}
                      aria-current={last ? 'page' : undefined}
                      className={`min-w-0 overflow-hidden text-ellipsis whitespace-nowrap ${c.mono ? 'font-mono' : ''}`}
                      style={{ color: last ? 'var(--sd-text)' : 'var(--sd-faint)', fontWeight: last ? 600 : 400 }}
                    >
                      {c.label}
                    </Link>
                  </span>
                )
              })}
            </nav>
            <button
              type="button"
              disabled
              title="Search is not built yet"
              className="flex h-[34px] min-w-[120px] flex-[0_1_300px] cursor-not-allowed items-center gap-2 rounded-lg border-0 bg-canvas px-3 text-[13px] text-fg-faint edge"
            >
              <Search size={14} strokeWidth={2} aria-hidden="true" className="flex-none" />
              <span className="flex-1 overflow-hidden text-left whitespace-nowrap">Search or run a command</span>
              <span className="rounded px-1.5 py-0.5 font-mono text-[10px] text-fg-muted" style={{ background: 'var(--sd-hover)' }}>
                ⌘K
              </span>
            </button>
            <button
              type="button"
              onClick={toggleTheme}
              aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
              className="h-[34px] cursor-pointer rounded-lg border-0 bg-transparent px-3 font-mono text-[10.5px] text-fg-muted edge hover:text-fg"
            >
              {theme}
            </button>
          </header>
          <main className="box-border flex w-full max-w-[1560px] flex-1 flex-col gap-5 px-6 pt-7 pb-8">{children}</main>
        </div>
      </div>
    </div>
  )
}
