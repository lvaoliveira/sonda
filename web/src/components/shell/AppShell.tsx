import {
  Activity,
  BookOpen,
  CircleCheck,
  CircleDot,
  Folder,
  LayoutGrid,
  LogOut,
  type LucideIcon,
  Menu,
  Package,
  Search,
  Shield,
  SlidersHorizontal,
  X,
} from 'lucide-react'
import { type ReactNode, useEffect, useState } from 'react'
import { Link, NavLink } from 'react-router'
import { useApi, useAsync } from '@/api/hooks'
import { useSessionActions } from '@/api/session'
import type { NavCounts } from '@/api/types'
import { compactCount } from '@/lib/format'
import { useTheme } from '@/lib/theme'

interface NavItem {
  to: string
  label: string
  icon: LucideIcon
  count?: (c: NavCounts) => number | null
  hot?: boolean
  /** Shown to admins only. */
  adminOnly?: boolean
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
  { to: '/admin', label: 'Administration', icon: SlidersHorizontal, adminOnly: true },
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
  const { signOut } = useSessionActions()
  const [theme, toggleTheme] = useTheme()
  const data = shell.state === 'ready' ? shell.data : null
  // Every trail starts at the organization, named by the server.
  const trail: Crumb[] = [{ label: data?.org.name ?? '…', to: '/' }, ...crumbs]
  // Below 900px the sidebar is a drawer, opened from the header's menu button.
  const [menuOpen, setMenuOpen] = useState(false)
  const close = () => setMenuOpen(false)
  useEffect(() => {
    if (!menuOpen) return
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setMenuOpen(false)
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [menuOpen])

  return (
    <div className="flex min-h-screen bg-canvas text-fg">
      {menuOpen && <div aria-hidden="true" onClick={close} className="fixed inset-0 z-20 bg-black/40 min-[900px]:hidden" />}
      <aside
        id="primary-nav"
        aria-label="Primary"
        className={`fixed inset-y-0 left-0 z-30 flex h-screen w-[228px] flex-none flex-col bg-canvas transition-transform duration-200 min-[900px]:sticky min-[900px]:top-0 min-[900px]:translate-x-0 ${
          menuOpen ? 'translate-x-0 shadow-2xl' : 'max-[899px]:invisible max-[899px]:-translate-x-full'
        }`}
      >
        <div className="flex h-[60px] items-center pr-3">
          <Link to="/" onClick={close} className="flex h-full flex-1 items-center gap-2.5 px-[18px] text-fg hover:text-fg">
            <Logo />
            <span className="text-[17px] font-semibold tracking-[-0.03em]">sonda</span>
          </Link>
          <button
            type="button"
            onClick={close}
            aria-label="Close menu"
            className="grid size-8 cursor-pointer place-items-center rounded-md border-0 bg-transparent text-fg-muted hover:bg-hover hover:text-fg min-[900px]:hidden"
          >
            <X size={16} strokeWidth={1.8} aria-hidden="true" />
          </button>
        </div>
        <div className="mx-3 mb-2.5 flex items-center gap-2.5 rounded-lg bg-panel px-2.5 py-2 edge">
          <span className="grid size-[22px] place-items-center rounded-md text-[10px] font-bold" style={{ background: 'var(--sd-text)', color: 'var(--sd-bg)' }}>
            {data?.org.initials ?? '··'}
          </span>
          <span className="flex min-w-0 flex-1 flex-col leading-[1.2]">
            <span className="text-[13px] font-semibold">{data?.org.name ?? ' '}</span>
            <span className="text-[11px] text-fg-faint">
              {data ? data.org.deployment + (data.org.projectCount != null ? ` · ${data.org.projectCount} projects` : '') : ' '}
            </span>
          </span>
        </div>
        <nav className="flex flex-1 flex-col gap-0.5 overflow-auto px-3 py-1">
          {NAV.filter((item) => item === 'Configure' || !item.adminOnly || data?.isAdmin).map((item) =>
            item === 'Configure' ? (
              <div key={item} className="px-2.5 pt-4 pb-1.5 font-mono text-[10px] tracking-[.08em] text-fg-faint uppercase">
                {item}
              </div>
            ) : (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === '/'}
                onClick={close}
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
                    {item.count && data && item.count(data.counts) != null && (
                      <span className="font-mono text-[10.5px]" style={{ color: item.hot ? 'var(--sd-crit)' : 'var(--sd-faint)' }}>
                        {compactCount(item.count(data.counts) ?? 0)}
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
          <Link to="/account" onClick={close} title="Your account" className="flex min-w-0 flex-1 flex-col leading-[1.25] text-fg hover:text-fg">
            <span className="text-[13px] font-semibold">{data?.user.name ?? ' '}</span>
            <span className="text-[11.5px] text-fg-faint">{data?.user.handle ?? ' '}</span>
          </Link>
          {signOut && (
            <button type="button" onClick={signOut} aria-label="Sign out" title="Sign out" className="grid size-7 cursor-pointer place-items-center rounded-md border-0 bg-transparent text-fg-faint hover:bg-hover hover:text-fg">
              <LogOut size={15} strokeWidth={1.6} aria-hidden="true" />
            </button>
          )}
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col min-[900px]:py-2.5 min-[900px]:pr-2.5">
        <div className="flex min-w-0 flex-1 flex-col bg-panel min-[900px]:rounded-[14px] min-[900px]:edge">
          <header className="sticky top-0 z-5 flex h-14 items-center gap-2 border-b border-line bg-panel px-4 min-[900px]:gap-3 min-[900px]:rounded-t-[14px] min-[900px]:px-6">
            <button
              type="button"
              onClick={() => setMenuOpen(true)}
              aria-label="Open menu"
              aria-expanded={menuOpen}
              aria-controls="primary-nav"
              className="-ml-1.5 grid size-[34px] flex-none cursor-pointer place-items-center rounded-lg border-0 bg-transparent text-fg-muted hover:bg-hover hover:text-fg min-[900px]:hidden"
            >
              <Menu size={18} strokeWidth={1.8} aria-hidden="true" />
            </button>
            <nav aria-label="Breadcrumb" className="flex min-w-0 flex-1 items-center gap-2 overflow-hidden text-[13.5px] whitespace-nowrap">
              {trail.map((c, i) => {
                const last = i === trail.length - 1
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
              className="flex h-[34px] min-w-[120px] flex-[0_1_300px] cursor-not-allowed items-center max-[640px]:hidden gap-2 rounded-lg border-0 bg-canvas px-3 text-[13px] text-fg-faint edge"
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
          <main className="box-border flex w-full max-w-[1560px] min-w-0 flex-1 flex-col gap-5 px-4 pt-5 pb-8 min-[900px]:px-6 min-[900px]:pt-7">{children}</main>
        </div>
      </div>
    </div>
  )
}
