import { Link } from 'react-router'
import { AppShell } from '@/components/shell/AppShell'
import { PageHeader } from '@/components/sonda/layout'

/** Any URL the app has no screen for. */
export function NotFoundPage() {
  return (
    <AppShell crumbs={[{ label: 'Not found' }]}>
      <PageHeader title="Page not found" summary="Nothing lives at this address." />
      <div className="flex max-w-[640px] flex-col gap-2 rounded-xl bg-panel-2 px-6 py-5 edge">
        <span className="text-[13px] text-fg-muted">
          Try the <Link to="/">Overview</Link>, <Link to="/projects">Projects</Link> or <Link to="/issues">Issues</Link>.
        </span>
      </div>
    </AppShell>
  )
}
