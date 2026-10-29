import { Link } from 'react-router'
import { AppShell } from '@/components/shell/AppShell'
import { PageHeader } from '@/components/sonda/layout'

/** Screens from the design handoff that are not built yet. */
export function NotBuiltPage({ title }: { title: string }) {
  return (
    <AppShell crumbs={[{ label: 'acme-corp', to: '/' }, { label: title }]}>
      <PageHeader title={title} summary="Designed, not built yet." />
      <div className="flex max-w-[640px] flex-col gap-2 rounded-xl bg-panel-2 px-6 py-5 edge">
        <span className="font-semibold">This screen is part of the next increment.</span>
        <span className="text-[13px] text-fg-muted">
          Its design lives in <span className="font-mono text-xs">docs/designs/</span>. Built so far: <Link to="/">Overview</Link>,{' '}
          <Link to="/issues">Issues</Link> and <Link to="/rules">Rules</Link>.
        </span>
      </div>
    </AppShell>
  )
}
