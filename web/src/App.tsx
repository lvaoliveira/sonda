import { BrowserRouter, Route, Routes } from 'react-router'
import { ApiProvider } from '@/api/ApiProvider'
import { SessionGate } from '@/components/shell/SessionGate'
import type { SondaApi } from '@/api/types'
import { AccountPage } from '@/pages/AccountPage'
import { AdminPage } from '@/pages/AdminPage'
import { IssuesPage } from '@/pages/IssuesPage'
import { NotBuiltPage } from '@/pages/NotBuiltPage'
import { OverviewPage } from '@/pages/OverviewPage'
import { RulesPage } from '@/pages/RulesPage'

const NOT_BUILT: [string, string][] = [
  ['/projects', 'Projects'],
  ['/components', 'Components'],
  ['/security', 'Security'],
  ['/analyses', 'Analyses'],
  ['/gates', 'Quality gates'],
]

export function App({ api }: { api: SondaApi }) {
  return (
    <ApiProvider api={api}>
      <BrowserRouter>
        <SessionGate>
          <AppRoutes />
        </SessionGate>
      </BrowserRouter>
    </ApiProvider>
  )
}

/** The routes alone, so tests can mount them in a MemoryRouter. */
export function AppRoutes() {
  return (
        <Routes>
          <Route path="/" element={<OverviewPage />} />
          <Route path="/issues" element={<IssuesPage />} />
          <Route path="/rules" element={<RulesPage />} />
          <Route path="/admin" element={<AdminPage />} />
          <Route path="/account" element={<AccountPage />} />
          {NOT_BUILT.map(([path, title]) => (
            <Route key={path} path={path} element={<NotBuiltPage title={title} />} />
          ))}
          <Route path="*" element={<NotBuiltPage title="Not found" />} />
        </Routes>
  )
}
