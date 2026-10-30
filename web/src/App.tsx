import { BrowserRouter, Route, Routes } from 'react-router'
import { ApiProvider } from '@/api/ApiProvider'
import { SessionGate } from '@/components/shell/SessionGate'
import type { SondaApi } from '@/api/types'
import { AccountPage } from '@/pages/AccountPage'
import { AnalysesPage } from '@/pages/AnalysesPage'
import { AnalysisPage } from '@/pages/AnalysisPage'
import { AdminPage } from '@/pages/AdminPage'
import { IssuesPage } from '@/pages/IssuesPage'
import { NotBuiltPage } from '@/pages/NotBuiltPage'
import { OverviewPage } from '@/pages/OverviewPage'
import { ProjectPage } from '@/pages/ProjectPage'
import { ProjectsPage } from '@/pages/ProjectsPage'
import { RulesPage } from '@/pages/RulesPage'

const NOT_BUILT: [string, string][] = [
  ['/components', 'Components'],
  ['/security', 'Security'],
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
          <Route path="/analyses" element={<AnalysesPage />} />
          <Route path="/analyses/:id" element={<AnalysisPage />} />
          <Route path="/projects" element={<ProjectsPage />} />
          <Route path="/projects/:key" element={<ProjectPage />} />
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
