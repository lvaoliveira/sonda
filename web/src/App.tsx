import { BrowserRouter, Route, Routes } from 'react-router'
import { ApiProvider } from '@/api/ApiProvider'
import { SessionGate } from '@/components/shell/SessionGate'
import type { SondaApi } from '@/api/types'
import { AccountPage } from '@/pages/AccountPage'
import { AnalysesPage } from '@/pages/AnalysesPage'
import { AnalysisPage } from '@/pages/AnalysisPage'
import { ComponentPage } from '@/pages/ComponentPage'
import { CoveragePage, FileCoveragePage } from '@/pages/CoveragePage'
import { DependenciesPage } from '@/pages/DependenciesPage'
import { ComponentsPage } from '@/pages/ComponentsPage'
import { GatesPage } from '@/pages/GatesPage'
import { AdminPage } from '@/pages/AdminPage'
import { IssuesPage } from '@/pages/IssuesPage'
import { NotFoundPage } from '@/pages/NotFoundPage'
import { OverviewPage } from '@/pages/OverviewPage'
import { ProjectPage } from '@/pages/ProjectPage'
import { ProjectSettingsPage } from '@/pages/ProjectSettingsPage'
import { ProjectsPage } from '@/pages/ProjectsPage'
import { RulesPage } from '@/pages/RulesPage'
import { SecurityPage } from '@/pages/SecurityPage'

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
          <Route path="/projects/:key/settings" element={<ProjectSettingsPage />} />
          <Route path="/projects/:key/components/:component" element={<ComponentPage />} />
          <Route path="/projects/:key/dependencies" element={<DependenciesPage />} />
          <Route path="/projects/:key/coverage" element={<CoveragePage />} />
          <Route path="/projects/:key/coverage/file" element={<FileCoveragePage />} />
          <Route path="/components" element={<ComponentsPage />} />
          <Route path="/security" element={<SecurityPage />} />
          <Route path="/gates" element={<GatesPage />} />
          <Route path="/issues" element={<IssuesPage />} />
          <Route path="/rules" element={<RulesPage />} />
          <Route path="/admin" element={<AdminPage />} />
          <Route path="/account" element={<AccountPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
  )
}
