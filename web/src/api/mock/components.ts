import type { ComponentDetail, ComponentList, Severity } from '../types'
import { PROJECT_LIST, projectDetail } from './projects'

const NOW = Date.parse('2026-10-30T09:41:00Z')

export function listComponents(project?: string): ComponentList {
  const components = PROJECT_LIST.projects
    .filter((p) => !project || p.key === project)
    .flatMap((p) => projectDetail(p.key)!.components.map((c) => ({ ...c, project: p.key })))
  const owners = [...new Set(components.map((c) => c.owner).filter((o): o is string => o != null))].sort()
  return { components, owners }
}

const FILES = ['handlers.go', 'repo.go', 'service.go', 'split.go', 'main.go', 'config.go']

export function componentDetail(project: string, path: string, branch?: string): ComponentDetail | null {
  const p = projectDetail(project, branch)
  const c = p?.components.find((x) => x.path === path)
  if (!p || !c) return null
  const severities: Severity[] = ['critical', 'major', 'major', 'minor', 'minor', 'info']
  const fileList = FILES.map((base, i) => ({
    path: `${path}/internal/${base}`,
    language: c.languages[0] ?? 'go',
    ncloc: 600 - i * 80,
    issues: Math.max(0, 6 - i),
    debtMinutes: Math.max(0, 6 - i) * 25,
    worst: severities[i],
  }))
  return {
    project,
    branch: p.branch,
    mainBranch: p.mainBranch,
    path,
    analyzedAt: p.analysis.analyzedAt,
    languages: c.languages.map((id, i) => ({ id, ncloc: Math.round(c.ncloc / 2 ** (i + 1)) })),
    files: c.files,
    ncloc: c.ncloc,
    owner: c.owner,
    owners: c.owner ? [{ owner: c.owner, files: c.files }, { owner: '@platform-sec', files: 12 }] : [],
    issues: {
      total: c.issues,
      new: Math.round(c.issues / 6),
      bySeverity: { critical: 2, major: Math.round(c.issues / 3), minor: c.issues - 2 - Math.round(c.issues / 3) },
      byCategory: { bug: Math.round(c.issues / 4), vulnerability: 2, code_smell: c.issues - 2 - Math.round(c.issues / 4) },
      debtMinutes: c.debtMinutes,
    },
    siblings: p.components,
    trend: Array.from({ length: 8 }, (_, i) => ({
      date: new Date(NOW - (7 - i) * 7 * 86_400_000).toISOString(),
      open: Math.max(0, c.issues - 8 + i + (i % 3)),
    })),
    fileList,
  }
}
