/** A project's page, on `branch` unless it's the main branch. */
export function projectUrl(project: string, branch?: string, mainBranch?: string): string {
  const base = `/projects/${encodeURIComponent(project)}`
  return branch && branch !== mainBranch ? `${base}?branch=${encodeURIComponent(branch)}` : base
}

/** A component's page; `.` (the project's root files) is a component too. */
export function componentUrl(project: string, path: string, branch?: string, mainBranch?: string): string {
  const base = `/projects/${encodeURIComponent(project)}/components/${encodeURIComponent(path)}`
  return branch && branch !== mainBranch ? `${base}?branch=${encodeURIComponent(branch)}` : base
}

/** A project's dependencies, on `branch` unless it's the main branch. */
export function dependenciesUrl(project: string, branch?: string, mainBranch?: string): string {
  const base = `/projects/${encodeURIComponent(project)}/dependencies`
  return branch && branch !== mainBranch ? `${base}?branch=${encodeURIComponent(branch)}` : base
}

/** A project's coverage report, in directory `dir` (the root by default). */
export function coverageUrl(project: string, branch?: string, mainBranch?: string, dir?: string): string {
  const params = new URLSearchParams()
  if (branch && branch !== mainBranch) params.set('branch', branch)
  if (dir) params.set('dir', dir)
  const query = params.toString()
  return `/projects/${encodeURIComponent(project)}/coverage${query ? `?${query}` : ''}`
}

/** One file's covered and uncovered lines. */
export function fileCoverageUrl(project: string, path: string, branch?: string, mainBranch?: string): string {
  const params = new URLSearchParams({ path })
  if (branch && branch !== mainBranch) params.set('branch', branch)
  return `/projects/${encodeURIComponent(project)}/coverage/file?${params}`
}

/** MITRE's page for a CWE weakness. */
export function cweUrl(id: number): string {
  return `https://cwe.mitre.org/data/definitions/${id}.html`
}

/** How a component is named: its directory, or "(root)" for files at the root. */
export function componentLabel(path: string): string {
  return path === '.' ? '(root)' : `${path}/`
}
