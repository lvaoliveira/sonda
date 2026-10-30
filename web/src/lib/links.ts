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

/** MITRE's page for a CWE weakness. */
export function cweUrl(id: number): string {
  return `https://cwe.mitre.org/data/definitions/${id}.html`
}

/** How a component is named: its directory, or "(root)" for files at the root. */
export function componentLabel(path: string): string {
  return path === '.' ? '(root)' : `${path}/`
}
