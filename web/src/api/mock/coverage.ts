import type { CodeLine, CoverageFile, CoverageList, FileCoverage, ProjectDetail } from '../types'

/** Each file's length and which of its lines run; one in four lines isn't coverable. */
const FILES: [path: string, lines: number, missed: number][] = [
  ['src/api/handlers.ts', 48, 6],
  ['src/api/routes.ts', 22, 0],
  ['src/api/auth/session.ts', 36, 14],
  ['src/api/auth/tokens.ts', 30, 2],
  ['src/billing/invoice.ts', 64, 21],
  ['src/billing/tax.ts', 40, 3],
  ['src/billing/refunds.ts', 28, 21],
  ['src/util/dates.ts', 18, 0],
  ['src/util/money.ts', 24, 1],
  ['src/index.ts', 12, 9],
  ['scripts/migrate.ts', 20, 15],
]

/** As the server lists them: every file, by path; null without coverage data. */
function files(withData: boolean): CoverageFile[] {
  const rows = FILES.map(([path, lines, missed]) => {
    const coverable = lines - Math.floor(lines / 4)
    return { path, language: 'typescript', covered: withData ? coverable - missed : null, uncovered: withData ? missed : null }
  })
  // A file the coverage reports didn't list.
  rows.push({ path: 'src/generated/schema.ts', language: 'typescript', covered: null, uncovered: null })
  return rows.sort((a, b) => a.path.localeCompare(b.path))
}

export function coverageList(p: ProjectDetail): CoverageList {
  const list = files(p.measures.overall.coverage != null)
  const covered = list.reduce((n, f) => n + (f.covered ?? 0), 0)
  const coverable = list.reduce((n, f) => n + (f.covered ?? 0) + (f.uncovered ?? 0), 0)
  return {
    project: p.key,
    branch: p.branch,
    analysis: { id: p.analysis.id, sha: p.analysis.sha, analyzedAt: p.analysis.analyzedAt },
    coverage: coverable === 0 ? null : Math.round((1000 * covered) / coverable) / 10,
    files: list,
  }
}

export function fileCoverage(p: ProjectDetail, path: string): FileCoverage {
  // Other paths (the Overview's drill-down names some) get a short, half
  // covered file; the generated schema is in no coverage report.
  const row = FILES.find(([f]) => f === path) ?? (path === 'src/generated/schema.ts' ? undefined : ([path, 24, 9] as const))
  const length = row?.[1] ?? 10
  const withData = row != null && p.measures.overall.coverage != null
  const lines: CodeLine[] = Array.from({ length }, (_, i) =>
    i % 4 === 3
      ? { number: i + 1, tokens: [{ text: '  // ' + (i % 8 === 3 ? 'keep totals in cents' : 'see the README'), role: 'comment' as const }] }
      : {
          number: i + 1,
          tokens: [
            { text: '  const ', role: 'keyword' as const },
            { text: `value${i + 1}`, role: 'plain' as const },
            { text: ' = ', role: 'punct' as const },
            { text: `compute(${i + 1})`, role: 'plain' as const },
          ],
        },
  )
  const coverable = lines.map((l) => l.number).filter((n) => n % 4 !== 0)
  // The missed lines are the last ones: an untested tail, as is common.
  const missed = row?.[2] ?? 0
  return {
    project: p.key,
    branch: p.branch,
    analysis: { id: p.analysis.id, sha: p.analysis.sha, analyzedAt: p.analysis.analyzedAt },
    path,
    language: 'typescript',
    covered: withData ? coverable.slice(0, coverable.length - missed) : null,
    uncovered: withData ? coverable.slice(coverable.length - missed) : null,
    lines,
    truncated: false,
  }
}
