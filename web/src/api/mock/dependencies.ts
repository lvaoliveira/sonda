import type { Advisory, DependencyList, DependencyRow, DependencySummary, ProjectDetail } from '../types'

type Seed = [ecosystem: string, name: string, version: string, direct: boolean | null, license: string | null, lockfiles: string[]]

const NPM = ['package-lock.json']
const WEB = ['web/package-lock.json']
const BOTH = [...NPM, ...WEB]

const SEEDS: Seed[] = [
  ['npm', '@babel/core', '7.24.4', false, 'MIT', WEB],
  ['npm', '@types/node', '20.12.7', true, 'MIT', BOTH],
  ['npm', 'debug', '4.3.4', false, 'MIT', NPM],
  ['npm', 'express', '4.19.2', true, 'MIT', NPM],
  ['npm', 'jsonwebtoken', '9.0.2', true, 'MIT', NPM],
  ['npm', 'lodash', '4.17.20', true, 'MIT', BOTH],
  ['npm', 'ms', '2.1.3', false, 'MIT', NPM],
  ['npm', 'react', '18.3.1', true, 'MIT', WEB],
  ['npm', 'react-dom', '18.3.1', true, 'MIT', WEB],
  ['npm', 'semver', '7.6.0', false, 'ISC', BOTH],
  ['npm', 'tslib', '2.6.2', false, '0BSD', WEB],
  ['npm', 'uglify-js', '3.17.4', false, 'BSD-2-Clause', NPM],
  ['npm', 'left-pad', '1.3.0', false, 'WTFPL', NPM],
  ['npm', 'internal-ui', '0.4.0', false, 'UNLICENSED', WEB],
  ['pypi', 'flask', '3.0.3', null, null, ['services/ml/requirements.txt']],
  ['pypi', 'requests', '2.31.0', null, null, ['services/ml/requirements.txt']],
  ['pypi', 'urllib3', '2.2.1', null, null, ['services/ml/requirements.txt']],
]

function purl(ecosystem: string, name: string, version: string): string {
  const [ns, bare] = name.startsWith('@') ? name.split('/') : [null, name]
  return `pkg:${ecosystem}/${ns ? `${encodeURIComponent(ns)}/` : ''}${bare}@${version}`
}

/** Real advisories for the versions above. */
const ADVISORIES: Record<string, Advisory[]> = {
  lodash: [
    {
      id: 'GHSA-35jh-r3h4-6jhm',
      aliases: ['CVE-2021-23337'],
      summary: 'Command Injection in lodash',
      severity: 'critical',
      score: 7.2,
      cwe: [77, 94],
      fixedIn: '4.17.21',
      source: 'GitHub Advisory Database (CC-BY 4.0)',
      url: 'https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm',
    },
  ],
  requests: [
    {
      id: 'GHSA-9wx4-h78v-vm56',
      aliases: ['CVE-2024-35195'],
      summary: 'Requests `Session` object does not verify requests after making first request with verify=False',
      severity: 'major',
      score: 5.6,
      cwe: [670],
      fixedIn: '2.32.0',
      source: 'GitHub Advisory Database (CC-BY 4.0)',
      url: 'https://osv.dev/vulnerability/GHSA-9wx4-h78v-vm56',
    },
  ],
}

const ROWS: DependencyRow[] = SEEDS.map(([ecosystem, name, version, direct, license, lockfiles]) => ({
  ecosystem,
  name,
  version,
  purl: purl(ecosystem, name, version),
  direct,
  license,
  lockfiles,
  advisories: ADVISORIES[name] ?? [],
  unchecked: [],
})).sort((a, b) => a.ecosystem.localeCompare(b.ecosystem) || a.name.localeCompare(b.name))

export function summarize(rows: DependencyRow[]): DependencySummary {
  const counts = new Map<string, number>()
  for (const r of rows) counts.set(r.ecosystem, (counts.get(r.ecosystem) ?? 0) + 1)
  return {
    total: rows.length,
    direct: rows.filter((r) => r.direct === true).length,
    vulnerable: rows.filter((r) => r.advisories.length > 0).length,
    ecosystems: [...counts].map(([id, count]) => ({ id, count })).sort((a, b) => b.count - a.count || a.id.localeCompare(b.id)),
  }
}

export const DEPENDENCY_SUMMARY = summarize(ROWS)

/** A project's dependencies: the same plausible set for every project. */
export function dependencyList(p: ProjectDetail): DependencyList {
  // As on the project page: some analyses recorded no lockfiles.
  const rows = p.dependencies ? ROWS : []
  const tally = <K,>(keys: K[]) => {
    const m = new Map<K, number>()
    for (const k of keys) m.set(k, (m.get(k) ?? 0) + 1)
    return m
  }
  return {
    project: p.key,
    branch: p.branch,
    mainBranch: p.mainBranch,
    analysis: { id: p.analysis.id, sha: p.analysis.sha, analyzedAt: p.analysis.analyzedAt },
    summary: summarize(rows),
    lockfiles: [...tally(rows.flatMap((r) => r.lockfiles))].map(([id, count]) => ({ id, count })).sort((a, b) => a.id.localeCompare(b.id)),
    licenses: [...tally(rows.map((r) => r.license))].map(([license, count]) => ({ license, count })).sort((a, b) => b.count - a.count),
    dependencies: rows,
    advisoryData: { importedAt: new Date(Date.parse(p.analysis.analyzedAt) - 3 * 3_600_000).toISOString(), advisories: 24_586 },
    changes: !p.dependencies ? null : {
      previousAnalysis: p.analysis.id - 1,
      added: [{ ecosystem: 'npm', name: 'jsonwebtoken', versions: ['9.0.2'] }],
      removed: [{ ecosystem: 'npm', name: 'request', versions: ['2.88.2'] }],
      updated: [
        { ecosystem: 'npm', name: 'express', from: ['4.18.2'], to: ['4.19.2'] },
        { ecosystem: 'pypi', name: 'requests', from: ['2.28.1'], to: ['2.31.0'] },
      ],
    },
  }
}
