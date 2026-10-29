import type { Drill, DrillMetric, Issue, IssuePatch, Rule, RuleCatalog, Shell, SondaApi } from '../types'
import issuesData from './issues.json'
import { DRILLS, overview } from './overview'
import rulesData from './rules.json'

/**
 * In-memory implementation of the contract, seeded from the design
 * prototypes. Writes (status, assignee, rule toggles) persist only until the
 * page reloads. `latency` makes loading states visible, as a server would.
 */
export function createMockApi(latency = 250): SondaApi {
  const issues = structuredClone(issuesData) as Issue[]
  const catalog = structuredClone(rulesData) as RuleCatalog
  const wait = <T>(value: T) => new Promise<T>((resolve) => setTimeout(() => resolve(structuredClone(value)), latency))

  const shell: Shell = {
    org: { name: 'acme-corp', initials: 'AC', deployment: 'self-hosted', projectCount: 312 },
    user: { name: 'Mara Okafor', handle: '@checkout', initials: 'MO' },
    counts: { projects: 312, components: 611, issues: 1342, security: 23 },
  }

  const findIssue = (id: number) => {
    const issue = issues.find((i) => i.id === id)
    if (!issue) throw new Error(`issue ${id} not found`)
    return issue
  }
  const findRule = (id: string) => {
    const rule = catalog.rules.find((r) => r.id === id)
    if (!rule) throw new Error(`rule ${id} not found`)
    return rule
  }

  return {
    shell: () => wait(shell),
    overview: (scope, range) => wait(overview(scope, range)),
    drill: (metric: DrillMetric) => wait<Drill>(DRILLS[metric]),
    issues: () => wait(issues),
    updateIssue: (id: number, patch: IssuePatch) => wait(Object.assign(findIssue(id), patch)),
    rules: () => wait(catalog),
    setRuleActive: (id: string, active: boolean) => wait<Rule>(Object.assign(findRule(id), { active })),
    setRuleParam: (id: string, key: string, value: string) => {
      const rule = findRule(id)
      const param = rule.params.find((p) => p.key === key)
      if (!param) throw new Error(`rule ${id} has no parameter ${key}`)
      param.value = value
      return wait(rule)
    },
  }
}
