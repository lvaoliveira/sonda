import type { ProjectRuleSetting, ProjectRules, ProjectRuleState, Rule, RuleSetBy, RuleSettingChange, SondaTomlRules } from '../types'

/** The repositories' `[rules]`, as their latest analyses recorded them; null when unknown. */
const SONDA_TOML: Record<string, SondaTomlRules | null> = {
  'payments-platform': {
    disabled: ['go/unchecked-error'],
    enabled: ['rust/undocumented-unsafe'],
    severity: { 'py/broad-except': 'minor' },
  },
  // Scanned with a sonda that didn't send them.
  'billing-service': null,
}

const TOML_CHANGES: Record<string, ProjectRules['tomlChanges']> = {
  'payments-platform': [
    { analysisId: 909, sha: '3f1c2a7d9e', at: '2026-10-28T10:00:00Z', rule: 'go/unchecked-error', change: 'disabled' },
    { analysisId: 905, sha: '8b2e44c1aa', at: '2026-10-20T10:00:00Z', rule: 'rust/undocumented-unsafe', change: 'enabled' },
  ],
}

/** Rule settings on the mock server, deciding states as the server does (ADR-0016). */
export function mockRuleSettings() {
  const global = new Map<string, RuleSettingChange>()
  const own = new Map<string, Map<string, { on: boolean; change: RuleSettingChange }>>()
  const change = (by: string, note?: string): RuleSettingChange => ({ note: note?.trim() || null, changedBy: by, changedAt: new Date().toISOString() })
  const checkNote = (note?: string) => {
    if (note && note.trim().length > 500) throw new Error('a note has at most 500 characters')
  }

  function state(rule: Rule, project: string): Omit<ProjectRuleState, 'name' | 'hiddenIssues'> {
    const toml = SONDA_TOML[project] ?? null
    const [scannerOn, scannerBy]: [boolean, RuleSetBy] = toml?.disabled.includes(rule.id)
      ? [false, 'sonda_toml']
      : toml?.enabled.includes(rule.id)
        ? [true, 'sonda_toml']
        : [rule.onByDefault, 'default']
    const mine = own.get(project)?.get(rule.id)
    const server = mine ? { on: mine.on, by: 'project' as const, change: mine.change } : global.has(rule.id) ? { on: false, by: 'profile' as const, change: global.get(rule.id)! } : null
    const severity = toml?.severity[rule.id] && toml.severity[rule.id] !== rule.severity ? toml.severity[rule.id] : null
    const base = { rule: rule.id, severity, severityBy: severity ? ('sonda_toml' as const) : null, projectSetting: mine ? (mine.on ? 'on' : 'off') : null } as const
    if (!scannerOn) return { ...base, on: false, setBy: scannerBy, change: server?.change ?? null, conflict: server?.on === true }
    if (server) return { ...base, on: server.on, setBy: server.by, change: server.change, conflict: false }
    return { ...base, on: true, setBy: scannerBy, change: null, conflict: false }
  }

  /** Whether the server leaves a rule's findings out for a project. */
  function off(rule: string, project: string): boolean {
    const mine = own.get(project)?.get(rule)
    return mine ? !mine.on : global.has(rule)
  }

  return {
    off,
    /** The catalog with where each rule is off. */
    withSettings(rules: Rule[], projects: string[]): Rule[] {
      return rules.map((r) => {
        const counts = { sondaToml: 0, server: 0 }
        for (const p of projects) {
          const s = state(r, p)
          if (s.on) continue
          if (s.setBy === 'sonda_toml') counts.sondaToml++
          if (s.setBy === 'profile' || s.setBy === 'project') counts.server++
        }
        return { ...r, serverOff: global.get(r.id) ?? null, offIn: counts.sondaToml + counts.server ? counts : null }
      })
    },
    projectRules(project: string, rules: Rule[], openIssues: { project: string; rule: string }[]): ProjectRules {
      const states = rules
        .map((r) => ({ ...state(r, project), name: r.name, hiddenIssues: off(r.id, project) ? openIssues.filter((i) => i.project === project && i.rule === r.id).length : 0 }))
        .filter((s) => s.setBy !== 'default' || s.projectSetting || s.conflict || s.severity || global.has(s.rule))
        .sort((a, b) => a.rule.localeCompare(b.rule))
      return {
        project,
        mainBranch: 'main',
        profile: { id: 1, name: global.size ? 'Server settings' : 'sonda way', isDefault: true, chosen: false },
        profileApplied: project in SONDA_TOML ? SONDA_TOML[project] !== null : null,
        sondaToml: SONDA_TOML[project] ?? null,
        rules: states,
        tomlChanges: TOML_CHANGES[project] ?? [],
      }
    },
    setGlobal(rule: string, isOff: boolean, by: string, note?: string) {
      checkNote(note)
      if (isOff) global.set(rule, change(by, note))
      else global.delete(rule)
    },
    setProject(project: string, rule: string, setting: ProjectRuleSetting, by: string, note?: string) {
      checkNote(note)
      if (!['on', 'off', 'inherit'].includes(setting)) throw new Error('state is on, off or inherit')
      const map = own.get(project) ?? new Map()
      own.set(project, map)
      if (setting === 'inherit') map.delete(rule)
      else map.set(rule, { on: setting === 'on', change: change(by, note) })
    },
  }
}
