import type { ProjectRule, ProjectRuleSetting, ProjectRuleState, ProjectRules, Rule, RuleProfileSummary, RuleSetBy, RuleSettingChange, Severity, SondaTomlRules } from '../types'

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

type ProfileRule = { on: boolean; severity: Severity | null; change: RuleSettingChange }
type MockProfile = { id: number; name: string; builtin: boolean; rules: Map<string, ProfileRule> }

/** Rule profiles and settings on the mock server, deciding states as the server does (ADR-0016, ADR-0018). */
export function mockRuleSettings() {
  const profiles: MockProfile[] = [{ id: 1, name: 'sonda way', builtin: true, rules: new Map() }]
  let defaultId = 1
  const chosen = new Map<string, number>()
  const own = new Map<string, Map<string, { on: boolean; change: RuleSettingChange }>>()
  const change = (by: string, note?: string): RuleSettingChange => ({ note: note?.trim() || null, changedBy: by, changedAt: new Date().toISOString() })
  const checkNote = (note?: string) => {
    if (note && note.trim().length > 500) throw new Error('a note has at most 500 characters')
  }
  const profileOf = (project: string) => profiles.find((p) => p.id === (chosen.get(project) ?? defaultId))!

  function state(rule: Rule, project: string): ProjectRuleState {
    const toml = SONDA_TOML[project] ?? null
    const [scannerOn, scannerBy]: [boolean, RuleSetBy] = toml?.disabled.includes(rule.id)
      ? [false, 'sonda_toml']
      : toml?.enabled.includes(rule.id)
        ? [true, 'sonda_toml']
        : [rule.onByDefault, 'default']
    const mine = own.get(project)?.get(rule.id)
    const inProfile = profileOf(project).rules.get(rule.id)
    const server = mine ? { on: mine.on, by: 'project' as const, change: mine.change } : inProfile ? { on: inProfile.on, by: 'profile' as const, change: inProfile.change } : null
    const tomlSeverity = toml?.severity[rule.id] && toml.severity[rule.id] !== rule.severity ? toml.severity[rule.id] : null
    const [severity, severityBy] = inProfile?.severity ? [inProfile.severity, 'profile' as const] : tomlSeverity ? [tomlSeverity, 'sonda_toml' as const] : [null, null]
    const base = { severity, severityBy, projectSetting: mine ? (mine.on ? 'on' : 'off') : null } as const
    // Scans apply the server's settings, except where the repository's are unknown.
    const applied = toml !== null
    if (server?.on && !applied && !scannerOn) return { ...base, on: false, setBy: scannerBy, change: server.change, conflict: true }
    if (server) return { ...base, on: server.on, setBy: server.by, change: server.change, conflict: false }
    return { ...base, on: scannerOn, setBy: scannerBy, change: null, conflict: false }
  }

  /** Whether the server leaves a rule's findings out for a project. */
  function off(rule: string, project: string): boolean {
    const mine = own.get(project)?.get(rule)
    if (mine) return !mine.on
    const p = profileOf(project).rules.get(rule)
    return p ? !p.on : false
  }

  /** The default profile, made editable: "sonda way" can't change, so "Server settings" takes its place. */
  function editableDefault(): MockProfile {
    const current = profiles.find((x) => x.id === defaultId)!
    if (!current.builtin) return current
    const p = profiles.find((x) => x.name === 'Server settings') ?? { id: Math.max(...profiles.map((x) => x.id)) + 1, name: 'Server settings', builtin: false, rules: new Map() }
    if (!profiles.includes(p)) profiles.push(p)
    defaultId = p.id
    return p
  }

  return {
    off,
    /** The catalog with where each rule is off, and which profiles set it. */
    withSettings(rules: Rule[], projects: string[]): Rule[] {
      const def = profiles.find((p) => p.id === defaultId)!
      return rules.map((r) => {
        const counts = { sondaToml: 0, server: 0 }
        for (const p of projects) {
          const s = state(r, p)
          if (s.on) continue
          if (s.setBy === 'sonda_toml') counts.sondaToml++
          if (s.setBy === 'profile' || s.setBy === 'project') counts.server++
        }
        const inDefault = def.rules.get(r.id)
        return {
          ...r,
          serverOff: inDefault && !inDefault.on ? inDefault.change : null,
          inProfiles: profiles.filter((p) => p.rules.has(r.id)).map((p) => ({ id: p.id, name: p.name, on: p.rules.get(r.id)!.on, severity: p.rules.get(r.id)!.severity })),
          offIn: counts.sondaToml + counts.server ? counts : null,
        }
      })
    },
    projectRules(project: string, languages: string[], rules: Rule[], openIssues: { project: string; rule: string }[]): ProjectRules {
      const p = profileOf(project)
      const relevant: ProjectRule[] = rules
        .filter((r) => r.languages.some((l) => languages.includes(l)))
        .map((r) => {
          const found = openIssues.filter((i) => i.project === project && i.rule === r.id).length
          const hidden = off(r.id, project)
          // The catalog's description, without the global counts.
          const { serverOff: _s, inProfiles: _p, offIn: _o, openIssues: _i, projects: _n, ...info } = r
          return { ...info, state: state(r, project), openIssues: hidden ? 0 : found, hiddenIssues: hidden ? found : 0 }
        })
      return {
        project,
        mainBranch: 'main',
        profile: { id: p.id, name: p.name, isDefault: p.id === defaultId, chosen: chosen.has(project) },
        profileApplied: project in SONDA_TOML ? SONDA_TOML[project] !== null : null,
        sondaToml: SONDA_TOML[project] ?? null,
        languages,
        rules: relevant,
        tomlChanges: TOML_CHANGES[project] ?? [],
      }
    },
    profiles(projects: string[]): RuleProfileSummary[] {
      return profiles
        .map((p) => ({ id: p.id, name: p.name, builtin: p.builtin, isDefault: p.id === defaultId, rules: p.rules.size, projects: projects.filter((k) => profileOf(k).id === p.id) }))
        .sort((a, b) => Number(b.isDefault) - Number(a.isDefault) || a.name.localeCompare(b.name))
    },
    setGlobal(rule: string, isOff: boolean, by: string, note?: string) {
      checkNote(note)
      const p = editableDefault()
      if (isOff) p.rules.set(rule, { on: false, severity: null, change: change(by, note) })
      else p.rules.delete(rule)
    },
    setProject(project: string, rule: string, setting: ProjectRuleSetting, by: string, note?: string) {
      checkNote(note)
      if (!['on', 'off', 'inherit'].includes(setting)) throw new Error('state is on, off or inherit')
      const map = own.get(project) ?? new Map()
      own.set(project, map)
      if (setting === 'inherit') map.delete(rule)
      else map.set(rule, { on: setting === 'on', change: change(by, note) })
    },
    setProjectProfile(project: string, profile: number | null) {
      if (profile === null) chosen.delete(project)
      else if (!profiles.some((p) => p.id === profile)) throw new Error(`no profile ${profile}`)
      else chosen.set(project, profile)
    },
  }
}
