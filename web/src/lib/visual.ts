import type { Category, GateState, IssueStatus, Level, Severity, TokenRole, TokenType } from '@/api/types'

/** Severity is always a glyph plus a label, never color alone. */
export const SEVERITY: Record<Severity, { glyph: string; label: string; color: string; soft: string; rank: number }> = {
  blocker: { glyph: '■', label: 'Blocker', color: 'var(--sd-crit)', soft: 'var(--sd-crit-soft)', rank: 0 },
  critical: { glyph: '▲', label: 'Critical', color: 'var(--sd-crit)', soft: 'var(--sd-crit-soft)', rank: 1 },
  major: { glyph: '◆', label: 'Major', color: 'var(--sd-warn)', soft: 'var(--sd-warn-soft)', rank: 2 },
  minor: { glyph: '●', label: 'Minor', color: 'var(--sd-info)', soft: 'var(--sd-info-soft)', rank: 3 },
  info: { glyph: '○', label: 'Info', color: 'var(--sd-faint)', soft: 'var(--sd-hover)', rank: 4 },
}

export const SEVERITY_ORDER: Severity[] = ['blocker', 'critical', 'major', 'minor', 'info']

export const CATEGORY_LABEL: Record<Category, string> = {
  bug: 'Bug',
  vulnerability: 'Vulnerability',
  code_smell: 'Code smell',
}

/** Gate status is a shaped dot plus a word, never a filled pill. */
export const GATE: Record<
  GateState,
  { label: string; color: string; dot: string; radius: string; ring: string; glyph: string; soft: string }
> = {
  passed: { label: 'Passing', color: 'var(--sd-ok)', dot: 'var(--sd-ok)', radius: '50%', ring: 'none', glyph: '✓', soft: 'var(--sd-ok-soft)' },
  failed: {
    label: 'Blocking',
    color: 'var(--sd-crit)',
    dot: 'var(--sd-crit)',
    radius: '2px',
    ring: '0 0 0 3px var(--sd-crit-soft)',
    glyph: '✕',
    soft: 'var(--sd-crit-soft)',
  },
  running: {
    label: 'Sounding',
    color: 'var(--sd-info)',
    dot: 'transparent',
    radius: '50%',
    ring: 'inset 0 0 0 2px var(--sd-info)',
    glyph: '◌',
    soft: 'var(--sd-info-soft)',
  },
  partial: { label: 'Partial', color: 'var(--sd-warn)', dot: 'var(--sd-warn)', radius: '1px', ring: 'none', glyph: '!', soft: 'var(--sd-warn-soft)' },
}

export const STATUS_LABEL: Record<IssueStatus, string> = {
  open: 'Open',
  confirmed: 'Confirmed',
  fixed: 'Fixed',
  accepted: 'Accepted',
  false_positive: 'False positive',
}

export const STATUS_COLOR: Record<IssueStatus, string> = {
  open: 'var(--sd-text)',
  confirmed: 'var(--sd-warn)',
  fixed: 'var(--sd-ok)',
  accepted: 'var(--sd-faint)',
  false_positive: 'var(--sd-faint)',
}

/** What the reason form asks before each decision that needs one (ADR-0014). */
export const DECISION_PROMPT = {
  accepted: { verb: 'Accept', prompt: 'Why is this risk acceptable?' },
  false_positive: { verb: 'Mark false positive', prompt: 'Why is this not a real problem?' },
} as const

/** Level 4–5 is good, 3 is a warning, 1–2 is critical. */
export function levelColor(level: Level): string {
  return level >= 4 ? 'var(--sd-ok)' : level === 3 ? 'var(--sd-warn)' : 'var(--sd-crit)'
}

export function coverageColor(pct: number): string {
  return pct >= 80 ? 'var(--sd-ok)' : pct >= 60 ? 'var(--sd-warn)' : 'var(--sd-crit)'
}

export function scoreColor(score: number): string {
  return score >= 75 ? 'var(--sd-ok)' : score >= 60 ? 'var(--sd-warn)' : 'var(--sd-crit)'
}

/** The design's project score: ratings weigh 70%, coverage 30%. */
/** Ratings weigh 70% and coverage 30%; without coverage, ratings alone. The server sorts projects the same way. */
export function projectScore(levels: Level[], coverage: number | null): number {
  const ratings = levels.reduce((sum, l) => sum + l, 0) / (levels.length * 5)
  return Math.round(coverage == null ? ratings * 100 : ratings * 70 + coverage * 0.3)
}

const LANGUAGE_LABEL: Record<string, string> = {
  javascript: 'JavaScript',
  typescript: 'TypeScript',
  tsx: 'TSX',
  python: 'Python',
  java: 'Java',
  c: 'C',
  cpp: 'C++',
  go: 'Go',
  rust: 'Rust',
}

/** Display name for a language id (as in reports); unknown ids show as is. */
export function languageLabel(id: string): string {
  return LANGUAGE_LABEL[id] ?? id
}

/** Package ecosystems, as dependencies report them. */
export const ECOSYSTEM_LABEL: Record<string, string> = { npm: 'npm', cargo: 'Cargo', pypi: 'PyPI' }

/** Token roles map to theme colors, as in the design handoff. */
export const ROLE_COLOR: Record<TokenRole, string> = {
  keyword: 'var(--sd-info)',
  string: 'var(--sd-ok)',
  number: 'var(--sd-warn)',
  comment: 'var(--sd-faint)',
  type: 'var(--sd-accent)',
  punct: 'var(--sd-muted)',
  plain: 'var(--sd-text)',
}

/** Token types (ADR-0012), as SonarQube names them. */
export const TOKEN_TYPE: Record<TokenType, { label: string; note: string }> = {
  user: { label: 'User', note: 'Acts as you: reads, triage and uploads, never account or token changes.' },
  project_analysis: { label: 'Project analysis', note: 'Uploads analyses of one project, nothing else. Best for CI.' },
  global_analysis: { label: 'Global analysis', note: 'Uploads analyses of any project, nothing else.' },
}
