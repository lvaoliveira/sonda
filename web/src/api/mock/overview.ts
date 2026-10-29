import type {
  AnalysisSummary,
  Drill,
  DrillMetric,
  FlowBucket,
  Kpi,
  Level,
  Overview,
  ProjectHealth,
  Range,
  Scope,
  Severity,
} from '../types'

// Sample data from docs/designs/Sonda Dashboard v3.dc.html.

const L: Record<'A' | 'B' | 'C' | 'D' | 'E', Level> = { A: 5, B: 4, C: 3, D: 2, E: 1 }

/** The prototype's seeded generator, so charts match the design exactly. */
function rng(seed: number): () => number {
  let s = seed
  return () => {
    s = (s * 16807) % 2147483647
    return (s - 1) / 2147483646
  }
}

function project(
  name: string,
  sub: string,
  gate: ProjectHealth['gate'],
  r: [keyof typeof L, keyof typeof L, keyof typeof L],
  coverage: number,
  newIssues: number,
  trend: number[],
  extra: Partial<ProjectHealth> = {},
): ProjectHealth {
  return { name, sub, gate, reliability: L[r[0]], security: L[r[1]], maintainability: L[r[2]], coverage, newIssues, trend, ...extra }
}

const PROJECTS: ProjectHealth[] = [
  project('payments-platform', 'acme/payments-platform · Go, Rust, TS, Python', 'failed', ['C', 'E', 'B'], 69.8, 14, [118, 120, 119, 123, 125, 124, 128, 131], {
    badge: '7 components',
    components: [
      project('services/checkout-api', 'Go · @checkout', 'failed', ['C', 'E', 'B'], 61.3, 6, [33, 34, 36, 35, 37, 38, 40, 41]),
      project('services/fraud-scoring', 'Python · @risk-ml', 'failed', ['B', 'D', 'C'], 48.9, 3, [29, 30, 31, 31, 33, 34, 36, 37]),
      project('packages/web-checkout', 'TypeScript · @web-platform', 'failed', ['B', 'D', 'A'], 72.0, 2, [24, 24, 25, 27, 26, 27, 28, 28]),
      project('services/ledger', 'Rust · @ledger-team', 'passed', ['A', 'A', 'B'], 84.1, 2, [18, 17, 17, 15, 14, 14, 13, 12]),
    ],
  }),
  project('billing-service', 'acme/billing-service · Java', 'failed', ['B', 'E', 'C'], 58.4, 9, [230, 226, 224, 221, 219, 218, 216, 214]),
  project('ml-feature-store', 'acme/ml-feature-store · Python', 'failed', ['C', 'B', 'D'], 41.7, 11, [150, 154, 158, 161, 165, 168, 170, 173]),
  project('mobile-bff', 'acme/mobile-bff · TypeScript', 'failed', ['C', 'C', 'B'], 63.1, 5, [74, 73, 75, 72, 71, 73, 72, 71]),
  project('data-pipeline', 'acme/data-pipeline · Python', 'partial', ['B', 'C', 'C'], 52.3, 4, [70, 69, 68, 68, 66, 65, 65, 64]),
  project('inventory-service', 'acme/inventory-service · Java', 'running', ['B', 'B', 'C'], 66.0, 0, [101, 100, 99, 99, 98, 97, 97, 96]),
]

type KpiRow = [DrillMetric, string, string, string, string, 'good' | 'bad', string, number[]]

const KPIS: Record<Scope, KpiRow[]> = {
  all: [
    ['gate', 'Gate pass rate', '81', '%', '−3 pts', 'bad', '253 of 312 passing', [86, 85, 85, 84, 84, 83, 82, 81]],
    ['critical', 'Blocker + critical', '47', '', '+9', 'bad', '9 introduced this week', [38, 40, 37, 39, 41, 40, 44, 47]],
    ['vulns', 'Vulnerabilities', '23', '', '−6', 'good', '5 critical · 14 projects', [33, 31, 32, 30, 28, 27, 25, 23]],
    ['coverage', 'Coverage', '72.4', '%', '+1.1', 'good', 'new code 76.8%', [70.9, 71.2, 71.0, 71.5, 71.8, 72.0, 72.1, 72.4]],
    ['dup', 'Duplication', '3.1', '%', '+0.2', 'bad', '1.2M duplicated lines', [2.8, 2.9, 2.9, 3.0, 2.9, 3.0, 3.1, 3.1]],
    ['debt', 'Tech debt', '412', 'days', '−18d', 'good', 'ratio 2.8%', [438, 434, 431, 427, 422, 419, 415, 412]],
  ],
  mine: [
    ['gate', 'Gate pass rate', '67', '%', '−8 pts', 'bad', '4 of 6 components passing', [80, 82, 78, 75, 76, 72, 70, 67]],
    ['critical', 'Blocker + critical', '9', '', '+3', 'bad', '2 assigned to you', [5, 5, 6, 6, 7, 6, 8, 9]],
    ['vulns', 'Vulnerabilities', '5', '', '+2', 'bad', '2 critical · checkout-api', [2, 3, 3, 3, 4, 3, 4, 5]],
    ['coverage', 'Coverage', '68.1', '%', '−1.4', 'bad', 'new code 61.0%', [70, 70.4, 69.8, 69.5, 69.1, 68.9, 68.4, 68.1]],
    ['dup', 'Duplication', '3.6', '%', '+0.3', 'bad', 'checkout handlers', [3.1, 3.2, 3.2, 3.3, 3.4, 3.4, 3.5, 3.6]],
    ['debt', 'Tech debt', '27', 'days', '−2d', 'good', 'ratio 3.1%', [31, 30, 30, 29, 29, 28, 28, 27]],
  ],
}

const SEVERITIES: Record<Scope, [Severity, number, number][]> = {
  all: [
    ['blocker', 12, 2],
    ['critical', 35, 7],
    ['major', 418, 31],
    ['minor', 692, 40],
    ['info', 185, 6],
  ],
  mine: [
    ['blocker', 1, 0],
    ['critical', 8, 3],
    ['major', 51, 6],
    ['minor', 77, 4],
    ['info', 22, 1],
  ],
}

const RECENT: AnalysisSummary[] = [
  { state: 'running', project: 'inventory-service', branch: 'feat/reservations', sha: '3be71d0', message: 'reservations: hold stock for 15 min on cart add', note: 'Running rules · stage 6 of 9', duration: '2:41', ago: 'now', progress: 64 },
  { state: 'failed', project: 'payments-platform', branch: 'main', sha: '9f3c2a1', message: 'checkout: support split tender for gift cards', note: '+14 new issues · 2 critical', duration: '4m 12s', ago: '12m' },
  { state: 'passed', project: 'web-console', branch: 'main', sha: '77a0c4e', message: 'settings: migrate billing tab to new table', note: '−6 issues · coverage +0.4%', duration: '2m 03s', ago: '26m' },
  { state: 'failed', project: 'mobile-bff', branch: 'main', sha: 'c01d9e2', message: 'auth: accept tokens from legacy issuer', note: 'Security level 3 → 2', duration: '1m 18s', ago: '40m' },
  { state: 'passed', project: 'auth-gateway', branch: 'release/1.8', sha: 'a4d0f19', message: 'release: 1.8.3', note: 'No new issues', duration: '48s', ago: '1h' },
  { state: 'partial', project: 'data-pipeline', branch: 'main', sha: '5e2f8b4', message: 'dags: nightly ledger reconciliation', note: 'Coverage report missing for 2 modules', duration: '3m 56s', ago: '4h' },
]

/** Ported from the prototype's flowData(): weekly buckets for 90d, daily otherwise. */
function flow(range: Range, scope: Scope): FlowBucket[] {
  const n = range === '7d' ? 7 : range === '30d' ? 30 : 13
  const rand = rng(range === '7d' ? 7 : range === '30d' ? 31 : 91)
  const scale = range === '90d' ? 1 : 0.16
  const sc = scope === 'mine' ? 0.12 : 1
  let open = Math.round((range === '90d' ? 1480 : range === '30d' ? 1398 : 1361) * sc)
  const out: FlowBucket[] = []
  for (let i = 0; i < n; i++) {
    const introduced = Math.round((60 + rand() * 50 + (i === Math.floor(n * 0.3) ? 40 : 0)) * scale * sc)
    const resolved = Math.round((70 + rand() * 45) * scale * sc)
    open += introduced - resolved
    out.push({ date: '', introduced, resolved, open })
  }
  const diff = Math.round(1342 * sc) - out[n - 1].open
  const step = range === '90d' ? 7 : 1
  out.forEach((d, i) => {
    d.open += Math.round((diff * (i + 1)) / n)
    d.date = new Date(Date.UTC(2026, 9, 29 - (n - 1 - i) * step)).toISOString()
  })
  return out
}

function gateDays() {
  const r = rng(42)
  return Array.from({ length: 30 }, (_, i) => ({
    date: new Date(Date.UTC(2026, 8, 30 + i)).toISOString(),
    passRate: Math.round((0.9 - r() * 0.12 - (i > 22 ? 0.05 : 0)) * 100),
  }))
}

export function overview(scope: Scope, range: Range): Overview {
  const mine = scope === 'mine'
  const kpis: Kpi[] = KPIS[scope].map(([metric, label, value, unit, delta, tone, sub, series]) => ({
    metric,
    label,
    value,
    unit,
    delta,
    improving: tone === 'good',
    sub,
    series,
  }))
  return {
    summary: { projects: 312, components: 611, lastSounding: '12m ago' },
    focus: [
      {
        severity: 'critical',
        tag: 'Your team · blocks main',
        title: 'checkout-api is blocking its gate on main',
        body: '2 critical vulnerabilities in new code — SQL built from request input in orders/repo.go. Blocking for 3 consecutive analyses.',
        trail: [
          { text: 'payments-platform', emphasis: 'muted' },
          { text: 'services/checkout-api', emphasis: 'strong' },
          { text: '~1h 15m', emphasis: 'faint' },
        ],
        cta: 'Review 2',
        drill: 'vulns',
      },
      {
        severity: 'blocker',
        tag: 'Blocker · 3h ago',
        title: 'Live Stripe secret committed to billing-service',
        body: 'StripeConfig.java:14 contains an sk_live key. Rotate it in Stripe first — it is already in git history.',
        trail: [
          { text: 'billing-service', emphasis: 'muted' },
          { text: 'config/StripeConfig.java', emphasis: 'strong' },
          { text: 'CWE-798', emphasis: 'faint' },
        ],
        cta: 'Open',
        drill: 'critical',
      },
      {
        severity: 'major',
        tag: 'Coverage −6.2 pts',
        title: 'fraud-scoring coverage fell to 48.9% on new code',
        body: 'The new scoring/config.py loader ships untested. Gate requires 80% on new code.',
        trail: [
          { text: 'payments-platform', emphasis: 'muted' },
          { text: 'services/fraud-scoring', emphasis: 'strong' },
        ],
        cta: 'Files',
        drill: 'coverage',
      },
      {
        severity: 'minor',
        tag: 'Assigned to you',
        title: '7 issues assigned to you · 3 introduced this week',
        body: 'Oldest: unchecked error from json.Encode in internal/http/handler.go (9 days).',
        trail: [
          { text: '4 in checkout-api', emphasis: 'muted' },
          { text: '3 in sdk-js', emphasis: 'muted' },
        ],
        cta: 'My issues',
        drill: 'critical',
      },
    ],
    focusTotal: 19,
    health: {
      score: mine ? 61 : 74,
      delta: mine ? '−4' : '+6',
      dimensions: [
        { label: 'Reliability', level: 4, score: 76, note: '214 bugs · 6 critical', drill: 'critical' },
        { label: 'Security', level: 2, score: 48, note: '23 vulnerabilities in 14 projects', drill: 'vulns' },
        { label: 'Maintainability', level: 4, score: 79, note: '412 days debt · 2.8% ratio', drill: 'debt' },
        { label: 'Coverage', level: 3, score: 72, note: '72.4% · 80% target on new code', drill: 'coverage' },
      ],
    },
    kpis,
    flow: flow(range, scope),
    severities: SEVERITIES[scope].map(([severity, open, newThisPeriod]) => ({ severity, open, newThisPeriod })),
    projects: mine ? [PROJECTS[0]] : PROJECTS,
    projectTotal: 312,
    gateHistory: {
      rate: 81,
      delta: -3,
      days: gateDays(),
      failing: [
        { label: 'Coverage on new code < 80%', failures: 31 },
        { label: 'New critical issues > 0', failures: 22 },
        { label: 'Duplication on new code > 3%', failures: 14 },
        { label: 'Hotspots reviewed < 100%', failures: 9 },
      ],
    },
    recent: mine ? RECENT.filter((a) => a.project === 'payments-platform') : RECENT,
  }
}

type DrillRow = [string, string, string, number, ([string, string, string] | [string, string, string, Severity, string, number])[]]

function drill(metric: DrillMetric, title: string, sub: string, tone: Drill['tone'], cta: string, unit: string, rows: DrillRow[], invert = false): Drill {
  return {
    metric,
    title,
    sub,
    tone,
    cta,
    unit,
    invert,
    items: rows.map(([component, project, owner, value, files]) => ({
      component,
      project,
      owner,
      value,
      files: files.map(([dir, base, v, severity, issue, line]) => ({
        dir,
        base,
        value: v,
        issue: severity && issue && line ? { severity, title: issue, line } : undefined,
      })),
    })),
  }
}

export const DRILLS: Record<DrillMetric, Drill> = {
  gate: drill('gate', '59 projects blocking on their gate', 'Components ordered by how many conditions they break. 41 of 59 trace to new-code coverage or new critical issues.', 'crit', 'Open failing projects', '', [
    ['services/checkout-api', 'payments-platform', '@checkout', 4, [['internal/orders/', 'repo.go', 'security', 'critical', 'SQL query built by concatenating user input', 88], ['internal/tender/', 'split.go', '38.6% cov', 'major', 'Partial-refund branch is never tested', 112]]],
    ['billing-service', 'billing-service', '@billing', 3, [['config/', 'StripeConfig.java', 'blocker', 'blocker', 'Hard-coded live Stripe secret key', 14]]],
    ['services/fraud-scoring', 'payments-platform', '@risk-ml', 3, [['scoring/', 'config.py', '22% cov', 'major', 'yaml.load with unsafe Loader on model config', 22]]],
    ['feature_store/ingest', 'ml-feature-store', '@data-platform', 2, [['ingest/', 'kafka_consumer.py', 'reliability', 'major', 'Broad except swallows deserialization errors', 61]]],
    ['packages/web-checkout', 'payments-platform', '@web-platform', 2, [['src/components/', 'PromoBanner.tsx', 'security', 'critical', 'Unsanitized HTML passed to dangerouslySetInnerHTML', 31]]],
  ]),
  critical: drill('critical', '47 blocker & critical issues', 'Grouped by component. 9 introduced this week; 2 assigned to you.', 'crit', 'Triage in issue explorer', '', [
    ['services/checkout-api', 'payments-platform', '@checkout', 9, [['internal/orders/', 'repo.go', '3', 'critical', 'SQL query built by concatenating user input', 88], ['internal/http/', 'handler.go', '2', 'critical', 'Request body size unbounded before JSON decode', 54]]],
    ['billing-service', 'billing-service', '@billing', 8, [['config/', 'StripeConfig.java', '1', 'blocker', 'Hard-coded live Stripe secret key', 14], ['invoice/', 'PdfRenderer.java', '2', 'critical', 'XXE: DocumentBuilderFactory allows external entities', 40]]],
    ['auth/session', 'mobile-bff', '@mobile', 6, [['src/auth/', 'jwt.ts', '2', 'critical', 'JWT decoded without signature verification', 27]]],
    ['packages/web-checkout', 'payments-platform', '@web-platform', 5, [['src/components/', 'PromoBanner.tsx', '1', 'critical', 'Unsanitized HTML passed to dangerouslySetInnerHTML', 31]]],
    ['services/fraud-scoring', 'payments-platform', '@risk-ml', 4, [['scoring/', 'config.py', '1', 'critical', 'yaml.load with unsafe Loader on model config', 22]]],
  ]),
  vulns: drill('vulns', '23 open vulnerabilities', '5 critical · 9 high · 9 medium. Reachable from a public endpoint first.', 'crit', 'Open security', '', [
    ['services/checkout-api', 'payments-platform', '@checkout', 5, [['internal/orders/', 'repo.go', 'CWE-89', 'critical', 'SQL injection reachable from POST /v1/orders', 88]]],
    ['billing-service', 'billing-service', '@billing', 4, [['config/', 'StripeConfig.java', 'CWE-798', 'blocker', 'Live secret committed to repository', 14]]],
    ['auth/session', 'mobile-bff', '@mobile', 4, [['src/auth/', 'jwt.ts', 'CWE-347', 'critical', 'JWT signature not verified', 27]]],
    ['packages/web-checkout', 'payments-platform', '@web-platform', 3, [['src/components/', 'PromoBanner.tsx', 'CWE-79', 'critical', 'Stored XSS via campaign body HTML', 31]]],
    ['services/fraud-scoring', 'payments-platform', '@risk-ml', 2, [['scoring/', 'config.py', 'CWE-502', 'major', 'Unsafe YAML deserialization', 22]]],
  ]),
  coverage: drill('coverage', 'Coverage 72.4% — where the gaps are', 'Components furthest below the 80% new-code threshold, with their least-covered files.', 'warn', 'Open coverage report', '%', [
    ['feature_store/ingest', 'ml-feature-store', '@data-platform', 41.7, [['ingest/', 'backfill.py', '12.0%'], ['ingest/', 'kafka_consumer.py', '38.5%']]],
    ['services/fraud-scoring', 'payments-platform', '@risk-ml', 48.9, [['scoring/', 'config.py', '22.0%'], ['scoring/', 'model.py', '51.3%']]],
    ['pipelines/nightly', 'data-pipeline', '@data-platform', 52.3, [['dags/', 'reconcile_ledger.py', '30.4%']]],
    ['billing-service', 'billing-service', '@billing', 58.4, [['invoice/', 'InvoiceCalculator.java', '44.9%']]],
    ['services/checkout-api', 'payments-platform', '@checkout', 61.3, [['internal/tender/', 'split.go', '38.6%'], ['internal/orders/', 'repo.go', '42.1%']]],
  ], true),
  dup: drill('dup', 'Duplication 3.1% of lines', 'Mostly copy-pasted request handlers.', 'warn', 'Open duplication report', '%', [
    ['mobile-bff', 'mobile-bff', '@mobile', 8.8, [['src/routes/', 'orders.ts', '14.2%'], ['src/routes/', 'returns.ts', '13.7%']]],
    ['billing-service', 'billing-service', '@billing', 7.1, [['invoice/', 'TaxRules.java', '18.0%']]],
    ['packages/web-checkout', 'payments-platform', '@web-platform', 6.3, [['src/components/', 'TenderPicker.tsx', '9.1%']]],
    ['feature_store/ingest', 'ml-feature-store', '@data-platform', 5.6, [['ingest/', 'schemas.py', '11.4%']]],
    ['services/checkout-api', 'payments-platform', '@checkout', 4.8, [['internal/orders/', 'repo.go', '8.4%']]],
  ]),
  debt: drill('debt', 'Technical debt 412 days', 'Estimated remediation effort. Top 5 components hold 38% of the total.', 'info', 'Open maintainability issues', 'd', [
    ['billing-service', 'billing-service', '@billing', 61, [['invoice/', 'InvoiceCalculator.java', '6d', 'major', 'Cognitive complexity 31 (max 15) in calculate()', 118]]],
    ['feature_store/ingest', 'ml-feature-store', '@data-platform', 44, [['ingest/', 'kafka_consumer.py', '4d', 'major', 'Function has 14 parameters (max 7)', 30]]],
    ['web-console/app', 'web-console', '@web-platform', 29, [['src/pages/', 'Settings.tsx', '2d', 'minor', 'Component is 1,240 lines; split by section', 1]]],
    ['services/fraud-scoring', 'payments-platform', '@risk-ml', 14, [['scoring/', 'model.py', '2d', 'major', 'Broad except Exception hides scoring failures', 47]]],
    ['services/checkout-api', 'payments-platform', '@checkout', 9, [['internal/orders/', 'service.go', '1d', 'minor', 'Duplicated validation across 4 handlers', 210]]],
  ]),
}
