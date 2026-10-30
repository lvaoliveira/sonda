import type { Security } from '../types'

const NOW = Date.parse('2026-10-30T09:41:00Z')
const days = (n: number) => new Date(NOW - n * 86_400_000).toISOString()

/** The design's numbers, where sonda records them. */
export const SECURITY: Security = {
  openBySeverity: { blocker: 2, critical: 5, major: 9, minor: 7 },
  open: 23,
  newThisWeek: 4,
  projectsAffected: 6,
  status: { open: 15, confirmed: 8, accepted: 4, fixedLast30Days: 31 },
  focus: [
    { id: 101, severity: 'blocker', rule: 'js/hardcoded-secret', message: 'Revoke this secret and read it from the environment or a secret store.', project: 'billing-service', branch: 'main', component: 'src', path: 'src/main/java/com/acme/billing/config/StripeConfig.java', line: 14, firstSeen: days(1), ageDays: 1 },
    { id: 102, severity: 'blocker', rule: 'js/xxe', message: "Remove 'noent: true' so external entities aren't expanded.", project: 'billing-service', branch: 'main', component: 'src', path: 'src/pdf/render.js', line: 41, firstSeen: days(9), ageDays: 9 },
    { id: 103, severity: 'critical', rule: 'js/no-eval', message: 'Remove this use of eval().', project: 'payments-platform', branch: 'main', component: 'services', path: 'services/checkout-api/handlers.js', line: 88, firstSeen: days(26), ageDays: 26 },
    { id: 104, severity: 'critical', rule: 'js/tls-unverified', message: "Remove 'rejectUnauthorized: false'; trust a private CA with the 'ca' option instead.", project: 'mobile-bff', branch: 'main', component: 'src', path: 'src/clients/legacy.ts', line: 12, firstSeen: days(4), ageDays: 4 },
    { id: 105, severity: 'critical', rule: 'js/weak-hash', message: 'Use a stronger algorithm such as SHA-256.', project: 'payments-platform', branch: 'main', component: 'packages', path: 'packages/sdk-js/sign.js', line: 7, firstSeen: days(3), ageDays: 3 },
    { id: 106, severity: 'major', rule: 'js/cors-any-origin', message: 'List the trusted origins instead of allowing every origin.', project: 'data-pipeline', branch: 'main', component: 'src', path: 'src/api/server.js', line: 22, firstSeen: days(40), ageDays: 40 },
  ],
  trend: Array.from({ length: 12 }, (_, i) => {
    const open = [31, 30, 32, 33, 31, 30, 29, 28, 27, 25, 24, 23][i]
    return { date: days((11 - i) * 7), open, weighted: open * 3 + (i < 6 ? 12 : 4), introduced: [5, 3, 6, 4, 2, 3, 4, 2, 3, 1, 3, 4][i], fixed: [4, 4, 4, 3, 4, 4, 5, 3, 4, 3, 4, 5][i] }
  }),
  projects: [
    { project: 'billing-service', severe: 3, other: 2 },
    { project: 'payments-platform', severe: 2, other: 5 },
    { project: 'mobile-bff', severe: 1, other: 3 },
    { project: 'data-pipeline', severe: 1, other: 2 },
    { project: 'ml-feature-store', severe: 0, other: 3 },
    { project: 'inventory-service', severe: 0, other: 1 },
  ],
  components: [
    { project: 'billing-service', path: 'src', count: 5, worst: 'blocker', weighted: 31 },
    { project: 'payments-platform', path: 'services', count: 4, worst: 'critical', weighted: 14 },
    { project: 'mobile-bff', path: 'src', count: 4, worst: 'critical', weighted: 11 },
    { project: 'payments-platform', path: 'packages', count: 3, worst: 'critical', weighted: 9 },
  ],
  rules: [
    { rule: 'js/hardcoded-password', count: 5 },
    { rule: 'js/weak-hash', count: 4 },
    { rule: 'js/no-eval', count: 3 },
    { rule: 'js/cors-any-origin', count: 3 },
    { rule: 'js/tls-unverified', count: 2 },
  ],
  remediation: { medianDaysSevere: 4.2, medianDaysAll: 9.5, fixedLast90Days: 88 },
}
