import type { Severity } from '@/api/types'

/**
 * Polyline points for a series in a 100-wide viewBox of height `h`,
 * scaled to the series' own min and max (flat series sit mid-height).
 */
export function linePoints(series: number[], h = 24, pad = 2): string {
  if (series.length === 0) return ''
  if (series.length === 1) return `0,${h / 2} 100,${h / 2}`
  const min = Math.min(...series)
  const range = Math.max(...series) - min || 1
  return series
    .map((v, i) => {
      const x = (i / (series.length - 1)) * 100
      const y = h - pad - ((v - min) / range) * (h - pad * 2)
      return `${x.toFixed(2)},${y.toFixed(2)}`
    })
    .join(' ')
}

/** The same line closed along the bottom edge, for filled sparklines. */
export function areaPoints(series: number[], h = 24): string {
  return `0,${h} ${linePoints(series, h)} 100,${h}`
}

/**
 * Splits 100 waffle cells by share of the total. Every non-zero severity
 * gets at least one cell (blockers stay visible); the largest group absorbs
 * the rounding difference so the cells always add up to exactly 100.
 */
export function waffleCells(counts: { severity: Severity; open: number }[]): Severity[] {
  const total = counts.reduce((sum, c) => sum + c.open, 0)
  if (total === 0) return []
  const shares = counts
    .filter((c) => c.open > 0)
    .map((c) => ({ severity: c.severity, cells: Math.max(1, Math.round((c.open / total) * 100)) }))
  const largest = shares.reduce((a, b) => (b.cells > a.cells ? b : a))
  largest.cells += 100 - shares.reduce((sum, s) => sum + s.cells, 0)
  return shares.flatMap((s) => Array<Severity>(s.cells).fill(s.severity))
}

/** Stroke dash for a ring of radius `r` filled to `pct` percent. */
export function ringDash(pct: number, r = 14): string {
  const circumference = 2 * Math.PI * r
  const clamped = Math.min(100, Math.max(0, pct))
  return `${((clamped / 100) * circumference).toFixed(1)} ${circumference.toFixed(1)}`
}
