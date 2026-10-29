/** Effort like sonda's text report: "45min", "2h", "1h 15m". */
export function formatEffort(minutes: number): string {
  if (minutes < 60) return `${minutes}min`
  const h = Math.floor(minutes / 60)
  const m = minutes % 60
  return m ? `${h}h ${m}m` : `${h}h`
}

/** Compact counts for navigation badges: 1342 → "1.3k". */
export function compactCount(n: number): string {
  if (n < 1000) return String(n)
  const k = n / 1000
  return `${k >= 10 ? Math.round(k) : Math.round(k * 10) / 10}k`
}

export function formatNumber(n: number): string {
  return n.toLocaleString('en-US')
}

export function shortDate(iso: string): string {
  return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' })
}
