import { describe, expect, it } from 'vitest'
import issuesData from '@/api/mock/issues.json'
import type { Issue } from '@/api/types'
import { areaPoints, linePoints, ringDash, waffleCells } from './charts'
import { compactCount, formatEffort } from './format'
import { DEFAULT_FILTER, facetCount, filterFromParams, filterIssues, matches } from './issues'
import { projectScore, SEVERITY } from './visual'

const issues = issuesData as Issue[]
const ME = 'Mara Okafor'

describe('charts', () => {
  it('scales a series to its own range, first point left, last right', () => {
    const pts = linePoints([10, 20, 30]).split(' ')
    expect(pts[0]).toBe('0.00,22.00') // minimum sits at the bottom padding
    expect(pts[2]).toBe('100.00,2.00') // maximum at the top padding
  })

  it('keeps flat and tiny series finite', () => {
    expect(linePoints([5, 5, 5])).not.toContain('NaN')
    expect(linePoints([7])).toBe('0,12 100,12')
    expect(linePoints([])).toBe('')
  })

  it('closes the area along the bottom edge', () => {
    expect(areaPoints([1, 2]).startsWith('0,24 ')).toBe(true)
    expect(areaPoints([1, 2]).endsWith(' 100,24')).toBe(true)
  })

  it('allocates exactly 100 waffle cells and never hides a non-zero severity', () => {
    // The design's sample: 12 blockers out of 1,342 open issues (< 1%).
    const cells = waffleCells([
      { severity: 'blocker', open: 12 },
      { severity: 'critical', open: 35 },
      { severity: 'major', open: 418 },
      { severity: 'minor', open: 692 },
      { severity: 'info', open: 185 },
    ])
    expect(cells).toHaveLength(100)
    expect(cells.filter((c) => c === 'blocker').length).toBeGreaterThanOrEqual(1)
    // Rounded shares sum to 101 (minor 51.6% → 52); the largest group gives
    // the extra cell back, as in the design.
    expect(cells.filter((c) => c === 'minor')).toHaveLength(51)
    // Grouped in severity order, as the legend reads.
    expect(cells.indexOf('blocker')).toBe(0)
  })

  it('handles empty and single-severity waffles', () => {
    expect(waffleCells([{ severity: 'major', open: 0 }])).toEqual([])
    expect(new Set(waffleCells([{ severity: 'info', open: 3 }]))).toEqual(new Set(['info']))
  })

  it('clamps coverage rings', () => {
    expect(ringDash(150)).toBe(ringDash(100))
    expect(ringDash(-5).startsWith('0.0 ')).toBe(true)
  })
})

describe('format', () => {
  it('formats effort like the CLI', () => {
    expect(formatEffort(45)).toBe('45min')
    expect(formatEffort(120)).toBe('2h')
    expect(formatEffort(75)).toBe('1h 15m')
  })

  it('compacts navigation counts', () => {
    expect(compactCount(312)).toBe('312')
    expect(compactCount(1342)).toBe('1.3k')
    expect(compactCount(25_400)).toBe('25k')
  })
})

describe('visual', () => {
  it('scores projects like the design (ratings 70%, coverage 30%)', () => {
    // payments-platform: Rel C (3), Sec E (1), Mnt B (4), coverage 69.8% → 58.
    expect(projectScore([3, 1, 4], 69.8)).toBe(58)
    expect(projectScore([5, 5, 5], 100)).toBe(100)
  })

  it('gives every severity a distinct glyph', () => {
    const glyphs = Object.values(SEVERITY).map((s) => s.glyph)
    expect(new Set(glyphs).size).toBe(glyphs.length)
  })
})

describe('issue filtering', () => {
  it('shows open and confirmed issues by default, most severe first', () => {
    const list = filterIssues(issues, DEFAULT_FILTER, ME)
    expect(list.every((i) => i.status === 'open' || i.status === 'confirmed')).toBe(true)
    const ranks = list.map((i) => SEVERITY[i.severity].rank)
    expect(ranks).toEqual([...ranks].sort((a, b) => a - b))
  })

  it('counts a facet without its own selection', () => {
    const f = { ...DEFAULT_FILTER, severity: ['critical' as const] }
    const majorCount = facetCount(issues, f, ME, 'severity', 'major')
    // Selecting "critical" must not zero out the other severities' counts.
    expect(majorCount).toBe(issues.filter((i) => matches(i, { ...f, severity: [] }, ME) && i.severity === 'major').length)
    expect(majorCount).toBeGreaterThan(0)
  })

  it('combines toggles and file filters', () => {
    const mine = filterIssues(issues, { ...DEFAULT_FILTER, mine: true, status: [] }, ME)
    expect(mine.length).toBeGreaterThan(0)
    expect(mine.every((i) => i.assignee === ME)).toBe(true)
    const file = issues[0].file
    expect(filterIssues(issues, { ...DEFAULT_FILTER, file, status: [] }, ME).every((i) => i.file.includes(file))).toBe(true)
  })

  it('reads drill-down links from query parameters', () => {
    const result = filterFromParams(new URLSearchParams('new&cat=vulnerability&comp=checkout'), (id) => `services/${id}-api`)
    expect(result?.filter).toMatchObject({ isNew: true, category: ['vulnerability'], component: ['checkout'] })
    expect(result?.description).toBe('Showing new code · vulnerabilities · services/checkout-api — from the metric you clicked')
  })

  it('ignores empty or unknown drill-down parameters', () => {
    expect(filterFromParams(new URLSearchParams(''), (x) => x)).toBeNull()
    expect(filterFromParams(new URLSearchParams('cat=exploit'), (x) => x)).toBeNull()
  })
})
