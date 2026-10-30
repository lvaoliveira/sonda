import { describe, expect, it } from 'vitest'
import issuesData from '@/api/mock/issues.json'
import { queryIssues } from '@/api/mock/query'
import type { IssueDetail } from '@/api/types'
import { areaPoints, linePoints, ringDash, waffleCells } from './charts'
import { compactCount, formatAge, formatEffort } from './format'
import { initials } from './identity'
import { DEFAULT_FILTER, filterFromParams, issueSearchParams, toQuery } from './issues'
import { languageLabel, projectScore, SEVERITY } from './visual'

const issues = issuesData as IssueDetail[]
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
    expect(compactCount(1_023_000)).toBe('1.0M')
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

describe('issue queries', () => {
  it('turns the page filter into an API query', () => {
    expect(toQuery({ ...DEFAULT_FILTER, mine: true, isNew: true }, ME, 50)).toEqual({
      severity: [],
      category: [],
      status: ['open', 'confirmed'],
      component: [],
      file: '',
      assignee: ME,
      isNew: true,
      offset: 50,
      limit: 50,
    })
    expect(toQuery(DEFAULT_FILTER, ME, 0).assignee).toBeUndefined()
  })

  it('encodes a query as the server parses it, leaving out empty filters', () => {
    const q = toQuery({ ...DEFAULT_FILTER, severity: ['critical', 'major'], file: 'a b.js', mine: true }, 'Ann Lee', 0)
    expect(issueSearchParams(q).toString()).toBe('severity=critical%2Cmajor&status=open%2Cconfirmed&file=a+b.js&assignee=Ann+Lee&offset=0&limit=50')
    expect(issueSearchParams(toQuery({ ...DEFAULT_FILTER, status: [] }, '', 0)).toString()).toBe('offset=0&limit=50')
  })

  it('reads drill-down links from query parameters', () => {
    const result = filterFromParams(new URLSearchParams('new&cat=vulnerability&comp=services'))
    expect(result?.filter).toMatchObject({ isNew: true, category: ['vulnerability'], component: ['services'] })
    expect(result?.description).toBe('Showing new code · vulnerabilities · services — from the metric you clicked')
  })

  it('ignores empty or unknown drill-down parameters', () => {
    expect(filterFromParams(new URLSearchParams(''))).toBeNull()
    expect(filterFromParams(new URLSearchParams('cat=exploit'))).toBeNull()
  })
})

describe('the mock server', () => {
  const all = (patch = {}) => queryIssues(issues, { ...toQuery({ ...DEFAULT_FILTER, status: [] }, ME, 0, 100), ...patch })

  it('sorts most severe first and pages', () => {
    const page = all()
    const ranks = page.items.map((i) => SEVERITY[i.severity].rank)
    expect(ranks).toEqual([...ranks].sort((a, b) => a - b))
    const second = all({ offset: 2, limit: 2 })
    expect(second.total).toBe(page.total)
    expect(second.items.map((i) => i.id)).toEqual(page.items.slice(2, 4).map((i) => i.id))
  })

  it('counts a facet without its own selection', () => {
    const critical = all({ severity: ['critical'] })
    // Selecting "critical" must not zero out the other severities' counts.
    expect(critical.facets.severity).toEqual(all().facets.severity)
    expect(critical.items.every((i) => i.severity === 'critical')).toBe(true)
    expect(critical.facets.category).not.toEqual(all().facets.category)
  })

  it('filters by assignee and path', () => {
    const mine = all({ assignee: ME })
    expect(mine.total).toBeGreaterThan(0)
    expect(mine.items.every((i) => i.assignee === ME)).toBe(true)
    const file = issues[0].file
    expect(all({ file }).items.every((i) => i.file.includes(file))).toBe(true)
  })
})

describe('labels', () => {
  it('formats ages compactly', () => {
    const now = Date.parse('2026-10-30T12:00:00Z')
    const ago = (ms: number) => new Date(now - ms).toISOString()
    const minute = 60_000
    expect([ago(5 * minute), ago(3 * 60 * minute), ago(2 * 1440 * minute), ago(20 * 1440 * minute), ago(100 * 1440 * minute), ago(800 * 1440 * minute)].map((iso) => formatAge(iso, now))).toEqual([
      '5m',
      '3h',
      '2d',
      '2w',
      '3mo',
      '2y',
    ])
  })

  it('names languages and initials', () => {
    expect(languageLabel('cpp')).toBe('C++')
    expect(languageLabel('kotlin')).toBe('kotlin')
    expect(initials('Ann Marie Lee')).toBe('AM')
    expect(initials('')).toBe('··')
  })
})
