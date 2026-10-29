import type { Level } from '@/api/types'
import { areaPoints, linePoints, ringDash } from '@/lib/charts'
import { coverageColor, levelColor } from '@/lib/visual'

/** A 5-segment rating meter: bars of rising height, filled up to the level. */
export function PipMeter({ level, label, width = 4 }: { level: Level; label: string; width?: number }) {
  const color = levelColor(level)
  return (
    <span role="img" aria-label={`${label}: level ${level} of 5`} title={`${label}: level ${level} of 5`} className="flex h-3.5 items-end gap-0.5">
      {[0, 1, 2, 3, 4].map((i) => (
        <span
          key={i}
          data-filled={i < level}
          style={{ width, height: 4 + i * 2, borderRadius: 1, background: i < level ? color : 'var(--sd-pip-off)' }}
        />
      ))}
    </span>
  )
}

/** Coverage as an 18px ring donut (stroke 5), with the value beside it. */
export function CoverageRing({ pct }: { pct: number }) {
  return (
    <span className="flex items-center gap-2">
      <svg width="18" height="18" viewBox="0 0 36 36" aria-hidden="true">
        <circle cx="18" cy="18" r="14" fill="none" stroke="var(--sd-pip-off)" strokeWidth="5" />
        <circle
          cx="18"
          cy="18"
          r="14"
          fill="none"
          stroke={coverageColor(pct)}
          strokeWidth="5"
          strokeDasharray={ringDash(pct)}
          transform="rotate(-90 18 18)"
        />
      </svg>
      <span className="font-mono text-xs">{pct.toFixed(1)}%</span>
    </span>
  )
}

/** A line sparkline in a 100×24 viewBox, optionally filled below. */
export function Sparkline({
  series,
  color,
  fill,
  className,
  label,
}: {
  series: number[]
  color: string
  fill?: string
  className?: string
  label?: string
}) {
  return (
    <svg
      viewBox="0 0 100 24"
      preserveAspectRatio="none"
      className={className}
      role={label ? 'img' : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
    >
      {fill && <polyline points={areaPoints(series)} fill={fill} stroke="none" />}
      <polyline
        points={linePoints(series)}
        fill="none"
        stroke={color}
        strokeWidth="1.5"
        vectorEffect="non-scaling-stroke"
        strokeLinejoin="round"
      />
    </svg>
  )
}

/** The 0–100 health index as a 20-segment meter: red, then amber, then green zones. */
export function HealthBar({ score }: { score: number }) {
  const filled = Math.round(score / 5)
  return (
    <div aria-hidden="true" className="flex gap-[3px]">
      {Array.from({ length: 20 }, (_, i) => (
        <span
          key={i}
          className="h-2.5 flex-1 rounded-[2px]"
          style={{
            background: i < filled ? (i < 8 ? 'var(--sd-crit)' : i < 14 ? 'var(--sd-warn)' : 'var(--sd-ok)') : 'var(--sd-pip-off)',
          }}
        />
      ))}
    </div>
  )
}
