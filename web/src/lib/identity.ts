/** Up to two initials for an avatar: "Ann Marie Lee" → "AM". */
export function initials(name: string): string {
  const letters = name
    .split(/\s+/)
    .filter(Boolean)
    .map((w) => w[0].toUpperCase())
  return letters.length > 0 ? letters.slice(0, 2).join('') : '··'
}
