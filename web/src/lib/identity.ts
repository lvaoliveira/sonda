/**
 * The viewer's display name, used for "Assign to me". The server has no
 * accounts yet (assignees are free text, ADR-0005), so it is what the viewer
 * typed at sign-in, kept in this browser only.
 */
const KEY = 'sonda-name'

export function storedName(): string {
  try {
    return localStorage.getItem(KEY) ?? ''
  } catch {
    return ''
  }
}

export function storeName(name: string): void {
  try {
    if (name) localStorage.setItem(KEY, name)
    else localStorage.removeItem(KEY)
  } catch {
    // Storage blocked (private mode, policy): the name just isn't remembered.
  }
}

export function initials(name: string): string {
  const letters = name
    .split(/\s+/)
    .filter(Boolean)
    .map((w) => w[0].toUpperCase())
  return letters.length > 0 ? letters.slice(0, 2).join('') : '··'
}
