/**
 * Copies `text`, and resolves whether it did. The Clipboard API exists only
 * on secure pages (HTTPS, or localhost): on a server's LAN address over
 * plain HTTP it's missing, so this falls back to the older copy command on
 * a hidden text area. That one needs a click shortly before, so a caller
 * that waited on the server should offer the text to copy by hand when this
 * fails.
 */
export async function copyText(text: string): Promise<boolean> {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text)
      return true
    } catch {
      // Refused (no permission, or the page lost focus): try the old way.
    }
  }
  if (typeof document.execCommand !== 'function') return false
  const area = document.createElement('textarea')
  area.value = text
  area.setAttribute('readonly', '')
  Object.assign(area.style, { position: 'fixed', top: '0', left: '0', opacity: '0' })
  document.body.appendChild(area)
  area.select()
  try {
    return document.execCommand('copy')
  } catch {
    return false
  } finally {
    area.remove()
  }
}
