import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach } from 'vitest'

afterEach(cleanup)

// jsdom has no modal dialogs: open them in place, and close the top one on
// Escape, with its close event, as a browser does.
HTMLDialogElement.prototype.showModal ??= function (this: HTMLDialogElement) {
  this.open = true
}
HTMLDialogElement.prototype.close ??= function (this: HTMLDialogElement) {
  if (!this.open) return
  this.open = false
  this.dispatchEvent(new Event('close'))
}
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') [...document.querySelectorAll<HTMLDialogElement>('dialog[open]')].at(-1)?.close()
})

// jsdom has no matchMedia; report a wide desktop window.
window.matchMedia ??= (query: string) =>
  ({
    matches: /min-width/.test(query),
    media: query,
    addEventListener: () => {},
    removeEventListener: () => {},
  }) as unknown as MediaQueryList
