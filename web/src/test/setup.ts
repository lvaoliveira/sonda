import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach } from 'vitest'

afterEach(cleanup)

// jsdom has no modal dialogs: open them in place.
HTMLDialogElement.prototype.showModal ??= function (this: HTMLDialogElement) {
  this.open = true
}

// jsdom has no matchMedia; report a wide desktop window.
window.matchMedia ??= (query: string) =>
  ({
    matches: /min-width/.test(query),
    media: query,
    addEventListener: () => {},
    removeEventListener: () => {},
  }) as unknown as MediaQueryList
