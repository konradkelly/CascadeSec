import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach, beforeEach, vi } from 'vitest'

afterEach(() => {
  cleanup()
  localStorage.clear()
  delete document.documentElement.dataset.theme
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

/** jsdom does not implement matchMedia. Tests that care set the answer
 *  with `stubPrefersLight`; everything else gets "no preference". */
export function stubPrefersLight(light: boolean) {
  vi.stubGlobal('matchMedia', (query: string) => ({
    matches: light && query === '(prefers-color-scheme: light)',
    media: query,
    onchange: null,
    addEventListener: () => {},
    removeEventListener: () => {},
    addListener: () => {},
    removeListener: () => {},
    dispatchEvent: () => false,
  }))
}

beforeEach(() => stubPrefersLight(false))
