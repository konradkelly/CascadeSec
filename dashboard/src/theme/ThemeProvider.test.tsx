import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { stubPrefersLight } from '../test/setup'
import { ThemeProvider, useTheme } from './ThemeProvider'

const THEME_KEY = 'cascadesec.theme'

function Probe() {
  const { theme, toggleTheme } = useTheme()
  return (
    <button type="button" onClick={toggleTheme}>
      {theme}
    </button>
  )
}

function renderProbe() {
  render(
    <ThemeProvider>
      <Probe />
    </ThemeProvider>,
  )
  return screen.getByRole('button')
}

describe('initial theme', () => {
  it('follows the OS when nothing is stored', () => {
    stubPrefersLight(true)
    expect(renderProbe()).toHaveTextContent('light')
  })

  it('defaults to dark when the OS has no light preference', () => {
    expect(renderProbe()).toHaveTextContent('dark')
  })

  it('lets a stored choice beat the OS', () => {
    stubPrefersLight(true)
    localStorage.setItem(THEME_KEY, 'dark')
    expect(renderProbe()).toHaveTextContent('dark')
  })

  it('ignores a stored value that is not a theme', () => {
    stubPrefersLight(true)
    localStorage.setItem(THEME_KEY, 'sepia')
    expect(renderProbe()).toHaveTextContent('light')
  })

  it('falls back to the OS when storage throws', () => {
    // Private mode, blocked site data: getItem raises rather than returning
    // null, and the page must still come up.
    stubPrefersLight(true)
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new DOMException('blocked', 'SecurityError')
    })
    expect(renderProbe()).toHaveTextContent('light')
  })
})

describe('toggling', () => {
  it('flips the theme, writes it to the document, and remembers it', async () => {
    const button = renderProbe()
    expect(document.documentElement.dataset.theme).toBe('dark')

    await userEvent.click(button)

    expect(button).toHaveTextContent('light')
    expect(document.documentElement.dataset.theme).toBe('light')
    expect(localStorage.getItem(THEME_KEY)).toBe('light')

    await userEvent.click(button)

    expect(document.documentElement.dataset.theme).toBe('dark')
    expect(localStorage.getItem(THEME_KEY)).toBe('dark')
  })

  it('still toggles when storage cannot be written', async () => {
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('quota', 'QuotaExceededError')
    })
    const button = renderProbe()

    await userEvent.click(button)

    expect(button).toHaveTextContent('light')
    expect(document.documentElement.dataset.theme).toBe('light')
  })
})

it('useTheme outside the provider is a programming error, not a silent default', () => {
  vi.spyOn(console, 'error').mockImplementation(() => {})
  expect(() => render(<Probe />)).toThrow(/inside ThemeProvider/)
})

describe('the inline script in index.html', () => {
  // ThemeProvider's docstring: the script "runs before first paint so the
  // page doesn't flash dark before React mounts; this only has to agree
  // with it." Two copies of one rule, in two languages, that nothing else
  // ties together. This runs the real script from index.html and checks
  // the provider reaches the same answer in every case it can face.
  const html = readFileSync(resolve(__dirname, '../../index.html'), 'utf-8')
  const script = /<script>([\s\S]*?)<\/script>/.exec(html)?.[1]

  it('exists', () => {
    expect(script).toBeDefined()
  })

  it.each([
    { stored: null, prefersLight: false },
    { stored: null, prefersLight: true },
    { stored: 'dark', prefersLight: true },
    { stored: 'light', prefersLight: false },
    { stored: 'sepia', prefersLight: true },
  ])('agrees with ThemeProvider for stored=$stored prefersLight=$prefersLight', ({ stored, prefersLight }) => {
    stubPrefersLight(prefersLight)
    if (stored !== null) localStorage.setItem(THEME_KEY, stored)

    new Function(script!)()
    const beforePaint = document.documentElement.dataset.theme

    delete document.documentElement.dataset.theme
    renderProbe()

    expect(document.documentElement.dataset.theme).toBe(beforePaint)
  })

  it('uses the same storage key as the provider', () => {
    expect(script).toContain(`'${THEME_KEY}'`)
  })
})
