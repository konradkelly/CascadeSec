import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { AuthProvider, useAuth } from './AuthProvider'

vi.mock('./token', () => ({
  readToken: () => 'header.payload.sig',
  actorFromToken: () => 'reviewer@example.test',
  clearToken: vi.fn(),
  storeToken: vi.fn(),
}))

vi.mock('./pkce', () => ({
  beginLogin: vi.fn(),
  hostedLogoutUrl: () => 'https://auth.example.test/logout',
}))

function Probe() {
  const { token, logout } = useAuth()
  return (
    <button type="button" onClick={logout}>
      {token ? 'signed in' : 'signed out'}
    </button>
  )
}

describe('AuthProvider', () => {
  it('signs out by leaving for Cognito, without dropping the token first', async () => {
    // Dropping it re-rendered RequireAuth, which started a login whose
    // navigation replaced this one: Cognito never ended the session, and
    // the same user was silently signed back in.
    const assign = vi.fn()
    vi.stubGlobal('location', { ...window.location, assign })
    const { clearToken } = await import('./token')

    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    )
    await userEvent.click(screen.getByRole('button'))

    expect(clearToken).toHaveBeenCalled()
    expect(assign).toHaveBeenCalledWith('https://auth.example.test/logout')
    expect(screen.getByRole('button')).toHaveTextContent('signed in')
  })
})
