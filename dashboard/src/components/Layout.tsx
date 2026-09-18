import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '../auth/AuthProvider'
import { useTheme } from '../theme/ThemeProvider'

interface LayoutProps {
  children: ReactNode
}

export function Layout({ children }: LayoutProps) {
  const { actor, logout } = useAuth()
  const { theme, toggleTheme } = useTheme()
  const nextTheme = theme === 'dark' ? 'light' : 'dark'

  return (
    <div className="layout">
      <header className="header">
        <Link to="/" className="header__brand">
          <span className="header__logo">CascadeSec</span>
          <span className="header__tagline">Review dashboard</span>
        </Link>
        <div className="header__account">
          {actor && <span className="muted">{actor}</span>}
          <button
            type="button"
            className="btn btn--secondary btn--icon"
            onClick={toggleTheme}
            aria-label={`Switch to ${nextTheme} mode`}
            title={`Switch to ${nextTheme} mode`}
          >
            {theme === 'dark' ? '☀' : '☾'}
          </button>
          {actor && (
            <button type="button" className="btn btn--secondary" onClick={logout}>
              Sign out
            </button>
          )}
        </div>
      </header>
      <main className="main">{children}</main>
      <footer className="footer">
        <p>Agent proposes, human disposes — every decision is audited and attributed to you.</p>
      </footer>
    </div>
  )
}
