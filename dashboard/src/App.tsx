import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { AuthProvider } from './auth/AuthProvider'
import { Callback } from './auth/Callback'
import { RequireAuth } from './auth/RequireAuth'
import { Layout } from './components/Layout'
import { FindingDetailPage } from './pages/FindingDetailPage'
import { HomePage } from './pages/HomePage'
import { PrFindingsPage } from './pages/PrFindingsPage'
import { ThemeProvider } from './theme/ThemeProvider'

export default function App() {
  return (
    <BrowserRouter>
      <ThemeProvider>
        <AuthProvider>
          <Layout>
            <Routes>
              {/* Outside RequireAuth: the Hosted UI redirect lands here before
                  a token exists, so this route can't itself require one. */}
              <Route path="/auth/callback" element={<Callback />} />
              <Route
                path="/*"
                element={
                  <RequireAuth>
                    <Routes>
                      <Route path="/" element={<HomePage />} />
                      <Route path="/prs/:prId" element={<PrFindingsPage />} />
                      <Route path="/prs/:prId/findings/:findingId" element={<FindingDetailPage />} />
                    </Routes>
                  </RequireAuth>
                }
              />
            </Routes>
          </Layout>
        </AuthProvider>
      </ThemeProvider>
    </BrowserRouter>
  )
}
