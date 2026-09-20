import { useCallback, useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ApiClientError, listFindings } from '../api/client'
import { FindingsTable } from '../components/FindingsTable'
import { FixGroups } from '../components/FixGroups'
import { DRAFTED_STATUSES } from '../review/fixGroups'
import type { Finding, FindingStatus } from '../types/finding'

export function PrFindingsPage() {
  const { prId } = useParams<{ prId: string }>()
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [statusFilter, setStatusFilter] = useState<FindingStatus | 'all'>('all')
  // 'by-control' collapses the same fix drafted across many files into one
  // decision (docs/multi-iac-spec.md §5). Offered only once there is
  // something to collapse.
  const [view, setView] = useState<'by-finding' | 'by-control'>('by-finding')

  const load = useCallback(async () => {
    if (!prId) return
    setLoading(true)
    setError(null)
    try {
      const data = await listFindings(prId)
      setFindings(data.findings)
    } catch (err) {
      setError(err instanceof ApiClientError ? err.message : 'Failed to load findings')
    } finally {
      setLoading(false)
    }
  }, [prId])

  useEffect(() => {
    load()
  }, [load])

  if (!prId) {
    return <p className="alert alert--error">Missing PR ID.</p>
  }

  const statusCounts = findings.reduce(
    (acc, f) => {
      acc[f.status] = (acc[f.status] ?? 0) + 1
      return acc
    },
    {} as Record<string, number>,
  )

  return (
    <div className="page pr-page">
      <nav className="breadcrumb">
        <Link to="/">Home</Link>
        <span aria-hidden="true"> / </span>
        <span>{prId}</span>
      </nav>

      <div className="page-header">
        <div>
          <h1>PR: {prId}</h1>
          <p className="muted">{findings.length} finding{findings.length === 1 ? '' : 's'}</p>
        </div>
        <button type="button" className="btn btn--secondary" onClick={load} disabled={loading}>
          Refresh
        </button>
      </div>

      {loading && <p className="muted">Loading findings…</p>}
      {error && <p className="alert alert--error">{error}</p>}

      {!loading && !error && (
        <>
          <div className="summary-cards">
            {(['fix-proposed', 'needs-human-only', 'not-drafted', 'mapped', 'raw', 'resolved'] as const).map(
              (status) =>
                statusCounts[status] ? (
                  <button
                    key={status}
                    type="button"
                    className={`summary-card summary-card--${status}${statusFilter === status ? ' summary-card--active' : ''}`}
                    onClick={() => setStatusFilter(statusFilter === status ? 'all' : status)}
                  >
                    <span className="summary-card__count">{statusCounts[status]}</span>
                    <span className="summary-card__label">{status}</span>
                  </button>
                ) : null,
            )}
          </div>

          {findings.some((f) => DRAFTED_STATUSES.has(f.status)) && (
            <div className="view-toggle" role="group" aria-label="View">
              <button
                type="button"
                className={`btn btn--small${view === 'by-finding' ? ' btn--primary' : ' btn--secondary'}`}
                aria-pressed={view === 'by-finding'}
                onClick={() => setView('by-finding')}
              >
                By finding
              </button>
              <button
                type="button"
                className={`btn btn--small${view === 'by-control' ? ' btn--primary' : ' btn--secondary'}`}
                aria-pressed={view === 'by-control'}
                onClick={() => setView('by-control')}
              >
                By control
              </button>
            </div>
          )}

          {view === 'by-control' ? (
            <FixGroups prId={prId} findings={findings} onReviewed={load} />
          ) : (
            <FindingsTable
              prId={prId}
              findings={findings}
              statusFilter={statusFilter}
              onStatusFilterChange={setStatusFilter}
            />
          )}
        </>
      )}
    </div>
  )
}
