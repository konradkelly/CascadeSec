import type { ReviewEvent } from '../types/finding'

/** An actor from a Commit fixes click on GitHub is recorded as
 *  "github:<login>" (github-first-review-spec §3.3); every other actor is a
 *  dashboard identity or "system". */
function githubLogin(actor: string): string | null {
  return actor.startsWith('github:') ? actor.slice('github:'.length) : null
}

function Actor({ actor }: { actor: string }) {
  const login = githubLogin(actor)
  if (login === null) return <span className="audit-trail__actor">{actor}</span>
  return (
    <span className="audit-trail__actor">
      {login}{' '}
      <span className="badge badge--muted" title="Decided on GitHub, as this GitHub account">
        GitHub
      </span>
    </span>
  )
}

interface AuditTrailProps {
  events: ReviewEvent[]
  loading?: boolean
}

function formatTimestamp(iso: string): string {
  try {
    return new Date(iso).toLocaleString()
  } catch {
    return iso
  }
}

export function AuditTrail({ events, loading }: AuditTrailProps) {
  if (loading) {
    return <p className="muted">Loading audit trail…</p>
  }

  if (events.length === 0) {
    return <p className="muted">No review decisions recorded yet.</p>
  }

  const sorted = [...events].sort((a, b) => b.created_at.localeCompare(a.created_at))

  return (
    <ul className="audit-trail">
      {sorted.map((event) => (
        <li key={event.sk} className="audit-trail__item">
          <div className="audit-trail__header">
            <span className={`audit-trail__action audit-trail__action--${event.action}`}>
              {event.action}
            </span>
            <Actor actor={event.actor} />
            <time className="audit-trail__time" dateTime={event.created_at}>
              {formatTimestamp(event.created_at)}
            </time>
          </div>
          {event.notes && <p className="audit-trail__notes">{event.notes}</p>}
        </li>
      ))}
    </ul>
  )
}
