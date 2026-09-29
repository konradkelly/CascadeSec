import { useCallback, useEffect, useState } from 'react'
import { ApiClientError, getCommitPlan, getCommitRequest, postCommit } from '../api/client'
import { useAuth } from '../auth/AuthProvider'
import {
  ACTIVE_COMMIT_STATUSES,
  type CommitPlanResponse,
  type CommitRequest,
  type PlannedFile,
} from '../types/commit'
import { DiffViewer } from './DiffViewer'

interface CommitPanelProps {
  prId: string
  /** Called when a request ends, so the page reloads the findings it marked. */
  onCommitted: () => Promise<void> | void
  /** How often a running request is polled. Tests shorten it. */
  pollMs?: number
}

const OUTCOME_LABEL: Record<PlannedFile['outcome'], string> = {
  commit: 'will commit',
  already: 'already on the branch',
  held: 'held',
}

/**
 * Commit a GitHub PR's approved fixes to its branch (docs/write-back-spec.md).
 *
 * What the reviewer confirms is what is committed: per file, the diff from
 * the branch as last scanned to the fixes' corrected file -- not any one
 * fix's diff -- with held files and why, and which fixes were never
 * verified. The request carries the tips and content hashes shown here, and
 * is refused if the plan has moved since.
 */
export function CommitPanel({ prId, onCommitted, pollMs = 3000 }: CommitPanelProps) {
  const { actor } = useAuth()
  const [plan, setPlan] = useState<CommitPlanResponse | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [request, setRequest] = useState<CommitRequest | null>(null)
  const [confirming, setConfirming] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [submitError, setSubmitError] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoadError(null)
    try {
      const next = await getCommitPlan(prId)
      setPlan(next)
      setRequest(next.latest_request)
    } catch (err) {
      setLoadError(err instanceof ApiClientError ? err.message : 'Failed to load the commit plan')
    }
  }, [prId])

  useEffect(() => {
    load()
  }, [load])

  const active = request !== null && ACTIVE_COMMIT_STATUSES.has(request.status)

  // Poll a running request until it ends, then reload: the plan changes
  // once fixes are committed, and so do the findings on the page.
  useEffect(() => {
    if (!active || !request) return
    let cancelled = false
    const timer = setTimeout(async () => {
      try {
        const next = await getCommitRequest(prId, request.request_id)
        if (cancelled) return
        setRequest(next)
        if (!ACTIVE_COMMIT_STATUSES.has(next.status)) {
          await Promise.all([load(), onCommitted()])
          setRequest(next)
        }
      } catch {
        // A failed poll is retried on the next tick; the request itself
        // ends on the server either way.
        if (!cancelled) setRequest({ ...request })
      }
    }, pollMs)
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [active, request, prId, pollMs, load, onCommitted])

  if (loadError) {
    return (
      <section className="panel commit-panel" aria-label="Commit approved fixes">
        <h2>Commit approved fixes</h2>
        <p className="muted">{loadError}</p>
      </section>
    )
  }
  if (!plan) {
    return <p className="muted">Loading the commit plan…</p>
  }

  const toCommit = plan.files.filter((f) => f.outcome === 'commit')
  const unverified = toCommit.flatMap((f) => f.chain.filter((c) => !c.verified))

  async function commit() {
    setSubmitting(true)
    setSubmitError(null)
    try {
      const { request_id } = await postCommit(
        prId,
        toCommit.map((f) => ({ file: f.file, tip: f.tip ?? '', content_sha256: f.content_sha256 ?? '' })),
      )
      setRequest({
        request_id,
        pr_id: prId,
        requested_by: actor ?? '',
        requested_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        status: 'requested',
      })
      setConfirming(false)
    } catch (err) {
      setSubmitError(err instanceof ApiClientError ? err.message : 'The commit request failed')
      // A 409 usually means the plan moved; show the one that stands now.
      await load()
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <section className="panel commit-panel" aria-label="Commit approved fixes">
      <div className="panel__header">
        <h2>Commit approved fixes</h2>
        <span className="muted">
          {plan.repository}#{plan.pr_number}
        </span>
      </div>

      <p className="muted">
        Commits every approved fix below to the pull request's branch as one commit, as the CascadeSec
        Fixes app. This is a preview from the latest scan: each file is checked against the branch again
        before anything is written, and one that has changed is held.
      </p>

      {plan.files.length === 0 ? (
        <p className="muted empty-state">No approved fixes to commit.</p>
      ) : (
        <ul className="commit-files">
          {plan.files.map((f) => (
            <PlannedFileItem key={f.file} file={f} />
          ))}
        </ul>
      )}

      {unverified.length > 0 && (
        <p className="alert alert--warn">
          {unverified.length} fix{unverified.length === 1 ? ' was' : 'es were'} approved without passing
          the self-check ({unverified.map((c) => c.rule_id).join(', ')}): edited, or held for review. They
          are committed and labelled unverified in the commit message; the scan of the commit's push is
          their check.
        </p>
      )}

      {request && <RequestStatus request={request} repository={plan.repository} />}

      {!plan.write_back_deployed ? (
        <p className="alert alert--info">Write-back is not deployed in this environment.</p>
      ) : !plan.can_commit ? (
        <p className="alert alert--info">
          Committing needs membership of the <code>committers</code> group. Approving fixes does not.
        </p>
      ) : active ? null : toCommit.length === 0 ? null : !confirming ? (
        <div className="review-actions__buttons">
          <button type="button" className="btn btn--primary" onClick={() => setConfirming(true)}>
            Commit {toCommit.length} file{toCommit.length === 1 ? '' : 's'}
          </button>
        </div>
      ) : (
        <div className="fix-group__confirm">
          <p>
            This commits <strong>{toCommit.length}</strong> file{toCommit.length === 1 ? '' : 's'} to the
            branch of <strong>{plan.repository}#{plan.pr_number}</strong>, exactly as the diffs above show.
            The request is recorded as <strong>{actor ?? 'you'}</strong>'s; the commit itself does not name
            you.
          </p>
          <div className="review-actions__buttons">
            <button type="button" className="btn btn--primary" disabled={submitting} onClick={commit}>
              {submitting ? 'Requesting…' : 'Confirm commit'}
            </button>
            <button
              type="button"
              className="btn btn--secondary"
              disabled={submitting}
              onClick={() => setConfirming(false)}
            >
              Cancel
            </button>
          </div>
        </div>
      )}
      {submitError && <p className="alert alert--error">{submitError}</p>}
    </section>
  )
}

function PlannedFileItem({ file }: { file: PlannedFile }) {
  return (
    <li className="commit-file">
      <div className="commit-file__header">
        <code>{file.file}</code>
        <span className={`badge commit-outcome commit-outcome--${file.outcome}`}>{OUTCOME_LABEL[file.outcome]}</span>
      </div>
      {file.chain.length > 0 && (
        <p className="commit-file__chain">
          {file.chain.map((link) => (
            <span key={link.finding_id} className="commit-file__link">
              <code>{link.rule_id}</code>
              {!link.verified && <span className="badge badge--fail">unverified</span>}
              {link.edited && <span className="badge badge--muted">edited</span>}
            </span>
          ))}
        </p>
      )}
      {file.reason && <p className="alert alert--info">Held: {file.reason}</p>}
      {file.left_out.length > 0 && (
        <p className="muted">
          Approved but not included: {file.left_out.join(', ')} -- drafted on a fix that is not approved.
        </p>
      )}
      {file.outcome === 'commit' && file.diff && (
        <details className="commit-file__diff" open>
          <summary>Change to {file.file}</summary>
          <DiffViewer diff={file.diff} />
        </details>
      )}
    </li>
  )
}

function RequestStatus({ request, repository }: { request: CommitRequest; repository: string }) {
  const running = ACTIVE_COMMIT_STATUSES.has(request.status)
  return (
    <div
      className={`alert ${request.status === 'committed' ? 'alert--success' : running ? 'alert--info' : 'alert--warn'}`}
      role="status"
    >
      <p>
        Commit request by {request.requested_by}: <strong>{request.status}</strong>
        {running && '…'}
        {request.commit_sha && (
          <>
            {' '}
            in{' '}
            <a href={`https://github.com/${repository}/commit/${request.commit_sha}`} target="_blank" rel="noreferrer">
              <code>{request.commit_sha.slice(0, 7)}</code>
            </a>
          </>
        )}
      </p>
      {request.reason && <p>{request.reason}</p>}
      {request.files && request.files.some((f) => f.outcome === 'held') && (
        <ul>
          {request.files
            .filter((f) => f.outcome === 'held')
            .map((f) => (
              <li key={f.file}>
                <code>{f.file}</code>: {f.reason}
              </li>
            ))}
        </ul>
      )}
    </div>
  )
}
