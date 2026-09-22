import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { postReview } from '../api/client'
import { useAuth } from '../auth/AuthProvider'
import { singleSourceTitle, singleSourceTool } from '../review/coverage'
import { groupFixes, isBulkApprovable, type FixGroup } from '../review/fixGroups'
import { findUnmetPrerequisites } from '../review/prerequisites'
import type { Finding } from '../types/finding'
import { SelfCheckBadge } from './SelfCheckBadge'
import { StatusBadge } from './StatusBadge'

interface FixGroupsProps {
  prId: string
  findings: Finding[]
  /** Called after a group approve has finished, successes and failures
   *  both, so the page reloads and shows what actually happened. */
  onReviewed: () => Promise<void> | void
}

export function FixGroups({ prId, findings, onReviewed }: FixGroupsProps) {
  const groups = groupFixes(findings)
  // Prerequisites are per fix and async (the hash check), so they are
  // resolved once for the page and handed down. A fix drafted on top of an
  // unaccepted one cannot be approved, in a group or alone -- review-api
  // 409s it -- so the group action has to know before it offers.
  const [blocked, setBlocked] = useState<Set<string> | null>(null)

  useEffect(() => {
    let cancelled = false
    const byId = new Map(findings.map((f) => [f.finding_id, f]))
    Promise.all(
      findings
        .filter(isBulkApprovable)
        .map(async (f) => {
          const unmet = await findUnmetPrerequisites(f.proposed_fix?.applies_after ?? [], byId)
          return unmet.length ? f.finding_id : null
        }),
    ).then((ids) => {
      if (!cancelled) setBlocked(new Set(ids.filter((id): id is string => id !== null)))
    })
    return () => {
      cancelled = true
    }
  }, [findings])

  if (groups.length === 0) {
    return <p className="muted empty-state">No drafted fixes to group.</p>
  }

  return (
    <div className="fix-groups">
      {groups.map((group) => (
        <FixGroupCard
          key={group.key}
          prId={prId}
          group={group}
          blocked={blocked}
          onReviewed={onReviewed}
        />
      ))}
    </div>
  )
}

interface FixGroupCardProps {
  prId: string
  group: FixGroup
  blocked: Set<string> | null
  onReviewed: () => Promise<void> | void
}

function FixGroupCard({ prId, group, blocked, onReviewed }: FixGroupCardProps) {
  const { actor } = useAuth()
  const [confirming, setConfirming] = useState(false)
  const [notes, setNotes] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [outcome, setOutcome] = useState<string | null>(null)

  const approvable = group.findings.filter((f) => isBulkApprovable(f) && !blocked?.has(f.finding_id))
  const held = group.findings.length - approvable.length

  async function approveAll() {
    setSubmitting(true)
    setOutcome(null)
    // Sequential, not parallel: each approve is an audit event and a status
    // write, and a burst of fourteen against one table is not worth the
    // seconds it saves. Failures are collected, not thrown -- the reviewer
    // needs to know which ones, and the ones that succeeded are already
    // recorded.
    const failed: string[] = []
    for (const finding of approvable) {
      try {
        await postReview(prId, finding.finding_id, {
          action: 'approved',
          notes: [
            `Approved as one of ${approvable.length} ${group.framework} ${group.control_id} fixes on ${group.target_type}.`,
            notes.trim(),
          ]
            .filter(Boolean)
            .join(' '),
        })
      } catch (err) {
        failed.push(`${finding.file} (${err instanceof Error ? err.message : 'failed'})`)
      }
    }
    setOutcome(
      failed.length
        ? `${approvable.length - failed.length} approved; ${failed.length} failed: ${failed.join('; ')}`
        : `${approvable.length} fix${approvable.length === 1 ? '' : 'es'} approved.`,
    )
    setSubmitting(false)
    setConfirming(false)
    setNotes('')
    await onReviewed()
  }

  // A group is the cheapest decision on the page -- one approval covers every
  // fix in it -- so a language only one scanner verified has to say so here,
  // not only on the individual fixes inside (multi-iac-spec §4).
  const groupTool = singleSourceTool(group.target_type)

  return (
    <section className="fix-group" aria-label={`${group.framework} ${group.control_id} on ${group.target_type}`}>
      <header className="fix-group__header">
        <div>
          <span className="control-item__framework">{group.framework}</span>{' '}
          <code className="control-item__id">{group.control_id}</code>
          <span
            className="badge badge--muted fix-group__target"
            title={groupTool ? singleSourceTitle(group.target_type, groupTool) : undefined}
          >
            {group.target_type}
            {groupTool && <> · {groupTool} only</>}
          </span>
        </div>
        <p className="muted">
          {group.findings.length} fix{group.findings.length === 1 ? '' : 'es'} across {group.file_count} file
          {group.file_count === 1 ? '' : 's'}
          {held > 0 && <> · {held} held for individual review</>}
        </p>
      </header>

      <table className="findings-table findings-table--compact">
        <thead>
          <tr>
            <th>Status</th>
            <th>Rule</th>
            <th>File</th>
            <th>Self-check</th>
          </tr>
        </thead>
        <tbody>
          {group.findings.map((finding) => (
            <tr key={finding.finding_id}>
              <td>
                <StatusBadge status={finding.status} />
              </td>
              <td>
                <Link
                  to={`/prs/${encodeURIComponent(prId)}/findings/${encodeURIComponent(finding.finding_id)}`}
                  className="finding-link"
                >
                  <span className="finding-link__source">{finding.source}</span>
                  <code className="finding-link__rule">{finding.rule_id}</code>
                </Link>
              </td>
              <td>
                <code>{finding.file}</code>
              </td>
              <td>
                <SelfCheckBadge proposedFix={finding.proposed_fix} targetType={finding.target_type} />
                {blocked?.has(finding.finding_id) && (
                  <span className="badge badge--muted" title="Drafted on a fix that has not been accepted yet">
                    Waits on an earlier fix
                  </span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {approvable.length > 1 && (
        <div className="fix-group__actions">
          {!confirming ? (
            <button
              type="button"
              className="btn btn--secondary"
              disabled={submitting || blocked === null}
              onClick={() => setConfirming(true)}
            >
              Approve {approvable.length} verified fixes
            </button>
          ) : (
            <div className="fix-group__confirm">
              <p>
                Open one of these diffs first: the scanner has verified each of the {approvable.length} on
                its own file, and this records <strong>{approvable.length}</strong> separate approvals
                attributed to <strong>{actor ?? 'you'}</strong>. Fixes held for human review are not
                included.
              </p>
              <div className="form-field">
                <label htmlFor={`group-notes-${group.key}`}>Notes (optional, on every approval)</label>
                <textarea
                  id={`group-notes-${group.key}`}
                  rows={2}
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  disabled={submitting}
                />
              </div>
              <div className="review-actions__buttons">
                <button type="button" className="btn btn--primary" disabled={submitting} onClick={approveAll}>
                  {submitting ? 'Approving…' : `Confirm: approve ${approvable.length}`}
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
        </div>
      )}
      {outcome && <p className="alert alert--info">{outcome}</p>}
    </section>
  )
}
