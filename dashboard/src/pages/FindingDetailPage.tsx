import { useCallback, useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import {
  ApiClientError,
  getFinding,
  getFixContent,
  listEvents,
  listFindings,
  postReview,
} from '../api/client'
import { AuditTrail } from '../components/AuditTrail'
import { ControlMapping } from '../components/ControlMapping'
import { RepositoryQuestions } from '../components/RepositoryQuestions'
import { DiffViewer } from '../components/DiffViewer'
import { ReviewActions } from '../components/ReviewActions'
import { SelfCheckBadge, humanGates } from '../components/SelfCheckBadge'
import { SeverityBadge } from '../components/SeverityBadge'
import { StatusBadge } from '../components/StatusBadge'
import type { Finding, Prerequisite, ReviewEvent } from '../types/finding'

/** Hex SHA-256, matching remediation-agent's _diff_sha256 byte for byte.
 *  crypto.subtle needs a secure context, which both CloudFront and localhost
 *  are. */
async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
}

/** Entries were bare id strings before the chain carried hashes. */
function normalizePrerequisite(entry: Prerequisite | string): Prerequisite {
  return typeof entry === 'string' ? { finding_id: entry } : entry
}

interface UnmetPrerequisite {
  finding_id: string
  reason: 'missing' | 'unresolved' | 'stale' | 'unverifiable'
}

const UNMET_EXPLANATION: Record<UnmetPrerequisite['reason'], string> = {
  missing: 'no longer exists',
  unresolved: 'has not been accepted yet',
  stale: 'was edited after this fix was drafted on it',
  unverifiable: 'was recorded without a hash, so it cannot be checked',
}

/** Which of this fix's prerequisites currently block accepting it.
 *
 *  This is the affordance, not the guarantee -- review-api runs the
 *  authoritative check and 409s regardless of what the page believes. It is
 *  deliberately the weaker check of the two: the page has each prerequisite's
 *  status but not its event log, so it cannot tell a rejection from a decision
 *  never made, and reports both as "unresolved". The server can, and says
 *  which. */
async function findUnmetPrerequisites(
  chain: Prerequisite[],
  byId: Map<string, Finding>,
): Promise<UnmetPrerequisite[]> {
  const unmet: UnmetPrerequisite[] = []

  for (const entry of chain.map(normalizePrerequisite)) {
    const prerequisite = byId.get(entry.finding_id)
    if (!prerequisite) {
      unmet.push({ finding_id: entry.finding_id, reason: 'missing' })
      continue
    }
    if (prerequisite.status !== 'resolved') {
      unmet.push({ finding_id: entry.finding_id, reason: 'unresolved' })
      continue
    }
    if (!entry.diff_sha256) {
      unmet.push({ finding_id: entry.finding_id, reason: 'unverifiable' })
      continue
    }
    const currentDiff = prerequisite.proposed_fix?.diff
    if (currentDiff === undefined || (await sha256Hex(currentDiff)) !== entry.diff_sha256) {
      unmet.push({ finding_id: entry.finding_id, reason: 'stale' })
    }
  }

  return unmet
}

export function FindingDetailPage() {
  const { prId, findingId } = useParams<{ prId: string; findingId: string }>()
  const [finding, setFinding] = useState<Finding | null>(null)
  const [events, setEvents] = useState<ReviewEvent[]>([])
  const [loading, setLoading] = useState(true)
  const [eventsLoading, setEventsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showAgentDiff, setShowAgentDiff] = useState(false)
  const [unmet, setUnmet] = useState<UnmetPrerequisite[]>([])
  // The corrected file, for the edit textarea. undefined until fetched and
  // when the fix has none stored; the edit button hides on undefined.
  const [fixContent, setFixContent] = useState<string | undefined>(undefined)

  const loadFinding = useCallback(async () => {
    if (!prId || !findingId) return
    setLoading(true)
    setError(null)
    try {
      const loaded = await getFinding(prId, findingId)
      setFinding(loaded)
      // Separate call, separate failure: a finding whose content is missing
      // is still reviewable (approve, reject), just not editable.
      if (loaded.proposed_fix?.diff) {
        try {
          setFixContent((await getFixContent(prId, findingId)).content)
        } catch {
          setFixContent(undefined)
        }
      } else {
        setFixContent(undefined)
      }
    } catch (err) {
      setError(err instanceof ApiClientError ? err.message : 'Failed to load finding')
    } finally {
      setLoading(false)
    }
  }, [prId, findingId])

  const loadEvents = useCallback(async () => {
    if (!prId || !findingId) return
    setEventsLoading(true)
    try {
      const data = await listEvents(prId, findingId)
      setEvents(data.events)
    } catch {
      setEvents([])
    } finally {
      setEventsLoading(false)
    }
  }, [prId, findingId])

  useEffect(() => {
    loadFinding()
    loadEvents()
  }, [loadFinding, loadEvents])

  // Reads the whole PR partition to resolve the chain. Runs off `finding` so
  // it re-evaluates after a review lands: approving a prerequisite in another
  // tab should unblock this one on the next load, not stay stale.
  useEffect(() => {
    const chain = finding?.proposed_fix?.applies_after
    if (!prId || !chain || chain.length === 0) return

    let cancelled = false
    listFindings(prId)
      .then(async (data) => {
        const byId = new Map(data.findings.map((f) => [f.finding_id, f]))
        const result = await findUnmetPrerequisites(chain, byId)
        // Blocking on a stale computation would be worse than not blocking:
        // the server check still stands either way.
        if (!cancelled) setUnmet(result)
      })
      .catch(() => {
        if (!cancelled) setUnmet([])
      })

    return () => {
      cancelled = true
    }
  }, [prId, finding])

  async function handleReview(payload: {
    action: 'approved' | 'edited' | 'rejected'
    notes: string
    edited_content?: string
  }) {
    if (!prId || !findingId) return
    await postReview(prId, findingId, payload)
    setShowAgentDiff(false)
    await Promise.all([loadFinding(), loadEvents()])
  }

  if (!prId || !findingId) {
    return <p className="alert alert--error">Missing PR or finding ID.</p>
  }

  if (loading) {
    return <p className="muted">Loading finding…</p>
  }

  if (error || !finding) {
    return (
      <div className="page">
        <p className="alert alert--error">{error ?? 'Finding not found'}</p>
        <Link to={`/prs/${encodeURIComponent(prId)}`}>Back to findings list</Link>
      </div>
    )
  }

  const canReview = finding.status !== 'resolved'
  const awaitingRemediation = finding.status === 'raw' || finding.status === 'mapped'
  const chain = finding.proposed_fix?.applies_after ?? []
  // Derived rather than reset in the effect: state left over from the
  // previously-viewed finding must not block this one.
  const activeUnmet = chain.length > 0 ? unmet : []
  const blockedByChain = activeUnmet.length > 0
  // Any drafted diff is shown, including one the self-check rejected: a fix
  // held for review has a verified diff waiting for a decision, and a fix
  // that introduced one new finding is often one edit from passing -- the
  // reviewer can only make that edit if they can see it. The alerts above
  // say which case this is.
  const showDiff =
    Boolean(finding.proposed_fix?.diff) &&
    (finding.status === 'fix-proposed' ||
      finding.status === 'needs-human-only' ||
      finding.status === 'resolved')
  // An assumption that was asked and came back unknown is listed under both
  // assumptions and questions (remediation-agent puts it back by code). The
  // assumptions list marks those, so "assumed" and "asked, unanswered" do
  // not read the same.
  const askedUnanswered = new Set(
    (finding.proposed_fix?.questions ?? [])
      .filter((q) => q.answer === 'unknown')
      .map((q) => q.question),
  )

  return (
    <div className="page finding-page">
      <nav className="breadcrumb">
        <Link to="/">Home</Link>
        <span aria-hidden="true"> / </span>
        <Link to={`/prs/${encodeURIComponent(prId)}`}>{prId}</Link>
        <span aria-hidden="true"> / </span>
        <span>{finding.finding_id}</span>
      </nav>

      <div className="finding-header">
        <div>
          <h1>
            <code>{finding.rule_id}</code>
          </h1>
          <p className="finding-meta">
            <span>{finding.source}</span>
            <span>·</span>
            <code>{finding.file}</code>
            {finding.line_range?.[0] != null && (
              <>
                <span>·</span>
                <span>
                  {finding.line_range[1] != null && finding.line_range[1] !== finding.line_range[0]
                    ? `lines ${finding.line_range[0]}–${finding.line_range[1]}`
                    : `line ${finding.line_range[0]}`}
                </span>
              </>
            )}
          </p>
        </div>
        <div className="finding-header__badges">
          <SeverityBadge severity={finding.severity} />
          <StatusBadge status={finding.status} />
          <SelfCheckBadge proposedFix={finding.proposed_fix} />
        </div>
      </div>

      <section className="panel">
        <h2>Control mapping</h2>
        <ControlMapping mappings={finding.control_mappings} />
      </section>

      {finding.status === 'superseded' && (
        <section className="panel">
          <h2>Superseded</h2>
          <p>
            No fix was drafted for this finding: another fix on the same file already cleared the
            rule it fires on, and the scanner confirmed it no longer reports.
          </p>
          {finding.superseded_by && (
            <p>
              Cleared by{' '}
              <Link
                to={`/prs/${encodeURIComponent(prId)}/findings/${encodeURIComponent(finding.superseded_by)}`}
              >
                {finding.superseded_by}
              </Link>
              . That fix is still a proposal — if it is rejected, this finding comes back and will
              be remediated on its own.
            </p>
          )}
        </section>
      )}

      {finding.proposed_fix?.rationale && (
        <section className="panel">
          <h2>Remediation rationale</h2>
          <p>{finding.proposed_fix.rationale}</p>

          {finding.proposed_fix.suppression_attempt &&
            finding.proposed_fix.suppression_attempt.length > 0 && (
              <div className="alert alert--error">
                <p>
                  <strong>This fix tried to silence the scanner, not fix the finding.</strong> It
                  was rejected before being scanned — a suppression comment would clear the rule
                  without changing anything, and would otherwise have passed the self-check.
                </p>
                <ul>
                  {finding.proposed_fix.suppression_attempt.map((line) => (
                    <li key={line}>
                      <code>{line}</code>
                    </li>
                  ))}
                </ul>
                <p>
                  If the flagged configuration really is intentional, that's a human decision to
                  record here — not something the agent may assert for you.
                </p>
              </div>
            )}

          {finding.proposed_fix.stale_reason && (
            <div className="alert alert--warn">
              <p>
                <strong>This fix was reopened by the system.</strong>{' '}
                {finding.proposed_fix.stale_reason}
              </p>
            </div>
          )}

          {finding.proposed_fix.applies_after &&
            finding.proposed_fix.applies_after.length > 0 && (
              <div className="alert alert--warn">
                <p>
                  <strong>
                    This fix is drafted on top of{' '}
                    {finding.proposed_fix.applies_after.length} earlier fix
                    {finding.proposed_fix.applies_after.length === 1 ? '' : 'es'} to the same file.
                  </strong>{' '}
                  The diff below assumes those are already applied — on their own they do not
                  apply cleanly, and approving this one without them lands a change whose context
                  never existed. Review them first:
                </p>
                <ul>
                  {finding.proposed_fix.applies_after
                    .map(normalizePrerequisite)
                    .map((entry) => {
                      const blocker = activeUnmet.find((u) => u.finding_id === entry.finding_id)
                      return (
                        <li key={entry.finding_id}>
                          <Link
                            to={`/prs/${encodeURIComponent(prId)}/findings/${encodeURIComponent(entry.finding_id)}`}
                          >
                            {entry.finding_id}
                          </Link>
                          {blocker && <> — {UNMET_EXPLANATION[blocker.reason]}</>}
                        </li>
                      )
                    })}
                </ul>
              </div>
            )}

          {finding.proposed_fix.scan_errors &&
            finding.proposed_fix.scan_errors.length > 0 && (
              <div className="alert alert--error">
                <p>
                  <strong>The scanner could not parse this fix, so nothing was verified.</strong>{' '}
                  A file that does not parse produces no findings — which looks identical to a
                  finding that was cleared. The self-check was stopped rather than allowed to read
                  that silence as success.
                </p>
                <ul>
                  {finding.proposed_fix.scan_errors.map((f) => (
                    <li key={f}>
                      <code>{f}</code>
                    </li>
                  ))}
                </ul>
                <p>
                  The diff below is the agent's attempt, unverified. Treat it as a starting point,
                  not a proposal that passed anything.
                </p>
              </div>
            )}

          {finding.proposed_fix.dropped_resources &&
            finding.proposed_fix.dropped_resources.length > 0 && (
              <div className="alert alert--warn">
                <p>
                  <strong>This fix deletes infrastructure rather than tightening it.</strong>{' '}
                  Removing a resource always satisfies the scanner, because the thing that raised
                  the finding is gone — but it may remove something the running system depends on.
                  The scanner cannot tell the difference.
                </p>
                <ul>
                  {finding.proposed_fix.dropped_resources.map((r) => (
                    <li key={r}>
                      <code>{r}</code>
                    </li>
                  ))}
                </ul>
              </div>
            )}

          {finding.proposed_fix.assumptions &&
            finding.proposed_fix.assumptions.length > 0 && (
              <div className="alert alert--warn">
                <p>
                  <strong>This fix rests on facts the agent could not check.</strong>{' '}
                  {finding.proposed_fix.questions?.length ? (
                    <>
                      It saw this one file and what it asked the repository (below) — not the
                      running system. An assumption marked <em>asked</em> was looked for and the
                      repository does not say.
                    </>
                  ) : (
                    <>
                      It saw only this one file — not the rest of the repository, nor the running
                      system.
                    </>
                  )}{' '}
                  Verify each of these before approving:
                </p>
                <ul>
                  {finding.proposed_fix.assumptions.map((a) => (
                    <li key={a}>
                      {a}
                      {askedUnanswered.has(a) && (
                        <span className="badge badge--muted assumption__asked">asked</span>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            )}

          {/* Shown when the scanner itself rejected the fix. A clean rescan
              held by a human gate is not that, and says so through the badge
              and the assumptions / deletion alerts instead -- but a fix can
              be held by a gate *and* have introduced a new finding, and then
              the reviewer needs to see both. */}
          {finding.proposed_fix.self_check_passed === false &&
            !finding.proposed_fix.suppression_attempt?.length &&
            !finding.proposed_fix.scan_errors?.length &&
            humanGates(finding.proposed_fix).length === 0 && (
            <div className="alert alert--warn">
              {/* cleared distinguishes two different failures: the fix missed
                  the original finding, or it cleared the original but
                  introduced new ones. The second is often one edit away from
                  passing; the first is not. Reporting both as a single
                  generic "self-check failed" understates the second case. */}
              {finding.proposed_fix.cleared === false ? (
                <p>
                  <strong>The rescan still reports this finding</strong> — the fix did not clear it.
                  Do not apply as-is.
                </p>
              ) : finding.proposed_fix.cleared === true ? (
                <p>
                  <strong>The rescan confirmed this finding cleared</strong>, but the fix introduced
                  new findings. Do not apply as-is without addressing them.
                </p>
              ) : (
                <p>The scanner did not confirm this fix. Do not apply as-is.</p>
              )}
              {finding.proposed_fix.self_check_new_findings &&
                finding.proposed_fix.self_check_new_findings.length > 0 && (
                  <>
                    <strong>New findings from self-check:</strong>
                    <ul>
                      {finding.proposed_fix.self_check_new_findings.map((id) => (
                        <li key={id}>
                          <code>{id}</code>
                        </li>
                      ))}
                    </ul>
                  </>
                )}
            </div>
          )}
        </section>
      )}

      {finding.proposed_fix?.questions && finding.proposed_fix.questions.length > 0 && (
        <section className="panel">
          <h2>What the agent checked in the repository</h2>
          <p className="muted">
            Questions the draft asked instead of assuming. A <strong>yes</strong> or{' '}
            <strong>no</strong> cites the file and lines it rests on, verified against the
            snapshot before it was accepted; <strong>unknown</strong> means the repository does
            not say, and that question stays an assumption above.
          </p>
          <RepositoryQuestions questions={finding.proposed_fix.questions} />
        </section>
      )}

      {finding.status === 'needs-human-only' && !showDiff && (
        <section className="panel">
          <h2>Proposed fix</h2>
          <div className="alert alert--warn">
            No diff was drafted for this finding. Review the rationale and address it manually.
          </div>
        </section>
      )}

      {showDiff && (
        <section className="panel">
          <div className="panel__header">
            <h2>Proposed diff</h2>
            {finding.proposed_fix?.agent_diff && (
              <button
                type="button"
                className="btn btn--secondary btn--small"
                onClick={() => setShowAgentDiff((shown) => !shown)}
              >
                {showAgentDiff ? "Show reviewer's edit" : "Show agent's original"}
              </button>
            )}
          </div>
          <DiffViewer
            diff={
              showAgentDiff && finding.proposed_fix?.agent_diff
                ? finding.proposed_fix.agent_diff
                : finding.proposed_fix?.diff
            }
            fileName={finding.file}
          />
        </section>
      )}

      {canReview && (
        <ReviewActions
          disabled={awaitingRemediation || blockedByChain}
          // Reject stays live on a chain block, but not while remediation
          // hasn't run: there is no fix to refuse yet.
          allowReject={!awaitingRemediation && blockedByChain}
          disabledReason={
            awaitingRemediation
              ? 'Remediation has not run for this finding yet, so there is no proposed fix to accept or refuse. Review unlocks at status fix-proposed or needs-human-only.'
              : blockedByChain
                ? `This fix is drafted on top of ${activeUnmet
                    .map((u) => `${u.finding_id} (${UNMET_EXPLANATION[u.reason]})`)
                    .join(', ')}. Accepting it would record a decision that cannot be carried out, so approve and edit are held until that is settled. You can still reject it.`
                : undefined
          }
          currentContent={fixContent}
          onSubmit={handleReview}
        />
      )}

      {finding.status === 'resolved' && (
        <p className="alert alert--success">This finding has been resolved.</p>
      )}

      <section className="panel">
        <h2>Audit trail</h2>
        <AuditTrail events={events} loading={eventsLoading} />
      </section>
    </div>
  )
}
