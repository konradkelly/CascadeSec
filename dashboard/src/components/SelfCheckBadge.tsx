import { singleSourceTitle, singleSourceTool } from '../review/coverage'
import type { ProposedFix } from '../types/finding'

interface SelfCheckBadgeProps {
  proposedFix?: ProposedFix | null
  /** The finding's target_type, so a language only one scanner parses says
   *  so here rather than leaving the reviewer to discover it
   *  (docs/multi-iac-spec.md §4). Optional: a caller that does not pass it
   *  gets the verdict alone, exactly as before. */
  targetType?: string | null
}

/** Why a fix whose rescan came back clean is still not `fix-proposed`.
 *
 *  remediation-agent overrides a passing rescan for two human-review gates
 *  (a deleted resource, a declared assumption) and records the override as
 *  self_check_passed=false with cleared=true and nothing new. That is a
 *  different thing from a fix the scanner rejected, and the two must not
 *  read the same: one has a verified diff waiting for a decision, the other
 *  has a diff that does not work. Empty when the fix is not in that state. */
export function humanGates(proposedFix?: ProposedFix | null): string[] {
  if (
    !proposedFix ||
    proposedFix.self_check_passed !== false ||
    proposedFix.cleared !== true ||
    proposedFix.self_check_new_findings?.length ||
    proposedFix.scan_errors?.length ||
    proposedFix.suppression_attempt?.length
  ) {
    return []
  }
  const gates: string[] = []
  if (proposedFix.dropped_resources?.length) gates.push('deletes a resource')
  if (proposedFix.assumptions?.length) gates.push('rests on assumptions')
  if (proposedFix.questions?.some((q) => q.answer === 'unknown')) {
    gates.push('asked the repository something it could not answer')
  }
  return gates
}

export function SelfCheckBadge({ proposedFix, targetType }: SelfCheckBadgeProps) {
  const tool = singleSourceTool(targetType)
  return (
    <>
      <SelfCheckVerdict proposedFix={proposedFix} />
      {tool && targetType && (
        <span className="badge badge--muted" title={singleSourceTitle(targetType, tool)}>
          {tool} only
        </span>
      )}
    </>
  )
}

/** The verdict itself. Split out so the coverage caveat can sit beside it
 *  rather than replacing it: it adds information about how the check was
 *  made, and must never soften what the check decided. */
function SelfCheckVerdict({ proposedFix }: { proposedFix?: ProposedFix | null }) {
  if (!proposedFix || proposedFix.self_check_passed === undefined) {
    return <span className="badge badge--muted">No self-check</span>
  }

  if (proposedFix.self_check_passed) {
    return <span className="badge badge--pass">Self-check passed</span>
  }

  const gates = humanGates(proposedFix)
  if (gates.length > 0) {
    return (
      <span
        className="badge badge--needs-human-only"
        title={`The rescan cleared the finding and introduced nothing; held because the fix ${gates.join(' and ')}`}
      >
        Rescan clean, held for review
      </span>
    )
  }

  // A parse failure has to be read before cleared/newCount, not alongside them:
  // it sets cleared=false with no new findings, which is the same shape as a
  // fix that was scanned and missed its finding. Falling through would explain
  // an unverified fix as a failed one.
  if (proposedFix.scan_errors?.length) {
    return (
      <span className="badge badge--fail" title="The scanner could not parse the fix, so nothing was verified">
        Fix did not parse
      </span>
    )
  }

  const newCount = proposedFix.self_check_new_findings?.length ?? 0
  const reasons: string[] = []

  // cleared distinguishes the two ways a self-check fails -- a fix that
  // missed the original finding entirely, versus one that cleared it but
  // introduced new findings along the way. A record can be both at once, and
  // guessing from newCount alone (the pre-`cleared` heuristic) silently drops
  // the "original not cleared" half whenever new findings are also present.
  // proposedFix.cleared is undefined on records written before this field
  // existed, in which case that heuristic is the best available fallback.
  if (proposedFix.cleared === false || (proposedFix.cleared === undefined && newCount === 0)) {
    reasons.push('original issue not cleared')
  }
  if (newCount > 0) {
    reasons.push(`${newCount} new finding${newCount === 1 ? '' : 's'} introduced`)
  }

  const detail = reasons.length > 0 ? reasons.join('; ') : 'Original issue not cleared'

  return (
    <span className="badge badge--fail" title={detail}>
      Self-check failed
    </span>
  )
}
