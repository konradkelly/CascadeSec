import type { Finding, Prerequisite } from '../types/finding'

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
export function normalizePrerequisite(entry: Prerequisite | string): Prerequisite {
  return typeof entry === 'string' ? { finding_id: entry } : entry
}

export interface UnmetPrerequisite {
  finding_id: string
  reason: 'missing' | 'unresolved' | 'stale' | 'unverifiable'
}

export const UNMET_EXPLANATION: Record<UnmetPrerequisite['reason'], string> = {
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
export async function findUnmetPrerequisites(
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
