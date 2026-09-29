/** Write-back (docs/write-back-spec.md): what committing a PR's approved
 *  fixes would do, and the requests to do it. Mirrors review-api's
 *  commit-plan and commit routes. */

/** One link of the chain a file's tip carries. `verified` is false for an
 *  edit (never self-checked) and for a fix a reviewer approved despite a
 *  failed or held self-check; those are committed, labelled, and the push
 *  scan is their check (write-back-spec §5.5). */
export interface CommitChainLink {
  finding_id: string
  rule_id: string
  verified: boolean
  edited: boolean
}

/** Per file: "commit" writes the tip's corrected file over the head,
 *  "already" means the head already is that file, "held" says why not. */
export type PlannedOutcome = 'commit' | 'already' | 'held'

export interface PlannedFile {
  file: string
  outcome: PlannedOutcome
  reason: string | null
  tip: string | null
  chain: CommitChainLink[]
  /** Rule ids of approved fixes the tip does not carry. */
  left_out: string[]
  /** What the reviewer confirms along with the tip: an edit keeps the
   *  finding id and changes the content. */
  content_sha256: string | null
  /** Head to tip: the whole change the commit makes to this file. */
  diff: string | null
}

export type CommitStatus = 'requested' | 'committing' | 'committed' | 'held' | 'failed'

export interface CommittedFile {
  file: string
  outcome: 'committed' | 'already' | 'held'
  reason: string | null
  tip: string | null
  chain: string[]
  unverified: string[]
  left_out: string[]
}

export interface CommitRequest {
  request_id: string
  pr_id: string
  requested_by: string
  requested_at: string
  updated_at: string
  status: CommitStatus
  reason?: string
  commit_sha?: string
  head_sha_before?: string
  files?: CommittedFile[]
}

export interface CommitPlanResponse {
  pr_id: string
  repository: string
  pr_number: number
  /** Always true: the plan reads the head from the latest snapshot, and the
   *  committer re-checks every file against GitHub before writing. */
  preview: boolean
  write_back_deployed: boolean
  /** Whether this reviewer is in the committers group. Approving is open to
   *  every reviewer; committing is not (write-back-spec §9). */
  can_commit: boolean
  counts: Record<PlannedOutcome, number>
  files: PlannedFile[]
  latest_request: CommitRequest | null
}

export interface CommitConfirmation {
  file: string
  tip: string
  content_sha256: string
}

export const ACTIVE_COMMIT_STATUSES: ReadonlySet<CommitStatus> = new Set(['requested', 'committing'])
