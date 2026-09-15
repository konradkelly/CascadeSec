/** Mirrors spec §5 FindingRecord + ReviewEvent shapes from review-api. */

export type FindingStatus =
  | 'raw'
  | 'mapped'
  | 'fix-proposed'
  | 'needs-human-only'
  /** Another fix on the same file already cleared this finding's rule, so no
   *  fix was drafted for it. Conditional on that fix surviving review: if it
   *  is rejected, this finding comes back. Not 'resolved', which means a human
   *  accepted something. */
  | 'superseded'
  | 'resolved'

export type ReviewAction = 'approved' | 'edited' | 'rejected'

/** What can appear in an audit trail. "reopened" is never submitted by a
 *  person: the system writes it when an edit upstream invalidates a fix that
 *  had already been accepted. Kept distinct from ReviewAction so it cannot be
 *  posted to the review endpoint by mistake. */
export type AuditAction = ReviewAction | 'reopened'

export interface ControlMapping {
  framework: string
  control_id: string
  control_text_ref?: string
  citation_span?: string
  rationale?: string
}

/** Where a repository answer came from. The excerpt was checked against the
 *  cited lines by context-agent before the answer was accepted; a citation
 *  that did not verify was dropped, and an answer left without one became
 *  'unknown'. So what reaches the UI is verified, and it can be shown as
 *  fact rather than as a claim. */
export interface RepositoryCitation {
  file: string
  line_range: [number, number]
  excerpt: string
}

/** A question the draft asked about the rest of the repository instead of
 *  guessing, and what context-agent found. 'yes' and 'no' always carry at
 *  least one citation. 'unknown' means the repository does not say (or the
 *  question was never put to it -- the explanation says which); it holds
 *  the fix for review the way an assumption does, from here, and is not
 *  copied into `assumptions`, which are the model's own claims. */
export interface RepositoryQuestion {
  question: string
  answer: 'yes' | 'no' | 'unknown'
  explanation: string
  citations: RepositoryCitation[]
}

export interface ProposedFix {
  diff?: string
  /** The agent's original diff, preserved the first time a reviewer edits the
   *  fix and never overwritten afterwards. Null/absent until an edit happens
   *  -- that's what lets the UI offer an "agent's original / reviewer's edit"
   *  toggle only when there's something to toggle to. */
  agent_diff?: string | null
  rationale?: string
  self_check_passed?: boolean
  self_check_new_findings?: string[]
  /** Whether the rescan confirmed the original finding is gone -- distinct
   *  from self_check_passed, which also requires no new findings. A fix can
   *  clear the original and still fail the self-check by introducing new
   *  ones; without this field that case is indistinguishable from a fix that
   *  missed the original entirely. Absent on records written before this
   *  field existed. */
  cleared?: boolean
  /** Suppression directives the agent tried to add (tfsec:ignore, checkov:skip
   *  and friends). Non-empty means the fix was refused before it was ever
   *  scanned: silencing a rule would pass the self-check by construction, so
   *  it can never be treated as a fix. */
  suppression_attempt?: string[]
  /** Resources the fix deletes outright rather than tightening. Deleting
   *  always satisfies the scanner, so these are held for review however clean
   *  the rescan came back. */
  dropped_resources?: string[]
  /** Facts the fix depends on that the agent could not verify: its own
   *  claims, worded as claims. Non-empty forces human review, as does an
   *  'unknown' in `questions`. */
  assumptions?: string[]
  /** What the draft asked about the repository and what it was told, with
   *  citations. Absent on records written before context-agent existed;
   *  empty when the draft had nothing to ask. */
  questions?: RepositoryQuestion[]
  /** The fixes, in order, this one is drafted on top of -- empty means it
   *  applies to the pristine file. Every file in this project carries several
   *  findings, so most fixes are not independent: this diff will not apply
   *  cleanly unless these have been applied first. Preserved across a
   *  reviewer's edit, unlike the self-check fields, because editing a diff
   *  does not change what it is rooted on. */
  applies_after?: Prerequisite[]
  /** Set by the system when a prerequisite was edited after this fix was
   *  drafted on it, which sends the fix back to needs-human-only however it
   *  had been decided before. Explains why a fix the reviewer remembers
   *  resolving is open again. */
  stale_reason?: string
  /** Files the scanner could not parse when rescanning the fix. Non-empty means
   *  the fix was never actually verified -- an unparseable file produces no
   *  findings, which the self-check would otherwise read as the finding having
   *  been cleared. Distinct from a fix that was verified and failed, and the
   *  reviewer has to be told which one this is. */
  scan_errors?: string[]
}

/** One link in a fix chain: an earlier finding on the same file whose fix
 *  this one was drafted on top of.
 *
 *  diff_sha256 is a hash of that prerequisite's diff *as it stood when this
 *  fix was drafted*, which is what makes staleness detectable without either
 *  side reconstructing file content: if the reviewer edits the prerequisite,
 *  the hash stops matching and this fix is known to be rooted on something
 *  that no longer exists. Optional because records written before the chain
 *  carried hashes are still readable; absent means unverifiable, not fresh.
 */
export interface Prerequisite {
  finding_id: string
  diff_sha256?: string
}

export interface Finding {
  pk: string
  sk: string
  finding_id: string
  iac_type?: string
  source: string
  rule_id: string
  file: string
  line_range?: [number | null, number | null]
  severity?: string
  control_mappings?: ControlMapping[]
  status: FindingStatus
  /** Set with status 'superseded': the finding whose fix cleared this one. */
  superseded_by?: string
  proposed_fix?: ProposedFix | null
  created_at?: string
  updated_at?: string
  /** When a scan of this PR first stopped reporting this finding: the fix
   *  landed, the file went away, or a tool upgrade dropped the rule -- they
   *  are indistinguishable from here, so it is marked rather than deleted
   *  and the review trail stays. Cleared if it fires again. Absent means it
   *  was in the most recent scan. */
  no_longer_detected?: string
  /** When a scan last reported this finding. Absent on records written
   *  before the scanner started recording it. */
  last_seen_at?: string
}

export interface ReviewEvent {
  pk: string
  sk: string
  finding_id: string
  pr_id?: string
  actor: string
  action: AuditAction
  notes?: string
  /** The diff a reviewer submitted with an "edited" decision, stored verbatim
   *  on the event so the audit record is self-contained even if the finding
   *  itself is edited again later. */
  edited_diff?: string | null
  created_at: string
}

export interface FindingsListResponse {
  pr_id: string
  count: number
  findings: Finding[]
}

export interface EventsListResponse {
  finding_id: string
  count: number
  events: ReviewEvent[]
}

export interface ReviewResponse {
  finding_id: string
  action: ReviewAction
  status: string | null
  recorded_at: string
  /** Fixes this decision sent back to needs-human-only, because they were
   *  drafted on the diff it just replaced. Surfaced to the reviewer who caused
   *  it rather than left to appear in someone else's queue. */
  reopened_dependents?: string[]
}

export interface ApiError {
  error: string
}
