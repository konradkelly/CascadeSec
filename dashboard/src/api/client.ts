import type {
  ApiError,
  EventsListResponse,
  Finding,
  FindingsListResponse,
  ReviewAction,
  ReviewResponse,
} from '../types/finding'
import type {
  CommitConfirmation,
  CommitPlanResponse,
  CommitRequest,
} from '../types/commit'
import { readToken } from '../auth/token'

const API_BASE = import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, '') ?? ''

export class ApiClientError extends Error {
  status: number

  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiClientError'
    this.status = status
  }
}

function apiConfigured(): boolean {
  return API_BASE.length > 0
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  if (!apiConfigured()) {
    throw new ApiClientError(
      'VITE_API_BASE_URL is not set. Copy .env.example to .env and point it at your review-api endpoint.',
      0,
    )
  }

  const token = readToken()

  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      'content-type': 'application/json',
      // Every route requires this. Its absence here means either the session
      // expired between page load and this call, or auth was never set up --
      // both surface as the same 401 apiConfigured() can't detect in advance.
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...init?.headers,
    },
  })

  const body = await response.json().catch(() => ({}))

  if (!response.ok) {
    const message = (body as ApiError).error ?? `Request failed (${response.status})`
    throw new ApiClientError(message, response.status)
  }

  return body as T
}

export function listFindings(prId: string): Promise<FindingsListResponse> {
  return request<FindingsListResponse>(`/prs/${encodeURIComponent(prId)}/findings`)
}

export function getFinding(prId: string, findingId: string): Promise<Finding> {
  return request<Finding>(
    `/prs/${encodeURIComponent(prId)}/findings/${encodeURIComponent(findingId)}`,
  )
}

export interface FixContentResponse {
  finding_id: string
  file: string
  content: string
}

/** The fix's corrected file, as it currently stands -- the agent's draft, or
 *  the reviewer's edit if one has been made. What the edit textarea prefills
 *  with. Read from S3 on each request rather than carried on the finding: a
 *  module's main.tf can exceed a DynamoDB item. */
export function getFixContent(prId: string, findingId: string): Promise<FixContentResponse> {
  return request<FixContentResponse>(
    `/prs/${encodeURIComponent(prId)}/findings/${encodeURIComponent(findingId)}/content`,
  )
}

export function listEvents(prId: string, findingId: string): Promise<EventsListResponse> {
  return request<EventsListResponse>(
    `/prs/${encodeURIComponent(prId)}/findings/${encodeURIComponent(findingId)}/events`,
  )
}

export function postReview(
  prId: string,
  findingId: string,
  // No actor field: the API derives the reviewer's identity from the bearer
  // token (see review-api's _actor_from_claims), not from anything the client
  // sends. Passing one here would be silently ignored.
  // edited_content is the whole corrected file, not a diff. The API computes
  // the diff against the fix's base, the same way remediation-agent computes
  // the agent's, so a reviewer's edit is validated the same way an agent's is.
  // A hand-authored diff would not be, and the API refuses one.
  payload: { action: ReviewAction; notes?: string; edited_content?: string },
): Promise<ReviewResponse> {
  return request<ReviewResponse>(
    `/prs/${encodeURIComponent(prId)}/findings/${encodeURIComponent(findingId)}/review`,
    { method: 'POST', body: JSON.stringify(payload) },
  )
}

/** What committing the PR's approved fixes would do, per file. A preview:
 *  the committer re-reads every file from GitHub before it writes. */
export function getCommitPlan(prId: string): Promise<CommitPlanResponse> {
  return request<CommitPlanResponse>(`/prs/${encodeURIComponent(prId)}/commit-plan`)
}

/** Ask for a commit. `confirm` is what the reviewer was shown -- per file,
 *  the tip and its content hash -- and the API refuses the request if the
 *  plan no longer matches it, rather than committing something unseen. */
export function postCommit(
  prId: string,
  confirm: CommitConfirmation[],
): Promise<{ request_id: string; status: string }> {
  return request(`/prs/${encodeURIComponent(prId)}/commits`, {
    method: 'POST',
    body: JSON.stringify({ confirm }),
  })
}

export function getCommitRequest(prId: string, requestId: string): Promise<CommitRequest> {
  return request<CommitRequest>(
    `/prs/${encodeURIComponent(prId)}/commits/${encodeURIComponent(requestId)}`,
  )
}

export { apiConfigured }
