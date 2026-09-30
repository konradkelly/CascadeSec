import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiClientError, getCommitPlan, getCommitRequest, postCommit } from '../api/client'
import type { CommitPlanResponse, PlannedFile } from '../types/commit'
import { CommitPanel } from './CommitPanel'

vi.mock('../auth/AuthProvider', () => ({
  useAuth: () => ({ actor: 'reviewer@example.test', logout: vi.fn() }),
}))

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return { ...actual, getCommitPlan: vi.fn(), postCommit: vi.fn(), getCommitRequest: vi.fn() }
})

const toCommit: PlannedFile = {
  file: 'reports.tf',
  outcome: 'commit',
  reason: null,
  tip: 'kms',
  chain: [
    { finding_id: 'kms', rule_id: 'CKV_AWS_7', verified: true, edited: false },
    { finding_id: 'log', rule_id: 'CKV_AWS_158', verified: false, edited: true },
  ],
  left_out: [],
  content_sha256: 'h1',
  diff: '--- a/reports.tf\n+++ b/reports.tf\n@@ -1 +1 @@\n-a\n+enable_key_rotation = true\n',
}

const held: PlannedFile = {
  file: 'bastion.tf',
  outcome: 'held',
  reason: 'the file has changed since these fixes were drafted; run Draft fixes again',
  tip: 'ssh',
  chain: [{ finding_id: 'ssh', rule_id: 'CKV_AWS_24', verified: true, edited: false }],
  left_out: [],
  content_sha256: null,
  diff: null,
}

function plan(overrides: Partial<CommitPlanResponse> = {}): CommitPlanResponse {
  return {
    pr_id: 'gh-1-3',
    repository: 'konradkelly/cascadesec-testbed',
    pr_number: 3,
    preview: true,
    write_back_deployed: true,
    can_commit: true,
    counts: { commit: 1, already: 0, held: 1 },
    files: [held, toCommit],
    latest_request: null,
    ...overrides,
  }
}

beforeEach(() => {
  vi.mocked(getCommitPlan).mockReset()
  vi.mocked(postCommit).mockReset()
  vi.mocked(getCommitRequest).mockReset()
})

describe('CommitPanel', () => {
  it('shows the whole change per file, held files with why, and unverified links', async () => {
    vi.mocked(getCommitPlan).mockResolvedValue(plan())
    render(<CommitPanel prId="gh-1-3" onCommitted={vi.fn()} />)

    expect(await screen.findByText('konradkelly/cascadesec-testbed#3')).toBeInTheDocument()
    // The head-to-tip diff, which is what the commit writes.
    expect(screen.getByText('+enable_key_rotation = true')).toBeInTheDocument()
    expect(screen.getByText(/Held: the file has changed since/)).toBeInTheDocument()
    // An edit was never self-checked, and says so before anyone commits it.
    expect(screen.getByText('unverified')).toHaveClass('badge--fail')
    expect(screen.getByText(/approved without passing the self-check \(CKV_AWS_158\)/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Commit 1 file' })).toBeEnabled()
  })

  it('tells a reviewer outside the committers group why there is no button', async () => {
    vi.mocked(getCommitPlan).mockResolvedValue(plan({ can_commit: false }))
    render(<CommitPanel prId="gh-1-3" onCommitted={vi.fn()} />)

    expect(await screen.findByText(/needs membership of the/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Commit/ })).toBeNull()
  })

  it('offers nothing when write-back is not deployed', async () => {
    vi.mocked(getCommitPlan).mockResolvedValue(plan({ write_back_deployed: false }))
    render(<CommitPanel prId="gh-1-3" onCommitted={vi.fn()} />)

    expect(await screen.findByText(/Write-back is not deployed/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Commit/ })).toBeNull()
  })

  it('confirms, sends what was shown, and follows the request to its commit', async () => {
    vi.mocked(getCommitPlan).mockResolvedValue(plan())
    vi.mocked(postCommit).mockResolvedValue({ request_id: 'R1', status: 'requested' })
    vi.mocked(getCommitRequest).mockResolvedValue({
      request_id: 'R1',
      pr_id: 'gh-1-3',
      requested_by: 'reviewer@example.test',
      requested_at: 't',
      updated_at: 't',
      status: 'committed',
      commit_sha: 'abcdef1234567890',
    })
    const onCommitted = vi.fn()
    render(<CommitPanel prId="gh-1-3" onCommitted={onCommitted} pollMs={1} />)

    await userEvent.click(await screen.findByRole('button', { name: 'Commit 1 file' }))
    expect(screen.getByText(/exactly as the diffs above show/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Confirm commit' }))

    // Only the file that will commit, with the content hash that was shown.
    expect(postCommit).toHaveBeenCalledWith('gh-1-3', [
      { file: 'reports.tf', tip: 'kms', content_sha256: 'h1' },
    ])
    const link = await screen.findByRole('link', { name: 'abcdef1' })
    expect(link).toHaveAttribute('href', 'https://github.com/konradkelly/cascadesec-testbed/commit/abcdef1234567890')
    await waitFor(() => expect(onCommitted).toHaveBeenCalled())
  })

  it('shows why a request was refused and reloads the plan', async () => {
    vi.mocked(getCommitPlan).mockResolvedValue(plan())
    vi.mocked(postCommit).mockRejectedValue(
      new ApiClientError('the commit plan has changed since it was shown; review it again', 409),
    )
    render(<CommitPanel prId="gh-1-3" onCommitted={vi.fn()} />)

    await userEvent.click(await screen.findByRole('button', { name: 'Commit 1 file' }))
    await userEvent.click(screen.getByRole('button', { name: 'Confirm commit' }))

    expect(await screen.findByText(/plan has changed since it was shown/)).toHaveClass('alert--error')
    expect(getCommitPlan).toHaveBeenCalledTimes(2)
  })

  it('picks up a request already running and offers no second one', async () => {
    vi.mocked(getCommitPlan).mockResolvedValue(
      plan({
        latest_request: {
          request_id: 'R0',
          pr_id: 'gh-1-3',
          requested_by: 'someone@example.test',
          requested_at: 't',
          updated_at: 't',
          status: 'committing',
        },
      }),
    )
    vi.mocked(getCommitRequest).mockReturnValue(new Promise(() => {}))
    render(<CommitPanel prId="gh-1-3" onCommitted={vi.fn()} pollMs={1} />)

    expect(await screen.findByRole('status')).toHaveTextContent('someone@example.test: committing')
    expect(screen.queryByRole('button', { name: /Commit/ })).toBeNull()
  })

  it('says a request came from a Commit fixes click on GitHub', async () => {
    vi.mocked(getCommitPlan).mockResolvedValue(
      plan({
        latest_request: {
          request_id: 'R2',
          pr_id: 'gh-1-3',
          source: 'github',
          requested_by: 'github:konradkelly',
          requested_at: 't',
          updated_at: 't',
          status: 'committed',
          commit_sha: 'abcdef1234567890',
        },
      }),
    )
    render(<CommitPanel prId="gh-1-3" onCommitted={vi.fn()} />)

    expect(await screen.findByRole('status')).toHaveTextContent(
      'Commit fixes clicked on GitHub by konradkelly: committed',
    )
  })

  it('says why there is no plan for a PR GitHub does not know', async () => {
    vi.mocked(getCommitPlan).mockRejectedValue(new ApiClientError('not a GitHub pull request', 404))
    render(<CommitPanel prId="gh-1-3" onCommitted={vi.fn()} />)

    expect(await screen.findByText('not a GitHub pull request')).toBeInTheDocument()
  })
})
