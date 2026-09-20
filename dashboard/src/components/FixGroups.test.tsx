import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Finding } from '../types/finding'
import { FixGroups } from './FixGroups'

vi.mock('../auth/AuthProvider', () => ({
  useAuth: () => ({ actor: 'reviewer@example.test', logout: vi.fn() }),
}))

const postReview = vi.fn()
vi.mock('../api/client', () => ({
  postReview: (...args: unknown[]) => postReview(...args),
}))

function finding(overrides: Partial<Finding> & { finding_id: string; file: string }): Finding {
  return {
    pk: 'PR#p',
    sk: `FINDING#${overrides.finding_id}`,
    source: 'trivy',
    rule_id: 'KSV-0118',
    status: 'fix-proposed',
    target_type: 'kubernetes',
    control_mappings: [{ framework: 'CIS-Kubernetes-2.0', control_id: '5.6.3' }],
    proposed_fix: { diff: '+x', self_check_passed: true, applies_after: [] },
    ...overrides,
  }
}

function renderGroups(findings: Finding[], onReviewed = vi.fn()) {
  render(
    <MemoryRouter>
      <FixGroups prId="pr-1" findings={findings} onReviewed={onReviewed} />
    </MemoryRouter>,
  )
  return onReviewed
}

beforeEach(() => {
  postReview.mockReset()
  postReview.mockResolvedValue({})
})

describe('FixGroups', () => {
  it('approves every verified fix in the group, one review each, and reloads', async () => {
    const onReviewed = renderGroups([
      finding({ finding_id: 'a', file: 'k8s/api.yaml' }),
      finding({ finding_id: 'b', file: 'k8s/web.yaml' }),
      finding({ finding_id: 'c', file: 'k8s/worker.yaml' }),
    ])

    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Approve 3 verified fixes' }))
    await user.click(screen.getByRole('button', { name: 'Confirm: approve 3' }))

    await waitFor(() => expect(onReviewed).toHaveBeenCalled())
    expect(postReview).toHaveBeenCalledTimes(3)
    expect(postReview.mock.calls.map((c) => c[1])).toEqual(['a', 'b', 'c'])
    // Each approval says it was one of a group, so the audit trail explains
    // itself without the page.
    expect(postReview.mock.calls[0][2]).toMatchObject({ action: 'approved' })
    expect(postReview.mock.calls[0][2].notes).toContain('one of 3 CIS-Kubernetes-2.0 5.6.3 fixes on kubernetes')
    expect(await screen.findByText('3 fixes approved.')).toBeInTheDocument()
  })

  it('never bulk-approves a fix held for human review, and says it is held', async () => {
    renderGroups([
      finding({ finding_id: 'a', file: 'k8s/api.yaml' }),
      finding({ finding_id: 'b', file: 'k8s/web.yaml' }),
      finding({
        finding_id: 'held',
        file: 'k8s/worker.yaml',
        status: 'needs-human-only',
        proposed_fix: { diff: '+x', self_check_passed: false, dropped_resources: ['Service/worker'] },
      }),
    ])

    expect(await screen.findByRole('button', { name: 'Approve 2 verified fixes' })).toBeInTheDocument()
    expect(screen.getByText(/1 held for individual review/)).toBeInTheDocument()
  })

  it('leaves out a fix drafted on one that has not been accepted', async () => {
    // Second in its file's chain: review-api would 409 it, so offering it
    // would only turn the group approve into a partial failure.
    renderGroups([
      finding({ finding_id: 'a', file: 'k8s/api.yaml' }),
      finding({ finding_id: 'b', file: 'k8s/web.yaml' }),
      finding({
        finding_id: 'c',
        file: 'k8s/web.yaml',
        rule_id: 'KSV-0001',
        proposed_fix: { diff: '+y', self_check_passed: true, applies_after: [{ finding_id: 'b', diff_sha256: 'x' }] },
      }),
    ])

    expect(await screen.findByRole('button', { name: 'Approve 2 verified fixes' })).toBeInTheDocument()
    expect(screen.getByText('Waits on an earlier fix')).toBeInTheDocument()
  })

  it('offers no group action for a group of one', async () => {
    renderGroups([finding({ finding_id: 'a', file: 'k8s/api.yaml' })])

    expect(await screen.findByRole('table')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Approve/ })).toBeNull()
  })

  it('reports which approvals failed and keeps the ones that succeeded', async () => {
    postReview
      .mockResolvedValueOnce({})
      .mockRejectedValueOnce(new Error('prerequisite not accepted'))
    const onReviewed = renderGroups([
      finding({ finding_id: 'a', file: 'k8s/api.yaml' }),
      finding({ finding_id: 'b', file: 'k8s/web.yaml' }),
    ])

    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Approve 2 verified fixes' }))
    await user.click(screen.getByRole('button', { name: 'Confirm: approve 2' }))

    const outcome = await screen.findByText(/1 approved; 1 failed/)
    expect(within(outcome).getByText(/k8s\/web\.yaml \(prerequisite not accepted\)/)).toBeInTheDocument()
    expect(onReviewed).toHaveBeenCalled()
  })
})
