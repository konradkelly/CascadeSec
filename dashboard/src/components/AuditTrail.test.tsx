import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import type { ReviewEvent } from '../types/finding'
import { AuditTrail } from './AuditTrail'

function event(overrides: Partial<ReviewEvent>): ReviewEvent {
  return {
    pk: 'PR#gh-1-2#FINDING#f1',
    sk: 'EVENT#1',
    finding_id: 'f1',
    actor: 'konradky@example.test',
    action: 'approved',
    created_at: '2026-09-30T20:37:13Z',
    ...overrides,
  }
}

describe('AuditTrail', () => {
  it('labels an approval made on GitHub with the GitHub account', () => {
    // A Commit fixes click records "github:<login>" (github-first-review-spec
    // §3.3); a reader has to be able to tell it from a dashboard reviewer.
    render(<AuditTrail events={[event({ actor: 'github:konradkelly', github_user_id: 4242 })]} />)

    expect(screen.getByText('konradkelly')).toBeInTheDocument()
    expect(screen.getByText('GitHub')).toHaveClass('badge')
    expect(screen.queryByText('github:konradkelly')).toBeNull()
  })

  it('shows a dashboard reviewer and the system as they are', () => {
    render(
      <AuditTrail
        events={[
          event({ sk: 'EVENT#1', actor: 'konradky@example.test' }),
          event({ sk: 'EVENT#2', actor: 'system', action: 'committed', created_at: '2026-09-30T20:38:00Z' }),
        ]}
      />,
    )

    expect(screen.getByText('konradky@example.test')).toBeInTheDocument()
    expect(screen.getByText('system')).toBeInTheDocument()
    expect(screen.queryByText('GitHub')).toBeNull()
  })
})
