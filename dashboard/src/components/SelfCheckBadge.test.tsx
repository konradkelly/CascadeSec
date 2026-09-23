import { cleanup, render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import type { ProposedFix, RepositoryQuestion } from '../types/finding'
import { SelfCheckBadge, humanGates } from './SelfCheckBadge'

/** A rescan that came back clean and was then overridden for review: the
 *  shape remediation-agent writes for a human gate. */
const HELD: ProposedFix = { self_check_passed: false, cleared: true, self_check_new_findings: [] }

const unknownQ: RepositoryQuestion = {
  question: 'Does anything serve this bucket anonymously?',
  answer: 'unknown',
  explanation: 'The snapshot does not say.',
  citations: [],
}

describe('humanGates', () => {
  // A held fix and a failed fix arrive as the same self_check_passed=false.
  // The whole point of this function is to tell them apart, so the tests
  // are the boundary: which shapes are a gate, and which are a failure.

  it('names each gate the rescan was overridden for', () => {
    expect(humanGates({ ...HELD, dropped_resources: ['aws_s3_bucket.logs'] })).toEqual(['deletes a resource'])
    expect(humanGates({ ...HELD, assumptions: ['no other module reads this'] })).toEqual(['rests on assumptions'])
    expect(humanGates({ ...HELD, questions: [unknownQ] })).toEqual([
      'asked the repository something it could not answer',
    ])
  })

  it('lists every gate when more than one applies', () => {
    expect(
      humanGates({ ...HELD, dropped_resources: ['x'], assumptions: ['y'], questions: [unknownQ] }),
    ).toHaveLength(3)
  })

  it('is empty for a fix the scanner actually rejected', () => {
    // Same override flags, but something is wrong with the diff. That is a
    // failure with a reason of its own, not a clean fix waiting on a person.
    expect(humanGates({ ...HELD, assumptions: ['y'], self_check_new_findings: ['AWS-0132'] })).toEqual([])
    expect(humanGates({ ...HELD, assumptions: ['y'], scan_errors: ['main.tf: unclosed brace'] })).toEqual([])
    expect(humanGates({ ...HELD, assumptions: ['y'], suppression_attempt: ['#tfsec:ignore'] })).toEqual([])
  })

  it('is empty for a fix that did not clear its finding', () => {
    expect(humanGates({ ...HELD, cleared: false, assumptions: ['y'] })).toEqual([])
  })

  it('is empty for a fix that passed, whatever it assumed', () => {
    // A passing fix with assumptions is fix-proposed; the assumptions show
    // elsewhere. Nothing is held.
    expect(humanGates({ ...HELD, self_check_passed: true, assumptions: ['y'] })).toEqual([])
  })

  it('is empty when a question was answered', () => {
    expect(humanGates({ ...HELD, questions: [{ ...unknownQ, answer: 'no' }] })).toEqual([])
  })

  it('is empty when the override flags are set but nothing was gated', () => {
    // Defensive: the agent should never write this shape, and if it does
    // the badge must not claim a reason it cannot name.
    expect(humanGates(HELD)).toEqual([])
    expect(humanGates(undefined)).toEqual([])
    expect(humanGates(null)).toEqual([])
  })
})

describe('SelfCheckBadge', () => {
  /** Renders alone, so a test may call it more than once. */
  function badge(fix?: ProposedFix | null) {
    cleanup()
    render(<SelfCheckBadge proposedFix={fix} />)
    return screen.getByText(/./, { selector: '.badge' })
  }

  it('says there was no self-check when there was none', () => {
    expect(badge(undefined)).toHaveTextContent('No self-check')
    expect(badge({ diff: '...' })).toHaveTextContent('No self-check')
  })

  it('passes', () => {
    expect(badge({ self_check_passed: true })).toHaveTextContent('Self-check passed')
  })

  it('reads a held fix as held, with the gates in the title', () => {
    const el = badge({ ...HELD, dropped_resources: ['x'], assumptions: ['y'] })

    expect(el).toHaveTextContent('Rescan clean, held for review')
    expect(el).toHaveClass('badge--needs-human-only')
    expect(el).toHaveAttribute('title', expect.stringContaining('deletes a resource and rests on assumptions'))
  })

  it('reads a parse failure as unverified, not as failed', () => {
    // scan_errors sets cleared=false with no new findings -- the same shape
    // as a fix that missed its finding. Read first, or it would be explained
    // as "original issue not cleared" when nothing was checked at all.
    const el = badge({ self_check_passed: false, cleared: false, scan_errors: ['main.tf: unclosed brace'] })

    expect(el).toHaveTextContent('Fix did not parse')
    expect(el).toHaveAttribute('title', expect.stringContaining('nothing was verified'))
  })

  describe('a failed self-check explains which way it failed', () => {
    it('missed the original', () => {
      expect(badge({ self_check_passed: false, cleared: false })).toHaveAttribute(
        'title',
        'original issue not cleared',
      )
    })

    it('cleared it but introduced new findings', () => {
      expect(badge({ self_check_passed: false, cleared: true, self_check_new_findings: ['a', 'b'] })).toHaveAttribute(
        'title',
        '2 new findings introduced',
      )
    })

    it('both at once, and says both', () => {
      // The pre-`cleared` heuristic read any new findings as "cleared but
      // introduced", dropping the half that matters more.
      expect(badge({ self_check_passed: false, cleared: false, self_check_new_findings: ['a'] })).toHaveAttribute(
        'title',
        'original issue not cleared; 1 new finding introduced',
      )
    })

    it('falls back to the old heuristic on a record written before `cleared` existed', () => {
      expect(badge({ self_check_passed: false, self_check_new_findings: [] })).toHaveAttribute(
        'title',
        'original issue not cleared',
      )
      expect(badge({ self_check_passed: false, self_check_new_findings: ['a'] })).toHaveAttribute(
        'title',
        '1 new finding introduced',
      )
    })
  })
})

describe('coverage caveat', () => {
  // multi-iac-spec §4: where only one of the two scanners parses a language,
  // the self-check has one source rather than two. That is weaker, not
  // absent, and §4 says it should be said in the UI rather than discovered.

  function badges(targetType?: string) {
    cleanup()
    render(<SelfCheckBadge proposedFix={{ self_check_passed: true }} targetType={targetType} />)
    return screen.queryByText(/only$/)
  }

  it('says which scanner ran when only one covers the language', () => {
    // checkov will not open a .tofu file, so Trivy carries OpenTofu alone.
    expect(badges('opentofu')).toHaveTextContent('Trivy only')
  })

  it('says nothing extra for a language more than one scanner parses', () => {
    expect(badges('terraform')).toBeNull()
    expect(badges('arm')).toBeNull()
    expect(badges('kubernetes')).toBeNull()
    expect(badges(undefined)).toBeNull()
  })

  it('stopped flagging bicep once KICS gave it a second source', () => {
    // Bicep was checkov-only while Trivy was the other tool, and Trivy has
    // no Bicep scanner. KICS parses .bicep natively (2026-09-23), so the
    // self-check compares two tools and the caveat would now be false.
    expect(badges('bicep')).toBeNull()
  })

  it('adds to the verdict and never replaces it', () => {
    // The caveat explains how the check was made. It must not soften what
    // the check decided, or a failed fix on a single-source language would
    // read as merely unverified.
    cleanup()
    render(
      <SelfCheckBadge
        proposedFix={{ self_check_passed: false, cleared: false, self_check_new_findings: [] }}
        targetType="opentofu"
      />,
    )

    expect(screen.getByText('Self-check failed')).toBeInTheDocument()
    expect(screen.getByText('Trivy only')).toBeInTheDocument()
  })

  it('explains the caveat on hover rather than only labelling it', () => {
    cleanup()
    render(<SelfCheckBadge proposedFix={{ self_check_passed: true }} targetType="opentofu" />)

    expect(screen.getByText('Trivy only')).toHaveAttribute(
      'title',
      "Trivy and checkov do not both parse opentofu, so the rescan compared Trivy's findings alone. " +
        'Weaker than a two-tool check, not absent.',
    )
  })
})
