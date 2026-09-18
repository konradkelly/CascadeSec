import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import type { RepositoryQuestion } from '../types/finding'
import { RepositoryQuestions } from './RepositoryQuestions'

const answered: RepositoryQuestion = {
  question: 'Is var.admin_cidrs populated anywhere?',
  answer: 'yes',
  explanation: 'terraform.tfvars sets it to the office range.',
  citations: [{ file: 'terraform.tfvars', line_range: [3, 3], excerpt: 'admin_cidrs = ["10.0.0.0/16"]' }],
}

const unanswered: RepositoryQuestion = {
  question: 'Does anything serve this bucket anonymously?',
  answer: 'unknown',
  explanation: 'No CloudFront or website configuration references it.',
  citations: [],
}

describe('RepositoryQuestions', () => {
  it('renders nothing when the draft asked nothing', () => {
    expect(render(<RepositoryQuestions questions={[]} />).container).toBeEmptyDOMElement()
    expect(render(<RepositoryQuestions />).container).toBeEmptyDOMElement()
  })

  it('shows an answered question with the file and lines it rests on', () => {
    // The citation is a fact the reviewer can open, verified by
    // context-agent before it was accepted -- not a claim.
    render(<RepositoryQuestions questions={[answered]} />)

    expect(screen.getByText('yes')).toHaveClass('badge--answered')
    expect(screen.getByText(answered.question)).toBeInTheDocument()
    expect(screen.getByText('terraform.tfvars:3')).toBeInTheDocument()
    expect(screen.getByText(answered.citations[0].excerpt)).toBeInTheDocument()
  })

  it('shows a line range as start-end and a single line as just the line', () => {
    const ranged = {
      ...answered,
      citations: [{ ...answered.citations[0], line_range: [3, 7] as [number, number] }],
    }
    render(<RepositoryQuestions questions={[ranged]} />)

    expect(screen.getByText('terraform.tfvars:3-7')).toBeInTheDocument()
  })

  it('shows an unanswered question quietly, with no citations', () => {
    // "We looked and it does not say" is the one outcome that is not a
    // fact, so it is the one that is visually muted. It still appears: an
    // assumption the agent could not check and one it checked and the
    // repository did not answer must not look the same.
    render(<RepositoryQuestions questions={[unanswered]} />)

    expect(screen.getByText('unknown')).toHaveClass('badge--muted')
    expect(screen.getByText(unanswered.explanation)).toBeInTheDocument()
    expect(document.querySelector('blockquote')).toBeNull()
  })

  it('treats no the same as yes: both are established', () => {
    render(<RepositoryQuestions questions={[{ ...answered, answer: 'no' }]} />)

    expect(screen.getByText('no')).toHaveClass('badge--answered')
  })
})
