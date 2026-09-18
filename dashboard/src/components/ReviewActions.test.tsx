import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { ReviewActions } from './ReviewActions'

vi.mock('../auth/AuthProvider', () => ({
  useAuth: () => ({ actor: 'reviewer@example.test', logout: vi.fn() }),
}))

function buttons() {
  return {
    approve: screen.getByRole('button', { name: 'Approve' }),
    edit: screen.queryByRole('button', { name: 'Approve with edits' }),
    reject: screen.getByRole('button', { name: 'Reject fix' }),
  }
}

describe('ReviewActions', () => {
  it('offers all three decisions when nothing blocks them', () => {
    render(<ReviewActions currentContent="resource {}" onSubmit={vi.fn()} />)

    const b = buttons()
    expect(b.approve).toBeEnabled()
    expect(b.edit).toBeEnabled()
    expect(b.reject).toBeEnabled()
  })

  it('hides Approve with edits when there is nothing to edit', () => {
    render(<ReviewActions onSubmit={vi.fn()} />)

    expect(buttons().edit).toBeNull()
  })

  it('disables everything and says why', () => {
    // Dead controls with no explanation read as a bug.
    render(
      <ReviewActions disabled disabledReason="This fix has no diff to accept." currentContent="x" onSubmit={vi.fn()} />,
    )

    const b = buttons()
    expect(b.approve).toBeDisabled()
    expect(b.edit).toBeDisabled()
    expect(b.reject).toBeDisabled()
    expect(screen.getByText('This fix has no diff to accept.')).toHaveClass('alert--info')
  })

  it('keeps Reject live behind an unmet prerequisite', () => {
    // Refusing a fix is always coherent, and it is the reviewer's only way
    // out of a chain that cannot be assembled. Disabling it would trap them.
    render(
      <ReviewActions
        disabled
        allowReject
        disabledReason="Prerequisite f1 has not been accepted yet."
        currentContent="x"
        onSubmit={vi.fn()}
      />,
    )

    const b = buttons()
    expect(b.approve).toBeDisabled()
    expect(b.edit).toBeDisabled()
    expect(b.reject).toBeEnabled()
  })

  it('submits a rejection with trimmed notes and reports the finding stays open', async () => {
    const onSubmit = vi.fn().mockResolvedValue(undefined)
    render(<ReviewActions disabled allowReject disabledReason="blocked" onSubmit={onSubmit} />)

    await userEvent.type(screen.getByRole('textbox'), '  the prerequisite was wrong too  ')
    await userEvent.click(buttons().reject)

    expect(onSubmit).toHaveBeenCalledWith({
      action: 'rejected',
      notes: 'the prerequisite was wrong too',
      edited_content: undefined,
    })
    expect(screen.getByText(/Rejection recorded/)).toBeInTheDocument()
  })

  it('submits an edit as the whole corrected file, not a diff', async () => {
    const onSubmit = vi.fn().mockResolvedValue(undefined)
    render(<ReviewActions currentContent="resource {}" onSubmit={onSubmit} />)

    await userEvent.click(buttons().edit!)
    const save = screen.getByRole('button', { name: 'Save edited fix' })
    // Unchanged content is not an edit.
    expect(save).toBeDisabled()

    const textarea = screen.getByLabelText('Edited file')
    await userEvent.clear(textarea)
    await userEvent.type(textarea, 'resource {{ versioning = true }')
    await userEvent.click(save)

    expect(onSubmit).toHaveBeenCalledWith({
      action: 'edited',
      notes: '',
      edited_content: 'resource { versioning = true }',
    })
  })

  it('will not save an edit that empties the file', async () => {
    render(<ReviewActions currentContent="resource {}" onSubmit={vi.fn()} />)

    await userEvent.click(buttons().edit!)
    await userEvent.clear(screen.getByLabelText('Edited file'))

    expect(screen.getByRole('button', { name: 'Save edited fix' })).toBeDisabled()
  })

  it('shows the API error and leaves the reviewer where they were', async () => {
    const onSubmit = vi.fn().mockRejectedValue(new Error('prerequisite f1 was rejected'))
    render(<ReviewActions onSubmit={onSubmit} />)

    await userEvent.click(buttons().approve)

    expect(screen.getByText('prerequisite f1 was rejected')).toBeInTheDocument()
    expect(buttons().approve).toBeEnabled()
  })
})
