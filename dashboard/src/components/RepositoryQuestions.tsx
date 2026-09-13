import type { RepositoryQuestion } from '../types/finding'

interface RepositoryQuestionsProps {
  questions?: RepositoryQuestion[]
}

/** What the draft asked about the rest of the repository, and what it found.
 *
 *  The point of showing this next to the assumptions is the difference
 *  between "assumed" and "asked": an assumption the agent could not check
 *  and one it checked and the repository did not answer look identical in
 *  the assumptions list. Here, an answered question shows the file and
 *  lines it rests on -- verified by context-agent before it was accepted, so
 *  the citation is a fact the reviewer can open, not a claim -- and an
 *  unanswered one says so. */
export function RepositoryQuestions({ questions }: RepositoryQuestionsProps) {
  if (!questions?.length) {
    return null
  }

  return (
    <ul className="question-list">
      {questions.map((q) => (
        <li key={q.question} className="question-item">
          <div className="question-item__header">
            <AnswerBadge answer={q.answer} />
            <span className="question-item__question">{q.question}</span>
          </div>
          <p className="question-item__explanation">{q.explanation}</p>
          {q.citations.length > 0 && (
            <ul className="question-item__citations">
              {q.citations.map((c) => (
                <li key={`${c.file}:${c.line_range[0]}-${c.line_range[1]}:${c.excerpt}`}>
                  <code className="question-item__ref">
                    {c.file}:{c.line_range[0]}
                    {c.line_range[1] !== c.line_range[0] && `-${c.line_range[1]}`}
                  </code>
                  <blockquote className="question-item__excerpt">{c.excerpt}</blockquote>
                </li>
              ))}
            </ul>
          )}
        </li>
      ))}
    </ul>
  )
}

function AnswerBadge({ answer }: { answer: RepositoryQuestion['answer'] }) {
  // Yes and no are both established facts with citations behind them; only
  // unknown is the "we looked and it does not say" outcome, so only it is
  // visually quiet.
  if (answer === 'unknown') {
    return <span className="badge badge--muted">unknown</span>
  }
  return <span className="badge badge--answered">{answer}</span>
}
