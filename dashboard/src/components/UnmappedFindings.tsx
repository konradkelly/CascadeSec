import { Link } from 'react-router-dom'
import {
  REASON_DESCRIPTIONS,
  REASON_LABELS,
  groupUnmapped,
  type UnmappedGroup,
} from '../review/unmapped'
import type { Finding } from '../types/finding'
import { SeverityBadge } from './SeverityBadge'

interface UnmappedFindingsProps {
  prId: string
  findings: Finding[]
}

function location(finding: Finding): string {
  const start = finding.line_range?.[0]
  return start != null ? `${finding.file}:${start}` : finding.file
}

function Group({ prId, group }: { prId: string; group: UnmappedGroup }) {
  return (
    // The backlog opens by default; groups that were decided stay folded.
    <details className="unmapped-group" open={group.reason === 'unreviewed'}>
      <summary>
        <span className={`unmapped-group__label unmapped-group__label--${group.reason}`}>
          {REASON_LABELS[group.reason]}
        </span>
        <span className="muted">
          {' '}
          {group.finding_count} finding{group.finding_count === 1 ? '' : 's'}, {group.rules.length}{' '}
          rule{group.rules.length === 1 ? '' : 's'}
        </span>
      </summary>
      <p className="muted unmapped-group__why">{REASON_DESCRIPTIONS[group.reason]}</p>
      <table className="findings-table unmapped-table">
        <thead>
          <tr>
            <th>Rule</th>
            <th>Severity</th>
            <th>Findings</th>
          </tr>
        </thead>
        <tbody>
          {group.rules.map((rule) => (
            <tr key={rule.key}>
              <td>
                <span className="finding-link__source">{rule.source}</span>{' '}
                <code className="finding-link__rule">{rule.rule_id}</code>
                {rule.title && <div className="muted unmapped-table__title">{rule.title}</div>}
              </td>
              <td>
                <SeverityBadge severity={rule.severity} />
              </td>
              <td>
                <details>
                  <summary>
                    {rule.findings.length} in {rule.file_count} file{rule.file_count === 1 ? '' : 's'}
                  </summary>
                  <ul className="unmapped-table__locations">
                    {rule.findings.map((f) => (
                      <li key={f.finding_id}>
                        <Link
                          to={`/prs/${encodeURIComponent(prId)}/findings/${encodeURIComponent(f.finding_id)}`}
                        >
                          <code>{location(f)}</code>
                        </Link>
                      </li>
                    ))}
                  </ul>
                </details>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </details>
  )
}

/** Raw findings, out of the review table and grouped by why they have no
 *  control. See review/unmapped.ts. */
export function UnmappedFindings({ prId, findings }: UnmappedFindingsProps) {
  const groups = groupUnmapped(findings)
  if (groups.length === 0) return null
  const total = groups.reduce((n, g) => n + g.finding_count, 0)

  return (
    <section className="unmapped" aria-labelledby="unmapped-heading">
      <h2 id="unmapped-heading">Reported by the scanner, no control mapped ({total})</h2>
      <p className="muted">
        Not hidden, and not review work: nothing is drafted for these. Grouped by why they have no
        control, one row per rule.
      </p>
      {groups.map((g) => (
        <Group key={g.reason} prId={prId} group={g} />
      ))}
    </section>
  )
}
