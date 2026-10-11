import { describe, expect, it } from 'vitest'
import type { Finding } from '../types/finding'
import { groupUnmapped, mappedShare } from './unmapped'

function finding(overrides: Partial<Finding> & { finding_id: string }): Finding {
  return {
    pk: 'PR#p',
    sk: `FINDING#${overrides.finding_id}`,
    source: 'checkov',
    rule_id: 'CKV_AZURE_43',
    file: 'storage.json',
    status: 'raw',
    target_type: 'arm',
    ...overrides,
  }
}

describe('groupUnmapped', () => {
  it('leaves out every finding that has a control', () => {
    const groups = groupUnmapped([
      finding({ finding_id: 'a', unmapped_reason: 'hygiene' }),
      finding({ finding_id: 'b', status: 'mapped' }),
      finding({ finding_id: 'c', status: 'fix-proposed' }),
    ])

    expect(groups.flatMap((g) => g.rules.flatMap((r) => r.findings.map((f) => f.finding_id)))).toEqual(['a'])
  })

  it('puts the backlog first and the decided groups after it', () => {
    const groups = groupUnmapped([
      finding({ finding_id: 'a', unmapped_reason: 'hygiene' }),
      finding({ finding_id: 'b', rule_id: 'CKV_AWS_999', unmapped_reason: 'unreviewed' }),
      finding({ finding_id: 'c', rule_id: 'AZU-0058', source: 'trivy', unmapped_reason: 'no-control' }),
      finding({ finding_id: 'd', rule_id: 'CKV_K8S_1' }),
    ])

    expect(groups.map((g) => g.reason)).toEqual(['unreviewed', 'not-examined', 'no-control', 'hygiene'])
  })

  it('reads a raw finding with no tag as never examined, not as reviewed', () => {
    // A GitHub run maps only the PR's changed files; the rest stay raw with
    // no verdict, and must not be counted with rules someone has judged.
    const [group] = groupUnmapped([finding({ finding_id: 'a' })])

    expect(group.reason).toBe('not-examined')
  })

  it('collapses one rule across files into one row, worst severity first', () => {
    const [group] = groupUnmapped([
      finding({ finding_id: 'a', file: 'b.json', severity: 'LOW', unmapped_reason: 'no-control' }),
      finding({ finding_id: 'b', file: 'a.json', severity: 'HIGH', unmapped_reason: 'no-control' }),
      finding({ finding_id: 'c', file: 'a.json', severity: 'LOW', unmapped_reason: 'no-control' }),
      finding({
        finding_id: 'd',
        rule_id: 'CKV_AZURE_206',
        severity: 'MEDIUM',
        unmapped_reason: 'no-control',
      }),
    ])

    expect(group.finding_count).toBe(4)
    expect(group.rules.map((r) => r.rule_id)).toEqual(['CKV_AZURE_43', 'CKV_AZURE_206'])
    const [first] = group.rules
    expect(first.severity).toBe('HIGH')
    expect(first.file_count).toBe(2)
    expect(first.findings.map((f) => f.file)).toEqual(['a.json', 'a.json', 'b.json'])
  })

  it('keeps the same rule id from two scanners apart', () => {
    const [group] = groupUnmapped([
      finding({ finding_id: 'a', rule_id: 'X-1', source: 'trivy', unmapped_reason: 'hygiene' }),
      finding({ finding_id: 'b', rule_id: 'X-1', source: 'checkov', unmapped_reason: 'hygiene' }),
    ])

    expect(group.rules).toHaveLength(2)
  })
})

describe('mappedShare', () => {
  it('counts everything that is not raw as mapped', () => {
    expect(
      mappedShare([
        finding({ finding_id: 'a' }),
        finding({ finding_id: 'b', status: 'mapped' }),
        finding({ finding_id: 'c', status: 'resolved' }),
        finding({ finding_id: 'd', status: 'superseded' }),
      ]),
    ).toBe(0.75)
  })

  it('is null for a PR with no findings, not 0%', () => {
    expect(mappedShare([])).toBeNull()
  })
})
