import { describe, expect, it } from 'vitest'
import type { Finding } from '../types/finding'
import { groupFixes, isBulkApprovable } from './fixGroups'

function finding(overrides: Partial<Finding> & { finding_id: string }): Finding {
  return {
    pk: 'PR#p',
    sk: `FINDING#${overrides.finding_id}`,
    source: 'trivy',
    rule_id: 'KSV-0118',
    file: 'k8s/base/api-deployment.yaml',
    status: 'fix-proposed',
    target_type: 'kubernetes',
    control_mappings: [{ framework: 'CIS-Kubernetes-2.0', control_id: '5.6.3' }],
    proposed_fix: { diff: '+x', self_check_passed: true },
    ...overrides,
  }
}

describe('groupFixes', () => {
  it('collapses the same control across files and across the two scanners', () => {
    // PugetScope's shape: one securityContext fix per Deployment, reached by
    // a Trivy rule and a checkov rule that map to the same control.
    const groups = groupFixes([
      finding({ finding_id: 'a', file: 'k8s/base/api-deployment.yaml' }),
      finding({ finding_id: 'b', file: 'k8s/base/api-deployment.yaml', source: 'checkov', rule_id: 'CKV_K8S_29' }),
      finding({ finding_id: 'c', file: 'k8s/base/frontend-deployment.yaml' }),
    ])

    expect(groups).toHaveLength(1)
    expect(groups[0].key).toBe('kubernetes|CIS-Kubernetes-2.0:5.6.3')
    expect(groups[0].file_count).toBe(2)
    // Ordered by file, then rule id within a file.
    expect(groups[0].findings.map((f) => f.finding_id)).toEqual(['b', 'a', 'c'])
  })

  it('keeps the same control on different target types apart', () => {
    // A Terraform fix and a Kubernetes fix are never the same diff, whatever
    // control they cite; the reviewer cannot approve one on the strength of
    // the other.
    const groups = groupFixes([
      finding({ finding_id: 'a' }),
      finding({ finding_id: 'b', target_type: 'terraform', file: 'main.tf' }),
    ])

    expect(groups.map((g) => g.key).sort()).toEqual([
      'kubernetes|CIS-Kubernetes-2.0:5.6.3',
      'terraform|CIS-Kubernetes-2.0:5.6.3',
    ])
  })

  it('only groups findings that have a drafted fix', () => {
    const groups = groupFixes([
      finding({ finding_id: 'drafted' }),
      finding({ finding_id: 'held', status: 'needs-human-only' }),
      finding({ finding_id: 'sup', status: 'superseded' }),
      finding({ finding_id: 'nd', status: 'not-drafted' }),
      finding({ finding_id: 'mapped', status: 'mapped' }),
      finding({ finding_id: 'done', status: 'resolved' }),
    ])

    expect(groups[0].findings.map((f) => f.finding_id)).toEqual(['drafted', 'held'])
  })

  it('puts the most repeated group first', () => {
    const groups = groupFixes([
      finding({ finding_id: 'a', control_mappings: [{ framework: 'F', control_id: 'once' }] }),
      finding({ finding_id: 'b', file: 'one.yaml' }),
      finding({ finding_id: 'c', file: 'two.yaml' }),
    ])

    expect(groups.map((g) => g.control_id)).toEqual(['5.6.3', 'once'])
  })

  it('lands an unmapped record under its rule rather than dropping it', () => {
    const [group] = groupFixes([finding({ finding_id: 'a', control_mappings: undefined })])

    expect(group.framework).toBe('trivy')
    expect(group.control_id).toBe('KSV-0118')
  })
})

describe('isBulkApprovable', () => {
  it('is only a scanner-verified fix-proposed fix', () => {
    expect(isBulkApprovable(finding({ finding_id: 'ok' }))).toBe(true)
    expect(isBulkApprovable(finding({ finding_id: 'held', status: 'needs-human-only' }))).toBe(false)
    expect(
      isBulkApprovable(finding({ finding_id: 'unverified', proposed_fix: { diff: '+x', self_check_passed: false } })),
    ).toBe(false)
    expect(
      isBulkApprovable(
        finding({
          finding_id: 'unparsed',
          proposed_fix: { diff: '+x', self_check_passed: true, scan_errors: ['bad.yaml'] },
        }),
      ),
    ).toBe(false)
  })
})
