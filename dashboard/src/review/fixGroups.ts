import type { Finding } from '../types/finding'

/** Drafted fixes grouped by what they fix: the control, on the kind of file.
 *
 *  Why this exists: Terraform findings cluster in a few files, Kubernetes
 *  findings repeat across many. On PugetScope one securityContext edit is
 *  drafted fourteen times, once per Deployment, and the reviewer would make
 *  the same decision fourteen times (docs/multi-iac-spec.md §5). The pipeline
 *  is deliberately left drafting every one -- the self-check is per file and
 *  each diff is verified on its own file -- and the repetition is collapsed
 *  here instead, where the attention is spent.
 *
 *  Keyed on (target_type, framework, control_id), not on rule_id: the same
 *  control is reached by a Trivy rule and a checkov rule, and grouping by
 *  rule would show the reviewer the same securityContext fix twice. */
export interface FixGroup {
  key: string
  target_type: string
  framework: string
  control_id: string
  findings: Finding[]
  /** Distinct files the group's fixes touch. */
  file_count: number
}

/** Findings with a drafted fix behind them. Superseded, not-drafted and
 *  resolved ones have nothing to approve; raw and mapped ones nothing yet. */
export const DRAFTED_STATUSES = new Set<Finding['status']>(['fix-proposed', 'needs-human-only'])

function groupKeyOf(finding: Finding): Pick<FixGroup, 'key' | 'target_type' | 'framework' | 'control_id'> {
  const target_type = finding.target_type ?? 'unknown'
  const mapping = finding.control_mappings?.[0]
  // A drafted fix always has a mapping (remediation only touches mapped
  // findings), but a record from before control_mappings was written this
  // way should still land somewhere visible rather than vanish.
  const framework = mapping?.framework ?? finding.source
  const control_id = mapping?.control_id ?? finding.rule_id
  return { key: `${target_type}|${framework}:${control_id}`, target_type, framework, control_id }
}

export function groupFixes(findings: Finding[]): FixGroup[] {
  const groups = new Map<string, FixGroup>()
  for (const finding of findings) {
    if (!DRAFTED_STATUSES.has(finding.status)) continue
    const id = groupKeyOf(finding)
    let group = groups.get(id.key)
    if (!group) {
      group = { ...id, findings: [], file_count: 0 }
      groups.set(id.key, group)
    }
    group.findings.push(finding)
  }
  for (const group of groups.values()) {
    group.file_count = new Set(group.findings.map((f) => f.file)).size
    group.findings.sort((a, b) => a.file.localeCompare(b.file) || a.rule_id.localeCompare(b.rule_id))
  }
  // Most repeated first: that is the group where one decision saves the most.
  return Array.from(groups.values()).sort(
    (a, b) => b.file_count - a.file_count || b.findings.length - a.findings.length || a.key.localeCompare(b.key),
  )
}

/** A fix the group action may approve on the reviewer's behalf: drafted,
 *  scanner-verified, and not held for anything. A needs-human-only fix is in
 *  the group so the reviewer sees it, but is never approved in bulk -- it is
 *  held because it deletes something or rests on a claim, and that is a
 *  per-fix judgement by construction. */
export function isBulkApprovable(finding: Finding): boolean {
  return (
    finding.status === 'fix-proposed' &&
    finding.proposed_fix?.self_check_passed === true &&
    !finding.proposed_fix.scan_errors?.length
  )
}
