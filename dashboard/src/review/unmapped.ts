import type { Finding, UnmappedReason } from '../types/finding'

/** Findings the scanner reported that no control was mapped to.
 *
 *  They are not hidden (corpus/README.md: "the scanner reported something,
 *  we are not hiding it, and we are not pretending we can fix it"), but they
 *  are not review work either: remediation never touches a raw finding. So
 *  they are kept out of the main table and the status cards and shown here,
 *  grouped by why they are unmapped and then by rule -- one row per rule,
 *  because 100 findings of one rule are one decision, not 100.
 *
 *  Only `unreviewed` is a backlog. The other reasons were decided in
 *  corpus/rule_mappings.json's `unmapped` section, and `not-examined` means
 *  the mapping stage left no verdict: a GitHub run maps only the files its
 *  PR changed, a mapping that failed or was refused is retried rather than
 *  tagged, and records written before the tag existed carry none. */
export type UnmappedGroupReason = UnmappedReason | 'not-examined'

export const REASON_ORDER: UnmappedGroupReason[] = [
  'unreviewed',
  'not-examined',
  'no-control',
  'not-fixable',
  'hygiene',
]

export const REASON_LABELS: Record<UnmappedGroupReason, string> = {
  unreviewed: 'Not yet reviewed',
  'not-examined': 'Not examined',
  'no-control': 'No control in the loaded frameworks',
  'not-fixable': 'Cannot be fixed in the file',
  hygiene: 'Hygiene, not a security control',
}

export const REASON_DESCRIPTIONS: Record<UnmappedGroupReason, string> = {
  unreviewed:
    'Nobody has judged these rules yet. Each is either a mapping waiting to be written or ' +
    'a decision to record in the corpus; this is the only group that is a backlog.',
  'not-examined':
    'The mapping stage has not settled these: they are outside the files this PR changed, ' +
    'their mapping failed and will be retried on the next run, or they were scanned before ' +
    'unmapped findings were tagged.',
  'no-control':
    'Real advice, but no loaded framework has a control these violate. Mapping them anyway ' +
    'would cite a control for something it does not say. Loading a framework that covers them ' +
    'is what moves them.',
  'not-fixable':
    'No edit to the file can clear these with the current scanners, so a fix would be drafted, ' +
    'fail its self-check and be drafted again on every run.',
  hygiene: 'Conventions and tidiness, such as names and descriptions, rather than exposure.',
}

const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 }

function rank(severity?: string): number {
  return SEVERITY_RANK[severity?.toLowerCase() ?? ''] ?? 4
}

export interface UnmappedRule {
  key: string
  source: string
  rule_id: string
  title?: string
  /** The worst severity among this rule's findings. */
  severity?: string
  file_count: number
  findings: Finding[]
}

export interface UnmappedGroup {
  reason: UnmappedGroupReason
  finding_count: number
  rules: UnmappedRule[]
}

export function isUnmapped(finding: Finding): boolean {
  return finding.status === 'raw'
}

/** Group raw findings by reason, then by (source, rule_id). Groups follow
 *  REASON_ORDER, and within one the rules run worst severity first, then by
 *  how many findings they carry. Empty groups are left out. */
export function groupUnmapped(findings: Finding[]): UnmappedGroup[] {
  const byReason = new Map<UnmappedGroupReason, Map<string, Finding[]>>()
  for (const f of findings) {
    if (!isUnmapped(f)) continue
    const reason: UnmappedGroupReason = f.unmapped_reason ?? 'not-examined'
    const key = `${f.source}:${f.rule_id}`
    const rules = byReason.get(reason) ?? new Map<string, Finding[]>()
    rules.set(key, [...(rules.get(key) ?? []), f])
    byReason.set(reason, rules)
  }

  return REASON_ORDER.filter((r) => byReason.has(r)).map((reason) => {
    const rules = [...byReason.get(reason)!.entries()].map(([key, fs]): UnmappedRule => {
      const worst = fs.reduce((a, b) => (rank(b.severity) < rank(a.severity) ? b : a))
      return {
        key,
        source: fs[0].source,
        rule_id: fs[0].rule_id,
        title: fs.find((f) => f.title)?.title,
        severity: worst.severity,
        file_count: new Set(fs.map((f) => f.file)).size,
        findings: fs.slice().sort((a, b) => a.file.localeCompare(b.file)),
      }
    })
    rules.sort(
      (a, b) =>
        rank(a.severity) - rank(b.severity) ||
        b.findings.length - a.findings.length ||
        a.key.localeCompare(b.key),
    )
    return {
      reason,
      finding_count: rules.reduce((n, r) => n + r.findings.length, 0),
      rules,
    }
  })
}

/** Share of findings with a control: everything not raw. Null when there
 *  are no findings, so a clean PR does not read as 0% covered. */
export function mappedShare(findings: Finding[]): number | null {
  if (findings.length === 0) return null
  return findings.filter((f) => !isUnmapped(f)).length / findings.length
}
