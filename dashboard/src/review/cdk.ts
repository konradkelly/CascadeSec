import type { Finding } from '../types/finding'

/** A finding on a template the sandbox synthesized from a CDK app
 *  (docs/sandbox-spec.md §9 step 2). Its `file` is the template, which
 *  nobody wrote; where it belongs is the source line in `origin`. */
export function isCdk(finding: Pick<Finding, 'target_type'>): boolean {
  return finding.target_type === 'cdk'
}

/** `lib/network.ts:8`, or null when the app's metadata named no line. */
export function cdkSource(finding: Finding): string | null {
  const origin = finding.origin
  if (!isCdk(finding) || !origin?.file || origin.line == null) return null
  return `${origin.file}:${origin.line}`
}

export const CDK_EXPLAINER =
  'Found in a template synthesized from a CDK app. Its fix is drafted in the app’s source, ' +
  'the file that made the resource, and verified by synthesizing the app again and rescanning.'
