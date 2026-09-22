/** Languages only one of the two scanners parses.
 *
 *  The self-check proves a fix by rescanning the corrected file and comparing
 *  (source, rule_id) counts. For these target types that comparison has one
 *  source rather than two -- weaker than a two-tool check, but not broken
 *  (docs/multi-iac-spec.md §4).
 *
 *  Bicep because Trivy has no Bicep scanner at all; OpenTofu because checkov
 *  will not open a `.tofu` file, which is the same situation with the tools
 *  the other way round. Both were measured, not assumed (multi-iac-spec §2,
 *  §6 step 1).
 *
 *  This exists because §4 says the caveat "should be said in the UI, not
 *  discovered". Until now OpenTofu's identical caveat was recorded only in
 *  corpus/eval/README.md, where no reviewer would ever meet it. */
export const SINGLE_SOURCE_TARGETS: Record<string, string> = {
  bicep: 'checkov',
  opentofu: 'Trivy',
}

/** The one scanner that covers this target type, or undefined when both do. */
export function singleSourceTool(targetType?: string | null): string | undefined {
  if (!targetType) return undefined
  return SINGLE_SOURCE_TARGETS[targetType]
}

/** What to put on a badge's `title` for a single-source target. */
export function singleSourceTitle(targetType: string, tool: string): string {
  return (
    `Trivy and checkov do not both parse ${targetType}, so the rescan compared ` +
    `${tool}'s findings alone. Weaker than a two-tool check, not absent.`
  )
}
