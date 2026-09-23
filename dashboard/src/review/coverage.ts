/** Languages only one scanner parses.
 *
 *  The self-check proves a fix by rescanning the corrected file and comparing
 *  (source, rule_id) counts. For these target types that comparison has one
 *  source rather than two -- weaker than a two-tool check, but not broken
 *  (docs/multi-iac-spec.md §4).
 *
 *  OpenTofu, because checkov will not open a `.tofu` file and Trivy is left
 *  carrying it alone (multi-iac-spec §6 step 1).
 *
 *  Bicep was here too until 2026-09-23, on the grounds that Trivy has no
 *  Bicep scanner. Adding KICS -- which parses `.bicep` natively -- gave it a
 *  second source, so the caveat stopped being true and the entry is gone
 *  rather than left to mislead. That is what keeping this list in one place
 *  is for: when a language stops being single-source, exactly one thing has
 *  to change.
 *
 *  This exists because §4 says the caveat "should be said in the UI, not
 *  discovered". Before this file, OpenTofu's caveat was recorded only in
 *  corpus/eval/README.md, where no reviewer would ever meet it. */
export const SINGLE_SOURCE_TARGETS: Record<string, string> = {
  opentofu: 'Trivy',
}

/** The one scanner that covers this target type, or undefined when more than
 *  one does. */
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
