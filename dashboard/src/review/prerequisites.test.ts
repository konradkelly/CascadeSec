import { describe, expect, it } from 'vitest'
import type { Finding, FindingStatus } from '../types/finding'
import { findUnmetPrerequisites } from './prerequisites'

const DIFF = '--- a/main.tf\n+++ b/main.tf\n@@ -1 +1 @@\n-x\n+y\n'

function finding(id: string, status: FindingStatus, diff?: string): Finding {
  return {
    pk: 'PR#pr-1', sk: `FINDING#${id}`, finding_id: id,
    source: 'trivy', rule_id: 'AWS-0132', file: 'main.tf', status,
    proposed_fix: diff === undefined ? null : { diff },
  }
}

async function sha(text: string) {
  const { createHash } = await import('node:crypto')
  return createHash('sha256').update(text).digest('hex')
}

describe('findUnmetPrerequisites', () => {
  // The page's copy of the fix-chain check. review-api runs the real one
  // and 409s regardless; this is the affordance that explains a disabled
  // Accept before the reviewer clicks it.

  it('is satisfied by a resolved prerequisite whose diff still hashes the same', async () => {
    const byId = new Map([['f1', finding('f1', 'resolved', DIFF)]])

    expect(await findUnmetPrerequisites([{ finding_id: 'f1', diff_sha256: await sha(DIFF) }], byId)).toEqual([])
  })

  it('is satisfied by an empty chain', async () => {
    expect(await findUnmetPrerequisites([], new Map())).toEqual([])
  })

  it('reports a prerequisite that no longer exists', async () => {
    expect(await findUnmetPrerequisites([{ finding_id: 'gone', diff_sha256: 'x' }], new Map())).toEqual([
      { finding_id: 'gone', reason: 'missing' },
    ])
  })

  it('reports a prerequisite not yet accepted, and cannot tell that from rejected', async () => {
    // The page has each prerequisite's status but not its event log. A
    // rejection and a decision never made both read as "unresolved" here;
    // the server can tell them apart, and does.
    for (const status of ['mapped', 'fix-proposed', 'rejected', 'needs-human-only'] as FindingStatus[]) {
      const byId = new Map([['f1', finding('f1', status, DIFF)]])
      expect(await findUnmetPrerequisites([{ finding_id: 'f1', diff_sha256: await sha(DIFF) }], byId)).toEqual([
        { finding_id: 'f1', reason: 'unresolved' },
      ])
    }
  })

  it('reports a resolved prerequisite whose diff was edited since', async () => {
    // Accepted, but a reviewer then edited the diff this fix was drafted
    // on. This fix's patch may no longer apply, so it must be looked at.
    const byId = new Map([['f1', finding('f1', 'resolved', DIFF + '+extra\n')]])

    expect(await findUnmetPrerequisites([{ finding_id: 'f1', diff_sha256: await sha(DIFF) }], byId)).toEqual([
      { finding_id: 'f1', reason: 'stale' },
    ])
  })

  it('reports a resolved prerequisite that has lost its diff', async () => {
    const byId = new Map([['f1', finding('f1', 'resolved')]])

    expect(await findUnmetPrerequisites([{ finding_id: 'f1', diff_sha256: await sha(DIFF) }], byId)).toEqual([
      { finding_id: 'f1', reason: 'stale' },
    ])
  })

  it('reports a prerequisite recorded without a hash as unverifiable', async () => {
    // Chain entries were bare id strings before hashes were carried. Those
    // can be looked up but not checked; the reason says so rather than
    // passing them or calling them stale.
    const byId = new Map([['f1', finding('f1', 'resolved', DIFF)]])

    expect(await findUnmetPrerequisites(['f1' as never], byId)).toEqual([{ finding_id: 'f1', reason: 'unverifiable' }])
    expect(await findUnmetPrerequisites([{ finding_id: 'f1' }], byId)).toEqual([
      { finding_id: 'f1', reason: 'unverifiable' },
    ])
  })

  it('checks status before the hash, so an unresolved prerequisite is not also called stale', async () => {
    const byId = new Map([['f1', finding('f1', 'mapped', 'something else')]])

    expect(await findUnmetPrerequisites([{ finding_id: 'f1', diff_sha256: await sha(DIFF) }], byId)).toEqual([
      { finding_id: 'f1', reason: 'unresolved' },
    ])
  })

  it('reports every unmet entry in a chain, in order', async () => {
    const byId = new Map([
      ['ok', finding('ok', 'resolved', DIFF)],
      ['pending', finding('pending', 'fix-proposed', DIFF)],
    ])
    const chain = [
      { finding_id: 'ok', diff_sha256: await sha(DIFF) },
      { finding_id: 'pending', diff_sha256: await sha(DIFF) },
      { finding_id: 'gone', diff_sha256: 'x' },
    ]

    expect(await findUnmetPrerequisites(chain, byId)).toEqual([
      { finding_id: 'pending', reason: 'unresolved' },
      { finding_id: 'gone', reason: 'missing' },
    ])
  })
})
