import { describe, expect, it } from 'vitest'
import type { Finding } from '../types/finding'
import { cdkSource, isCdk } from './cdk'

const base: Finding = {
  pk: 'PR#p', sk: 'FINDING#1', finding_id: '1', source: 'checkov', rule_id: 'CKV_AWS_24',
  file: 'infra/cdk.out/Stack.template.json', status: 'mapped', target_type: 'cdk',
}

describe('cdkSource', () => {
  it('is the source line that made the resource', () => {
    expect(cdkSource({ ...base, origin: { file: 'infra/lib/network.ts', line: 8 } })).toBe('infra/lib/network.ts:8')
  })

  it('is null without a line, or for any other target type', () => {
    expect(cdkSource({ ...base, origin: { file: null, line: null } })).toBeNull()
    expect(cdkSource({ ...base, origin: null })).toBeNull()
    expect(cdkSource({ ...base, target_type: 'cloudformation', origin: { file: 'a.ts', line: 1 } })).toBeNull()
    expect(isCdk({ target_type: 'terraform' })).toBe(false)
  })
})
