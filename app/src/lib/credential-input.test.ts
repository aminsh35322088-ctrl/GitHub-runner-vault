import { describe, expect, test } from 'vitest'
import { normalizeCredentialName } from './credential-input.ts'

describe('credential name normalization', () => {
  test('turns a human label into a stable environment-variable name', () => {
    expect(normalizeCredentialName('Cloudflare API Token')).toBe('CLOUDFLARE_API_TOKEN')
    expect(normalizeCredentialName(' GitHub--Fine Grained PAT ')).toBe('GITHUB_FINE_GRAINED_PAT')
  })

  test('limits names to the supported database length and rejects names without a letter prefix', () => {
    expect(normalizeCredentialName('x'.repeat(100))).toBe('X'.repeat(64))
    expect(normalizeCredentialName('123 token')).toBe('TOKEN')
    expect(normalizeCredentialName('')).toBe('')
  })
})
