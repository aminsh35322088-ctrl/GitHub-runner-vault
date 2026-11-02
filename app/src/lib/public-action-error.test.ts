import { describe, expect, test } from 'vitest'
import { z } from 'zod'
import { publicCredentialActionError } from './public-action-error.ts'

describe('credential action error serialization', () => {
  test('preserves provider verification messages instead of redacting them behind a generic server-action error', () => {
    expect(publicCredentialActionError(new Error('توکن GitHub نامعتبر یا منقضی است.')))
      .toBe('توکن GitHub نامعتبر یا منقضی است.')
  })

  test('preserves safe domain error codes returned by the credential service', () => {
    expect(publicCredentialActionError(new Error('invalid_hosts: only hostnames are allowed'))).toBe('invalid_hosts: only hostnames are allowed')
    expect(publicCredentialActionError(new Error('exists'))).toBe('exists')
  })

  test('maps schema issues to a field-level message without exposing raw input', () => {
    const error = z.object({ value: z.string().min(1) }).safeParse({ value: '' })
    if (error.success) throw new Error('test setup failed')
    expect(publicCredentialActionError(error.error)).toBe('مقدار توکن خالی یا دارای قالب نامعتبر است.')
  })

  test('does not leak database, stack or arbitrary exception messages', () => {
    expect(publicCredentialActionError(new Error('D1_ERROR: SQL query failed with secret value'))).toBe('internal_error')
    expect(publicCredentialActionError(new Error('/home/runner/app/src/file.ts: unexpected'))).toBe('internal_error')
  })
})
