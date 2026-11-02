import { describe, expect, test, vi } from 'vitest'
import { validateWithServiceAdapter } from './service-adapter-validation.ts'
import type { ServiceAdapter } from './service-adapter.ts'

const adapter: ServiceAdapter = {
  apiBaseUrl: 'https://api.example.com/v1',
  authHeader: 'Authorization',
  authScheme: 'Bearer',
  validation: {
    method: 'GET',
    path: '/me',
    identityPointer: '/user/name',
    permissionsPointer: '/permissions',
  },
  cliTools: [],
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
}

describe('service adapter validation', () => {
  test('uses only the allowed HTTPS host and does not put the token in its report', async () => {
    const fetchFn = vi.fn<typeof fetch>().mockResolvedValue(json({
      user: { name: 'automation-user' },
      permissions: ['projects:read', 'deployments:read'],
    }))
    const token = 'very-secret-token-value'
    const report = await validateWithServiceAdapter('Example', token, adapter, ['api.example.com'], fetchFn, 1234)

    expect(report).toMatchObject({
      provider: 'Example',
      status: 'valid',
      identity: 'automation-user',
      permissionsComplete: true,
      permissionSource: 'service-adapter',
      checkedAt: 1234,
    })
    expect(report.permissions.map((permission) => permission.name)).toEqual(['projects:read', 'deployments:read'])
    expect(fetchFn).toHaveBeenCalledTimes(1)
    const [url, init] = fetchFn.mock.calls[0]!
    expect(url).toBe('https://api.example.com/v1/me')
    expect(init).toMatchObject({ method: 'GET', redirect: 'manual' })
    expect(new Headers(init?.headers).get('authorization')).toBe(`Bearer ${token}`)
    expect(JSON.stringify(report)).not.toContain(token)
  })

  test('fails closed when the adapter host is not in the credential allow-list', async () => {
    const fetchFn = vi.fn<typeof fetch>()
    const report = await validateWithServiceAdapter('Example', 'secret-value', adapter, ['other.example.com'], fetchFn)
    expect(report.status).toBe('unsupported')
    expect(fetchFn).not.toHaveBeenCalled()
  })

  test.each([
    [401, 'invalid'],
    [403, 'insufficient_permissions'],
    [429, 'unavailable'],
    [503, 'unavailable'],
    [302, 'unavailable'],
  ] as const)('maps HTTP %s to %s without following redirects', async (status, expected) => {
    const fetchFn = vi.fn<typeof fetch>().mockResolvedValue(new Response('', {
      status,
      headers: status === 302 ? { location: 'https://attacker.example/collect' } : {},
    }))
    const report = await validateWithServiceAdapter('Example', 'secret-value', adapter, ['api.example.com'], fetchFn)
    expect(report.status).toBe(expected)
    expect(fetchFn).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ redirect: 'manual' }))
  })

  test.each([
    [{ ok: false, error: 'invalid_auth' }, 'invalid'],
    [{ ok: false, error: 'missing_scope' }, 'insufficient_permissions'],
    [{ ok: false, error: 'internal_error' }, 'unavailable'],
    [{ ok: false }, 'unavailable'],
  ] as const)('maps provider success marker response %j to %s', async (body, expected) => {
    const slack: ServiceAdapter = {
      apiBaseUrl: 'https://slack.com',
      authHeader: 'Authorization',
      authScheme: 'Bearer',
      validation: { method: 'GET', path: '/api/auth.test', successPointer: '/ok', successValue: true },
      cliTools: [],
    }
    const rejected = vi.fn<typeof fetch>().mockResolvedValue(json(body))
    const report = await validateWithServiceAdapter('Slack', 'secret-value', slack, ['slack.com'], rejected)
    expect(report.status).toBe(expected)
  })

  test('does not infer validity when a required success marker cannot be read', async () => {
    const slack: ServiceAdapter = {
      apiBaseUrl: 'https://slack.com',
      authHeader: 'Authorization',
      authScheme: 'Bearer',
      validation: { method: 'GET', path: '/api/auth.test', successPointer: '/ok', successValue: true },
      cliTools: [],
    }
    const report = await validateWithServiceAdapter('Slack', 'secret-value', slack, ['slack.com'], vi.fn().mockResolvedValue(new Response('not-json')))
    expect(report.status).toBe('unavailable')
  })

  test('does not misreport network errors as invalid tokens', async () => {
    const report = await validateWithServiceAdapter('Example', 'secret-value', adapter, ['api.example.com'], vi.fn().mockRejectedValue(new Error('offline')))
    expect(report.status).toBe('unavailable')
  })

  test('keeps an adapter without a validation endpoint explicitly unsupported', async () => {
    const noCheck: ServiceAdapter = { ...adapter, validation: undefined }
    const fetchFn = vi.fn<typeof fetch>()
    const report = await validateWithServiceAdapter('Example', 'secret-value', noCheck, ['api.example.com'], fetchFn)
    expect(report.status).toBe('unsupported')
    expect(fetchFn).not.toHaveBeenCalled()
  })
})
