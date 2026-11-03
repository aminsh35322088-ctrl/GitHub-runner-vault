import { describe, expect, test, vi } from 'vitest'
import { validateWithServiceAdapter } from './service-adapter-validation.ts'
import { serviceAdapterFor, serviceAdapterFromDocument, type ServiceAdapter } from './service-adapter.ts'

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

describe('built-in CLI adapter mappings', () => {
  test('maps Cloudflare tokens to Wrangler through its documented API base URL override', () => {
    const adapter = serviceAdapterFor('Cloudflare')
    expect(adapter?.cliTools).toContainEqual(expect.objectContaining({
      id: 'wrangler', binary: 'wrangler', integration: 'base-url-env',
      variable: 'CLOUDFLARE_API_BASE_URL', tokenVariable: 'CLOUDFLARE_API_TOKEN',
    }))
  })

  test('configures Cloudflare token verification from its documented endpoint and maps all explicit token states', async () => {
    const cloudflare = serviceAdapterFor('Cloudflare')!
    expect(cloudflare.validation).toMatchObject({
      method: 'GET', path: '/user/tokens/verify', successPointer: '/result/status',
      successValue: 'active', invalidValues: ['disabled', 'expired'],
    })

    const token = 'cloudflare-test-token-that-must-not-leak'
    const activeFetch = vi.fn<typeof fetch>().mockResolvedValue(json({
      success: true, result: { id: 'provider-token-id', status: 'active' },
    }))
    const active = await validateWithServiceAdapter('Cloudflare', token, cloudflare, ['api.cloudflare.com'], activeFetch, 1234)
    expect(active).toMatchObject({ status: 'valid', identity: 'provider-token-id', checkedAt: 1234 })
    expect(activeFetch).toHaveBeenCalledWith('https://api.cloudflare.com/client/v4/user/tokens/verify', expect.objectContaining({ method: 'GET', redirect: 'manual' }))
    expect(JSON.stringify(active)).not.toContain(token)

    for (const status of ['disabled', 'expired']) {
      const fetchFn = vi.fn<typeof fetch>().mockResolvedValue(json({ success: true, result: { id: 'provider-token-id', status } }))
      const report = await validateWithServiceAdapter('Cloudflare', token, cloudflare, ['api.cloudflare.com'], fetchFn)
      expect(report.status).toBe('invalid')
    }
  })

  test('retains the documented Northflank token environment variable', () => {
    const adapter = serviceAdapterFor('Northflank')
    expect(adapter?.cliTools).toContainEqual(expect.objectContaining({
      id: 'northflank', variable: 'NF_API_BASE_URL', tokenVariable: 'NF_API_TOKEN',
    }))
  })

  test('loads a token variable only from the reviewed credential document field', () => {
    const adapter = serviceAdapterFromDocument({
      service_adapter: {
        api_base_url: 'https://api.custom.dev',
        auth_header: 'Authorization',
        auth_scheme: 'Bearer',
        validation: { method: 'GET', path: '/verify', success_pointer: '/status', success_value: 'ok', invalid_values: ['revoked', 'expired'] },
        cli_tools: [{
          id: 'custom-cli', label: 'Custom CLI', binary: 'custom',
          integration: 'base-url-env', variable: 'CUSTOM_API_BASE_URL',
          token_variable: 'CUSTOM_API_TOKEN', setup_hint: 'Use the local bridge.',
        }],
      },
    })
    expect(adapter?.cliTools[0]).toMatchObject({
      id: 'custom-cli', variable: 'CUSTOM_API_BASE_URL', tokenVariable: 'CUSTOM_API_TOKEN',
    })
    expect(adapter?.validation).toMatchObject({ successPointer: '/status', successValue: 'ok', invalidValues: ['revoked', 'expired'] })
  })
})

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
