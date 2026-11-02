import { describe, expect, test, vi } from 'vitest'
import { validateProviderToken } from './credential-validation.ts'

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } })
}

describe('provider token validation', () => {
  test('identifies a GitHub classic PAT and reports its granted OAuth scopes', async () => {
    const fetchFn = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(
      { login: 'aminsh', id: 123 },
      200,
      { 'x-oauth-scopes': 'repo, workflow, read:org' },
    ))
    const report = await validateProviderToken('GitHub', 'ghp_example_secret_value', fetchFn, 1234)
    expect(report).toMatchObject({
      provider: 'GitHub',
      status: 'valid',
      identity: '@aminsh',
      tokenType: 'classic',
      permissionsComplete: true,
      permissions: [
        { name: 'repo', access: 'granted' },
        { name: 'workflow', access: 'granted' },
        { name: 'read:org', access: 'granted' },
      ],
      checkedAt: 1234,
    })
    expect(JSON.stringify(report)).not.toContain('ghp_example_secret_value')
    expect(fetchFn).toHaveBeenCalledWith('https://api.github.com/user', expect.objectContaining({
      headers: expect.any(Headers),
    }))
  })

  test('recognizes a valid GitHub fine-grained PAT without inventing a complete permission list', async () => {
    const fetchFn = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ login: 'aminsh', id: 123 }))
      .mockResolvedValueOnce(jsonResponse([{ id: 1, full_name: 'aminsh/private-repo' }]))
    const report = await validateProviderToken('GitHub', 'github_pat_example_secret_value', fetchFn, 5678)
    expect(report).toMatchObject({
      status: 'valid',
      identity: '@aminsh',
      tokenType: 'fine-grained',
      permissionsComplete: false,
      permissionSource: 'capability-probe',
    })
    expect(report.permissions).toContainEqual({ name: 'Repository list', access: 'available' })
  })

  test('validates GitHub App installation tokens through installation repositories rather than the user endpoint', async () => {
    const fetchFn = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({
      total_count: 1,
      repositories: [{ full_name: 'aminsh/app-repo', permissions: { contents: true, metadata: true, administration: false } }],
    }))
    const report = await validateProviderToken('GitHub', 'ghs_installation_secret_value', fetchFn, 321)
    expect(report).toMatchObject({
      status: 'valid',
      identity: 'GitHub App installation',
      tokenType: 'GitHub App installation token',
      permissionsComplete: false,
      permissions: [
        { name: 'Repository contents', access: 'granted', scope: 'aminsh/app-repo' },
        { name: 'Repository metadata', access: 'granted', scope: 'aminsh/app-repo' },
      ],
    })
    expect(JSON.stringify(report)).not.toContain('ghs_installation_secret_value')
    expect(fetchFn).toHaveBeenCalledWith('https://api.github.com/installation/repositories?per_page=50', expect.any(Object))
  })

  test('rejects an invalid GitHub token from an authentication 401', async () => {
    const fetchFn = vi.fn<typeof fetch>().mockResolvedValue(new Response('', { status: 401 }))
    const report = await validateProviderToken('GitHub', 'ghp_invalid_secret_value', fetchFn, 1)
    expect(report).toMatchObject({ status: 'invalid', message: expect.stringContaining('نامعتبر') })
  })

  test('does not mark GitHub rate limiting as an invalid token', async () => {
    const fetchFn = vi.fn<typeof fetch>().mockResolvedValue(new Response('', {
      status: 403, headers: { 'x-ratelimit-remaining': '0' },
    }))
    const report = await validateProviderToken('GitHub', 'ghp_valid_secret_value', fetchFn, 1)
    expect(report.status).toBe('unavailable')
  })

  test('verifies an active Cloudflare token and reads its assigned permission policies', async () => {
    const fetchFn = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ success: true, result: { id: 'token-id', status: 'active' } }))
      .mockResolvedValueOnce(jsonResponse({
        success: true,
        result: {
          name: 'Vault token',
          policies: [{
            effect: 'allow',
            permission_groups: [{ id: 'workers-read', name: 'Workers Scripts Read', meta: { scopes: 'com.cloudflare.api.account' } }],
            resources: { 'com.cloudflare.api.account.123': '*' },
          }],
        },
      }))
    const report = await validateProviderToken('Cloudflare', 'cfut_example_secret_value', fetchFn, 9876)
    expect(report).toMatchObject({
      status: 'valid',
      identity: 'Vault token',
      tokenType: 'User API Token',
      permissionsComplete: true,
      permissions: [{ name: 'Workers Scripts Read', access: 'allow', scope: 'com.cloudflare.api.account' }],
    })
    expect(JSON.stringify(report)).not.toContain('cfut_example_secret_value')
    expect(fetchFn).toHaveBeenNthCalledWith(1, 'https://api.cloudflare.com/client/v4/user/tokens/verify', expect.any(Object))
    expect(fetchFn).toHaveBeenNthCalledWith(2, 'https://api.cloudflare.com/client/v4/user/tokens/token-id', expect.any(Object))
  })

  test('uses an explicitly supplied Cloudflare account ID when an account token cannot list accounts', async () => {
    const fetchFn = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ success: true, result: { id: 'token-id', status: 'active' } }))
      .mockResolvedValueOnce(jsonResponse({
        success: true,
        result: { name: 'Account token', policies: [{ effect: 'allow', permission_groups: [{ name: 'Workers Scripts Read' }] }] },
      }))
    const report = await validateProviderToken('Cloudflare', 'cfat_account_secret_value', fetchFn, 9, '0123456789abcdef0123456789abcdef')
    expect(report).toMatchObject({ status: 'valid', tokenType: 'Account API Token', permissions: [{ name: 'Workers Scripts Read', access: 'allow' }] })
    expect(fetchFn).toHaveBeenNthCalledWith(1, 'https://api.cloudflare.com/client/v4/accounts/0123456789abcdef0123456789abcdef/tokens/verify', expect.any(Object))
    expect(fetchFn).toHaveBeenNthCalledWith(2, 'https://api.cloudflare.com/client/v4/accounts/0123456789abcdef0123456789abcdef/tokens/token-id', expect.any(Object))
  })

  test('recognizes an account-owned Cloudflare API token and inspects its account-scoped policies', async () => {
    const fetchFn = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ success: true, result: [{ id: '0123456789abcdef0123456789abcdef', name: 'Production' }] }))
      .mockResolvedValueOnce(jsonResponse({ success: true, result: { id: 'token-id', status: 'active' } }))
      .mockResolvedValueOnce(jsonResponse({
        success: true,
        result: {
          name: 'Account deploy token',
          policies: [{
            effect: 'allow',
            permission_groups: [{ id: 'workers-edit', name: 'Workers Scripts Write', meta: { scopes: 'com.cloudflare.api.account' } }],
            resources: { 'com.cloudflare.api.account.account-id': '*' },
          }],
        },
      }))
    const report = await validateProviderToken('Cloudflare', 'cfat_account_secret_value', fetchFn, 9877)
    expect(report).toMatchObject({
      status: 'valid',
      identity: 'Account deploy token · Production',
      tokenType: 'Account API Token',
      permissionsComplete: true,
      permissions: [{ name: 'Workers Scripts Write', access: 'allow', scope: 'com.cloudflare.api.account' }],
    })
    expect(JSON.stringify(report)).not.toContain('cfat_account_secret_value')
    expect(fetchFn).toHaveBeenNthCalledWith(1, 'https://api.cloudflare.com/client/v4/accounts?page=1&per_page=50', expect.any(Object))
    expect(fetchFn).toHaveBeenNthCalledWith(2, 'https://api.cloudflare.com/client/v4/accounts/0123456789abcdef0123456789abcdef/tokens/verify', expect.any(Object))
    expect(fetchFn).toHaveBeenNthCalledWith(3, 'https://api.cloudflare.com/client/v4/accounts/0123456789abcdef0123456789abcdef/tokens/token-id', expect.any(Object))
  })

  test('routes cfat_ tokens to the Account API without calling the User Token endpoint', async () => {
    const fetchFn = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ success: true, result: { id: 'token-id', status: 'active' } }))
      .mockResolvedValueOnce(jsonResponse({ success: true, result: { name: 'Account token', policies: [] } }))
    const report = await validateProviderToken('Cloudflare', 'cfat_account_secret_value', fetchFn, 11, '0123456789abcdef0123456789abcdef')
    expect(report).toMatchObject({ status: 'valid', tokenType: 'Account API Token' })
    expect(fetchFn).toHaveBeenCalledTimes(2)
    expect(fetchFn).toHaveBeenNthCalledWith(1, 'https://api.cloudflare.com/client/v4/accounts/0123456789abcdef0123456789abcdef/tokens/verify', expect.any(Object))
  })

  test('rejects Cloudflare Global API Keys with a precise explanation instead of treating them as API Tokens', async () => {
    const fetchFn = vi.fn<typeof fetch>()
    const report = await validateProviderToken('Cloudflare', 'cfk_global_key_secret_value', fetchFn, 12)
    expect(report).toMatchObject({ status: 'invalid', tokenType: 'Global API Key', message: expect.stringContaining('Global API Key') })
    expect(fetchFn).not.toHaveBeenCalled()
  })

  test('does not mislabel an account token as invalid when the account cannot be discovered', async () => {
    const fetchFn = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ success: true, result: [] }))
    const report = await validateProviderToken('Cloudflare', 'cfat_account_secret_value', fetchFn, 10)
    expect(report).toMatchObject({
      status: 'unavailable',
      message: expect.stringContaining('شناسه ۳۲ کاراکتری Account'),
    })
  })

  test('keeps an active Cloudflare token valid when its own permissions cannot be inspected', async () => {
    const fetchFn = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ success: true, result: { id: 'token-id', status: 'active' } }))
      .mockResolvedValueOnce(new Response('', { status: 403 }))
    const report = await validateProviderToken('Cloudflare', 'cfut_valid_secret_value', fetchFn, 1)
    expect(report).toMatchObject({
      status: 'valid',
      permissionsComplete: false,
      permissionSource: 'not-readable',
    })
  })

  test('rejects a disabled Cloudflare token', async () => {
    const fetchFn = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({
      success: true, result: { id: 'token-id', status: 'disabled' },
    }))
    const report = await validateProviderToken('Cloudflare', 'cfut_disabled_secret_value', fetchFn, 1)
    expect(report.status).toBe('invalid')
  })

  test('reports network failures as unavailable and supports unknown providers without false validation', async () => {
    const network = await validateProviderToken('GitHub', 'github_pat_secret_value', vi.fn<typeof fetch>().mockRejectedValue(new Error('offline')), 1)
    const other = await validateProviderToken('Custom API', 'custom-secret-value', fetch, 2)
    expect(network.status).toBe('unavailable')
    expect(other.status).toBe('unsupported')
  })
})
