import { beforeEach, describe, expect, test } from 'vitest'
import { getDb, schema } from 'db'
import { app } from './app.tsx'
import { newSetupState, resetVaultKeyCache, SETUP_STATE_COOKIE } from './lib/vault-config.ts'

const ORIGIN = 'https://vault.test'

const req = (method: string, path: string, cookie?: string) =>
  app.handle(new Request(`${ORIGIN}${path}`, { method, redirect: 'manual', headers: { accept: 'text/html', ...(cookie ? { cookie } : {}) } }))

beforeEach(async () => {
  resetVaultKeyCache()
  await getDb().delete(schema.vaultSetting)
})

describe('security headers and sign-out', () => {
  // First full-page SSR render in this file pays the cold-start cost, so it
  // gets more than the default 5s test budget.
  test('page responses carry the baseline security headers', async () => {
    const res = await req('GET', '/login')
    expect(res.status).toBe(200)
    const csp = res.headers.get('content-security-policy') ?? ''
    expect(csp).toContain("default-src 'self'")
    expect(csp).toContain("frame-ancestors 'none'")
    expect(csp).toContain("form-action 'self'")
    expect(res.headers.get('x-content-type-options')).toBe('nosniff')
    expect(res.headers.get('referrer-policy')).toBe('no-referrer')
    expect(res.headers.get('x-frame-options')).toBe('DENY')
  }, 30_000)

  test('runner API responses carry the headers too', async () => {
    const res = await req('GET', '/api/runner/registry')
    expect(res.headers.get('x-content-type-options')).toBe('nosniff')
    expect(res.headers.get('x-frame-options')).toBe('DENY')
  })

  test('GET /logout no longer clears the session', async () => {
    const res = await req('GET', '/logout')
    expect(res.status).toBe(405)
    expect(res.headers.get('allow')).toBe('POST')
    expect(res.headers.get('set-cookie')).toBeNull()
    expect(res.headers.get('location')).toBeNull()
  })

  test('POST /logout still redirects to the login page', async () => {
    const res = await req('POST', '/logout')
    expect(res.status).toBe(302)
    expect(res.headers.get('location')).toContain('/login')
  })
})


describe('deployment-bound first-time setup', () => {
  test('setup start remains locked until Workers Builds provisions OWNER_GITHUB_ID', async () => {
    const start = await req('POST', '/setup/start')
    expect(start.status).toBe(303)
    expect(start.headers.get('location')).toContain('/setup?error=provisioning')
    expect(start.headers.get('set-cookie')).toBeNull()
  })

  test('the GitHub callback cannot claim ownership before deployment identity is provisioned', async () => {
    const state = newSetupState()
    const res = await req(
      'GET',
      `/setup/github/callback?code=abcdefgh12&state=${state}`,
      `${SETUP_STATE_COOKIE}=${state}`,
    )
    expect(res.status).toBe(303)
    expect(res.headers.get('location')).toContain('/setup?error=provisioning')
    const keys = (await getDb().select().from(schema.vaultSetting)).map((r) => r.key)
    expect(keys).not.toContain('owner_github_id')
    expect(keys).not.toContain('github_client_secret')
  })
})
