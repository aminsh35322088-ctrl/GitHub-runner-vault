import { beforeEach, describe, expect, test } from 'vitest'
import { getDb, schema } from 'db'
import { app } from './app.tsx'
import { newSetupState, resetVaultKeyCache, SETUP_STATE_COOKIE } from './lib/vault-config.ts'

const ORIGIN = 'https://vault.test'

const req = (method: string, path: string, cookie?: string) =>
  app.handle(new Request(`${ORIGIN}${path}`, { method, redirect: 'manual', headers: cookie ? { cookie } : {} }))

beforeEach(async () => {
  resetVaultKeyCache()
  await getDb().delete(schema.vaultSetting)
})

describe('first-time setup flow', () => {
  test('starting setup hands the browser a state cookie and a form that posts the manifest to GitHub', async () => {
    const res = await req('POST', '/setup/start')
    expect(res.status).toBe(200)
    const setCookie = res.headers.get('set-cookie')!
    expect(setCookie).toMatch(/HttpOnly/i)
    expect(setCookie).toMatch(/Secure/i)
    expect(setCookie).toMatch(/SameSite=Lax/i)
    const state = new RegExp(`${SETUP_STATE_COOKIE}=([A-Za-z0-9_-]+)`).exec(setCookie)![1]!
    const html = await res.text()
    expect(html).toContain(`action="https://github.com/settings/apps/new?state=${state}"`)
    expect(html).toContain('&quot;public&quot;:false')
    expect(html).not.toContain('<script>alert')
    expect(res.headers.get('cache-control')).toBe('no-store')
  })

  test('the callback refuses a missing cookie, a forged state and a replayed state', async () => {
    const state = newSetupState()
    const noCookie = await req('GET', `/setup/github/callback?code=abcdefgh12&state=${state}`)
    expect(noCookie.headers.get('location')).toContain('/setup?error=github')
    const forged = await req('GET', '/setup/github/callback?code=abcdefgh12&state=forgedforgedforgedforgedforged', `${SETUP_STATE_COOKIE}=${state}`)
    expect(forged.headers.get('location')).toContain('/setup?error=github')
    expect((await getDb().select().from(schema.vaultSetting)).map((r) => r.key)).not.toContain('owner_github_id')
  })

  test('a failed GitHub exchange leaves the vault unconfigured and claimable', async () => {
    const state = newSetupState()
    // Outbound fetches fail in tests, as GitHub would for a bad or reused code.
    const res = await req('GET', `/setup/github/callback?code=abcdefgh12&state=${state}`, `${SETUP_STATE_COOKIE}=${state}`)
    expect(res.headers.get('location')).toContain('/setup?error=github')
    const keys = (await getDb().select().from(schema.vaultSetting)).map((r) => r.key)
    expect(keys).not.toContain('owner_github_id')
    expect(keys).not.toContain('github_client_secret')
  })
})
