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

describe('deployment-bound first-time setup', () => {
  test('setup remains locked until the deployment workflow provisions OWNER_GITHUB_ID', async () => {
    const page = await req('GET', '/setup')
    expect(page.status).toBe(200)
    expect(await page.text()).toContain('Waiting for deployment verification')

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
