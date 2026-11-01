import { beforeEach, describe, expect, test } from 'vitest'
import { getDb, schema } from 'db'
import { app } from './app.tsx'
import { consumeSetupState, newSetupState, resetVaultKeyCache, SETUP_MAX_FAILURES } from './lib/vault-config.ts'

const ORIGIN = 'https://vault.test'
const CODE = 'correct horse battery staple'

const req = (method: string, path: string, init: { form?: Record<string, string>; cookie?: string; ip?: string } = {}) =>
  app.handle(new Request(`${ORIGIN}${path}`, {
    method,
    redirect: 'manual',
    headers: {
      ...(init.cookie ? { cookie: init.cookie } : {}),
      ...(init.ip ? { 'cf-connecting-ip': init.ip } : {}),
      ...(init.form ? { 'Content-Type': 'application/x-www-form-urlencoded' } : {}),
    },
    body: init.form ? new URLSearchParams(init.form).toString() : undefined,
  }))

const cookieFrom = (res: Response) => (res.headers.get('set-cookie') ?? '').split(';')[0]!

beforeEach(async () => {
  resetVaultKeyCache()
  await getDb().delete(schema.vaultSetting)
})

describe('first-time setup flow', () => {
  test('a wrong code is refused with no cookie; the right code sets a locked-down cookie', async () => {
    const bad = await req('POST', '/setup/unlock', { form: { code: 'nope nope nope nope' } })
    expect(bad.status).toBe(303)
    expect(bad.headers.get('location')).toContain('/setup?error=code')
    expect(bad.headers.get('set-cookie')).toBeNull()

    const good = await req('POST', '/setup/unlock', { form: { code: CODE } })
    expect(good.status).toBe(303)
    const setCookie = good.headers.get('set-cookie')!
    expect(setCookie).toMatch(/HttpOnly/i)
    expect(setCookie).toMatch(/Secure/i)
    expect(setCookie).toMatch(/SameSite=Lax/i)
    expect(setCookie).toMatch(/Max-Age=1800/)
  })

  test('setup lockout is per source IP and does not lock out another owner', async () => {
    for (let i = 0; i < SETUP_MAX_FAILURES; i++) await req('POST', '/setup/unlock', { ip: '192.0.2.30', form: { code: 'wrong wrong wrong' } })
    const blocked = await req('POST', '/setup/unlock', { ip: '192.0.2.30', form: { code: CODE } })
    expect(blocked.headers.get('location')).toContain('error=locked')
    expect(blocked.headers.get('set-cookie')).toBeNull()
    const otherIp = await req('POST', '/setup/unlock', { ip: '192.0.2.31', form: { code: CODE } })
    expect(otherIp.headers.get('location')).toBe(`${ORIGIN}/setup`)
    expect(otherIp.headers.get('set-cookie')).toContain('HttpOnly')
  })

  test('the GitHub callback does nothing without the setup cookie', async () => {
    const state = await newSetupState(getDb(), Date.now())
    const res = await req('GET', `/setup/github/callback?code=abcdefgh12&state=${state}`)
    expect(res.headers.get('location')).toBe(`${ORIGIN}/setup`)
    // Without the cookie the state is not even consumed.
    expect(await consumeSetupState(getDb(), state, Date.now())).toBe(true)
  })

  test('the callback rejects a forged state and burns the real one', async () => {
    const cookie = cookieFrom(await req('POST', '/setup/unlock', { form: { code: CODE } }))
    const state = await newSetupState(getDb(), Date.now())
    const forged = await req('GET', '/setup/github/callback?code=abcdefgh12&state=forged', { cookie })
    expect(forged.headers.get('location')).toContain('/setup?error=github')
    expect(await consumeSetupState(getDb(), state, Date.now())).toBe(false)
    expect((await getDb().select().from(schema.vaultSetting)).map((r) => r.key)).not.toContain('owner_github_id')
  })

  test('a failed GitHub exchange leaves the vault unconfigured', async () => {
    const cookie = cookieFrom(await req('POST', '/setup/unlock', { form: { code: CODE } }))
    const state = await newSetupState(getDb(), Date.now())
    // Outbound fetches fail in tests, as GitHub would for a bad or reused code.
    const res = await req('GET', `/setup/github/callback?code=abcdefgh12&state=${state}`, { cookie })
    expect(res.headers.get('location')).toContain('/setup?error=github')
    const keys = (await getDb().select().from(schema.vaultSetting)).map((r) => r.key)
    expect(keys).not.toContain('owner_github_id')
    expect(keys).not.toContain('github_client_secret')
  })
})
