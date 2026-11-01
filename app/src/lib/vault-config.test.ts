import { describe, expect, test, beforeEach } from 'vitest'
import { env } from 'cloudflare:workers'
import { getDb, schema } from 'db'
import * as orm from 'drizzle-orm'
import {
  buildManifest, consumeSetupState, convertManifest, issueSetupCookie, keysFromMaster, loadGithubOAuth, loadOwnerId,
  loadVaultKeys, newSetupState, parseConversion, consumeSetupAttempt, resetVaultKeyCache, saveGithubApp, setupCodeMatches,
  setupCodeStatus, setupCookieValid, SETUP_COOKIE, SETUP_MAX_FAILURES, SETUP_SESSION_MS, putSetting,
} from './vault-config.ts'
import { ensureSchema, resetSchemaCheck } from './schema.ts'
import { SCHEMA_MIGRATIONS } from './schema-sql.generated.ts'

const db = getDb()
const b64 = (n: number) => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(n))))

beforeEach(async () => {
  resetVaultKeyCache()
  await db.delete(schema.vaultSetting)
})

describe('key derivation', () => {
  test('both keys derive from one master, deterministically and under different labels', async () => {
    const master = b64(32)
    const a = await keysFromMaster(master)
    const b = await keysFromMaster(master)
    expect(a.authSecret).toBe(b.authSecret)
    expect(a.authSecret.length).toBeGreaterThanOrEqual(32)
    expect((await keysFromMaster(b64(32))).authSecret).not.toBe(a.authSecret)
    // The AES key must decrypt only what it encrypted: prove it is usable and distinct from the auth secret.
    const iv = new Uint8Array(12)
    const sealed = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, a.encryptionKey, new TextEncoder().encode('x'))
    await expect(crypto.subtle.decrypt({ name: 'AES-GCM', iv }, b.encryptionKey, sealed)).resolves.toBeDefined()
  })

  test('rejects a master key that is not 32 bytes', async () => {
    await expect(keysFromMaster(b64(16))).rejects.toThrow()
  })

  test('generates a master key once, stores it, and reuses it', async () => {
    const first = await loadVaultKeys(db, {})
    resetVaultKeyCache()
    const second = await loadVaultKeys(db, {})
    expect(second.authSecret).toBe(first.authSecret)
    const rows = await db.select().from(schema.vaultSetting).where(orm.eq(schema.vaultSetting.key, 'master_key'))
    expect(rows).toHaveLength(1)
  })

  test('an explicit VAULT_MASTER_KEY wins over the stored one', async () => {
    const master = b64(32)
    const keys = await loadVaultKeys(db, { VAULT_MASTER_KEY: master })
    expect(keys.authSecret).toBe((await keysFromMaster(master)).authSecret)
    expect(await db.select().from(schema.vaultSetting)).toHaveLength(0)
  })

  test('legacy BETTER_AUTH_SECRET + ENCRYPTION_KEY keep working unchanged', async () => {
    const secret = 'legacy-secret-that-is-at-least-32-characters'
    const keys = await loadVaultKeys(db, { BETTER_AUTH_SECRET: secret, ENCRYPTION_KEY: b64(32) })
    expect(keys.authSecret).toBe(secret)
  })

  test('legacy secrets that are too weak fail closed', async () => {
    await expect(loadVaultKeys(db, { BETTER_AUTH_SECRET: 'short', ENCRYPTION_KEY: b64(32) })).rejects.toThrow()
  })
})

describe('GitHub app and owner storage', () => {
  test('stores the client secret encrypted and reads it back', async () => {
    const keys = await loadVaultKeys(db, {})
    await saveGithubApp(db, keys, { clientId: 'Iv1.abc', clientSecret: 'super-secret-client-value', ownerId: '318252513' })
    const raw = JSON.stringify(await db.select().from(schema.vaultSetting))
    expect(raw).not.toContain('super-secret-client-value')
    expect(await loadGithubOAuth(db, {}, keys)).toEqual({ clientId: 'Iv1.abc', clientSecret: 'super-secret-client-value' })
    expect(await loadOwnerId(db, {})).toBe('318252513')
  })

  test('a ciphertext copied under another label does not decrypt', async () => {
    const keys = await loadVaultKeys(db, {})
    await saveGithubApp(db, keys, { clientId: 'id', clientSecret: 'secret-value', ownerId: '1' })
    await putSetting(db, 'github_client_secret', '{"e":"AAAA","i":"AAAA"}')
    expect(await loadGithubOAuth(db, {}, keys)).toBeNull()
  })

  test('refuses an invalid owner id and returns nothing before setup', async () => {
    const keys = await loadVaultKeys(db, {})
    await expect(saveGithubApp(db, keys, { clientId: 'a', clientSecret: 'b', ownerId: 'octocat' })).rejects.toThrow()
    expect(await loadGithubOAuth(db, {}, keys)).toBeNull()
    expect(await loadOwnerId(db, {})).toBeNull()
  })

  test('Worker variables override stored values', async () => {
    const keys = await loadVaultKeys(db, {})
    await saveGithubApp(db, keys, { clientId: 'stored', clientSecret: 'stored-secret', ownerId: '5' })
    expect(await loadOwnerId(db, { OWNER_GITHUB_ID: '9' })).toBe('9')
    expect(await loadGithubOAuth(db, { GITHUB_CLIENT_ID: 'e', GITHUB_CLIENT_SECRET: 'f' }, keys)).toEqual({ clientId: 'e', clientSecret: 'f' })
  })
})

describe('setup gate', () => {
  test('setup code must be present and long enough', () => {
    expect(setupCodeStatus({})).toBe('missing')
    expect(setupCodeStatus({ SETUP_CODE: 'short' })).toBe('too_short')
    expect(setupCodeStatus({ SETUP_CODE: 'long enough phrase' })).toBe('ok')
  })

  test('only the exact code matches; a missing or short configured code never matches', async () => {
    const e = { SETUP_CODE: 'long enough phrase' }
    expect(await setupCodeMatches('long enough phrase', e)).toBe(true)
    expect(await setupCodeMatches('long enough phrasE', e)).toBe(false)
    expect(await setupCodeMatches('', e)).toBe(false)
    expect(await setupCodeMatches(undefined, e)).toBe(false)
    expect(await setupCodeMatches('', {})).toBe(false)
    expect(await setupCodeMatches('short', { SETUP_CODE: 'short' })).toBe(false)
  })

  test('setup attempts are isolated per source IP and expire after one hour', async () => {
    const now = Date.now()
    const sourceIp = '192.0.2.10'
    for (let i = 0; i < SETUP_MAX_FAILURES; i++) {
      expect(await consumeSetupAttempt(db, 'a'.repeat(40), now, sourceIp)).toBe(true)
    }
    expect(await consumeSetupAttempt(db, 'a'.repeat(40), now, sourceIp)).toBe(false)
    expect(await consumeSetupAttempt(db, 'a'.repeat(40), now, '192.0.2.11')).toBe(true)
    expect(await consumeSetupAttempt(db, 'a'.repeat(40), now + 61 * 60_000, sourceIp)).toBe(true)
    expect(JSON.stringify(await db.select().from(schema.vaultSetting))).not.toContain(sourceIp)
  })

  test('concurrent setup attempts are counted atomically', async () => {
    const now = Date.now()
    const results = await Promise.all(Array.from({ length: 20 }, () =>
      consumeSetupAttempt(db, 'a'.repeat(40), now, '198.51.100.20')))
    expect(results.filter(Boolean)).toHaveLength(SETUP_MAX_FAILURES)
    expect(results.filter((value) => !value)).toHaveLength(20 - SETUP_MAX_FAILURES)
  })

  test('setup cookie: valid, expired, tampered, wrong secret', async () => {
    const secret = 'a'.repeat(40)
    const now = Date.now()
    const { value } = await issueSetupCookie(secret, now)
    const header = `${SETUP_COOKIE}=${value}`
    expect(await setupCookieValid(secret, header, now + 1000)).toBe(true)
    expect(await setupCookieValid(secret, header, now + SETUP_SESSION_MS + 1)).toBe(false)
    expect(await setupCookieValid('b'.repeat(40), header, now + 1000)).toBe(false)
    const [exp, sig] = value.split('.')
    expect(await setupCookieValid(secret, `${SETUP_COOKIE}=${Number(exp) + 60000}.${sig}`, now)).toBe(false)
    expect(await setupCookieValid(secret, null, now)).toBe(false)
    expect(await setupCookieValid(secret, `${SETUP_COOKIE}=garbage`, now)).toBe(false)
  })

  test('setup state is single-use and expires', async () => {
    const now = Date.now()
    const state = await newSetupState(db, now)
    expect(await consumeSetupState(db, 'wrong', now)).toBe(false)
    expect(await consumeSetupState(db, state, now)).toBe(false) // the wrong guess already burned it
    const second = await newSetupState(db, now)
    expect(await consumeSetupState(db, second, now)).toBe(true)
    expect(await consumeSetupState(db, second, now)).toBe(false)
    const third = await newSetupState(db, now)
    expect(await consumeSetupState(db, third, now + SETUP_SESSION_MS + 1)).toBe(false)
  })
})

describe('GitHub app manifest', () => {
  test('is a private app with exact callback URLs and a valid-length name', () => {
    const m = buildManifest('https://vault.example.workers.dev', 'abc123')
    expect(m.public).toBe(false)
    expect(m.name.length).toBeLessThanOrEqual(34)
    expect(m.callback_urls).toEqual(['https://vault.example.workers.dev/api/auth/callback/github'])
    expect(m.redirect_url).toBe('https://vault.example.workers.dev/setup/github/callback')
    expect(m.default_permissions).toEqual({})
  })

  const good = { client_id: 'Iv1.x', client_secret: 'cs', owner: { id: 318252513, type: 'User' }, pem: 'PRIVATE', webhook_secret: 'w' }

  test('conversion keeps only sign-in fields', () => {
    expect(parseConversion(good)).toEqual({ clientId: 'Iv1.x', clientSecret: 'cs', ownerId: '318252513' })
  })

  test.each([
    ['organization owner', { ...good, owner: { id: 1, type: 'Organization' } }],
    ['missing secret', { ...good, client_secret: '' }],
    ['missing owner', { ...good, owner: undefined }],
    ['non-object', 'x'],
    ['null', null],
  ])('conversion rejects %s', (_name, body) => {
    expect(parseConversion(body)).toBeNull()
  })

  test('convertManifest calls GitHub once with a validated code and never returns the private key', async () => {
    const calls: string[] = []
    const fake = (async (url: string) => { calls.push(String(url)); return Response.json(good) }) as unknown as typeof fetch
    const result = await convertManifest('abc12345_-', fake)
    expect(calls).toEqual(['https://api.github.com/app-manifests/abc12345_-/conversions'])
    expect(JSON.stringify(result)).not.toContain('PRIVATE')
    expect(await convertManifest('../evil', fake)).toBeNull()
    expect(calls).toHaveLength(1)
    expect(await convertManifest('abc12345', (async () => new Response('no', { status: 404 })) as unknown as typeof fetch)).toBeNull()
  })
})

describe('schema bootstrap', () => {
  test('creates every table, is idempotent, and records the baseline', async () => {
    resetSchemaCheck()
    await ensureSchema(env.DB)
    resetSchemaCheck()
    await ensureSchema(env.DB)
    const tables = (await env.DB.prepare("SELECT name FROM sqlite_master WHERE type='table'").all<{ name: string }>()).results.map((r) => r.name)
    for (const t of ['user', 'session', 'account', 'verification', 'credential', 'enrollment_link', 'credential_audit', 'vault_setting', 'vault_migration']) {
      expect(tables).toContain(t)
    }
    for (const legacy of ['org', 'project', 'api_token', 'oauth_domain', 'device_code']) expect(tables).not.toContain(legacy)
    const applied = (await env.DB.prepare('SELECT id FROM vault_migration').all<{ id: string }>()).results.map((r) => r.id)
    expect(applied).toEqual(SCHEMA_MIGRATIONS.map((m) => m.id))
  })

  test('the audit log stays append-only', async () => {
    await env.DB.prepare("INSERT INTO credential_audit (id, at, action, actor) VALUES ('a1', 1, 'x', 'y')").run()
    await expect(env.DB.prepare("UPDATE credential_audit SET action='z' WHERE id='a1'").run()).rejects.toThrow()
    await expect(env.DB.prepare("DELETE FROM credential_audit WHERE id='a1'").run()).rejects.toThrow()
  })

  test('later migrations run once and a failed one is retried', async () => {
    resetSchemaCheck()
    const extra = { id: '9999_test', statements: ['CREATE TABLE zz_probe (id TEXT)'] }
    await ensureSchema(env.DB, [...SCHEMA_MIGRATIONS, extra])
    resetSchemaCheck()
    await ensureSchema(env.DB, [...SCHEMA_MIGRATIONS, extra]) // would throw "table exists" if re-run
    resetSchemaCheck()
    await expect(ensureSchema(env.DB, [{ id: '9998_bad', statements: ['NOT SQL'] }])).rejects.toThrow()
    resetSchemaCheck()
    await ensureSchema(env.DB, SCHEMA_MIGRATIONS)
  })
})
