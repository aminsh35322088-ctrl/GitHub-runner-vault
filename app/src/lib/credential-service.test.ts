import { describe, expect, test } from 'vitest'
import { getDb, schema } from 'db'
import * as orm from 'drizzle-orm'
import { importEncryptionKey } from './credential-crypto.ts'
import {
  deleteCredential, getCredentialForOwner, listCredentialsForOwner, listRegistryForRunner,
  readCredentialValue, registerExternallyManaged, requestRegistration, setEnabled, setVisibility,
  storeCredentialValue, MAX_TEMPORARY_MS,
} from './credential-service.ts'
import { consumeEnrollmentLink, peekEnrollmentLink } from './enrollment.ts'

const KEY_B64 = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))
const SECRET = 'cfut_SUPERSECRETVALUE_123456789'
const HOUR = 3600_000

const doc = {
  overview: 'Needed to deploy a Worker.',
  task: 'Deploy a Worker',
  token_type: 'API token',
  creation_steps: ['Open the dashboard'],
  required_permissions: [{ name: 'Workers Scripts', level: 'Edit', why: 'Deploying uploads a script' }],
  unnecessary_permissions: ['DNS'],
  security_notes: ['Set an expiry'],
  expiration_guidance: ['7 days'],
  official_documentation_links: [{ title: 'Wrangler', url: 'https://developers.cloudflare.com/workers/wrangler/' }],
  verification: 'verified',
}

let counter = 0
function uniqueName(prefix = 'CF') {
  counter += 1
  return `${prefix}_${Date.now().toString(36).toUpperCase()}_${counter}_${Math.floor(Math.random() * 1e6)}`
}

async function setup() {
  const db = getDb()
  const key = await importEncryptionKey(KEY_B64)
  const now = Date.now()
  return { db, key, now }
}

async function activeCredential(opts: Partial<Parameters<typeof storeCredentialValue>[2]> = {}) {
  const { db, key, now } = await setup()
  const name = uniqueName()
  const req = await requestRegistration(db, { name, service: 'Cloudflare', purpose: 'Deploy', doc, requestedBy: 'runner:test', now })
  if (!req.ok) throw new Error(`setup failed: ${req.error}`)
  const stored = await storeCredentialValue(db, key, {
    credentialId: req.value.credentialId, value: SECRET, lifetime: 'permanent', expiresAt: null, visible: true,
    delivery: 'proxy', allowedHosts: ['api.cloudflare.com'], now, ...opts,
  })
  if (!stored.ok) throw new Error(`store failed: ${stored.error}`)
  return { db, key, now, name, id: req.value.credentialId }
}

describe('registration requests', () => {
  test('create a pending, hidden entry with docs and a one-time link', async () => {
    const { db, now } = await setup()
    const name = uniqueName()
    const result = await requestRegistration(db, { name, service: 'Cloudflare', purpose: 'Deploy', doc, requestedBy: 'runner:1', now })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    const row = await getCredentialForOwner(db, result.value.credentialId)
    expect(row).toMatchObject({ status: 'pending', visible: false, hasValue: false, name })
    expect(row?.doc?.task).toBe('Deploy a Worker')
    expect(await peekEnrollmentLink(db, result.value.link.token, now)).not.toBeNull()
    // A model-created entry is never visible to runners until the owner activates it.
    expect((await listRegistryForRunner(db, now)).some((c) => c.name === name)).toBe(false)
  })

  test.each([['lowercase'], ['1BAD'], ['A']])('rejects invalid name %s', async (name) => {
    const { db, now } = await setup()
    const result = await requestRegistration(db, { name, service: 's', purpose: 'p', doc, requestedBy: 'r', now })
    expect(result).toMatchObject({ ok: false, error: 'invalid_name' })
  })

  test.each(['PATH', 'LD_PRELOAD', 'NODE_OPTIONS', 'HTTPS_PROXY'])('rejects reserved name %s', async (name) => {
    const { db, now } = await setup()
    expect(await requestRegistration(db, { name, service: 's', purpose: 'p', doc, requestedBy: 'r', now })).toMatchObject({ ok: false, error: 'reserved_name' })
  })

  test('rejects an invalid document and creates nothing', async () => {
    const { db, now } = await setup()
    const name = uniqueName()
    const result = await requestRegistration(db, { name, service: 's', purpose: 'p', doc: { ...doc, html: '<b>' }, requestedBy: 'r', now })
    expect(result).toMatchObject({ ok: false, error: 'invalid_doc' })
    expect(await db.select().from(schema.credential).where(orm.eq(schema.credential.name, name))).toHaveLength(0)
  })

  test('a second request for a pending entry reuses it and supersedes the old link', async () => {
    const { db, now } = await setup()
    const name = uniqueName()
    const a = await requestRegistration(db, { name, service: 's', purpose: 'p', doc, requestedBy: 'r', now })
    const b = await requestRegistration(db, { name, service: 's', purpose: 'p2', doc, requestedBy: 'r', now })
    if (!a.ok || !b.ok) throw new Error('unexpected')
    expect(b.value.credentialId).toBe(a.value.credentialId)
    expect(await peekEnrollmentLink(db, a.value.link.token, now)).toBeNull()
    expect(await peekEnrollmentLink(db, b.value.link.token, now)).not.toBeNull()
  })

  test('a model cannot re-request an entry that already exists', async () => {
    const { db, now, name } = await activeCredential()
    expect(await requestRegistration(db, { name, service: 's', purpose: 'p', doc, requestedBy: 'r', now })).toMatchObject({ ok: false, error: 'exists' })
  })

  test('the registration request is audited by the worker', async () => {
    const { db, now } = await setup()
    const name = uniqueName()
    await requestRegistration(db, { name, service: 's', purpose: 'p', doc, requestedBy: 'runner:abc', now })
    const rows = await db.select().from(schema.credentialAudit).where(orm.eq(schema.credentialAudit.credentialName, name))
    expect(rows.map((r) => r.action)).toContain('registration_requested')
    expect(rows[0]?.actor).toBe('runner:abc')
  })
})

describe('storing a value', () => {
  test('encrypts at rest and never exposes the value in any listing', async () => {
    const { db, id, now, name } = await activeCredential()
    const [raw] = await db.select({ enc: schema.credential.valueEncrypted, iv: schema.credential.valueIv }).from(schema.credential).where(orm.eq(schema.credential.id, id))
    expect(raw?.enc).toBeTruthy()
    expect(raw?.enc).not.toContain('SUPERSECRET')
    const everything = JSON.stringify([
      await listCredentialsForOwner(db),
      await getCredentialForOwner(db, id),
      await listRegistryForRunner(db, now),
    ])
    expect(everything).not.toContain('SUPERSECRET')
    expect(everything).not.toContain(raw!.enc!)
    expect(everything).toContain(name)
  })

  test('the owner view reports only whether a value exists', async () => {
    const { db, id } = await activeCredential()
    const row = await getCredentialForOwner(db, id)
    expect(row?.hasValue).toBe(true)
    expect(Object.keys(row!)).not.toContain('valueEncrypted')
    expect(Object.keys(row!)).not.toContain('valueIv')
  })

  test('proxy delivery needs at least one allowed host', async () => {
    const { db, key, now } = await setup()
    const req = await requestRegistration(db, { name: uniqueName(), service: 's', purpose: 'p', doc, requestedBy: 'r', now })
    if (!req.ok) throw new Error('unexpected')
    const base = { credentialId: req.value.credentialId, value: SECRET, lifetime: 'permanent' as const, expiresAt: null, visible: true, now }
    expect(await storeCredentialValue(db, key, { ...base, delivery: 'proxy', allowedHosts: [] })).toMatchObject({ ok: false, error: 'hosts_required' })
    expect(await storeCredentialValue(db, key, { ...base, delivery: 'proxy', allowedHosts: ['127.0.0.1'] })).toMatchObject({ ok: false, error: 'invalid_hosts' })
    expect(await storeCredentialValue(db, key, { ...base, delivery: 'proxy', allowedHosts: ['*.cloudflare.com'] })).toMatchObject({ ok: false, error: 'invalid_hosts' })
    expect(await storeCredentialValue(db, key, { ...base, delivery: 'inject', allowedHosts: [] })).toMatchObject({ ok: true })
  })

  test.each(['', '   ', 'line1\nline2', 'nul\u0000byte', 'x'.repeat(9000)])('rejects an invalid value', async (value) => {
    const { db, key, now } = await setup()
    const req = await requestRegistration(db, { name: uniqueName(), service: 's', purpose: 'p', doc, requestedBy: 'r', now })
    if (!req.ok) throw new Error('unexpected')
    const result = await storeCredentialValue(db, key, { credentialId: req.value.credentialId, value, lifetime: 'permanent', expiresAt: null, visible: true, delivery: 'inject', allowedHosts: [], now })
    expect(result).toMatchObject({ ok: false, error: 'invalid_value' })
  })

  test('temporary credentials always expire and never after 24 hours', async () => {
    const { db, key, now } = await setup()
    const req = await requestRegistration(db, { name: uniqueName(), service: 's', purpose: 'p', doc, requestedBy: 'r', now })
    if (!req.ok) throw new Error('unexpected')
    const base = { credentialId: req.value.credentialId, value: SECRET, lifetime: 'temporary' as const, visible: true, delivery: 'inject' as const, allowedHosts: [], now }
    expect(await storeCredentialValue(db, key, { ...base, expiresAt: now + MAX_TEMPORARY_MS + 1 })).toMatchObject({ ok: false, error: 'invalid_expiry' })
    expect(await storeCredentialValue(db, key, { ...base, expiresAt: now - 1 })).toMatchObject({ ok: false, error: 'invalid_expiry' })
    expect(await storeCredentialValue(db, key, { ...base, expiresAt: null })).toMatchObject({ ok: true })
    const row = await getCredentialForOwner(db, req.value.credentialId)
    expect(row?.expiresAt).toBe(now + MAX_TEMPORARY_MS)
  })

  test('storing a value is audited without the value', async () => {
    const { db, id } = await activeCredential()
    const rows = await db.select().from(schema.credentialAudit).where(orm.eq(schema.credentialAudit.credentialId, id))
    expect(rows.map((r) => r.action)).toContain('value_stored')
    expect(JSON.stringify(rows)).not.toContain('SUPERSECRET')
  })

  test('the link is still usable by the owner flow exactly once', async () => {
    const { db, now } = await setup()
    const req = await requestRegistration(db, { name: uniqueName(), service: 's', purpose: 'p', doc, requestedBy: 'r', now })
    if (!req.ok) throw new Error('unexpected')
    expect(await consumeEnrollmentLink(db, req.value.link.token, now)).not.toBeNull()
    expect(await consumeEnrollmentLink(db, req.value.link.token, now)).toBeNull()
  })
})

describe('runner registry visibility rules', () => {
  test('active + visible appears; hidden, disabled and expired do not', async () => {
    const { db, now, name, id } = await activeCredential()
    const names = async (at = now) => (await listRegistryForRunner(db, at)).map((c) => c.name)
    expect(await names()).toContain(name)

    await setVisibility(db, id, false, now)
    expect(await names()).not.toContain(name)
    await setVisibility(db, id, true, now)
    expect(await names()).toContain(name)

    await setEnabled(db, id, false, now)
    expect(await names()).not.toContain(name)
    await setEnabled(db, id, true, now)
    expect(await names()).toContain(name)

    const expiring = await activeCredential({ lifetime: 'temporary', expiresAt: now + HOUR })
    expect((await names()).includes(expiring.name)).toBe(true)
    expect((await names(now + 2 * HOUR)).includes(expiring.name)).toBe(false)
  })

  test('the runner registry never includes secrets, hosts or documentation', async () => {
    const { db, now, name } = await activeCredential()
    const entry = (await listRegistryForRunner(db, now)).find((c) => c.name === name)
    expect(Object.keys(entry!).sort()).toEqual(['delivery', 'expiresAt', 'externallyManaged', 'lifetime', 'name', 'purpose', 'service', 'validation'])
  })

  test('permanent and temporary credentials both appear when active and visible', async () => {
    const { db, now } = await setup()
    const permanent = await activeCredential()
    const temporary = await activeCredential({ lifetime: 'temporary', expiresAt: now + HOUR })
    const registry = await listRegistryForRunner(db, now)
    expect(registry.find((c) => c.name === permanent.name)?.lifetime).toBe('permanent')
    expect(registry.find((c) => c.name === temporary.name)?.lifetime).toBe('temporary')
  })

  test('an externally managed entry is discoverable, holds no value, and cannot be read', async () => {
    const { db, key, now } = await setup()
    const name = uniqueName('GITHUB')
    const created = await registerExternallyManaged(db, { name, service: 'GitHub', purpose: 'Repository development', now })
    expect(created.ok).toBe(true)
    expect((await listRegistryForRunner(db, now)).find((c) => c.name === name)?.externallyManaged).toBe(true)
    expect(await readCredentialValue(db, key, name, now)).toEqual({ ok: false, reason: 'unavailable' })
    const row = await db.select({ enc: schema.credential.valueEncrypted }).from(schema.credential).where(orm.eq(schema.credential.name, name))
    expect(row[0]?.enc).toBeNull()
  })
})

describe('reading a value for use', () => {
  test('returns the value only while the credential is available', async () => {
    const { db, key, now, name, id } = await activeCredential()
    const first = await readCredentialValue(db, key, name, now)
    expect(first).toMatchObject({ ok: true, value: SECRET })
    if (first.ok) expect(first.credential).toMatchObject({ delivery: 'proxy', allowedHosts: ['api.cloudflare.com'] })

    await setEnabled(db, id, false, now)
    expect(await readCredentialValue(db, key, name, now)).toEqual({ ok: false, reason: 'unavailable' })
    await setEnabled(db, id, true, now)
    await setVisibility(db, id, false, now)
    expect(await readCredentialValue(db, key, name, now)).toEqual({ ok: false, reason: 'unavailable' })
  })

  test('expiry takes effect immediately and is reported as expired', async () => {
    const { db, key, now, name } = await activeCredential({ lifetime: 'temporary', expiresAt: Date.now() + HOUR })
    expect(await readCredentialValue(db, key, name, now)).toMatchObject({ ok: true })
    expect(await readCredentialValue(db, key, name, now + 2 * HOUR)).toEqual({ ok: false, reason: 'expired' })
  })

  test('unknown names are indistinguishable from hidden ones', async () => {
    const { db, key, now, name, id } = await activeCredential()
    await setVisibility(db, id, false, now)
    const hidden = await readCredentialValue(db, key, name, now)
    const unknown = await readCredentialValue(db, key, uniqueName('NOPE'), now)
    expect(hidden).toEqual(unknown)
  })

  test('a ciphertext moved to another credential cannot be decrypted there', async () => {
    const a = await activeCredential()
    const b = await activeCredential()
    const [rowA] = await a.db.select({ enc: schema.credential.valueEncrypted, iv: schema.credential.valueIv }).from(schema.credential).where(orm.eq(schema.credential.id, a.id))
    await a.db.update(schema.credential).set({ valueEncrypted: rowA!.enc, valueIv: rowA!.iv }).where(orm.eq(schema.credential.id, b.id))
    await expect(readCredentialValue(b.db, b.key, b.name, b.now)).rejects.toThrow('could not be decrypted')
  })

  test('deleting a credential revokes it at once and removes its links', async () => {
    const { db, key, now, name, id } = await activeCredential()
    expect(await deleteCredential(db, id, now)).toMatchObject({ ok: true })
    expect(await readCredentialValue(db, key, name, now)).toEqual({ ok: false, reason: 'unavailable' })
    expect(await db.select().from(schema.enrollmentLink).where(orm.eq(schema.enrollmentLink.credentialId, id))).toHaveLength(0)
    const audit = await db.select().from(schema.credentialAudit).where(orm.eq(schema.credentialAudit.credentialId, id))
    expect(audit.map((r) => r.action)).toContain('deleted')
  })

  test('cannot enable a credential that has no value', async () => {
    const { db, now } = await setup()
    const req = await requestRegistration(db, { name: uniqueName(), service: 's', purpose: 'p', doc, requestedBy: 'r', now })
    if (!req.ok) throw new Error('unexpected')
    expect(await setEnabled(db, req.value.credentialId, true, now)).toMatchObject({ ok: false })
  })
})
