import { describe, expect, test } from 'vitest'
import { getDb, schema } from 'db'
import * as orm from 'drizzle-orm'
import { importEncryptionKey } from './credential-crypto.ts'
import {
  createCredential, deleteCredential, getCredentialForOwner, listCredentialsForOwner, listRegistryForRunner,
  readCredentialValue, registerExternallyManaged, requestRegistration, setEnabled, setVisibility,
  storeCredentialValue, MAX_TEMPORARY_MS,
} from './credential-service.ts'
import { consumeEnrollmentLink, peekEnrollmentLink } from './enrollment.ts'
import { listNotifications, listRunnerIntegrationMetadata, runScheduledCredentialValidation } from './vault-observability.ts'

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
    const result = await requestRegistration(db, { name, service: 'Cloudflare', doc, requestedBy: 'runner:1', now })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    const row = await getCredentialForOwner(db, result.value.credentialId)
    expect(row).toMatchObject({ status: 'pending', visible: false, hasValue: false, name })
    expect(row?.doc?.task).toBe('Deploy a Worker')
    expect(row?.purpose).toBe('Manage zones, DNS, Workers and account resources.')
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

describe('direct owner dashboard creation', () => {
  test('creates an active credential with encrypted value and audited metadata', async () => {
    const { db, key, now } = await setup()
    const name = uniqueName('PANEL')
    const result = await createCredential(db, key, {
      name, service: 'Cloudflare', purpose: 'This value is ignored and generated by the service.',
      value: SECRET, lifetime: 'permanent', expiresAt: null, visible: true,
      delivery: 'proxy', allowedHosts: ['api.cloudflare.com'],
      authHeader: 'Authorization', authScheme: 'Bearer', validation: 'valid',
      validationDetails: JSON.stringify({ provider: 'Cloudflare', status: 'valid', permissions: [{ name: 'Workers Scripts Read', access: 'allow' }] }), now,
    })
    expect(result).toMatchObject({ ok: true, value: { name } })
    if (!result.ok) return
    const row = await getCredentialForOwner(db, result.value.id)
    expect(row).toMatchObject({
      name, service: 'Cloudflare', purpose: 'Manage zones, DNS, Workers and account resources.',
      status: 'active', visible: true, hasValue: true, validation: 'valid',
      allowedHosts: ['api.cloudflare.com'], authHeader: 'Authorization', authScheme: 'Bearer',
    })
    expect(row?.validationDetails).toContain('Workers Scripts Read')
    const runnerRegistry = await listRegistryForRunner(db, now)
    const runnerEntry = runnerRegistry.find((entry) => entry.name === name)
    expect(runnerEntry).toBeDefined()
    expect(runnerEntry).not.toHaveProperty('validationDetails')
    expect(JSON.stringify(runnerEntry)).not.toContain('Workers Scripts Read')
    const used = await readCredentialValue(db, key, name, now)
    expect(used).toMatchObject({ ok: true, value: SECRET })
    const audit = await db.select().from(schema.credentialAudit).where(orm.eq(schema.credentialAudit.credentialId, result.value.id))
    expect(audit.map((entry) => entry.action)).toContain('credential_created')
    expect(JSON.stringify(audit)).not.toContain(SECRET)
  })

  test('rejects unsafe hosts and duplicate names without storing a credential', async () => {
    const { db, key, now } = await setup()
    const name = uniqueName('PANEL')
    const input = {
      name, service: 'Custom API', purpose: 'Test custom provider',
      value: SECRET, lifetime: 'permanent' as const, expiresAt: null,
      visible: true, delivery: 'proxy' as const, allowedHosts: ['*.example.com'],
      authHeader: 'Authorization', authScheme: 'Bearer' as const, now,
    }
    expect(await createCredential(db, key, input)).toMatchObject({ ok: false, error: 'invalid_hosts' })
    expect(await db.select().from(schema.credential).where(orm.eq(schema.credential.name, name))).toHaveLength(0)
    const safe = { ...input, allowedHosts: ['api.example.com'] }
    expect(await createCredential(db, key, safe)).toMatchObject({ ok: true })
    expect(await createCredential(db, key, safe)).toMatchObject({ ok: false, error: 'exists' })
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
    expect(await storeCredentialValue(db, key, { ...base, delivery: 'inject' as 'proxy', allowedHosts: [] })).toMatchObject({ ok: false, error: 'invalid_value' })
  })

  test.each(['', '   ', 'line1\nline2', 'nul\u0000byte', 'x'.repeat(9000)])('rejects an invalid value', async (value) => {
    const { db, key, now } = await setup()
    const req = await requestRegistration(db, { name: uniqueName(), service: 's', purpose: 'p', doc, requestedBy: 'r', now })
    if (!req.ok) throw new Error('unexpected')
    const result = await storeCredentialValue(db, key, { credentialId: req.value.credentialId, value, lifetime: 'permanent', expiresAt: null, visible: true, delivery: 'proxy', allowedHosts: ['api.cloudflare.com'], now })
    expect(result).toMatchObject({ ok: false, error: 'invalid_value' })
  })

  test('temporary credentials always expire and never after 24 hours', async () => {
    const { db, key, now } = await setup()
    const req = await requestRegistration(db, { name: uniqueName(), service: 's', purpose: 'p', doc, requestedBy: 'r', now })
    if (!req.ok) throw new Error('unexpected')
    const base = { credentialId: req.value.credentialId, value: SECRET, lifetime: 'temporary' as const, visible: true, delivery: 'proxy' as const, allowedHosts: ['api.cloudflare.com'], now }
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

describe('auth style', () => {
  test('custom header and scheme are stored; forbidden headers are refused', async () => {
    const { db, key, now } = await setup()
    const req = await requestRegistration(db, { name: uniqueName(), service: 's', purpose: 'p', doc, requestedBy: 'r', now })
    if (!req.ok) throw new Error('unexpected')
    const base = { credentialId: req.value.credentialId, value: SECRET, lifetime: 'permanent' as const, expiresAt: null, visible: true, delivery: 'proxy' as const, allowedHosts: ['api.a.com'], now }
    for (const header of ['Host', 'Cookie', 'Content-Length', 'X-Forwarded-For', 'cf-connecting-ip', 'bad header', '']) {
      expect(await storeCredentialValue(db, key, { ...base, authHeader: header, authScheme: 'Bearer' })).toMatchObject({ ok: false, error: 'invalid_auth_style' })
    }
    expect(await storeCredentialValue(db, key, { ...base, authHeader: 'X-Auth-Key', authScheme: 'Raw' })).toMatchObject({ ok: true })
    const row = await getCredentialForOwner(db, req.value.credentialId)
    expect(row).toMatchObject({ authHeader: 'X-Auth-Key', authScheme: 'Raw' })
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

  test('CLI adapter metadata is isolated to its own endpoint and only active visible credentials', async () => {
    const { db, now, name, id } = await activeCredential()
    await db.update(schema.credential).set({
      service: 'Northflank',
      allowedHosts: JSON.stringify(['api.northflank.com']),
    }).where(orm.eq(schema.credential.id, id))
    const listed = await listRunnerIntegrationMetadata(db, now)
    const entry = listed.find((item) => item.name === name)
    expect(entry).toMatchObject({
      name,
      service: 'Northflank',
      adapter: {
        apiBaseUrl: 'https://api.northflank.com/v1',
        cliTools: [{ id: 'northflank', variable: 'NF_API_BASE_URL' }],
      },
    })
    expect(JSON.stringify(listed)).not.toContain(SECRET)
    await setVisibility(db, id, false, now)
    expect((await listRunnerIntegrationMetadata(db, now)).some((item) => item.name === name)).toBe(false)
    await setVisibility(db, id, true, now)
    await setEnabled(db, id, false, now)
    expect((await listRunnerIntegrationMetadata(db, now)).some((item) => item.name === name)).toBe(false)
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
    if (first.ok) expect(first.credential).toMatchObject({ delivery: 'proxy', allowedHosts: ['api.cloudflare.com'], authHeader: 'Authorization', authScheme: 'Bearer' })

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

  test('scheduled validation updates credential health and emits a deduplicated notification', async () => {
    const { db, key, now } = await setup()
    const name = uniqueName('ADAPTER')
    const adapterDoc = {
      ...doc,
      official_documentation_links: [{ title: 'Example API', url: 'https://example.com/docs' }],
      service_adapter: {
        api_base_url: 'https://api.example.com/v1',
        auth_header: 'Authorization',
        auth_scheme: 'Bearer',
        validation: {
          method: 'GET',
          path: '/me',
          identity_pointer: '/user',
          permissions_pointer: '/permissions',
        },
        cli_tools: [],
      },
    }
    const request = await requestRegistration(db, {
      name, service: 'Example Service', doc: adapterDoc, requestedBy: 'runner:test', now,
    })
    if (!request.ok) throw new Error(request.error)
    const stored = await storeCredentialValue(db, key, {
      credentialId: request.value.credentialId,
      value: SECRET,
      lifetime: 'permanent',
      expiresAt: null,
      visible: true,
      delivery: 'proxy',
      allowedHosts: ['api.example.com'],
      validationIntervalHours: 1,
      now,
    })
    expect(stored.ok).toBe(true)
    await db.update(schema.credential).set({ nextValidationAt: now - 1 })
      .where(orm.eq(schema.credential.id, request.value.credentialId))

    const goodFetch = async (url: string | URL | Request, init?: RequestInit) => {
      expect(String(url)).toBe('https://api.example.com/v1/me')
      expect(new Headers(init?.headers).get('authorization')).toBe(`Bearer ${SECRET}`)
      return Response.json({ user: 'automation-user', permissions: ['read:projects'] })
    }
    await runScheduledCredentialValidation(db, key, now, goodFetch as typeof fetch, 12)
    let credential = await getCredentialForOwner(db, request.value.credentialId)
    expect(credential).toMatchObject({ validationStatus: 'valid', validation: 'valid', lastValidatedAt: now })
    expect(credential?.validationDetails).not.toContain(SECRET)
    expect(JSON.parse(credential!.validationDetails!)).toMatchObject({
      status: 'valid',
      identity: 'automation-user',
      permissions: [{ name: 'read:projects', access: 'granted' }],
    })

    await db.update(schema.credential).set({ nextValidationAt: now - 1 })
      .where(orm.eq(schema.credential.id, request.value.credentialId))
    const badFetch = async () => new Response('', { status: 401 })
    await runScheduledCredentialValidation(db, key, now + 1, badFetch as typeof fetch, 12)
    credential = await getCredentialForOwner(db, request.value.credentialId)
    expect(credential).toMatchObject({ validationStatus: 'invalid', validation: 'invalid' })
    const notifications = await listNotifications(db, 200)
    expect(notifications.filter((item) => item.credentialId === request.value.credentialId && item.kind === 'validation_invalid')).toHaveLength(1)
    expect(JSON.stringify(notifications)).not.toContain(SECRET)

    await db.update(schema.credential).set({ nextValidationAt: now + 2 })
      .where(orm.eq(schema.credential.id, request.value.credentialId))
    await db.delete(schema.credential).where(orm.eq(schema.credential.id, request.value.credentialId))
    const retained = await listNotifications(db, 200)
    expect(retained.find((item) => item.kind === 'validation_invalid' && item.credentialName === name)?.credentialId).toBeNull()
  })
})
