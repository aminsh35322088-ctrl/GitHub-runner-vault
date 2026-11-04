import { describe, expect, test } from 'vitest'
import { getDb, schema } from 'db'
import * as orm from 'drizzle-orm'
import { importEncryptionKey } from './credential-crypto.ts'
import {
  createCredential, deleteCredential, dismissPendingRegistrationRequest, getCredentialForOwner, listCredentialsForOwner, listPendingRegistrationRequestsForOwner, listRegistryForRunner,
  readCredentialValue, reencryptStoredCredentials, registerExternallyManaged, renewRegistrationLink, requestRegistration, setEnabled, setVisibility,
  storeCredentialValue, MAX_TEMPORARY_MS,
} from './credential-service.ts'
import { consumeEnrollmentLink, listLatestRegistrationLinks, peekEnrollmentLink } from './enrollment.ts'
import { createNotification, DEFAULT_VAULT_PREFERENCES, getUsageAnalytics, listCredentialValidationHistory, listNotifications, listRunnerIntegrationMetadata, listUnreadRegistrationNotificationIds, loadVaultPreferences, markNotificationIdsRead, markRegistrationNotificationsRead, recordCredentialUsage, recordRuntimeCredentialEvidence, resetVaultPreferencesCache, runScheduledCredentialValidation, saveVaultPreferences, validateStoredCredentialNow } from './vault-observability.ts'

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

describe('Vault preferences', () => {
  test('loads safe defaults and atomically persists all tunable traffic limits', async () => {
    const { db, now } = await setup()
    resetVaultPreferencesCache()
    try {
      expect(await loadVaultPreferences(db, now)).toMatchObject(DEFAULT_VAULT_PREFERENCES)
      const next = {
        ...DEFAULT_VAULT_PREFERENCES,
        proxyTimeoutMs: 15_000,
        proxyRequestsPerMinute: 240,
        runnerSessionsPerHour: 80,
        runnerRegistrationsPerHour: 40,
        validationIntervalHours: 3,
        analyticsRetentionDays: 30,
        notificationRetentionDays: 60,
        defaultVisible: false,
        defaultLifetime: 'temporary' as const,
      }
      await saveVaultPreferences(db, next, now + 1)
      expect(await loadVaultPreferences(db, now + 2)).toEqual(next)

      resetVaultPreferencesCache()
      expect(await loadVaultPreferences(db, now + 3)).toEqual(next)
    } finally {
      resetVaultPreferencesCache()
    }
  })
})

describe('registration requests', () => {
  test('resolving a request marks only that request notification as read', async () => {
    const { db, now } = await setup()
    const first = await requestRegistration(db, { name: uniqueName(), service: 'Cloudflare', doc, requestedBy: 'runner:first', now })
    const second = await requestRegistration(db, { name: uniqueName(), service: 'Cloudflare', doc, requestedBy: 'runner:second', now })
    if (!first.ok || !second.ok) throw new Error('unexpected registration failure')
    const credentialId = first.value.credentialId
    await createNotification(db, {
      dedupeKey: 'registration:resolved:' + credentialId,
      kind: 'credential_registration_requested', severity: 'info',
      title: 'Runner requested a credential', message: 'Waiting for owner.',
      credentialId, credentialName: 'REQUEST_TOKEN', now,
    })
    await createNotification(db, {
      dedupeKey: 'other-event:' + credentialId,
      kind: 'credential_validation_failed', severity: 'warning',
      title: 'Validation failed', message: 'Review the token.',
      credentialId, credentialName: 'REQUEST_TOKEN', now,
    })
    await createNotification(db, {
      dedupeKey: 'registration:other-credential',
      kind: 'credential_registration_requested', severity: 'info',
      title: 'Runner requested a credential', message: 'Another request.',
      credentialId: second.value.credentialId, credentialName: 'OTHER_TOKEN', now,
    })
    await markRegistrationNotificationsRead(db, credentialId, now + 1)
    const rows = await db.select().from(schema.vaultNotification)
    expect(rows.find((row) => row.dedupeKey === 'registration:resolved:' + credentialId)?.readAt).toBe(now + 1)
    expect(rows.find((row) => row.dedupeKey === 'other-event:' + credentialId)?.readAt).toBeNull()
    expect(rows.find((row) => row.dedupeKey === 'registration:other-credential')?.readAt).toBeNull()
  })

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
    const inbox = await listPendingRegistrationRequestsForOwner(db)
    expect(inbox.rows.find((item) => item.id === result.value.credentialId)).toMatchObject({
      name, status: 'pending', hasValue: false, doc: { task: 'Deploy a Worker' },
    })
    expect(JSON.stringify(inbox.rows.find((item) => item.id === result.value.credentialId))).not.toContain(SECRET)
  })

  test('pending request inbox is paginated, ordered and clamps out-of-range pages', async () => {
    const { db, now } = await setup()
    const baseline = await listPendingRegistrationRequestsForOwner(db, { page: 1, pageSize: 1 })
    const ids: string[] = []
    for (let index = 0; index < 3; index += 1) {
      const result = await requestRegistration(db, {
        name: uniqueName(), service: 'Cloudflare', doc,
        requestedBy: `runner:page-${index}`, now: now + 1_000_000 + index,
      })
      if (!result.ok) throw new Error('unexpected registration failure')
      ids.push(result.value.credentialId)
    }
    const first = await listPendingRegistrationRequestsForOwner(db, { page: 1, pageSize: 1 })
    const second = await listPendingRegistrationRequestsForOwner(db, { page: 2, pageSize: 1 })
    const third = await listPendingRegistrationRequestsForOwner(db, { page: 3, pageSize: 1 })
    const clamped = await listPendingRegistrationRequestsForOwner(db, { page: 99, pageSize: 1 })
    expect(first.total).toBeGreaterThanOrEqual(baseline.total + 3)
    expect(first).toMatchObject({ page: 1, pageSize: 1 })
    expect(second).toMatchObject({ total: first.total, page: 2, pageSize: 1 })
    expect(third).toMatchObject({ total: first.total, page: 3, pageSize: 1 })
    expect(clamped).toMatchObject({ total: first.total, page: first.totalPages, pageSize: 1, totalPages: first.total })
    expect(first.rows).toHaveLength(1)
    expect(second.rows).toHaveLength(1)
    expect(third.rows).toHaveLength(1)
    expect([first.rows[0]?.id, second.rows[0]?.id, third.rows[0]?.id]).toEqual([...ids].reverse())
  })

  test('registration stores a value only while the credential is still pending', async () => {
    const { db, key, now } = await setup()
    const name = uniqueName()
    const requested = await requestRegistration(db, { name, service: 'Cloudflare', doc, requestedBy: 'runner:atomic-store', now })
    if (!requested.ok) throw new Error('unexpected registration failure')
    const stored = await storeCredentialValue(db, key, {
      credentialId: requested.value.credentialId, value: SECRET,
      lifetime: 'permanent', expiresAt: null, visible: true, delivery: 'proxy',
      allowedHosts: ['api.cloudflare.com'], now,
    }, { requirePending: true })
    expect(stored).toMatchObject({ ok: true, value: { name } })
    expect(await getCredentialForOwner(db, requested.value.credentialId)).toMatchObject({
      status: 'active', hasValue: true, visible: true,
    })
  })

  test('registration cannot overwrite an active credential after its link was checked', async () => {
    const { db, key, now, id, name } = await activeCredential()
    const stored = await storeCredentialValue(db, key, {
      credentialId: id, value: 'cfut_DIFFERENT_SECRET_987654321',
      lifetime: 'permanent', expiresAt: null, visible: true, delivery: 'proxy',
      allowedHosts: ['api.cloudflare.com'], now,
    }, { requirePending: true })
    expect(stored).toMatchObject({ ok: false, error: 'not_found' })
    const current = await readCredentialValue(db, key, name, now)
    expect(current).toMatchObject({ ok: true, value: SECRET })
  })

  test('owner can renew a pending request link without exposing stored token hashes', async () => {
    const { db, now } = await setup()
    const name = uniqueName()
    const requested = await requestRegistration(db, { name, service: 'Cloudflare', doc, requestedBy: 'runner:owner/repo', now })
    if (!requested.ok) throw new Error('unexpected registration failure')
    const renewed = await renewRegistrationLink(db, requested.value.credentialId, 'owner:manual-reissue', now + 1)
    expect(renewed).toMatchObject({ ok: true, value: { credentialId: requested.value.credentialId, name } })
    if (!renewed.ok) return
    expect(await peekEnrollmentLink(db, requested.value.link.token, now + 1)).toBeNull()
    expect(await peekEnrollmentLink(db, renewed.value.link.token, now + 1)).not.toBeNull()
    const latest = await listLatestRegistrationLinks(db, [requested.value.credentialId])
    expect(latest.find((row) => row.credentialId === requested.value.credentialId)).toMatchObject({
      requestedBy: 'runner:owner/repo', expiresAt: renewed.value.link.expiresAt, usedAt: null,
    })
    expect(JSON.stringify(latest)).not.toContain(renewed.value.link.token)
    expect(JSON.stringify(latest)).not.toContain('tokenHash')
    const events = await db.select().from(schema.credentialAudit).where(orm.eq(schema.credentialAudit.credentialId, requested.value.credentialId))
    expect(events.map((event) => event.action)).toContain('registration_link_renewed')
  })

  test('owner can dismiss a pending request and invalidate every registration link', async () => {
    const { db, now } = await setup()
    const name = uniqueName()
    const requested = await requestRegistration(db, { name, service: 'Cloudflare', doc, requestedBy: 'runner:owner/repo', now })
    if (!requested.ok) throw new Error('unexpected registration failure')
    await createNotification(db, {
      dedupeKey: 'registration:dismiss-test:' + requested.value.credentialId,
      kind: 'credential_registration_requested', severity: 'info',
      title: 'Runner requested a credential', message: 'Waiting for owner.',
      credentialId: requested.value.credentialId, credentialName: name, now,
    })
    const notificationIds = await listUnreadRegistrationNotificationIds(db, requested.value.credentialId)
    expect(notificationIds).toHaveLength(1)
    const dismissed = await dismissPendingRegistrationRequest(db, requested.value.credentialId, now + 1)
    expect(dismissed).toMatchObject({ ok: true, value: { name } })
    expect(await getCredentialForOwner(db, requested.value.credentialId)).toBeNull()
    expect(await peekEnrollmentLink(db, requested.value.link.token, now + 1)).toBeNull()
    expect((await listPendingRegistrationRequestsForOwner(db)).rows.some((row) => row.id === requested.value.credentialId)).toBe(false)
    await markNotificationIdsRead(db, notificationIds, now + 1)
    const [notification] = await db.select().from(schema.vaultNotification)
      .where(orm.eq(schema.vaultNotification.id, notificationIds[0]!))
    expect(notification).toMatchObject({ credentialId: null, readAt: now + 1 })
    const events = await db.select().from(schema.credentialAudit).where(orm.eq(schema.credentialAudit.credentialId, requested.value.credentialId))
    expect(events.map((event) => event.action)).toContain('registration_request_dismissed')
  })

  test('cannot dismiss a request after it has become an active credential', async () => {
    const { db, now } = await setup()
    const active = await activeCredential()
    expect(await dismissPendingRegistrationRequest(db, active.id, now)).toMatchObject({ ok: false, error: 'not_found' })
    expect(await getCredentialForOwner(db, active.id)).not.toBeNull()
  })

  test('cannot renew a request after it has become an active credential', async () => {
    const { db, now } = await setup()
    const active = await activeCredential()
    expect(await renewRegistrationLink(db, active.id, 'owner:manual-reissue', now)).toMatchObject({ ok: false, error: 'not_found' })
    expect((await listPendingRegistrationRequestsForOwner(db)).rows.some((row) => row.id === active.id)).toBe(false)
    expect(await listLatestRegistrationLinks(db, [])).toEqual([])
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
    const a = await requestRegistration(db, { name, service: 's', purpose: 'p', doc, requestedBy: 'runner:first', now })
    const b = await requestRegistration(db, { name, service: 's', purpose: 'p2', doc, requestedBy: 'runner:second', now })
    if (!a.ok || !b.ok) throw new Error('unexpected')
    expect(b.value.credentialId).toBe(a.value.credentialId)
    expect(await peekEnrollmentLink(db, a.value.link.token, now)).toBeNull()
    expect(await peekEnrollmentLink(db, b.value.link.token, now)).not.toBeNull()
    expect(await listLatestRegistrationLinks(db, [a.value.credentialId])).toMatchObject([
      { credentialId: a.value.credentialId, requestedBy: 'runner:second', usedAt: null },
    ])
  })

  test('simultaneous first requests for one name never create duplicates or throw uniqueness errors', async () => {
    const { db, now } = await setup()
    const name = uniqueName()
    const results = await Promise.allSettled(Array.from({ length: 8 }, (_, index) =>
      requestRegistration(db, {
        name, service: 'Cloudflare', purpose: 'Deploy', doc,
        requestedBy: `runner:concurrent-${index}`, now: now + index,
      }),
    ))
    expect(results.every((result) => result.status === 'fulfilled')).toBe(true)
    const rows = await db.select().from(schema.credential).where(orm.eq(schema.credential.name, name))
    expect(rows).toHaveLength(1)
    const links = await db.select().from(schema.enrollmentLink)
      .where(orm.and(orm.eq(schema.enrollmentLink.credentialId, rows[0]!.id), orm.eq(schema.enrollmentLink.kind, 'register')))
    expect(links.filter((link) => link.usedAt === null)).toHaveLength(1)
    const activeTokens = await Promise.all(results.flatMap((result) =>
      result.status === 'fulfilled' && result.value.ok
        ? [peekEnrollmentLink(db, result.value.value.link.token, now + 10)]
        : [],
    ))
    expect(activeTokens.filter((link) => link !== null)).toHaveLength(1)
  })

  test('a model cannot re-request or change metadata on an active credential', async () => {
    const { db, now, name, id } = await activeCredential()
    const before = await getCredentialForOwner(db, id)
    const result = await requestRegistration(db, {
      name, service: 'Different provider', purpose: 'Different purpose',
      doc: { ...doc, task: 'Overwrite an active credential' }, requestedBy: 'runner:late', now,
    })
    expect(result).toMatchObject({ ok: false, error: 'exists' })
    const after = await getCredentialForOwner(db, id)
    expect(after).toMatchObject({
      service: before?.service,
      purpose: before?.purpose,
      doc: before?.doc,
      status: 'active',
      hasValue: true,
    })
  })

  test('a requested purpose is stored and audited instead of the generated default', async () => {
    const { db, now } = await setup()
    const name = uniqueName()
    const result = await requestRegistration(db, { name, service: 'Cloudflare', purpose: 'Deploy the worker', doc, requestedBy: 'runner:1', now })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    const row = await getCredentialForOwner(db, result.value.credentialId)
    expect(row?.purpose).toBe('Deploy the worker')
    const audits = await db.select().from(schema.credentialAudit).where(orm.eq(schema.credentialAudit.credentialName, name))
    expect(audits.find((entry) => entry.action === 'registration_requested')?.purpose).toBe('Deploy the worker')
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

describe('runtime validation evidence', () => {
  test('promotes credentials after authenticated success and ignores evidence for a rotated value', async () => {
    const { db, key, now, name, id } = await activeCredential()
    const used = await readCredentialValue(db, key, name, now)
    if (!used.ok) throw new Error('credential could not be read')
    expect(await getCredentialForOwner(db, id)).toMatchObject({ validationStatus: 'not_tested' })

    expect(await recordRuntimeCredentialEvidence(db, {
      credentialId: id, valueIv: used.credential.valueIv, provider: 'Cloudflare',
      status: 'valid', message: 'Authenticated provider request succeeded.', now: now + 1,
    })).toBe(true)
    expect(await getCredentialForOwner(db, id)).toMatchObject({ validationStatus: 'valid', validation: 'valid', lastValidatedAt: now + 1 })
    let history = await listCredentialValidationHistory(db, 10)
    expect(history[0]).toMatchObject({ credentialId: id, source: 'runtime', status: 'valid' })

    const replacement = await storeCredentialValue(db, key, {
      credentialId: id, value: 'replacement-secret-value-123456', lifetime: 'permanent',
      expiresAt: null, visible: true, delivery: 'proxy', allowedHosts: ['api.cloudflare.com'], now: now + 2,
    })
    expect(replacement.ok).toBe(true)
    expect(await recordRuntimeCredentialEvidence(db, {
      credentialId: id, valueIv: used.credential.valueIv, provider: 'Cloudflare',
      status: 'invalid', message: 'Late rejection for a rotated value.', now: now + 3,
    })).toBe(false)
    expect(await getCredentialForOwner(db, id)).toMatchObject({ validationStatus: 'not_tested' })
    history = await listCredentialValidationHistory(db, 10)
    expect(history.filter((entry) => entry.credentialId === id)).toHaveLength(1)
    expect(JSON.stringify(history)).not.toContain('replacement-secret-value-123456')
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

  test('stores syntactically valid credentials even when optional provider validation says invalid', async () => {
    const { db, key, now } = await setup()
    const result = await createCredential(db, key, {
      name: uniqueName('UNVERIFIED'), service: 'Cloudflare', purpose: 'Optional validation regression',
      value: SECRET, lifetime: 'permanent', expiresAt: null, visible: true,
      delivery: 'proxy', allowedHosts: ['api.cloudflare.com'],
      authHeader: 'Authorization', authScheme: 'Bearer',
      validation: 'invalid',
      validationDetails: JSON.stringify({ provider: 'Cloudflare', status: 'invalid', message: 'Provider verifier rejected the token.' }),
      now,
    })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(await getCredentialForOwner(db, result.value.id)).toMatchObject({
      status: 'active', hasValue: true, validation: 'invalid', validationStatus: 'invalid',
    })
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

describe('provider connections and encrypted multi-field credentials', () => {
  const connectionDoc = {
    ...doc,
    official_documentation_links: [{ title: 'Example API documentation', url: 'https://example.com/docs' }],
    service_adapter: {
      api_base_url: 'https://api.example.com',
      auth_header: 'Authorization',
      auth_scheme: 'Bearer',
      credential_fields: [
        { id: 'client_secret', label: 'Client secret', required: true, secret: true },
        { id: 'workspace_id', label: 'Workspace ID', required: false, secret: false },
        { id: 'signing_key', label: 'Signing key', required: false, secret: true },
      ],
      auth_field_headers: [
        { field: 'client_secret', header: 'X-Client-Secret', scheme: 'Raw' },
        { field: 'signing_key', header: 'X-Signing-Key', scheme: 'Raw' },
      ],
      cli_tools: [],
    },
  }

  async function createConnection(label: string, accountId: string, secondary: string) {
    const { db, key, now } = await setup()
    const name = uniqueName('EXAMPLE')
    const requested = await requestRegistration(db, {
      name, service: 'Example API', purpose: 'Access a separate provider account',
      doc: connectionDoc, requestedBy: 'runner:connections', now,
    })
    if (!requested.ok) throw new Error(requested.error)
    const stored = await storeCredentialValue(db, key, {
      credentialId: requested.value.credentialId,
      value: 'primary-token-' + label.toLowerCase(),
      authFields: { client_secret: secondary, workspace_id: 'workspace-' + label },
      authFieldIds: ['client_secret', 'workspace_id', 'signing_key'],
      requiredAuthFields: ['client_secret'],
      connectionLabel: label,
      providerAccountId: accountId,
      lifetime: 'permanent', expiresAt: null, visible: true, delivery: 'proxy',
      allowedHosts: ['api.example.com'], authHeader: 'Authorization', authScheme: 'Bearer', now,
    }, { requirePending: true })
    if (!stored.ok) throw new Error(stored.error)
    return { db, key, now, name, id: requested.value.credentialId, secondary }
  }

  test('stores same-provider accounts independently and exposes only their public connection metadata', async () => {
    const personal = await createConnection('Personal', 'acct-personal-001', 'personal-client-secret-value')
    const work = await createConnection('Work', 'acct-work-002', 'work-client-secret-value')

    const personalRead = await readCredentialValue(personal.db, personal.key, personal.name, personal.now)
    const workRead = await readCredentialValue(work.db, work.key, work.name, work.now)
    expect(personalRead).toMatchObject({
      ok: true,
      value: 'primary-token-personal',
      authFields: { client_secret: 'personal-client-secret-value', workspace_id: 'workspace-Personal' },
      credential: { connectionLabel: 'Personal', providerAccountId: 'acct-personal-001' },
    })
    expect(workRead).toMatchObject({
      ok: true,
      value: 'primary-token-work',
      authFields: { client_secret: 'work-client-secret-value', workspace_id: 'workspace-Work' },
      credential: { connectionLabel: 'Work', providerAccountId: 'acct-work-002' },
    })
    if (personalRead.ok) {
      expect(personalRead.credential.authFieldHeaders).toContainEqual({
        field: 'client_secret', header: 'X-Client-Secret', scheme: 'Raw', required: true,
      })
    }

    const [personalRow] = await personal.db.select({
      encrypted: schema.credential.valueEncrypted,
      label: schema.credential.connectionLabel,
      account: schema.credential.providerAccountId,
    }).from(schema.credential).where(orm.eq(schema.credential.id, personal.id))
    expect(personalRow).toMatchObject({ label: 'Personal', account: 'acct-personal-001' })
    expect(personalRow?.encrypted).not.toContain('personal-client-secret-value')
    expect(personalRow?.encrypted).not.toContain('primary-token-personal')

    const runnerRows = await listRegistryForRunner(personal.db, personal.now)
    expect(runnerRows.find((row) => row.name === personal.name)).toMatchObject({
      connectionLabel: 'Personal', providerAccountId: 'acct-personal-001',
    })
    expect(runnerRows.find((row) => row.name === work.name)).toMatchObject({
      connectionLabel: 'Work', providerAccountId: 'acct-work-002',
    })
    expect(JSON.stringify(runnerRows)).not.toContain('personal-client-secret-value')
    expect(JSON.stringify(runnerRows)).not.toContain('work-client-secret-value')
  })

  test('retains write-only secondary credentials when only the primary token is rotated', async () => {
    const connection = await createConnection('Production', 'acct-prod-003', 'production-client-secret-value')
    const replaced = await storeCredentialValue(connection.db, connection.key, {
      credentialId: connection.id,
      value: 'rotated-primary-token-value',
      authFieldIds: ['client_secret', 'workspace_id', 'signing_key'],
      requiredAuthFields: ['client_secret'],
      connectionLabel: 'Production',
      providerAccountId: 'acct-prod-003',
      lifetime: 'permanent', expiresAt: null, visible: true, delivery: 'proxy',
      allowedHosts: ['api.example.com'], authHeader: 'Authorization', authScheme: 'Bearer',
      now: connection.now + 1,
    })
    expect(replaced.ok).toBe(true)
    const read = await readCredentialValue(connection.db, connection.key, connection.name, connection.now + 1)
    expect(read).toMatchObject({
      ok: true,
      value: 'rotated-primary-token-value',
      authFields: { client_secret: 'production-client-secret-value', workspace_id: 'workspace-Production' },
      credential: { connectionLabel: 'Production', providerAccountId: 'acct-prod-003' },
    })
  })

  test('rejects undeclared, short and missing required fields before storing', async () => {
    const { db, now } = await setup()
    const name = uniqueName('EXAMPLE')
    const requested = await requestRegistration(db, {
      name, service: 'Example API', doc: connectionDoc, requestedBy: 'runner:connections', now,
    })
    if (!requested.ok) throw new Error('unexpected registration failure')
    const base = {
      credentialId: requested.value.credentialId,
      value: 'primary-token-value',
      authFieldIds: ['client_secret'],
      requiredAuthFields: ['client_secret'],
      lifetime: 'permanent' as const, expiresAt: null, visible: true, delivery: 'proxy' as const,
      allowedHosts: ['api.example.com'], now,
    }
    expect(await storeCredentialValue(db, await importEncryptionKey(KEY_B64), {
      ...base, authFields: { unknown_field: 'another-secret-value' },
    }, { requirePending: true })).toMatchObject({ ok: false, error: 'invalid_value' })
    expect(await storeCredentialValue(db, await importEncryptionKey(KEY_B64), {
      ...base, authFields: { client_secret: 'x' },
    }, { requirePending: true })).toMatchObject({ ok: false, error: 'invalid_value' })
    expect(await storeCredentialValue(db, await importEncryptionKey(KEY_B64), base, { requirePending: true }))
      .toMatchObject({ ok: false, error: 'invalid_value' })
  })
})

describe('storing a value', () => {
  test('does not set lastValidatedAt when a credential is stored without running validation', async () => {
    const { db, id, now } = await activeCredential()
    expect(await getCredentialForOwner(db, id)).toMatchObject({
      validationStatus: 'not_tested',
      validation: 'not_tested',
      lastValidatedAt: null,
    })

    const replaced = await storeCredentialValue(db, await importEncryptionKey(KEY_B64), {
      credentialId: id,
      value: 'replacement-primary-token-value',
      lifetime: 'permanent',
      expiresAt: null,
      visible: true,
      delivery: 'proxy',
      allowedHosts: ['api.cloudflare.com'],
      validation: 'not_tested',
      validationStatus: 'not_tested',
      now: now + 1,
    })
    expect(replaced.ok).toBe(true)
    expect(await getCredentialForOwner(db, id)).toMatchObject({
      validationStatus: 'not_tested',
      validation: 'not_tested',
      lastValidatedAt: null,
    })
  })

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
    expect(Object.keys(entry!).sort()).toEqual(['connectionLabel', 'delivery', 'expiresAt', 'externallyManaged', 'lifetime', 'name', 'providerAccountId', 'purpose', 'service', 'validation'])
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

  test('expired temporary credentials are excluded from the CLI integration query', async () => {
    const { db, now, name } = await activeCredential({ lifetime: 'temporary', expiresAt: Date.now() + 1_000 })
    expect((await listRunnerIntegrationMetadata(db, now)).some((item) => item.name === name)).toBe(true)
    expect((await listRunnerIntegrationMetadata(db, now + 1_001)).some((item) => item.name === name)).toBe(false)
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

describe('optional validation save states', () => {
  test.each([
    ['invalid', 'invalid'],
    ['invalid', 'expired'],
    ['insufficient_permissions', 'insufficient_permissions'],
    ['not_tested', 'unsupported'],
    ['not_tested', 'unavailable'],
  ] as const)('stores credentials with validation=%s and status=%s without blocking save', async (validation, validationStatus) => {
    const { db, key, now } = await setup()
    const result = await createCredential(db, key, {
      name: uniqueName('OPTIONAL_VALIDATION'),
      service: 'Cloudflare',
      purpose: 'Optional validation regression',
      value: SECRET,
      lifetime: 'permanent',
      expiresAt: null,
      visible: true,
      delivery: 'proxy',
      allowedHosts: ['api.cloudflare.com'],
      authHeader: 'Authorization',
      authScheme: 'Bearer',
      validation,
      validationStatus,
      validationDetails: JSON.stringify({ status: validationStatus, message: 'Stored as non-blocking test evidence.' }),
      now,
    })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(await getCredentialForOwner(db, result.value.id)).toMatchObject({
      status: 'active',
      hasValue: true,
      validation,
      validationStatus,
      validationDetails: expect.stringContaining(validationStatus),
    })
  })
})

describe('provider-specific token syntax', () => {
  test('requires the BotFather Telegram Bot API token format before storage', async () => {
    const { db, key, now } = await setup()
    const name = uniqueName('TELEGRAM')
    const requested = await requestRegistration(db, {
      name, service: 'Telegram Bot API', purpose: 'Telegram Bot API', doc, requestedBy: 'runner:test', now,
    })
    if (!requested.ok) throw new Error('unexpected registration failure')
    expect(await storeCredentialValue(db, key, {
      credentialId: requested.value.credentialId, value: 'not-a-telegram-token',
      lifetime: 'permanent', expiresAt: null, visible: true, delivery: 'proxy',
      allowedHosts: ['api.telegram.org'], authHeader: 'X-Telegram-Bot-Api-Token',
      authScheme: 'Raw', now,
    }, { requirePending: true })).toMatchObject({ ok: false, error: 'invalid_value' })
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

    // Keep a second due credential behind the first one to verify that the
    // batch summary counts the whole queue, not just the selected page.
    const backlogName = uniqueName('BACKLOG')
    const backlogRequest = await requestRegistration(db, {
      name: backlogName, service: 'Example Service', doc: adapterDoc, requestedBy: 'runner:test', now,
    })
    if (!backlogRequest.ok) throw new Error(backlogRequest.error)
    const backlogStored = await storeCredentialValue(db, key, {
      credentialId: backlogRequest.value.credentialId, value: SECRET, lifetime: 'permanent',
      expiresAt: null, visible: true, delivery: 'proxy', allowedHosts: ['api.example.com'],
      validationIntervalHours: 1, now,
    })
    expect(backlogStored.ok).toBe(true)
    await db.update(schema.credential).set({ nextValidationAt: now - 1 })
      .where(orm.eq(schema.credential.id, request.value.credentialId))
    await db.update(schema.credential).set({ nextValidationAt: now })
      .where(orm.eq(schema.credential.id, backlogRequest.value.credentialId))

    const goodFetch = async (url: string | URL | Request, init?: RequestInit) => {
      expect(String(url)).toBe('https://api.example.com/v1/me')
      expect(new Headers(init?.headers).get('authorization')).toBe(`Bearer ${SECRET}`)
      return Response.json({ user: 'automation-user', permissions: ['read:projects'] })
    }
    const firstBatch = await runScheduledCredentialValidation(db, key, now, goodFetch as typeof fetch, 1)
    expect(firstBatch).toMatchObject({ checked: 1, remainingDue: 1 })
    await db.update(schema.credential).set({ status: 'disabled' })
      .where(orm.eq(schema.credential.id, backlogRequest.value.credentialId))
    let credential = await getCredentialForOwner(db, request.value.credentialId)
    expect(credential).toMatchObject({ validationStatus: 'valid', validation: 'valid', lastValidatedAt: now })
    expect(credential?.validationDetails).not.toContain(SECRET)
    expect(JSON.parse(credential!.validationDetails!)).toMatchObject({
      status: 'valid',
      identity: 'automation-user',
      permissions: [{ name: 'read:projects', access: 'granted' }],
    })
    expect(credential).toMatchObject({ validationFailureCount: 0, firstValidationFailureAt: null })
    let history = await listCredentialValidationHistory(db, 20)
    expect(history.filter((item) => item.credentialId === request.value.credentialId)).toHaveLength(1)
    expect(history[0]).toMatchObject({ source: 'scheduled', status: 'valid', credentialName: name })
    expect(JSON.stringify(history)).not.toContain(SECRET)

    await db.update(schema.credential).set({ nextValidationAt: now - 1 })
      .where(orm.eq(schema.credential.id, request.value.credentialId))
    const badFetch = async () => new Response('', { status: 401 })
    await runScheduledCredentialValidation(db, key, now + 1, badFetch as typeof fetch, 12)
    credential = await getCredentialForOwner(db, request.value.credentialId)
    expect(credential).toMatchObject({
      validationStatus: 'invalid',
      validation: 'invalid',
      validationFailureCount: 1,
      firstValidationFailureAt: now + 1,
      nextValidationAt: now + 1 + 15 * 60_000,
    })

    // A second consecutive failure doubles the retry delay and preserves the
    // timestamp of the first failure instead of resetting it.
    await db.update(schema.credential).set({ nextValidationAt: now + 1 })
      .where(orm.eq(schema.credential.id, request.value.credentialId))
    await runScheduledCredentialValidation(db, key, now + 2, badFetch as typeof fetch, 12)
    credential = await getCredentialForOwner(db, request.value.credentialId)
    expect(credential).toMatchObject({
      validationStatus: 'invalid',
      validationFailureCount: 2,
      firstValidationFailureAt: now + 1,
      nextValidationAt: now + 2 + 30 * 60_000,
    })

    // Manual validation runs immediately, records its source and clears the
    // consecutive-failure state after the provider confirms the token again.
    const manual = await validateStoredCredentialNow(db, key, request.value.credentialId, now + 3, goodFetch as typeof fetch)
    expect(manual.status).toBe('valid')
    credential = await getCredentialForOwner(db, request.value.credentialId)
    expect(credential).toMatchObject({ validationStatus: 'valid', validationFailureCount: 0, firstValidationFailureAt: null })
    history = await listCredentialValidationHistory(db, 20)
    expect(history.filter((item) => item.credentialId === request.value.credentialId)).toHaveLength(4)
    expect(history.find((item) => item.source === 'manual')).toMatchObject({ status: 'valid', provider: 'Example Service' })
    expect(JSON.stringify(history)).not.toContain(SECRET)

    const notifications = await listNotifications(db, 200)
    expect(notifications.filter((item) => item.credentialId === request.value.credentialId && item.kind === 'validation_invalid')).toHaveLength(1)
    expect(notifications.filter((item) => item.credentialId === request.value.credentialId && item.kind === 'validation_recovered')).toHaveLength(1)
    expect(JSON.stringify(notifications)).not.toContain(SECRET)

    await db.update(schema.credential).set({ nextValidationAt: now + 4 })
      .where(orm.eq(schema.credential.id, request.value.credentialId))
    await db.delete(schema.credential).where(orm.eq(schema.credential.id, request.value.credentialId))
    const retained = await listNotifications(db, 200)
    expect(retained.find((item) => item.kind === 'validation_invalid' && item.credentialName === name)?.credentialId).toBeNull()
    expect((await listCredentialValidationHistory(db, 20)).some((item) => item.credentialId === request.value.credentialId)).toBe(false)
  })

  test('does not let an in-flight validation overwrite a replacement credential', async () => {
    const { db, key, now, id } = await activeCredential()
    let markStarted!: () => void
    let releaseFetch!: () => void
    const started = new Promise<void>((resolve) => { markStarted = resolve })
    const blockedFetch = new Promise<void>((resolve) => { releaseFetch = resolve })

    const validation = validateStoredCredentialNow(db, key, id, now + 1_000, (async (_url, init) => {
      expect(new Headers(init?.headers).get('authorization')).toBe(`Bearer ${SECRET}`)
      markStarted()
      await blockedFetch
      return new Response('', { status: 401 })
    }) as typeof fetch)

    // Wait until the old encrypted value has already been read and sent upstream.
    await started
    const replacement = await storeCredentialValue(db, key, {
      credentialId: id,
      value: 'cfut_REPLACEMENT_SECRET_987654321',
      lifetime: 'permanent',
      expiresAt: null,
      visible: true,
      delivery: 'proxy',
      allowedHosts: ['api.cloudflare.com'],
      validation: 'valid',
      validationStatus: 'valid',
      validationDetails: JSON.stringify({ status: 'valid', marker: 'replacement' }),
      now: now + 2_000,
    })
    expect(replacement.ok).toBe(true)

    releaseFetch()
    const staleReport = await validation
    expect(staleReport).toMatchObject({
      status: 'unavailable',
      message: 'Credential changed during validation; the stale result was discarded. Run validation again.',
    })

    const current = await getCredentialForOwner(db, id)
    expect(current).toMatchObject({
      validationStatus: 'valid',
      validation: 'valid',
      validationDetails: JSON.stringify({ status: 'valid', marker: 'replacement' }),
      lastValidatedAt: now + 2_000,
    })
    expect(await listCredentialValidationHistory(db, 20).then((rows) => rows.filter((row) => row.credentialId === id))).toHaveLength(0)
  })
})


describe('master-key migration', () => {
  test('re-encrypts values so only the new key can decrypt them', async () => {
    const { db, key, now, name } = await activeCredential()
    const otherKey = await importEncryptionKey(btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))))
    expect((await readCredentialValue(db, key, name, now)).ok).toBe(true)
    const migrated = await reencryptStoredCredentials(db, key, otherKey, [id])
    expect(migrated.failedIds).toEqual([])
    expect(migrated.migrated).toBeGreaterThanOrEqual(1)
    const withNewKey = await readCredentialValue(db, otherKey, name, now)
    expect(withNewKey.ok).toBe(true)
    if (withNewKey.ok) expect(withNewKey.value).toBe(SECRET)
    await expect(readCredentialValue(db, key, name, now)).rejects.toThrow(/could not be decrypted/)
  })

  test('one unreadable credential prevents every ciphertext from being rewritten', async () => {
    const first = await activeCredential()
    const second = await activeCredential()
    const [beforeFirst] = await first.db.select({ valueEncrypted: schema.credential.valueEncrypted, valueIv: schema.credential.valueIv })
      .from(schema.credential).where(orm.eq(schema.credential.id, first.id))
    const [beforeSecond] = await second.db.select({ valueEncrypted: schema.credential.valueEncrypted, valueIv: schema.credential.valueIv })
      .from(schema.credential).where(orm.eq(schema.credential.id, second.id))
    if (!beforeFirst?.valueEncrypted || !beforeFirst.valueIv || !beforeSecond?.valueEncrypted || !beforeSecond.valueIv) throw new Error('test credentials are missing ciphertext')
    await first.db.update(schema.credential).set({ valueEncrypted: 'corrupted-ciphertext' })
      .where(orm.eq(schema.credential.id, first.id))
    try {
      const otherKey = await importEncryptionKey(btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))))
      const result = await reencryptStoredCredentials(first.db, first.key, otherKey, [first.id, second.id])
      expect(result.migrated).toBe(0)
      expect(result.failedIds).toContain(first.id)
      const [afterFirst] = await first.db.select({ valueEncrypted: schema.credential.valueEncrypted, valueIv: schema.credential.valueIv })
        .from(schema.credential).where(orm.eq(schema.credential.id, first.id))
      const [afterSecond] = await first.db.select({ valueEncrypted: schema.credential.valueEncrypted, valueIv: schema.credential.valueIv })
        .from(schema.credential).where(orm.eq(schema.credential.id, second.id))
      expect(afterFirst).toMatchObject({ valueEncrypted: 'corrupted-ciphertext', valueIv: beforeFirst.valueIv })
      expect(afterSecond).toEqual(beforeSecond)
    } finally {
      await first.db.update(schema.credential).set({ valueEncrypted: beforeFirst.valueEncrypted, valueIv: beforeFirst.valueIv })
        .where(orm.eq(schema.credential.id, first.id))
    }
    expect((await readCredentialValue(first.db, first.key, first.name, first.now)).ok).toBe(true)
  })
})

describe('credential usage analytics', () => {
  test('aggregates requests by credential and by consuming tool without storing request data', async () => {
    const { db, now, id } = await activeCredential()
    await recordCredentialUsage(db, { credentialId: id, consumer: 'cli:northflank', success: true, latencyMs: 80, now })
    await recordCredentialUsage(db, { credentialId: id, consumer: 'cli:northflank', success: false, latencyMs: 160, now })
    await recordCredentialUsage(db, { credentialId: id, consumer: 'runner', success: true, latencyMs: 40, now })
    const analytics = await getUsageAnalytics(db, now + 1)
    expect(analytics.totals).toMatchObject({ requests: 3, successes: 2, errors: 1, averageLatencyMs: 93, maxLatencyMs: 160 })
    expect(analytics.credentials.find((row) => row.credentialId === id)).toMatchObject({
      credentialName: expect.any(String), requests: 3, successes: 2, errors: 1, averageLatencyMs: 93,
    })
    expect(analytics.consumers).toEqual(expect.arrayContaining([
      { consumer: 'cli:northflank', requests: 2, successes: 1, errors: 1, averageLatencyMs: 120, maxLatencyMs: 160 },
      { consumer: 'runner', requests: 1, successes: 1, errors: 0, averageLatencyMs: 40, maxLatencyMs: 40 },
    ]))
    expect(JSON.stringify(analytics)).not.toContain(SECRET)
  })
})
