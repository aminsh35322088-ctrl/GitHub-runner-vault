import { describe, expect, test } from 'vitest'
import { getDb, schema } from 'db'
import * as orm from 'drizzle-orm'
import { importEncryptionKey } from './credential-crypto.ts'
import { deleteCredential, requestRegistration, storeCredentialValue, setEnabled, setVisibility } from './credential-service.ts'
import { GITHUB_OIDC_ISSUER, type OidcPolicy } from './oidc.ts'
import { deriveSessionKey, issueRunnerSession, revokeRunnerSessions } from './runner-session.ts'
import { bearer, readBoundedRequestBody, tryAcquireProxyUploadSlot, MAX_CONCURRENT_PROXY_UPLOADS_PER_ISOLATE, createSession, registry, integrations, requestCredential, useCredential, USE_LIMIT_PER_MINUTE, SESSION_ATTEMPT_LIMIT_PER_HOUR, type RunnerDeps } from './runner-core.ts'
import { DEFAULT_VAULT_PREFERENCES } from './vault-observability.ts'
import { cleanupRunnerRateLimitEvents, releaseRunnerRateLimitReservation, reserveRunnerRateLimit } from './runner-rate-limit.ts'

const KEY_B64 = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))
const SECRET = 'cfut_END_TO_END_SECRET_0123456789'
const SESSION_SECRET = 'session-secret-that-is-long-enough-123456'


test('raw proxy upload slots cap concurrent buffered uploads per isolate', () => {
  const releases = Array.from({ length: MAX_CONCURRENT_PROXY_UPLOADS_PER_ISOLATE }, () => tryAcquireProxyUploadSlot())
  expect(releases.every((release) => typeof release === 'function')).toBe(true)
  expect(tryAcquireProxyUploadSlot()).toBeNull()

  const releaseFirst = releases[0]
  releaseFirst?.()
  releaseFirst?.()
  const replacement = tryAcquireProxyUploadSlot()
  expect(typeof replacement).toBe('function')
  replacement?.()

  for (const release of releases.slice(1)) release?.()
  const finalRelease = tryAcquireProxyUploadSlot()
  expect(typeof finalRelease).toBe('function')
  finalRelease?.()
})


test('bounded request body reader grows only for received bytes and validates declared length', async () => {
  const expected = new Uint8Array([0x00, 0xff, 0xc3, 0x28, 0x7b, 0x7d, 0x0d, 0x0a])
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(expected.subarray(0, 3))
      controller.enqueue(expected.subarray(3))
      controller.close()
    },
  })
  const result = await readBoundedRequestBody(stream, 16, expected.byteLength)
  expect(result).toEqual({ ok: true, body: expected })

  const largeExpected = new Uint8Array(70 * 1024)
  for (let index = 0; index < largeExpected.byteLength; index++) largeExpected[index] = index % 251
  const largeStream = new ReadableStream<Uint8Array>({
    start(controller) {
      for (let offset = 0; offset < largeExpected.byteLength; offset += 16 * 1024) {
        controller.enqueue(largeExpected.subarray(offset, offset + 16 * 1024))
      }
      controller.close()
    },
  })
  const grown = await readBoundedRequestBody(largeStream, 80 * 1024, largeExpected.byteLength)
  expect(grown).toEqual({ ok: true, body: largeExpected })

  let mismatchCancelled = false
  const mismatched = new ReadableStream<Uint8Array>({
    pull(controller) {
      controller.enqueue(new Uint8Array([1, 2, 3]))
    },
    cancel() {
      mismatchCancelled = true
    },
  }, { highWaterMark: 0 })
  expect(await readBoundedRequestBody(mismatched, 8, 2)).toEqual({ ok: false, error: 'invalid_body' })
  expect(mismatchCancelled).toBe(true)

  const oversized = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array(5))
      controller.enqueue(new Uint8Array(4))
      controller.close()
    },
  })
  expect(await readBoundedRequestBody(oversized, 8)).toEqual({ ok: false, error: 'body_too_large' })

  let pulled = false
  const untrustedLength = new ReadableStream<Uint8Array>({
    pull(controller) {
      pulled = true
      controller.enqueue(new Uint8Array([1]))
      controller.close()
    },
  }, { highWaterMark: 0 })
  expect(await readBoundedRequestBody(untrustedLength, 8, 9)).toEqual({ ok: false, error: 'body_too_large' })
  expect(pulled).toBe(false)
})

const doc = {
  overview: 'Needed to deploy a Worker.', task: 'Deploy', token_type: 'API token', creation_steps: ['Open dashboard'],
  required_permissions: [{ name: 'Workers', level: 'Edit', why: 'deploy' }], unnecessary_permissions: [],
  security_notes: [], expiration_guidance: [], official_documentation_links: [], verification: 'unverified', unverified_note: 'not checked',
}

const policy: OidcPolicy = {
  audience: 'https://vault.test', repository: 'o/r', repositoryId: '1',
  allowedRefs: ['refs/heads/main'], allowedEvents: ['workflow_dispatch', 'schedule', 'push'],
  allowedWorkflowRefs: ['o/r/.github/workflows/runner.yml@refs/heads/main'],
}
let n = 0
const uname = () => `E2E_${Date.now().toString(36).toUpperCase()}_${++n}_${Math.floor(Math.random() * 1e6)}`

async function deps(overrides: Partial<RunnerDeps> = {}): Promise<RunnerDeps> {
  return {
    db: getDb(), encryptionKey: await importEncryptionKey(KEY_B64), sessionKey: await deriveSessionKey(SESSION_SECRET), policy,
    jwks: async () => ({ keys: [] }), origin: 'https://vault.test',
    fetchFn: (async () => Response.json({ ok: true })) as unknown as typeof fetch, now: Date.now(), ...overrides,
  }
}

async function sessionHeader(d: RunnerDeps) {
  const { token } = await issueRunnerSession(d.sessionKey, {
    repository: 'o/r', repositoryId: '1', repositoryOwnerId: '2', runId: '9', runAttempt: '1', ref: 'refs/heads/main', event: 'workflow_dispatch', workflow: 'w', workflowRef: 'o/r/.github/workflows/w.yml@refs/heads/main', sha: 's', jti: 'j',
  }, d.now)
  return `Bearer ${token}`
}

async function activeCredential(d: RunnerDeps, opts: { visible?: boolean; service?: string; host?: string } = {}) {
  const name = uname()
  const service = opts.service ?? 'Cloudflare'
  const host = opts.host ?? 'api.cloudflare.com'
  const req = await requestRegistration(d.db, { name, service, purpose: 'Deploy', doc, requestedBy: 'runner:x', now: d.now })
  if (!req.ok) throw new Error(req.error)
  const stored = await storeCredentialValue(d.db, d.encryptionKey, {
    credentialId: req.value.credentialId, value: SECRET, lifetime: 'permanent', expiresAt: null, visible: opts.visible ?? true,
    delivery: 'proxy', allowedHosts: ['api.cloudflare.com'], now: d.now,
  })
  if (!stored.ok) throw new Error(stored.error)
  return { name, id: req.value.credentialId }
}

const call = { url: 'https://api.cloudflare.com/client/v4/user/tokens/verify', method: 'GET' }

async function activeTelegramApiCredential(d: RunnerDeps) {
  const name = uname()
  const token = String(123456789) + ':' + 'A'.repeat(35)
  const requested = await requestRegistration(d.db, {
    name, service: 'Telegram Bot API', purpose: 'Call the Telegram Bot API', doc,
    requestedBy: 'runner:telegram-test', now: d.now,
  })
  if (!requested.ok) throw new Error(requested.error)
  const stored = await storeCredentialValue(d.db, d.encryptionKey, {
    credentialId: requested.value.credentialId, value: token, lifetime: 'permanent',
    expiresAt: null, visible: true, delivery: 'proxy', allowedHosts: ['api.telegram.org'],
    authHeader: 'X-Telegram-Bot-Api-Token', authScheme: 'Raw', now: d.now,
  })
  if (!stored.ok) throw new Error(stored.error)
  return { name, id: requested.value.credentialId, token }
}

function b64url(value: Uint8Array | string) {
  const bytes = typeof value === 'string' ? new TextEncoder().encode(value) : value
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function signedOidcToken(now: number) {
  const pair = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true, ['sign', 'verify'],
  ) as CryptoKeyPair
  const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey)
  const seconds = Math.floor(now / 1000)
  const header = b64url(JSON.stringify({ alg: 'RS256', kid: 'runner-core-test', typ: 'JWT' }))
  const claims = b64url(JSON.stringify({
    iss: 'https://token.actions.githubusercontent.com', aud: policy.audience,
    iat: seconds, nbf: seconds - 5, exp: seconds + 300,
    repository: 'o/r', repository_id: '1', repository_owner: 'o', repository_owner_id: '2',
    ref: 'refs/heads/main', event_name: 'workflow_dispatch', run_id: '987654321', run_attempt: '1',
    workflow_ref: 'o/r/.github/workflows/runner.yml@refs/heads/main', sha: 'test-sha', jti: 'runner-core-test-jti',
  }))
  const input = `${header}.${claims}`
  const signature = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', pair.privateKey, new TextEncoder().encode(input)))
  return {
    token: `${input}.${b64url(signature)}`,
    jwks: async () => ({ keys: [{ kty: 'RSA', n: publicJwk.n!, e: publicJwk.e!, kid: 'runner-core-test', alg: 'RS256' }] }),
  }
}

describe('bearer parsing', () => {
  test.each([[null], [''], ['Bearer'], ['Bearer short'], ['Basic abcdefghijkl'], ['bearer abcdefghijklm'], ['Bearer a b c d e f g h i j']])('rejects %j', (h) => {
    expect(bearer(h as string | null)).toBeNull()
  })
  test('accepts a token', () => expect(bearer('Bearer abc.def-ghi_jkl')).toBe('abc.def-ghi_jkl'))
})

describe('authentication', () => {
  test('every runner operation needs a valid session', async () => {
    const d = await deps()
    expect((await registry(d, null)).status).toBe(401)
    expect((await integrations(d, null)).status).toBe(401)
    expect((await registry(d, 'Bearer rs1.not.valid.at.all')).status).toBe(401)
    expect((await useCredential(d, null, { name: 'X', ...call })).status).toBe(401)
    expect((await requestCredential(d, null, { name: 'X', service: 'y', purpose: 'z', doc })).status).toBe(401)
  })

  test('a rejected OIDC token is audited and gets a generic answer', async () => {
    const d = await deps()
    const res = await createSession(d, 'Bearer aaaa.bbbb.cccc')
    expect(res).toEqual({ status: 401, body: { error: 'unauthorized' } })
    const rows = await d.db.select().from(schema.credentialAudit).where(orm.eq(schema.credentialAudit.action, 'session_denied'))
    expect(rows.length).toBeGreaterThan(0)
  })

  test('revoking sessions locks out existing sessions at once', async () => {
    const d = await deps()
    const revokedKey = 'runner_revoked_before'
    // D1 state is shared across tests in this worker pool. Never let a prior
    // interrupted run or this test's future timestamp contaminate later cases.
    await d.db.delete(schema.vaultSetting).where(orm.eq(schema.vaultSetting.key, revokedKey))
    try {
      const header = await sessionHeader(d)
      expect((await registry(d, header)).status).toBe(200)
      await revokeRunnerSessions(d.db, d.now + 5)
      expect((await registry({ ...d, now: d.now + 10 }, header)).status).toBe(401)
    } finally {
      await d.db.delete(schema.vaultSetting).where(orm.eq(schema.vaultSetting.key, revokedKey))
    }
  })

  test('uses the owner-configured OIDC session issuance limit', async () => {
    const now = Date.now() + 24 * 60 * 60_000
    const signed = await signedOidcToken(now)
    const d = await deps({
      now,
      jwks: signed.jwks,
      getVaultPreferences: async () => ({ ...DEFAULT_VAULT_PREFERENCES, runnerSessionsPerHour: 1 }),
    })
    expect((await createSession(d, `Bearer ${signed.token}`)).status).toBe(200)
    expect(await createSession(d, `Bearer ${signed.token}`)).toEqual({ status: 429, body: { error: 'rate_limited' } })
  })

  test('the issuer constant is the real GitHub one', () => {
    expect(GITHUB_OIDC_ISSUER).toBe('https://token.actions.githubusercontent.com')
  })
})

describe('session attempt limiting (pre-verification)', () => {
  const deniedCount = async (d: RunnerDeps) =>
    (await d.db.select().from(schema.credentialAudit).where(orm.eq(schema.credentialAudit.action, 'session_denied'))).length

  const spendAttempts = async (d: RunnerDeps, subject: string, count: number) => {
    for (let i = 0; i < count; i++) {
      const id = await reserveRunnerRateLimit(d.db, {
        scope: 'session_attempt', subject, now: d.now, windowMs: 3600_000, limit: SESSION_ATTEMPT_LIMIT_PER_HOUR,
      })
      expect(id).toBeTruthy()
    }
  }

  test('an invalid-token flood from one IP is cut off with 429 and audit writes stop', async () => {
    const now = Date.now() + 72 * 60 * 60_000
    const ip = '203.0.113.10'
    const d = await deps({ now, clientIp: ip })
    await spendAttempts(d, `ip:${ip}`, SESSION_ATTEMPT_LIMIT_PER_HOUR - 1)

    // The last slot in the budget still goes through verification and its
    // denial is audited, exactly like a normal rejected token.
    const before = await deniedCount(d)
    expect((await createSession(d, 'Bearer aaaa.bbbb.cccc')).status).toBe(401)
    expect(await deniedCount(d)).toBe(before + 1)

    // Budget spent: the answer is 429 and no further audit row is written.
    expect(await createSession(d, 'Bearer aaaa.bbbb.cccc')).toEqual({ status: 429, body: { error: 'rate_limited' } })
    expect(await deniedCount(d)).toBe(before + 1)
  })

  test('the attempt budget is per client IP, with a shared fallback when the IP is unknown', async () => {
    const now = Date.now() + 96 * 60 * 60_000
    const ip = '198.51.100.7'
    const d = await deps({ now, clientIp: ip })
    await spendAttempts(d, `ip:${ip}`, SESSION_ATTEMPT_LIMIT_PER_HOUR)
    expect((await createSession(d, 'Bearer aaaa.bbbb.cccc')).status).toBe(429)

    // A different source IP still has its own budget and is verified (and denied) normally.
    const other = await deps({ now, clientIp: '198.51.100.8' })
    expect((await createSession(other, 'Bearer aaaa.bbbb.cccc')).status).toBe(401)

    // No client IP: the shared fallback budget applies instead of no limit at all.
    const anonymous = await deps({ now })
    expect((await createSession(anonymous, 'Bearer aaaa.bbbb.cccc')).status).toBe(401)
  })

  test('a valid OIDC exchange still succeeds when the client IP is known', async () => {
    const now = Date.now() + 120 * 60 * 60_000
    const signed = await signedOidcToken(now)
    const d = await deps({ now, jwks: signed.jwks, clientIp: '203.0.113.99' })
    expect((await createSession(d, `Bearer ${signed.token}`)).status).toBe(200)
  })
})

describe('registry', () => {
  test('lists only active, visible credentials and never values or hosts', async () => {
    const d = await deps()
    const shown = await activeCredential(d)
    const hidden = await activeCredential(d, { visible: false })
    const res = await registry(d, await sessionHeader(d))
    expect(res.status).toBe(200)
    const names = (res.body as { credentials: Array<{ name: string }> }).credentials.map((c) => c.name)
    expect(names).toContain(shown.name)
    expect(names).not.toContain(hidden.name)
    expect(JSON.stringify(res.body)).not.toContain(SECRET)
    expect(JSON.stringify(res.body)).not.toContain('api.cloudflare.com')
  })
})

describe('registration requests', () => {
  test('return an owner link, nothing else', async () => {
    const d = await deps()
    const name = uname()
    const res = await requestCredential(d, await sessionHeader(d), { name, service: 'Cloudflare', purpose: 'Deploy', doc })
    expect(res.status).toBe(200)
    const link = (res.body as { link: string }).link
    expect(link).toMatch(/^https:\/\/vault\.test\/vault\/register\/lnk_[A-Za-z0-9_-]{43}$/)
    const [notification] = await d.db.select().from(schema.vaultNotification)
      .where(orm.and(
        orm.eq(schema.vaultNotification.kind, 'credential_registration_requested'),
        orm.eq(schema.vaultNotification.credentialName, name),
      ))
    expect(notification).toMatchObject({
      severity: 'info', title: 'Runner requested a credential', credentialName: name,
    })
    expect(notification?.message).toContain('waiting for owner review')
    expect(JSON.stringify(notification)).not.toContain(link)
  })

  test('uses the owner-configured registration limit', async () => {
    const d = await deps({
      now: Date.now() + 24 * 60 * 60_000,
      getVaultPreferences: async () => ({ ...DEFAULT_VAULT_PREFERENCES, runnerRegistrationsPerHour: 1 }),
    })
    const header = await sessionHeader(d)
    const first = await requestCredential(d, header, { name: uname(), service: 'Cloudflare', doc })
    const second = await requestCredential(d, header, { name: uname(), service: 'GitHub', doc })
    expect(first.status).toBe(200)
    expect(second).toEqual({ status: 429, body: { error: 'rate_limited' } })
  })

  test('invalid input is rejected; existing names conflict', async () => {
    const d = await deps()
    const header = await sessionHeader(d)
    expect((await requestCredential(d, header, { name: 5, service: 'a', purpose: 'b', doc })).status).toBe(400)
    expect((await requestCredential(d, header, { name: 'bad name', service: 'a', purpose: 'b', doc })).status).toBe(400)
    const existing = await activeCredential(d)
    expect((await requestCredential(d, header, { name: existing.name, service: 'a', purpose: 'b', doc })).status).toBe(409)
  })
})

describe('runtime credential verification evidence', () => {
  test('promotes Telegram Bot API only on ok=true and preserves valid status across rate limits', async () => {
    let upstream = Response.json({ ok: true, result: { id: 123456789, is_bot: true } })
    const seen: string[] = []
    const d = await deps({
      fetchFn: (async (url: string) => { seen.push(url); return upstream }) as unknown as typeof fetch,
    })
    const credential = await activeTelegramApiCredential(d)
    const header = await sessionHeader(d)
    const input = { name: credential.name, method: 'GET', url: 'https://api.telegram.org/getMe' }

    expect((await useCredential(d, header, input)).status).toBe(200)
    expect(seen[0]).toBe('https://api.telegram.org/bot' + credential.token + '/getMe')
    let [row] = await d.db.select({ validationStatus: schema.credential.validationStatus })
      .from(schema.credential).where(orm.eq(schema.credential.id, credential.id))
    expect(row?.validationStatus).toBe('valid')

    upstream = new Response(JSON.stringify({ ok: false, error_code: 429, description: 'Too Many Requests' }), { status: 429 })
    expect((await useCredential(d, header, input)).status).toBe(200)
    ;[row] = await d.db.select({ validationStatus: schema.credential.validationStatus })
      .from(schema.credential).where(orm.eq(schema.credential.id, credential.id))
    expect(row?.validationStatus).toBe('valid')

    const history = await d.db.select().from(schema.credentialValidationHistory)
      .where(orm.eq(schema.credentialValidationHistory.credentialId, credential.id))
    expect(history.filter((entry) => entry.source === 'runtime' && entry.status === 'valid')).toHaveLength(1)
  })

  test('records Telegram rejection only for a definitive Bot API invalid-token response', async () => {
    let upstream = new Response(JSON.stringify({ ok: false, error_code: 404, description: 'Not Found' }), { status: 404 })
    const d = await deps({ fetchFn: (async () => upstream) as unknown as typeof fetch })
    const credential = await activeTelegramApiCredential(d)
    const header = await sessionHeader(d)
    const input = { name: credential.name, method: 'GET', url: 'https://api.telegram.org/getMe' }
    expect((await useCredential(d, header, input)).status).toBe(200)
    let [row] = await d.db.select({ validationStatus: schema.credential.validationStatus })
      .from(schema.credential).where(orm.eq(schema.credential.id, credential.id))
    expect(row?.validationStatus).toBe('invalid')

    upstream = new Response('temporarily unavailable', { status: 503 })
    expect((await useCredential(d, header, input)).status).toBe(200)
    ;[row] = await d.db.select({ validationStatus: schema.credential.validationStatus })
      .from(schema.credential).where(orm.eq(schema.credential.id, credential.id))
    expect(row?.validationStatus).toBe('invalid')
  })

  test('does not promote Cloudflare from a generic HTTP 200 response without its success marker', async () => {
    const d = await deps({ fetchFn: (async () => Response.json({ ok: true })) as unknown as typeof fetch })
    const credential = await activeCredential(d)
    expect((await useCredential(d, await sessionHeader(d), { name: credential.name, ...call })).status).toBe(200)
    const [row] = await d.db.select({ validationStatus: schema.credential.validationStatus })
      .from(schema.credential).where(orm.eq(schema.credential.id, credential.id))
    expect(row?.validationStatus).toBe('not_tested')
  })
})

describe('multi-field provider connections through the runner', () => {
  test('selects one named connection and injects only its declared encrypted fields', async () => {
    const seen: Array<{ url: string; authorization: string | null; clientSecret: string | null; workspace: string | null }> = []
    const d = await deps({
      fetchFn: (async (url: string, init: RequestInit) => {
        const headers = new Headers(init.headers)
        seen.push({
          url,
          authorization: headers.get('authorization'),
          clientSecret: headers.get('x-client-secret'),
          workspace: headers.get('x-workspace-id'),
        })
        return Response.json({
          echoedPrimary: headers.get('authorization'),
          echoedClientSecret: headers.get('x-client-secret'),
          echoedWorkspace: headers.get('x-workspace-id'),
        })
      }) as unknown as typeof fetch,
    })
    const name = uname()
    const docWithoutNote = Object.fromEntries(Object.entries(doc).filter(([key]) => key !== 'unverified_note'))
    const multiDoc = {
      ...docWithoutNote,
      verification: 'verified',
      official_documentation_links: [{ title: 'Example API docs', url: 'https://example.com/docs' }],
      service_adapter: {
        api_base_url: 'https://api.example.com',
        auth_header: 'Authorization',
        auth_scheme: 'Bearer',
        credential_fields: [
          { id: 'client_secret', label: 'Client secret', required: true, secret: true },
          { id: 'workspace_id', label: 'Workspace ID', required: false, secret: true },
        ],
        auth_field_headers: [
          { field: 'client_secret', header: 'X-Client-Secret', scheme: 'Raw' },
          { field: 'workspace_id', header: 'X-Workspace-ID', scheme: 'Raw' },
        ],
        cli_tools: [],
      },
    }
    const requested = await requestRegistration(d.db, {
      name, service: 'Example API', purpose: 'Use one account only', doc: multiDoc,
      requestedBy: 'runner:multi-field', now: d.now,
    })
    if (!requested.ok) throw new Error(requested.error)
    const primary = 'primary-example-token-value'
    const clientSecret = 'client-secret-example-value'
    const workspace = 'workspace-secret-example-value'
    const stored = await storeCredentialValue(d.db, d.encryptionKey, {
      credentialId: requested.value.credentialId, value: primary,
      authFields: { client_secret: clientSecret, workspace_id: workspace },
      authFieldIds: ['client_secret', 'workspace_id'],
      requiredAuthFields: ['client_secret'],
      connectionLabel: 'Production', providerAccountId: 'acct-9001',
      lifetime: 'permanent', expiresAt: null, visible: true, delivery: 'proxy',
      allowedHosts: ['api.example.com'], authHeader: 'Authorization', authScheme: 'Bearer', now: d.now,
    }, { requirePending: true })
    if (!stored.ok) throw new Error(stored.error)

    const response = await useCredential(d, await sessionHeader(d), {
      name, method: 'GET', url: 'https://api.example.com/me',
    })
    expect(response.status).toBe(200)
    expect(seen).toEqual([{
      url: 'https://api.example.com/me',
      authorization: 'Bearer ' + primary,
      clientSecret,
      workspace,
    }])
    const responseText = JSON.stringify(response.body)
    expect(responseText).not.toContain(primary)
    expect(responseText).not.toContain(clientSecret)
    expect(responseText).not.toContain(workspace)
    expect(responseText).toContain('[REDACTED]')
    const [metadata] = await d.db.select({
      connectionLabel: schema.credential.connectionLabel,
      providerAccountId: schema.credential.providerAccountId,
      encrypted: schema.credential.valueEncrypted,
    }).from(schema.credential).where(orm.eq(schema.credential.id, requested.value.credentialId))
    expect(metadata).toMatchObject({ connectionLabel: 'Production', providerAccountId: 'acct-9001' })
    expect(metadata?.encrypted).not.toContain(clientSecret)
    expect(metadata?.encrypted).not.toContain(workspace)
  })
})

describe('use (proxy)', () => {
  test('loads proxy settings only after an active proxy credential is accepted', async () => {
    let settingsReads = 0
    const d = await deps({
      getProxyTimeoutMs: async () => { settingsReads += 1; return 20_000 },
    })
    const header = await sessionHeader(d)

    expect((await registry(d, header)).status).toBe(200)
    expect(settingsReads).toBe(0)

    expect((await useCredential(d, header, { name: 'MISSING_CREDENTIAL', ...call })).status).toBe(404)
    expect(settingsReads).toBe(0)

    const cred = await activeCredential(d)
    expect((await useCredential(d, header, { name: cred.name, ...call })).status).toBe(200)
    expect(settingsReads).toBe(1)
  })

  test('schedules audit, usage and last-used writes after returning the provider response', async () => {
    const scheduled: Promise<unknown>[] = []
    const d = await deps({ waitUntil: (promise) => { scheduled.push(promise) } })
    const cred = await activeCredential(d)
    const res = await useCredential(d, await sessionHeader(d), { name: cred.name, ...call })

    expect(res.status).toBe(200)
    expect(scheduled).toHaveLength(1)
    await scheduled[0]

    const audits = await d.db.select().from(schema.credentialAudit).where(orm.and(
      orm.eq(schema.credentialAudit.credentialName, cred.name),
      orm.eq(schema.credentialAudit.action, 'proxy_use'),
    ))
    expect(audits.some((entry) => entry.result === 'ok')).toBe(true)
    const usage = await d.db.select().from(schema.credentialUsageHourly).where(orm.eq(schema.credentialUsageHourly.credentialId, cred.id))
    expect(usage.reduce((total, row) => total + row.requestCount, 0)).toBe(1)
    const [row] = await d.db.select({ lastUsedAt: schema.credential.lastUsedAt }).from(schema.credential).where(orm.eq(schema.credential.id, cred.id))
    expect(row?.lastUsedAt).toBe(d.now)
  })

  test('schedules upstream error audit and usage without changing the provider error', async () => {
    const scheduled: Promise<unknown>[] = []
    const d = await deps({
      waitUntil: (promise) => { scheduled.push(promise) },
      fetchFn: (async () => { throw new Error('upstream unavailable') }) as unknown as typeof fetch,
    })
    const cred = await activeCredential(d)
    const res = await useCredential(d, await sessionHeader(d), { name: cred.name, ...call })

    expect(res).toEqual({ status: 502, body: { error: 'upstream_error' } })
    expect(scheduled).toHaveLength(1)
    await scheduled[0]

    const audits = await d.db.select().from(schema.credentialAudit).where(orm.and(
      orm.eq(schema.credentialAudit.credentialName, cred.name),
      orm.eq(schema.credentialAudit.action, 'proxy_use'),
    ))
    expect(audits.some((entry) => entry.result === 'upstream_error')).toBe(true)
    const usage = await d.db.select().from(schema.credentialUsageHourly).where(orm.eq(schema.credentialUsageHourly.credentialId, cred.id))
    expect(usage.reduce((total, row) => total + row.errorCount, 0)).toBe(1)
  })

  test('performs the call, returns the response, never the token, and audits it', async () => {
    const seen: Array<{ url: string; auth: string | null }> = []
    const d = await deps({
      fetchFn: (async (url: string, init: RequestInit) => {
        seen.push({ url, auth: new Headers(init.headers).get('authorization') })
        return Response.json({ echoed: SECRET })
      }) as unknown as typeof fetch,
    })
    const cred = await activeCredential(d)
    const res = await useCredential(d, await sessionHeader(d), { name: cred.name, ...call, purpose: '' })
    expect(res.status).toBe(200)
    expect(JSON.stringify(res.body)).not.toContain(SECRET)
    expect(seen[0]).toEqual({ url: call.url, auth: `Bearer ${SECRET}` })
    const log = await d.db.select().from(schema.credentialAudit).where(orm.and(orm.eq(schema.credentialAudit.credentialName, cred.name), orm.eq(schema.credentialAudit.action, 'proxy_use')))
    expect(log[0]).toMatchObject({ result: 'ok', purpose: '', actor: 'runner:o/r#9.1' })
    expect(JSON.stringify(log)).not.toContain(SECRET)
    const [row] = await d.db.select({ lastUsedAt: schema.credential.lastUsedAt }).from(schema.credential).where(orm.eq(schema.credential.id, cred.id))
    expect(row?.lastUsedAt).toBe(d.now)
  })

  test('disabled, hidden, deleted and unknown credentials all look the same', async () => {
    const d = await deps()
    const header = await sessionHeader(d)
    const a = await activeCredential(d)
    const b = await activeCredential(d)
    const c = await activeCredential(d)
    await setEnabled(d.db, a.id, false, d.now)
    await setVisibility(d.db, b.id, false, d.now)
    await deleteCredential(d.db, c.id, d.now)
    for (const name of [a.name, b.name, c.name, 'DOES_NOT_EXIST']) {
      expect(await useCredential(d, header, { name, ...call })).toEqual({ status: 404, body: { error: 'unavailable' } })
    }
  })

  test('a host that was not approved by the owner is refused', async () => {
    let called = false
    const d = await deps({ fetchFn: (async () => { called = true; return new Response('x') }) as unknown as typeof fetch })
    const cred = await activeCredential(d)
    const res = await useCredential(d, await sessionHeader(d), { name: cred.name, method: 'GET', url: 'https://evil.example/steal' })
    expect(res).toEqual({ status: 403, body: { error: 'host_not_allowed' } })
    expect(called).toBe(false)
  })

  test('legacy Inject rows fail closed and cannot use the proxy', async () => {
    const d = await deps()
    const cred = await activeCredential(d)
    await d.db.update(schema.credential).set({ delivery: 'inject' as never }).where(orm.eq(schema.credential.id, cred.id))
    expect((await useCredential(d, await sessionHeader(d), { name: cred.name, ...call })).body).toEqual({ error: 'not_a_proxy_credential' })
  })

  test.each([
    ['Railway', 'backboard.railway.app', 'https://backboard.railway.app/graphql'],
    ['GitHub', 'api.github.com', 'https://api.github.com/user'],
  ])('%s credential proxy requests never disclose the token', async (provider, host, url) => {
    const seen: Array<{ authorization: string | null; host: string }> = []
    const d = await deps({
      fetchFn: (async (target: string, init: RequestInit) => {
        seen.push({ authorization: new Headers(init.headers).get('authorization'), host: new URL(target).host })
        return Response.json({ data: { ok: true }, echo: SECRET })
      }) as unknown as typeof fetch,
    })
    const name = uname()
    const req = await requestRegistration(d.db, { name, service: provider, purpose: 'API operation', doc, requestedBy: 'runner:test', now: d.now })
    if (!req.ok) throw new Error(req.error)
    const stored = await storeCredentialValue(d.db, d.encryptionKey, {
      credentialId: req.value.credentialId, value: SECRET, lifetime: 'permanent', expiresAt: null,
      visible: true, delivery: 'proxy', allowedHosts: [host], now: d.now,
    })
    if (!stored.ok) throw new Error(stored.error)
    const result = await useCredential(d, await sessionHeader(d), { name, method: 'GET', url, purpose: SECRET })
    expect(result.status).toBe(200)
    expect(seen).toEqual([{ authorization: 'Bearer ' + SECRET, host }])
    expect(JSON.stringify(result.body)).not.toContain(SECRET)
    const audits = await d.db.select().from(schema.credentialAudit).where(orm.eq(schema.credentialAudit.credentialName, name))
    expect(JSON.stringify(audits)).not.toContain(SECRET)
    expect(audits.find((entry) => entry.action === 'proxy_use')?.purpose).toBe('')
  })

  test('malformed input is rejected before anything is decrypted', async () => {
    const d = await deps()
    const header = await sessionHeader(d)
    for (const input of [
      { name: 1, ...call }, { name: 'X', method: 5, url: call.url }, { name: 'X', method: 'GET', url: call.url, headers: [] },
      { name: 'X', method: 'GET', url: call.url, headers: { a: 1 } }, { name: 'X', method: 'POST', url: call.url, body: 7 },
    ]) {
      expect((await useCredential(d, header, input as never)).status).toBe(400)
    }
  })

  test('uses the owner-configured proxy rate limit independently for each credential', async () => {
    const d = await deps({ getVaultPreferences: async () => ({ ...DEFAULT_VAULT_PREFERENCES, proxyRequestsPerMinute: 2 }) })
    const first = await activeCredential(d)
    const second = await activeCredential(d)
    const header = await sessionHeader(d)

    expect((await useCredential(d, header, { name: first.name, ...call })).status).toBe(200)
    expect((await useCredential(d, header, { name: first.name, ...call })).status).toBe(200)
    expect((await useCredential(d, header, { name: first.name, ...call })).status).toBe(429)
    expect((await useCredential(d, header, { name: second.name, ...call })).status).toBe(200)
  })

  test('does not carry a deleted credential rate limit into a new credential reusing its name', async () => {
    const d = await deps({ getVaultPreferences: async () => ({ ...DEFAULT_VAULT_PREFERENCES, proxyRequestsPerMinute: 1 }) })
    const previous = await activeCredential(d)
    const header = await sessionHeader(d)
    expect((await useCredential(d, header, { name: previous.name, ...call })).status).toBe(200)
    await deleteCredential(d.db, previous.id, d.now + 1)

    const registered = await requestRegistration(d.db, {
      name: previous.name, service: 'Cloudflare', purpose: 'Replacement credential', doc,
      requestedBy: 'runner:replacement', now: d.now + 2,
    })
    if (!registered.ok) throw new Error(registered.error)
    const stored = await storeCredentialValue(d.db, d.encryptionKey, {
      credentialId: registered.value.credentialId, value: SECRET, lifetime: 'permanent', expiresAt: null,
      visible: true, delivery: 'proxy', allowedHosts: ['api.cloudflare.com'], now: d.now + 2,
    })
    if (!stored.ok) throw new Error(stored.error)

    expect((await useCredential({ ...d, now: d.now + 3 }, header, { name: previous.name, ...call })).status).toBe(200)
  })

  test('is rate limited per credential', async () => {
    const d = await deps()
    const cred = await activeCredential(d)
    const header = await sessionHeader(d)
    for (let i = 0; i < USE_LIMIT_PER_MINUTE; i++) expect((await useCredential(d, header, { name: cred.name, ...call })).status).toBe(200)
    expect((await useCredential(d, header, { name: cred.name, ...call })).status).toBe(429)
  })
})


describe('atomic Runner rate-limit reservations', () => {
  test('does not over-issue slots under a concurrent burst', async () => {
    const db = getDb()
    const subject = `parallel-${crypto.randomUUID()}`
    const now = Date.now() + 48 * 60 * 60_000
    const outcomes = await Promise.all(Array.from({ length: 32 }, () => reserveRunnerRateLimit(db, {
      scope: 'session', subject, now, windowMs: 60_000, limit: 5,
    })))
    const accepted = outcomes.filter((id): id is string => id !== null)
    expect(accepted).toHaveLength(5)
    await Promise.all(accepted.map((id) => releaseRunnerRateLimitReservation(db, id)))
  })

  test('isolates scopes and subjects and applies the sliding-window cutoff', async () => {
    const db = getDb()
    const subject = `scope-${crypto.randomUUID()}`
    const now = Date.now() + 48 * 60 * 60_000
    const first = await reserveRunnerRateLimit(db, { scope: 'registration', subject, now, windowMs: 60_000, limit: 1 })
    expect(first).toBeTruthy()
    expect(await reserveRunnerRateLimit(db, { scope: 'registration', subject, now: now + 1, windowMs: 60_000, limit: 1 })).toBeNull()
    const otherScope = await reserveRunnerRateLimit(db, { scope: 'session', subject, now: now + 1, windowMs: 60_000, limit: 1 })
    expect(otherScope).toBeTruthy()
    const nextWindow = await reserveRunnerRateLimit(db, { scope: 'registration', subject, now: now + 60_001, windowMs: 60_000, limit: 1 })
    expect(nextWindow).toBeTruthy()
    await Promise.all([first, otherScope, nextWindow].filter((id): id is string => Boolean(id)).map((id) => releaseRunnerRateLimitReservation(db, id)))
  })

  test('prunes old reservations without touching active windows', async () => {
    const db = getDb()
    const subject = `cleanup-${crypto.randomUUID()}`
    const now = Date.now() + 48 * 60 * 60_000
    const old = await reserveRunnerRateLimit(db, { scope: 'session', subject, now: now - 4 * 60 * 60_000, windowMs: 60_000, limit: 1 })
    const fresh = await reserveRunnerRateLimit(db, { scope: 'session', subject, now, windowMs: 60_000, limit: 2 })
    expect(old).toBeTruthy()
    expect(fresh).toBeTruthy()
    await cleanupRunnerRateLimitEvents(db, now)
    const rows = await db.select({ id: schema.runnerRateLimitEvent.id }).from(schema.runnerRateLimitEvent)
      .where(orm.inArray(schema.runnerRateLimitEvent.id, [old!, fresh!]))
    expect(rows.map((row) => row.id)).toEqual([fresh])
    await releaseRunnerRateLimitReservation(db, fresh!)
  })
})
