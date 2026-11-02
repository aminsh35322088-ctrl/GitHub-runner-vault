import { describe, expect, test } from 'vitest'
import { getDb, schema } from 'db'
import * as orm from 'drizzle-orm'
import { importEncryptionKey } from './credential-crypto.ts'
import { deleteCredential, requestRegistration, storeCredentialValue, setEnabled, setVisibility } from './credential-service.ts'
import { GITHUB_OIDC_ISSUER, type OidcPolicy } from './oidc.ts'
import { deriveSessionKey, issueRunnerSession, revokeRunnerSessions } from './runner-session.ts'
import { bearer, createSession, registry, requestCredential, useCredential, USE_LIMIT_PER_MINUTE, type RunnerDeps } from './runner-core.ts'

const KEY_B64 = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))
const SECRET = 'cfut_END_TO_END_SECRET_0123456789'
const SESSION_SECRET = 'session-secret-that-is-long-enough-123456'

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

async function activeCredential(d: RunnerDeps, opts: { visible?: boolean } = {}) {
  const name = uname()
  const req = await requestRegistration(d.db, { name, service: 'Cloudflare', purpose: 'Deploy', doc, requestedBy: 'runner:x', now: d.now })
  if (!req.ok) throw new Error(req.error)
  const stored = await storeCredentialValue(d.db, d.encryptionKey, {
    credentialId: req.value.credentialId, value: SECRET, lifetime: 'permanent', expiresAt: null, visible: opts.visible ?? true,
    delivery: 'proxy', allowedHosts: ['api.cloudflare.com'], now: d.now,
  })
  if (!stored.ok) throw new Error(stored.error)
  return { name, id: req.value.credentialId }
}

const call = { url: 'https://api.cloudflare.com/client/v4/user/tokens/verify', method: 'GET' }

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

  test('the issuer constant is the real GitHub one', () => {
    expect(GITHUB_OIDC_ISSUER).toBe('https://token.actions.githubusercontent.com')
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
    const res = await requestCredential(d, await sessionHeader(d), { name: uname(), service: 'Cloudflare', purpose: 'Deploy', doc })
    expect(res.status).toBe(200)
    expect((res.body as { link: string }).link).toMatch(/^https:\/\/vault\.test\/vault\/register\/lnk_[A-Za-z0-9_-]{43}$/)
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

describe('use (proxy)', () => {
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

  test('is rate limited per credential', async () => {
    const d = await deps()
    const cred = await activeCredential(d)
    const header = await sessionHeader(d)
    for (let i = 0; i < USE_LIMIT_PER_MINUTE; i++) expect((await useCredential(d, header, { name: cred.name, ...call })).status).toBe(200)
    expect((await useCredential(d, header, { name: cred.name, ...call })).status).toBe(429)
  })
})
