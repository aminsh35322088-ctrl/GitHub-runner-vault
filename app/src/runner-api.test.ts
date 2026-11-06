import { describe, expect, test } from 'vitest'
import * as orm from 'drizzle-orm'
import { getDb, schema } from 'db'
import { app } from './app.tsx'
import { loadVaultAccessEnabled, loadVaultAccessState, saveVaultAccessEnabled } from './lib/vault-observability.ts'
import { parseRunnerBody } from './runner-api.ts'
import { MAX_REQUEST_BODY } from './lib/proxy.ts'

const call = (method: string, path: string, body?: unknown) =>
  app.handle(new Request(`https://vault.test${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer aaaaaaaaaa.bbbbbbbbbb.cccccccccc' },
    body: body === undefined ? undefined : JSON.stringify(body),
  }))

describe('runner HTTP surface', () => {
  test('session exchange fails closed (503, no-store) when OIDC policy is not configured', async () => {
    const res = await call('POST', '/api/runner/session')
    expect(res.status).toBe(503)
    expect(res.headers.get('cache-control')).toBe('no-store')
    expect(await res.json()).toEqual({ error: 'vault_not_configured' })
  })

  test.each([
    ['GET', '/api/runner/registry', undefined],
    ['GET', '/api/runner/integrations', undefined],
    ['POST', '/api/runner/registrations', { name: 'X' }],
    ['POST', '/api/runner/use', { name: 'X', method: 'GET', url: 'https://example.com' }],
  ])('%s %s does not require OIDC policy to reject an invalid runner session', async (method, path, body) => {
    const res = await call(method, path, body)
    expect(res.status).toBe(401)
    expect(res.headers.get('cache-control')).toBe('no-store')
    expect(await res.json()).toEqual({ error: 'unauthorized' })
  })

  test('global Vault disable blocks every Runner endpoint before credential handling', async () => {
    const db = getDb()
    const [previousAccess] = await db.select().from(schema.vaultSetting)
      .where(orm.eq(schema.vaultSetting.key, 'vault_access_enabled')).limit(1)
    const [previousRevocation] = await db.select().from(schema.vaultSetting)
      .where(orm.eq(schema.vaultSetting.key, 'runner_revoked_before')).limit(1)
    const [previousEpoch] = await db.select().from(schema.vaultSetting)
      .where(orm.eq(schema.vaultSetting.key, 'vault_access_epoch')).limit(1)
    const now = Date.now()
    const metadata = btoa(JSON.stringify({
      name: 'CF_TOKEN', method: 'GET', url: 'https://api.cloudflare.com/client/v4/user',
    })).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
    const requests: Request[] = [
      new Request('https://vault.test/api/runner/session', { method: 'POST' }),
      new Request('https://vault.test/api/runner/registry'),
      new Request('https://vault.test/api/runner/integrations'),
      new Request('https://vault.test/api/runner/registrations', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'CF_TOKEN', service: 'Cloudflare', doc: {} }),
      }),
      new Request('https://vault.test/api/runner/use', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'CF_TOKEN', method: 'GET', url: 'https://api.cloudflare.com/client/v4/user' }),
      }),
      new Request('https://vault.test/api/runner/use', {
        method: 'POST', headers: {
          'Content-Type': 'application/octet-stream',
          'X-Vault-Proxy-Metadata': metadata,
        }, body: 'ignored',
      }),
    ]
    try {
      await saveVaultAccessEnabled(db, false, now)
      for (const request of requests) {
        const res = await app.handle(request)
        expect(res.status, request.method + ' ' + new URL(request.url).pathname).toBe(403)
        expect(res.headers.get('cache-control')).toBe('no-store')
        expect(await res.json()).toEqual({ error: 'vault_disabled' })
      }
    } finally {
      await db.delete(schema.vaultSetting).where(orm.eq(schema.vaultSetting.key, 'vault_access_enabled'))
      await db.delete(schema.vaultSetting).where(orm.eq(schema.vaultSetting.key, 'runner_revoked_before'))
      await db.delete(schema.vaultSetting).where(orm.eq(schema.vaultSetting.key, 'vault_access_epoch'))
      if (previousAccess) await db.insert(schema.vaultSetting).values(previousAccess)
      if (previousRevocation) await db.insert(schema.vaultSetting).values(previousRevocation)
      if (previousEpoch) await db.insert(schema.vaultSetting).values(previousEpoch)
    }
  })

  test('disabled Vault access rejects POSTs before consuming their bodies', async () => {
    const db = getDb()
    const [previousAccess] = await db.select().from(schema.vaultSetting)
      .where(orm.eq(schema.vaultSetting.key, 'vault_access_enabled')).limit(1)
    const [previousEpoch] = await db.select().from(schema.vaultSetting)
      .where(orm.eq(schema.vaultSetting.key, 'vault_access_epoch')).limit(1)
    const [previousRevocation] = await db.select().from(schema.vaultSetting)
      .where(orm.eq(schema.vaultSetting.key, 'runner_revoked_before')).limit(1)
    let reads = 0
    const body = () => new ReadableStream<Uint8Array>({
      pull(controller) {
        reads++
        controller.enqueue(new TextEncoder().encode('{"name":"X"}'))
        controller.close()
      },
    }, { highWaterMark: 0 })
    try {
      await saveVaultAccessEnabled(db, false, Date.now())
      const registration = new Request('https://vault.test/api/runner/registrations', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: body(), duplex: 'half',
      } as RequestInit & { duplex: 'half' })
      const proxy = new Request('https://vault.test/api/runner/use', {
        method: 'POST', headers: { 'Content-Type': 'application/octet-stream' },
        body: body(), duplex: 'half',
      } as RequestInit & { duplex: 'half' })
      for (const request of [registration, proxy]) {
        const response = await app.handle(request)
        expect(response.status).toBe(403)
        expect(await response.json()).toEqual({ error: 'vault_disabled' })
      }
      expect(reads).toBe(0)
    } finally {
      const keys = ['vault_access_enabled', 'vault_access_epoch', 'runner_revoked_before']
      await db.delete(schema.vaultSetting).where(orm.inArray(schema.vaultSetting.key, keys))
      if (previousAccess) await db.insert(schema.vaultSetting).values(previousAccess)
      if (previousEpoch) await db.insert(schema.vaultSetting).values(previousEpoch)
      if (previousRevocation) await db.insert(schema.vaultSetting).values(previousRevocation)
    }
  })

  test('global access epoch advances on disable and survives re-enable', async () => {
    const db = getDb()
    const keys = ['vault_access_enabled', 'runner_revoked_before', 'vault_access_epoch']
    const previous = await db.select().from(schema.vaultSetting).where(orm.inArray(schema.vaultSetting.key, keys))
    const now = Date.now()
    try {
      const before = await loadVaultAccessState(db)
      await saveVaultAccessEnabled(db, false, now)
      const disabled = await loadVaultAccessState(db)
      expect(disabled).toEqual({ enabled: false, epoch: before.epoch + 1 })

      await saveVaultAccessEnabled(db, true, now + 1)
      const reenabled = await loadVaultAccessState(db)
      expect(reenabled).toEqual({ enabled: true, epoch: disabled.epoch })

      await saveVaultAccessEnabled(db, false, now + 2)
      const disabledAgain = await loadVaultAccessState(db)
      expect(disabledAgain).toEqual({ enabled: false, epoch: disabled.epoch + 1 })
    } finally {
      await db.delete(schema.vaultSetting).where(orm.inArray(schema.vaultSetting.key, keys))
      if (previous.length) await db.insert(schema.vaultSetting).values(previous)
    }
  })

  test('a malformed Vault access epoch fails the Runner gate closed', async () => {
    const db = getDb()
    const [previousAccess] = await db.select().from(schema.vaultSetting)
      .where(orm.eq(schema.vaultSetting.key, 'vault_access_enabled')).limit(1)
    const [previousEpoch] = await db.select().from(schema.vaultSetting)
      .where(orm.eq(schema.vaultSetting.key, 'vault_access_epoch')).limit(1)
    try {
      await saveVaultAccessEnabled(db, true, Date.now())
      await db.insert(schema.vaultSetting).values({
        key: 'vault_access_epoch', value: 'not-an-integer', updatedAt: Date.now(),
      }).onConflictDoUpdate({
        target: schema.vaultSetting.key,
        set: { value: 'not-an-integer', updatedAt: Date.now() },
      })
      // The Runner gate fails closed, but this Owner-side setting read stays
      // available so the dashboard can recover a malformed epoch.
      expect(await loadVaultAccessEnabled(db)).toBe(true)
      const res = await app.handle(new Request('https://vault.test/api/runner/registry'))
      expect(res.status).toBe(503)
      expect(res.headers.get('cache-control')).toBe('no-store')
      expect(await res.json()).toEqual({ error: 'vault_access_unavailable' })

      // The Owner can recover from malformed epoch data by disabling access;
      // the atomic upsert repairs the epoch and keeps the Owner dashboard live.
      await saveVaultAccessEnabled(db, false, Date.now() + 1)
      expect(await loadVaultAccessState(db)).toEqual({ enabled: false, epoch: 1 })
      await saveVaultAccessEnabled(db, true, Date.now() + 2)
      expect(await loadVaultAccessState(db)).toEqual({ enabled: true, epoch: 1 })
    } finally {
      await db.delete(schema.vaultSetting).where(orm.eq(schema.vaultSetting.key, 'vault_access_enabled'))
      await db.delete(schema.vaultSetting).where(orm.eq(schema.vaultSetting.key, 'vault_access_epoch'))
      if (previousAccess) await db.insert(schema.vaultSetting).values(previousAccess)
      if (previousEpoch) await db.insert(schema.vaultSetting).values(previousEpoch)
    }
  })

  test('malformed and non-object JSON bodies return a generic 400', async () => {
    for (const body of ['{', '[]', 'null', '"secret-value"']) {
      const res = await app.handle(new Request('https://vault.test/api/runner/use', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer aaaaaaaaaa.bbbbbbbbbb.cccccccccc' },
        body,
      }))
      expect(res.status).toBe(400)
      expect(res.headers.get('cache-control')).toBe('no-store')
      expect(await res.json()).toEqual({ error: 'invalid_request' })
    }
  })

  test('JSON parser enforces its byte limit before parsing', async () => {
    const request = new Request('https://vault.test/api/runner/use', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': '1025' },
      body: '{}',
    })
    expect(await parseRunnerBody(request, 1024)).toEqual({ ok: false, error: 'body_too_large' })
  })

  test('raw proxy transport rejects an oversized declared payload before reading it', async () => {
    const metadata = btoa(JSON.stringify({ name: 'X', method: 'POST', url: 'https://api.example.com/upload' }))
      .replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
    const res = await app.handle(new Request('https://vault.test/api/runner/use', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-Vault-Proxy-Metadata': metadata,
        'Content-Length': String(MAX_REQUEST_BODY + 1),
        Authorization: 'Bearer aaaaaaaaaa.bbbbbbbbbb.cccccccccc',
      },
      body: 'x',
    }))
    expect(res.status).toBe(413)
    expect(await res.json()).toEqual({ error: 'body_too_large' })
  })

  test('raw proxy transport rejects malformed metadata', async () => {
    const res = await app.handle(new Request('https://vault.test/api/runner/use', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-Vault-Proxy-Metadata': 'not-base64!',
        Authorization: 'Bearer aaaaaaaaaa.bbbbbbbbbb.cccccccccc',
      },
      body: 'x',
    }))
    expect(res.status).toBe(400)
    expect(await res.json()).toEqual({ error: 'invalid_request' })
  })

  test('no route returns a credential value endpoint of the old secrets API shape', async () => {
    const res = await call('GET', '/api/runner/secrets')
    expect([404, 405]).toContain(res.status)
  })
})
