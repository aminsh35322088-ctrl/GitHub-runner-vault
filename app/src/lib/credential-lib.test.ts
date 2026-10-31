import { describe, expect, test } from 'vitest'
import { getDb, schema } from 'db'
import * as orm from 'drizzle-orm'
import {
  CredentialCryptoError, decryptCredentialValue, encryptCredentialValue, importEncryptionKey,
} from './credential-crypto.ts'
import { availability, isExpired, publicReason } from './credential-policy.ts'
import { parseCredentialDoc, safeLink, cleanText, readStoredDoc } from './credential-docs.ts'
import {
  normalizeAllowedHosts, normalizeHost, readAllowedHosts, reservedName, validCredentialName,
} from './credential-input.ts'
import {
  consumeEnrollmentLink, createEnrollmentLink, hashLinkToken, peekEnrollmentLink, releaseEnrollmentLink, MAX_LINK_TTL_MS,
} from './enrollment.ts'

const KEY_B64 = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))

describe('credential encryption', () => {
  test('round trips and never stores plaintext', async () => {
    const key = await importEncryptionKey(KEY_B64)
    const { encrypted, iv } = await encryptCredentialValue(key, 'cred1', 1, 'cf-token-ABC123')
    expect(encrypted).not.toContain('ABC123')
    expect(await decryptCredentialValue(key, 'cred1', 1, encrypted, iv)).toBe('cf-token-ABC123')
  })

  test('same value encrypts differently each time (fresh IV)', async () => {
    const key = await importEncryptionKey(KEY_B64)
    const a = await encryptCredentialValue(key, 'cred1', 1, 'same')
    const b = await encryptCredentialValue(key, 'cred1', 1, 'same')
    expect(a.encrypted).not.toBe(b.encrypted)
    expect(a.iv).not.toBe(b.iv)
  })

  test('ciphertext is bound to its row and key version', async () => {
    const key = await importEncryptionKey(KEY_B64)
    const { encrypted, iv } = await encryptCredentialValue(key, 'cred1', 1, 'secret')
    await expect(decryptCredentialValue(key, 'cred2', 1, encrypted, iv)).rejects.toBeInstanceOf(CredentialCryptoError)
    await expect(decryptCredentialValue(key, 'cred1', 2, encrypted, iv)).rejects.toBeInstanceOf(CredentialCryptoError)
  })

  test('tampered ciphertext and wrong key fail closed', async () => {
    const key = await importEncryptionKey(KEY_B64)
    const other = await importEncryptionKey(btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))))
    const { encrypted, iv } = await encryptCredentialValue(key, 'c', 1, 'secret')
    const bytes = Uint8Array.from(atob(encrypted), (c) => c.charCodeAt(0))
    bytes[0] = bytes[0]! ^ 0xff
    const tampered = btoa(String.fromCharCode(...bytes))
    await expect(decryptCredentialValue(key, 'c', 1, tampered, iv)).rejects.toBeInstanceOf(CredentialCryptoError)
    await expect(decryptCredentialValue(other, 'c', 1, encrypted, iv)).rejects.toBeInstanceOf(CredentialCryptoError)
  })

  test.each([undefined, null, '', '   ', 'not base64!!', btoa('short'), btoa('x'.repeat(33))])(
    'rejects a missing or malformed key: %s',
    async (value) => {
      await expect(importEncryptionKey(value)).rejects.toBeInstanceOf(CredentialCryptoError)
    },
  )

  test('refuses to encrypt an empty value', async () => {
    const key = await importEncryptionKey(KEY_B64)
    await expect(encryptCredentialValue(key, 'c', 1, '')).rejects.toBeInstanceOf(CredentialCryptoError)
  })
})

describe('availability policy', () => {
  const now = 1_000_000
  const base = { status: 'active' as const, visible: true, expiresAt: null, hasValue: true }

  test('active + visible is usable', () => {
    expect(availability(base, now)).toEqual({ available: true })
  })

  test.each([
    [{ ...base, visible: false }, 'hidden'],
    [{ ...base, status: 'disabled' as const }, 'disabled'],
    [{ ...base, status: 'pending' as const }, 'pending'],
    [{ ...base, expiresAt: now }, 'expired'],
    [{ ...base, expiresAt: now - 1 }, 'expired'],
    [{ ...base, hasValue: false }, 'no_value'],
  ])('not usable: %o', (state, reason) => {
    expect(availability(state, now)).toEqual({ available: false, reason })
  })

  test('a future expiry is still usable', () => {
    expect(availability({ ...base, expiresAt: now + 1 }, now).available).toBe(true)
    expect(isExpired(null, now)).toBe(false)
  })

  test('externally managed entries are discoverable without a value', () => {
    expect(availability({ ...base, hasValue: false, externallyManaged: true }, now).available).toBe(true)
  })

  test('hidden credentials never reveal expiry, and public reasons stay coarse', () => {
    expect(availability({ ...base, visible: false, expiresAt: now - 1 }, now)).toEqual({ available: false, reason: 'hidden' })
    expect(publicReason('hidden')).toBe('unavailable')
    expect(publicReason('disabled')).toBe('unavailable')
    expect(publicReason('expired')).toBe('expired')
  })
})

describe('credential input validation', () => {
  test('names must look like environment variable names', () => {
    expect(validCredentialName('RAILWAY_API_TOKEN')).toBe(true)
    for (const bad of ['railway', '1TOKEN', 'A', 'HAS SPACE', 'A-B', 'A'.repeat(65), '', null, 5]) {
      expect(validCredentialName(bad)).toBe(false)
    }
  })

  test('reserved names that change process behaviour are refused', () => {
    for (const name of ['PATH', 'LD_PRELOAD', 'NODE_OPTIONS', 'HTTPS_PROXY', 'BASH_ENV', 'LD_ANYTHING']) {
      expect(reservedName(name)).toBe(true)
    }
    expect(reservedName('CLOUDFLARE_API_TOKEN')).toBe(false)
  })

  test('hosts must be exact public hostnames', () => {
    expect(normalizeHost('API.Cloudflare.com')).toBe('api.cloudflare.com')
    expect(normalizeHost('api.cloudflare.com.')).toBe('api.cloudflare.com')
    for (const bad of [
      '*.cloudflare.com', 'localhost', '127.0.0.1', '169.254.169.254', '10.0.0.5', 'metadata.internal',
      'printer.local', 'host:8443', 'https://a.com', 'a.com/path', 'user@a.com', 'nodots', '-a.com', '', 7,
    ]) {
      expect(normalizeHost(bad)).toBeNull()
    }
  })

  test('host lists are validated, de-duplicated and bounded', () => {
    expect(normalizeAllowedHosts(['a.com', 'A.com', 'b.org'])).toEqual({ ok: true, hosts: ['a.com', 'b.org'] })
    expect(normalizeAllowedHosts(['a.com', '*.b.org']).ok).toBe(false)
    expect(normalizeAllowedHosts(Array.from({ length: 11 }, (_, i) => `h${i}.com`)).ok).toBe(false)
    expect(normalizeAllowedHosts('a.com').ok).toBe(false)
  })

  test('a corrupt stored host list means "calls nothing"', () => {
    expect(readAllowedHosts('not json')).toEqual([])
    expect(readAllowedHosts('["127.0.0.1"]')).toEqual([])
    expect(readAllowedHosts('["api.a.com"]')).toEqual(['api.a.com'])
  })
})

const goodDoc = {
  overview: 'Needed to list Railway projects.',
  task: 'List Railway projects',
  token_type: 'Account token',
  creation_steps: ['Open the Railway dashboard', 'Create an account token'],
  required_permissions: [{ name: 'Projects', level: 'Read', why: 'Listing projects needs read access' }],
  unnecessary_permissions: ['Deployments write'],
  security_notes: ['Set an expiry'],
  expiration_guidance: ['30 days'],
  official_documentation_links: [{ title: 'Railway API', url: 'https://docs.railway.com/integrations/api' }],
  verification: 'verified' as const,
}

describe('credential documentation', () => {
  test('accepts a well-formed document', () => {
    const parsed = parseCredentialDoc(goodDoc)
    expect(parsed.ok).toBe(true)
    if (parsed.ok) expect(readStoredDoc(parsed.json)?.task).toBe('List Railway projects')
  })

  test.each([
    ['unknown key', { ...goodDoc, html: '<script>' }],
    ['missing field', { ...goodDoc, overview: undefined }],
    ['too many steps', { ...goodDoc, creation_steps: Array.from({ length: 21 }, () => 'x') }],
    ['too long text', { ...goodDoc, overview: 'x'.repeat(2001) }],
    ['verified without a link', { ...goodDoc, official_documentation_links: [] }],
    ['unverified without a note', { ...goodDoc, verification: 'unverified' }],
    ['non-string', { ...goodDoc, task: 5 }],
  ])('rejects %s', (_label, doc) => {
    expect(parseCredentialDoc(doc).ok).toBe(false)
  })

  test('unverified documents must say what is unverified', () => {
    const parsed = parseCredentialDoc({ ...goodDoc, verification: 'unverified', unverified_note: 'Docs page was unreachable' })
    expect(parsed.ok).toBe(true)
  })

  test.each([
    'http://docs.railway.com/x',
    'javascript:alert(1)',
    'https://user:pw@docs.railway.com/x',
    'https://192.168.1.1/x',
    'https://localhost/x',
    'https://intranet.corp/x',
    'https://docs.railway.com:8443/x',
    'https://nodots/x',
    'not a url',
    `https://docs.railway.com/${'a'.repeat(300)}`,
  ])('rejects unsafe link %s', (url) => {
    expect(safeLink(url)).toBeNull()
  })

  test('safe links are normalized and fragments dropped', () => {
    expect(safeLink('https://docs.railway.com/integrations/api#top')).toBe('https://docs.railway.com/integrations/api')
  })

  test('control and bidi-override characters are stripped', () => {
    expect(cleanText('ok‮evil\u0000​ text')).toBe('okevil text')
    const parsed = parseCredentialDoc({ ...goodDoc, overview: 'Open‮ the page' })
    expect(parsed.ok && parsed.doc.overview).toBe('Open the page')
  })

  test('an unparseable stored document reads as null', () => {
    expect(readStoredDoc('{}')).toBeNull()
    expect(readStoredDoc('garbage')).toBeNull()
  })
})

async function makeCredential(name = 'TEST_TOKEN') {
  const db = getDb()
  const id = `cred_${crypto.randomUUID()}`
  const now = Date.now()
  await db.insert(schema.credential).values({
    id, name: `${name}_${Math.floor(Math.random() * 1e9)}`, service: 'Test', purpose: 'testing', createdAt: now, updatedAt: now,
  })
  return { db, id }
}

describe('enrollment links', () => {
  test('a link works once: peek does not consume, consume does', async () => {
    const { db, id } = await makeCredential()
    const now = Date.now()
    const { token } = await createEnrollmentLink(db, { credentialId: id, kind: 'register', requestedBy: 'runner-1', now })
    expect(await peekEnrollmentLink(db, token, now)).not.toBeNull()
    expect(await peekEnrollmentLink(db, token, now)).not.toBeNull()
    const first = await consumeEnrollmentLink(db, token, now)
    expect(first?.credentialId).toBe(id)
    expect(await consumeEnrollmentLink(db, token, now)).toBeNull()
    expect(await peekEnrollmentLink(db, token, now)).toBeNull()
  })

  test('concurrent submissions: exactly one wins', async () => {
    const { db, id } = await makeCredential()
    const now = Date.now()
    const { token } = await createEnrollmentLink(db, { credentialId: id, kind: 'register', requestedBy: '', now })
    const results = await Promise.all(Array.from({ length: 8 }, () => consumeEnrollmentLink(db, token, now)))
    expect(results.filter((r) => r !== null)).toHaveLength(1)
  })

  test('a failed registration can release its consumed link once', async () => {
    const { db, id } = await makeCredential()
    const now = Date.now()
    const { token } = await createEnrollmentLink(db, { credentialId: id, kind: 'register', requestedBy: 'owner', now })
    const used = await consumeEnrollmentLink(db, token, now)
    expect(used).not.toBeNull()
    expect(await peekEnrollmentLink(db, token, now)).toBeNull()
    expect(await releaseEnrollmentLink(db, used!.id, now)).toBe(true)
    expect(await peekEnrollmentLink(db, token, now)).not.toBeNull()
    expect(await releaseEnrollmentLink(db, used!.id, now)).toBe(false)
  })

  test('concurrent link creation leaves exactly one active registration link', async () => {
    const { db, id } = await makeCredential()
    const now = Date.now()
    const results = await Promise.allSettled(Array.from({ length: 8 }, (_, i) =>
      createEnrollmentLink(db, { credentialId: id, kind: 'register', requestedBy: 'owner-' + i, now })))
    expect(results.every((item) => item.status === 'fulfilled')).toBe(true)
    const active = await db.select().from(schema.enrollmentLink).where(orm.and(
      orm.eq(schema.enrollmentLink.credentialId, id),
      orm.eq(schema.enrollmentLink.kind, 'register'),
      orm.isNull(schema.enrollmentLink.usedAt),
    ))
    expect(active).toHaveLength(1)
  })

  test('expired links are rejected', async () => {
    const { db, id } = await makeCredential()
    const now = Date.now()
    const { token, expiresAt } = await createEnrollmentLink(db, { credentialId: id, kind: 'edit', requestedBy: '', now, ttlMs: 60_000 })
    expect(await peekEnrollmentLink(db, token, expiresAt)).toBeNull()
    expect(await consumeEnrollmentLink(db, token, expiresAt)).toBeNull()
    expect(await consumeEnrollmentLink(db, token, expiresAt - 1)).not.toBeNull()
  })

  test('ttl is clamped to the maximum', async () => {
    const { db, id } = await makeCredential()
    const now = Date.now()
    const { expiresAt } = await createEnrollmentLink(db, { credentialId: id, kind: 'register', requestedBy: '', now, ttlMs: 24 * 3600_000 })
    expect(expiresAt - now).toBe(MAX_LINK_TTL_MS)
  })

  test('a new link invalidates the previous unused link of the same kind', async () => {
    const { db, id } = await makeCredential()
    const now = Date.now()
    const a = await createEnrollmentLink(db, { credentialId: id, kind: 'register', requestedBy: '', now })
    const b = await createEnrollmentLink(db, { credentialId: id, kind: 'register', requestedBy: '', now })
    expect(await peekEnrollmentLink(db, a.token, now)).toBeNull()
    expect(await peekEnrollmentLink(db, b.token, now)).not.toBeNull()
  })

  test('only the hash of the token is stored', async () => {
    const { db, id } = await makeCredential()
    const { token } = await createEnrollmentLink(db, { credentialId: id, kind: 'register', requestedBy: '', now: Date.now() })
    const rows = await db.select().from(schema.enrollmentLink).where(orm.eq(schema.enrollmentLink.credentialId, id))
    expect(JSON.stringify(rows)).not.toContain(token)
    expect(rows[0]?.tokenHash).toBe(await hashLinkToken(token))
  })

  test.each(['', 'lnk_short', 'x'.repeat(47), 'lnk_' + '!'.repeat(43)])('malformed token %s is rejected without a query', async (bad) => {
    const db = getDb()
    expect(await peekEnrollmentLink(db, bad, Date.now())).toBeNull()
    expect(await consumeEnrollmentLink(db, bad, Date.now())).toBeNull()
  })
})

describe('credential table constraints', () => {
  test('an active credential must hold a value unless externally managed', async () => {
    const { db, id } = await makeCredential()
    await expect(db.update(schema.credential).set({ status: 'active' }).where(orm.eq(schema.credential.id, id))).rejects.toThrow()
    await expect(db.update(schema.credential).set({ status: 'active', externallyManaged: true }).where(orm.eq(schema.credential.id, id))).resolves.toBeDefined()
  })

  test('an externally managed credential can never hold a value', async () => {
    const { db, id } = await makeCredential()
    await expect(db.update(schema.credential)
      .set({ externallyManaged: true, valueEncrypted: 'x', valueIv: 'y' })
      .where(orm.eq(schema.credential.id, id))).rejects.toThrow()
  })

  test('names are unique and must look like environment variable names', async () => {
    const db = getDb()
    const now = Date.now()
    await expect(db.insert(schema.credential).values({ id: 'bad1', name: 'lowercase', service: 's', purpose: 'p', createdAt: now, updatedAt: now })).rejects.toThrow()
  })

  test('the audit log is append-only', async () => {
    const db = getDb()
    const id = `audit_${crypto.randomUUID()}`
    await db.insert(schema.credentialAudit).values({ id, action: 'test', actor: 'owner' })
    await expect(db.update(schema.credentialAudit).set({ result: 'tampered' }).where(orm.eq(schema.credentialAudit.id, id))).rejects.toThrow()
    await expect(db.delete(schema.credentialAudit).where(orm.eq(schema.credentialAudit.id, id))).rejects.toThrow()
  })
})

import { formatAuthValue, normalizeAuthStyle } from './credential-input.ts'

describe('auth style helpers', () => {
  test('formats the header value for each scheme', () => {
    expect(formatAuthValue('Bearer', 'tok')).toBe('Bearer tok')
    expect(formatAuthValue('Token', 'tok')).toBe('Token tok')
    expect(formatAuthValue('Raw', 'tok')).toBe('tok')
  })
  test('unknown schemes are refused', () => {
    expect(normalizeAuthStyle('Authorization', 'Basic').ok).toBe(false)
    expect(normalizeAuthStyle('Authorization', undefined).ok).toBe(false)
    expect(normalizeAuthStyle('Authorization', 'Bearer').ok).toBe(true)
  })
})
