// Self-configuration for the vault, so a deployment needs no hand-made secrets.
//
//  - Keys: one random master key is generated on first use and kept in D1 (or
//    supplied as the optional VAULT_MASTER_KEY Worker secret, which wins). The
//    session-signing secret and the AES-256 credential key are both derived from
//    it with HKDF under separate labels. Explicit BETTER_AUTH_SECRET +
//    ENCRYPTION_KEY secrets (older deployments) keep working unchanged.
//  - GitHub sign-in: created through GitHub's app-manifest flow from /setup. The
//    client secret is stored encrypted; the app's creator becomes the owner.
//  - Setup is gated by SETUP_CODE, chosen by the deployer, because a fresh
//    *.workers.dev URL is discoverable before its owner first opens it.

import * as orm from 'drizzle-orm'
import { schema } from 'db'
import { decryptCredentialValue, encryptCredentialValue, importEncryptionKey } from './credential-crypto.ts'
import { normalizeOwnerId } from './owner.ts'

type Db = ReturnType<typeof import('db').getDb>
export type VaultEnv = Record<string, unknown>

const MASTER_KEY = 'master_key'
const GITHUB_CLIENT_ID = 'github_client_id'
const GITHUB_CLIENT_SECRET = 'github_client_secret'
const OWNER_ID = 'owner_github_id'
const SETUP_STATE = 'setup_state'
// The secret is bound to this label (see credential-crypto.ts) so it cannot be
// swapped with another encrypted row.
const SECRET_AAD_ID = 'setting-github-client-secret'

export const SETUP_COOKIE = 'vault_setup'
export const SETUP_SESSION_MS = 30 * 60_000
export const SETUP_MAX_FAILURES = 10
const SETUP_FAILURE_WINDOW_MS = 60 * 60_000
export const MIN_SETUP_CODE_LENGTH = 12

const enc = new TextEncoder()

function toB64(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s)
}
function fromB64(value: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(value), (c) => c.charCodeAt(0))
}
function nonEmpty(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value.trim() : null
}

// ── settings ──────────────────────────────────────────────────────

export async function getSetting(db: Db, key: string): Promise<string | null> {
  const [row] = await db.select({ value: schema.vaultSetting.value }).from(schema.vaultSetting).where(orm.eq(schema.vaultSetting.key, key)).limit(1)
  return row?.value ?? null
}

export async function putSetting(db: Db, key: string, value: string, now = Date.now()): Promise<void> {
  await db.insert(schema.vaultSetting)
    .values({ key, value, updatedAt: now })
    .onConflictDoUpdate({ target: schema.vaultSetting.key, set: { value, updatedAt: now } })
}

export async function deleteSetting(db: Db, key: string): Promise<void> {
  await db.delete(schema.vaultSetting).where(orm.eq(schema.vaultSetting.key, key))
}

// ── keys ──────────────────────────────────────────────────────────

export interface VaultKeys {
  /** Secret for BetterAuth cookies and runner-session signing (>= 32 chars). */
  authSecret: string
  /** AES-256-GCM key for stored credential values. */
  encryptionKey: CryptoKey
}

async function derive(master: Uint8Array<ArrayBuffer>, label: string): Promise<Uint8Array<ArrayBuffer>> {
  const base = await crypto.subtle.importKey('raw', master, 'HKDF', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: enc.encode('runner-vault/v1'), info: enc.encode(label) },
    base,
    256,
  )
  return new Uint8Array(bits)
}

/** Derive both keys from a master key. Exported for tests. */
export async function keysFromMaster(masterBase64: string): Promise<VaultKeys> {
  const master = fromB64(masterBase64)
  if (master.byteLength !== 32) throw new Error('master key must be exactly 32 bytes')
  const auth = await derive(master, 'better-auth-secret')
  const encryption = await derive(master, 'credential-encryption')
  return { authSecret: toB64(auth), encryptionKey: await importEncryptionKey(toB64(encryption)) }
}

let cachedKeys: Promise<VaultKeys> | null = null

export function loadVaultKeys(db: Db, e: VaultEnv): Promise<VaultKeys> {
  if (!cachedKeys) {
    cachedKeys = resolveKeys(db, e).catch((error) => {
      cachedKeys = null
      throw error
    })
  }
  return cachedKeys
}

/** Test helper. */
export function resetVaultKeyCache() { cachedKeys = null }

async function resolveKeys(db: Db, e: VaultEnv): Promise<VaultKeys> {
  const legacyAuth = nonEmpty(e.BETTER_AUTH_SECRET)
  const legacyKey = nonEmpty(e.ENCRYPTION_KEY)
  if (legacyAuth && legacyKey) {
    if (legacyAuth.length < 32) throw new Error('BETTER_AUTH_SECRET must be at least 32 characters')
    return { authSecret: legacyAuth, encryptionKey: await importEncryptionKey(legacyKey) }
  }
  const supplied = nonEmpty(e.VAULT_MASTER_KEY)
  if (supplied) return keysFromMaster(supplied)

  let stored = await getSetting(db, MASTER_KEY)
  if (!stored) {
    const fresh = toB64(crypto.getRandomValues(new Uint8Array(32)))
    // Two cold starts may race; the first insert wins and both read it back.
    await db.insert(schema.vaultSetting).values({ key: MASTER_KEY, value: fresh, updatedAt: Date.now() }).onConflictDoNothing()
    stored = await getSetting(db, MASTER_KEY)
  }
  if (!stored) throw new Error('could not initialise the vault key')
  return keysFromMaster(stored)
}

// ── GitHub sign-in app + owner ────────────────────────────────────

export interface GithubOAuth { clientId: string; clientSecret: string }

export async function loadGithubOAuth(db: Db, e: VaultEnv, keys: VaultKeys): Promise<GithubOAuth | null> {
  const envId = nonEmpty(e.GITHUB_CLIENT_ID)
  const envSecret = nonEmpty(e.GITHUB_CLIENT_SECRET)
  if (envId && envSecret) return { clientId: envId, clientSecret: envSecret }
  const clientId = await getSetting(db, GITHUB_CLIENT_ID)
  const sealed = await getSetting(db, GITHUB_CLIENT_SECRET)
  if (!clientId || !sealed) return null
  try {
    const { e: encrypted, i: iv } = JSON.parse(sealed) as { e: string; i: string }
    return { clientId, clientSecret: await decryptCredentialValue(keys.encryptionKey, SECRET_AAD_ID, 1, encrypted, iv) }
  } catch {
    return null
  }
}

export async function loadOwnerId(db: Db, e: VaultEnv): Promise<string | null> {
  return normalizeOwnerId(e.OWNER_GITHUB_ID) ?? normalizeOwnerId(await getSetting(db, OWNER_ID))
}

export async function saveGithubApp(db: Db, keys: VaultKeys, app: { clientId: string; clientSecret: string; ownerId: string }): Promise<void> {
  if (!normalizeOwnerId(app.ownerId)) throw new Error('invalid owner id')
  const sealed = await encryptCredentialValue(keys.encryptionKey, SECRET_AAD_ID, 1, app.clientSecret)
  const now = Date.now()
  // One batch: either the app and its owner are both recorded, or neither is.
  const upsert = (key: string, value: string) => db.insert(schema.vaultSetting)
    .values({ key, value, updatedAt: now })
    .onConflictDoUpdate({ target: schema.vaultSetting.key, set: { value, updatedAt: now } })
  await db.batch([
    upsert(GITHUB_CLIENT_ID, app.clientId),
    upsert(GITHUB_CLIENT_SECRET, JSON.stringify({ e: sealed.encrypted, i: sealed.iv })),
    upsert(OWNER_ID, app.ownerId),
  ])
}

/** True once sign-in and an owner exist, whether from Worker secrets or from setup. */
export async function isConfigured(db: Db, e: VaultEnv, keys: VaultKeys): Promise<boolean> {
  return (await loadGithubOAuth(db, e, keys)) !== null && (await loadOwnerId(db, e)) !== null
}

// ── setup gate ────────────────────────────────────────────────────

export type SetupCodeStatus = 'ok' | 'missing' | 'too_short'

export function setupCodeStatus(e: VaultEnv): SetupCodeStatus {
  const code = nonEmpty(e.SETUP_CODE)
  if (!code) return 'missing'
  return code.length >= MIN_SETUP_CODE_LENGTH ? 'ok' : 'too_short'
}

async function sha256(value: string): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(value)))
}

/** Constant-time comparison of the typed code against SETUP_CODE. */
export async function setupCodeMatches(provided: unknown, e: VaultEnv): Promise<boolean> {
  if (setupCodeStatus(e) !== 'ok' || typeof provided !== 'string') return false
  const [a, b] = await Promise.all([sha256(provided.trim()), sha256(nonEmpty(e.SETUP_CODE)!)])
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!
  return diff === 0
}

/**
 * Atomically consume a setup-code attempt for this source IP and time window.
 * The IP is HMACed with the vault auth secret; only the digest is stored in D1.
 * A single UPSERT/RETURNING statement prevents concurrent requests bypassing the limit.
 */
export async function consumeSetupAttempt(db: Db, authSecret: string, now: number, sourceIp: string | null): Promise<boolean> {
  const identity = sourceIp?.trim() || 'unknown'
  const digest = new Uint8Array(await crypto.subtle.sign('HMAC', await hmacKey(authSecret), enc.encode(identity)))
  const suffix = Array.from(digest.subarray(0, 16), (b) => b.toString(16).padStart(2, '0')).join('')
  const key = `setup_attempts_${suffix}`
  const storedValue = schema.vaultSetting.value
  const separator = orm.sql`instr(${storedValue}, ':')`
  const nextValue = orm.sql<string>`CASE
    WHEN ${separator} = 0
      OR CAST(substr(${storedValue}, ${separator} + 1) AS INTEGER) <= ${now - SETUP_FAILURE_WINDOW_MS}
    THEN ${`1:${now}`}
    ELSE (CAST(substr(${storedValue}, 1, ${separator} - 1) AS INTEGER) + 1)
      || ':' || substr(${storedValue}, ${separator} + 1)
    END`
  const [row] = await db.insert(schema.vaultSetting)
    .values({ key, value: `1:${now}`, updatedAt: now })
    .onConflictDoUpdate({ target: schema.vaultSetting.key, set: { value: nextValue, updatedAt: now } })
    .returning({ value: storedValue })
  const [count, since] = (row?.value ?? '').split(':').map(Number)
  return Number.isSafeInteger(count) && count! >= 1 && count! <= SETUP_MAX_FAILURES
    && Number.isFinite(since) && now - since! <= SETUP_FAILURE_WINDOW_MS
}

async function hmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify'])
}

/** Value for the setup cookie: proof that this browser entered the setup code. */
export async function issueSetupCookie(authSecret: string, now: number): Promise<{ value: string; maxAgeSeconds: number }> {
  const exp = now + SETUP_SESSION_MS
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', await hmacKey(authSecret), enc.encode(`setup:${exp}`)))
  return { value: `${exp}.${toB64(sig)}`, maxAgeSeconds: SETUP_SESSION_MS / 1000 }
}

export function readCookie(header: string | null, name: string): string | null {
  if (!header) return null
  for (const part of header.split(';')) {
    const [k, ...rest] = part.trim().split('=')
    if (k === name) return rest.join('=')
  }
  return null
}

export async function setupCookieValid(authSecret: string, cookieHeader: string | null, now: number): Promise<boolean> {
  const raw = readCookie(cookieHeader, SETUP_COOKIE)
  if (!raw) return false
  const [expText, sigText] = raw.split('.')
  const exp = Number(expText)
  if (!Number.isFinite(exp) || exp <= now || exp > now + SETUP_SESSION_MS || !sigText) return false
  try {
    return await crypto.subtle.verify('HMAC', await hmacKey(authSecret), fromB64(decodeURIComponent(sigText)), enc.encode(`setup:${exp}`))
  } catch {
    return false
  }
}

/** Single-use anti-CSRF state for the manifest round trip to github.com. */
export async function newSetupState(db: Db, now: number): Promise<string> {
  const state = toB64(crypto.getRandomValues(new Uint8Array(24))).replace(/[+/=]/g, (c) => ({ '+': '-', '/': '_', '=': '' })[c]!)
  await putSetting(db, SETUP_STATE, `${state}:${now + SETUP_SESSION_MS}`, now)
  return state
}

export async function consumeSetupState(db: Db, provided: unknown, now: number): Promise<boolean> {
  const raw = await getSetting(db, SETUP_STATE)
  if (!raw || typeof provided !== 'string') return false
  await deleteSetting(db, SETUP_STATE)
  const [state, exp] = raw.split(':')
  if (!state || Number(exp) <= now) return false
  const [a, b] = await Promise.all([sha256(provided), sha256(state)])
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!
  return diff === 0
}

// ── GitHub app manifest ───────────────────────────────────────────

/** Manifest for a private (owner-only) GitHub App used purely for sign-in. */
export function buildManifest(origin: string, suffix: string) {
  return {
    // GitHub App names are global and at most 34 characters.
    name: `Runner Vault ${suffix}`.slice(0, 34),
    url: origin,
    redirect_url: `${origin}/setup/github/callback`,
    callback_urls: [`${origin}/api/auth/callback/github`],
    description: 'Owner sign-in for my Runner Credential Vault.',
    public: false,
    request_oauth_on_install: false,
    default_permissions: {},
    default_events: [],
  }
}

export interface ConvertedApp { clientId: string; clientSecret: string; ownerId: string }

/** Validate GitHub's manifest-conversion response; keeps only what sign-in needs. */
export function parseConversion(body: unknown): ConvertedApp | null {
  if (typeof body !== 'object' || body === null) return null
  const b = body as Record<string, unknown>
  const owner = b.owner as Record<string, unknown> | undefined
  const clientId = nonEmpty(b.client_id)
  const clientSecret = nonEmpty(b.client_secret)
  const ownerId = normalizeOwnerId(typeof owner?.id === 'number' ? String(owner.id) : owner?.id)
  if (!clientId || !clientSecret || !ownerId || owner?.type !== 'User') return null
  return { clientId, clientSecret, ownerId }
}

export async function convertManifest(code: string, fetchFn: typeof fetch = fetch): Promise<ConvertedApp | null> {
  if (!/^[A-Za-z0-9_-]{8,128}$/.test(code)) return null
  let res: Response
  try {
    res = await fetchFn(`https://api.github.com/app-manifests/${code}/conversions`, {
      method: 'POST',
      headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'runner-credential-vault', 'X-GitHub-Api-Version': '2022-11-28' },
      redirect: 'manual',
    })
  } catch {
    return null
  }
  if (res.status !== 201 && res.status !== 200) return null
  // The response also carries the app's private key and webhook secret. They are
  // not read, stored or logged: sign-in does not need them.
  return parseConversion(await res.json().catch(() => null))
}
