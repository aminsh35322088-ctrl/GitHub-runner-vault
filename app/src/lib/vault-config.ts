// Self-configuration for the vault, so a deployment needs no hand-made secrets.
//
//  - Keys: one random master key is generated on first use and kept in D1 (or
//    supplied as the optional VAULT_MASTER_KEY Worker secret, which wins). The
//    session-signing secret and the AES-256 credential key are both derived from
//    it with HKDF under separate labels. Explicit BETTER_AUTH_SECRET +
//    ENCRYPTION_KEY secrets (older deployments) keep working unchanged.
//  - GitHub sign-in: created through GitHub's app-manifest flow from /setup. The
//    client secret is stored encrypted; its creator must match the immutable owner
//    ID provisioned by the Deploy to Cloudflare GitHub Actions bootstrap.
//  - /setup stays locked until that deployment identity exists; visitors cannot
//    claim ownership by arriving first.

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
const OWNER_LOGIN = 'owner_github_login'
// The secret is bound to this label (see credential-crypto.ts) so it cannot be
// swapped with another encrypted row.
const SECRET_AAD_ID = 'setting-github-client-secret'


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
  // The build-derived owner ID is the bootstrap identity. Pin it in D1 once so
  // later repository transfers or build metadata changes cannot transfer a vault.
  const stored = normalizeOwnerId(await getSetting(db, OWNER_ID))
  if (stored) return stored
  const expected = normalizeOwnerId(e.OWNER_GITHUB_ID)
  if (!expected) return null
  await db.insert(schema.vaultSetting)
    .values({ key: OWNER_ID, value: expected, updatedAt: Date.now() })
    .onConflictDoNothing()
  return normalizeOwnerId(await getSetting(db, OWNER_ID))
}

export async function saveGithubApp(db: Db, keys: VaultKeys, app: { clientId: string; clientSecret: string; ownerId: string; ownerLogin?: string }, expectedOwnerId: unknown): Promise<void> {
  const expected = normalizeOwnerId(expectedOwnerId)
  if (!expected) throw new Error('deployment owner is not provisioned')
  if (!normalizeOwnerId(app.ownerId)) throw new Error('invalid owner id')
  if (app.ownerId !== expected) throw new Error('GitHub account does not match deployment owner')

  // Owner identity is pinned from the deployment repository before /setup is
  // enabled. Keep the claim guard for direct calls and concurrent first requests.
  const storedOwner = normalizeOwnerId(await getSetting(db, OWNER_ID))
  if (storedOwner && storedOwner !== expected) throw new Error('This vault is bound to a different deployment owner')
  if (!storedOwner) {
    await db.insert(schema.vaultSetting)
      .values({ key: OWNER_ID, value: expected, updatedAt: Date.now() })
      .onConflictDoNothing()
    if (normalizeOwnerId(await getSetting(db, OWNER_ID)) !== expected) {
      throw new Error('This vault is bound to a different deployment owner')
    }
  }

  // Claim the GitHub App slot atomically. The owner ID itself is already pinned,
  // so the app client ID is now the one-time setup marker.
  const existingClientId = await getSetting(db, GITHUB_CLIENT_ID)
  if (existingClientId) throw new Error('This vault already has a sign-in app')
  const claimed = await db.insert(schema.vaultSetting)
    .values({ key: GITHUB_CLIENT_ID, value: app.clientId, updatedAt: Date.now() })
    .onConflictDoNothing()
    .returning({ key: schema.vaultSetting.key })
  if (claimed.length === 0) {
    const currentClientId = await getSetting(db, GITHUB_CLIENT_ID)
    if (currentClientId !== app.clientId || await getSetting(db, GITHUB_CLIENT_SECRET)) {
      throw new Error('This vault already has a sign-in app')
    }
  }

  const sealed = await encryptCredentialValue(keys.encryptionKey, SECRET_AAD_ID, 1, app.clientSecret)
  const now = Date.now()
  const upsert = (key: string, value: string) => db.insert(schema.vaultSetting)
    .values({ key, value, updatedAt: now })
    .onConflictDoUpdate({ target: schema.vaultSetting.key, set: { value, updatedAt: now } })
  await db.batch([
    upsert(GITHUB_CLIENT_SECRET, JSON.stringify({ e: sealed.encrypted, i: sealed.iv })),
    ...(app.ownerLogin && /^[A-Za-z0-9-]{1,39}$/.test(app.ownerLogin) ? [upsert(OWNER_LOGIN, app.ownerLogin)] : []),
  ])
}

/** True once sign-in and an owner exist, whether from Worker secrets or from setup. */
export async function isConfigured(db: Db, e: VaultEnv, keys: VaultKeys): Promise<boolean> {
  return (await loadGithubOAuth(db, e, keys)) !== null && (await loadOwnerId(db, e)) !== null
}

// ── setup state ───────────────────────────────────────────────────
//
// The deployment workflow provisions the expected numeric GitHub owner ID before
// /setup is enabled. The manifest callback must return that exact creator ID. The
// flow is also bound to one browser: /setup hands out a random state in an HttpOnly
// cookie and GitHub must return the same value. The atomic database claim is a
// second guard; it is not used to choose the owner.

export const SETUP_STATE_COOKIE = 'vault_setup_state'
export const SETUP_STATE_MAX_AGE_SECONDS = 30 * 60

export function readCookie(header: string | null, name: string): string | null {
  if (!header) return null
  for (const part of header.split(';')) {
    const [k, ...rest] = part.trim().split('=')
    if (k === name) return rest.join('=')
  }
  return null
}

export function newSetupState(): string {
  return toB64(crypto.getRandomValues(new Uint8Array(24))).replace(/[+/=]/g, (c) => ({ '+': '-', '/': '_', '=': '' })[c]!)
}

/** True when the state GitHub returned equals the one this browser was given. */
export function setupStateMatches(cookieHeader: string | null, returned: unknown): boolean {
  const cookie = readCookie(cookieHeader, SETUP_STATE_COOKIE)
  if (!cookie || typeof returned !== 'string' || cookie.length < 16 || cookie.length !== returned.length) return false
  let diff = 0
  for (let i = 0; i < cookie.length; i++) diff |= cookie.charCodeAt(i) ^ returned.charCodeAt(i)
  return diff === 0
}

/** Public GitHub login of the owner, shown so a vault claimed by someone else is noticed. */
export async function loadOwnerLogin(db: Db): Promise<string | null> {
  const login = await getSetting(db, OWNER_LOGIN)
  return login && /^[A-Za-z0-9-]{1,39}$/.test(login) ? login : null
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

export interface ConvertedApp { clientId: string; clientSecret: string; ownerId: string; ownerLogin?: string }

/** Validate GitHub's manifest-conversion response; keeps only what sign-in needs. */
export function parseConversion(body: unknown): ConvertedApp | null {
  if (typeof body !== 'object' || body === null) return null
  const b = body as Record<string, unknown>
  const owner = b.owner as Record<string, unknown> | undefined
  const clientId = nonEmpty(b.client_id)
  const clientSecret = nonEmpty(b.client_secret)
  const ownerId = normalizeOwnerId(typeof owner?.id === 'number' ? String(owner.id) : owner?.id)
  if (!clientId || !clientSecret || !ownerId || owner?.type !== 'User') return null
  const ownerLogin = typeof owner?.login === 'string' && /^[A-Za-z0-9-]{1,39}$/.test(owner.login) ? owner.login : undefined
  return { clientId, clientSecret, ownerId, ownerLogin }
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
