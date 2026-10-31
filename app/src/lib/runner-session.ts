// Short-lived runner sessions.
//
// After a runner proves its identity with a GitHub OIDC token, the vault hands back an
// HMAC-signed session token (stateless, 30 minutes, never renewable without a fresh OIDC
// token). The owner can revoke every session issued before a given moment at once.
// The signing key is derived from BETTER_AUTH_SECRET with HKDF under its own label, so it is
// unrelated to the credential encryption key.

import * as orm from 'drizzle-orm'
import { getDb, schema } from 'db'
import type { RunnerIdentity } from './oidc.ts'

type Db = ReturnType<typeof getDb>

export const SESSION_TTL_MS = 30 * 60_000
const REVOKED_KEY = 'runner_revoked_before'

export type RunnerSession = {
  sub: string
  repository: string
  runId: string
  runAttempt: string
  workflow: string
  iat: number
  exp: number
}

function b64url(bytes: Uint8Array): string {
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function fromB64url(value: string): Uint8Array<ArrayBuffer> {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=')
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0))
}

export async function deriveSessionKey(secret: unknown): Promise<CryptoKey> {
  if (typeof secret !== 'string' || secret.length < 32) throw new Error('BETTER_AUTH_SECRET must be at least 32 characters')
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), 'HKDF', false, ['deriveKey'])
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new TextEncoder().encode('runner-vault'), info: new TextEncoder().encode('runner-session-v1') },
    base,
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    false,
    ['sign', 'verify'],
  )
}

export async function issueRunnerSession(
  key: CryptoKey,
  identity: RunnerIdentity,
  nowMs: number,
): Promise<{ token: string; expiresAt: number; session: RunnerSession }> {
  const session: RunnerSession = {
    sub: `runner:${identity.repository}#${identity.runId}.${identity.runAttempt}`,
    repository: identity.repository,
    runId: identity.runId,
    runAttempt: identity.runAttempt,
    workflow: identity.workflow,
    iat: nowMs,
    exp: nowMs + SESSION_TTL_MS,
  }
  const payload = b64url(new TextEncoder().encode(JSON.stringify(session)))
  const signature = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload)))
  return { token: `rs1.${payload}.${b64url(signature)}`, expiresAt: session.exp, session }
}

export type SessionResult = { ok: true; session: RunnerSession } | { ok: false; error: string }

export async function verifyRunnerSession(key: CryptoKey, token: string, nowMs: number, revokedBeforeMs: number): Promise<SessionResult> {
  const parts = token.split('.')
  if (parts.length !== 3 || parts[0] !== 'rs1' || token.length > 2048) return { ok: false, error: 'invalid session' }
  let valid = false
  try {
    valid = await crypto.subtle.verify('HMAC', key, fromB64url(parts[2]!), new TextEncoder().encode(parts[1]!))
  } catch {
    valid = false
  }
  if (!valid) return { ok: false, error: 'invalid session' }
  let session: RunnerSession
  try {
    session = JSON.parse(new TextDecoder().decode(fromB64url(parts[1]!))) as RunnerSession
  } catch {
    return { ok: false, error: 'invalid session' }
  }
  if (typeof session.exp !== 'number' || typeof session.iat !== 'number') return { ok: false, error: 'invalid session' }
  if (session.exp <= nowMs) return { ok: false, error: 'session expired' }
  if (session.iat <= revokedBeforeMs) return { ok: false, error: 'session revoked' }
  return { ok: true, session }
}

export async function getRunnerRevokedBefore(db: Db): Promise<number> {
  const [row] = await db.select({ value: schema.vaultSetting.value }).from(schema.vaultSetting).where(orm.eq(schema.vaultSetting.key, REVOKED_KEY)).limit(1)
  const parsed = row ? Number(row.value) : 0
  return Number.isFinite(parsed) ? parsed : 0
}

/** Invalidate every session issued at or before `nowMs`. */
export async function revokeRunnerSessions(db: Db, nowMs: number): Promise<void> {
  await db.insert(schema.vaultSetting)
    .values({ key: REVOKED_KEY, value: String(nowMs), updatedAt: nowMs })
    .onConflictDoUpdate({ target: schema.vaultSetting.key, set: { value: String(nowMs), updatedAt: nowMs } })
}
