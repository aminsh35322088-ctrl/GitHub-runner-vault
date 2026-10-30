// Runner-facing operations, written as plain functions with injected dependencies so
// they can be tested without HTTP. runner-api.ts maps them onto routes.

import * as orm from 'drizzle-orm'
import { getDb, schema } from 'db'
import { audit, listRegistryForRunner, readCredentialValue, requestRegistration } from './credential-service.ts'
import { verifyGithubOidc, type JwksSource, type OidcPolicy } from './oidc.ts'
import { issueRunnerSession, verifyRunnerSession, getRunnerRevokedBefore, type RunnerSession } from './runner-session.ts'
import { runProxy, type ProxyError } from './proxy.ts'

type Db = ReturnType<typeof getDb>

export const USE_LIMIT_PER_MINUTE = 30
export const SESSION_LIMIT_PER_HOUR = 20
export const REGISTRATION_LIMIT_PER_HOUR = 10

export type RunnerDeps = {
  db: Db
  encryptionKey: CryptoKey
  sessionKey: CryptoKey
  policy: OidcPolicy
  jwks: JwksSource
  origin: string
  fetchFn: typeof fetch
  now: number
}

export type CoreResult<T> = { status: number; body: T }
const fail = (status: number, error: string, extra: Record<string, unknown> = {}): CoreResult<{ error: string } & Record<string, unknown>> =>
  ({ status, body: { error, ...extra } })

export function bearer(header: string | null | undefined): string | null {
  const match = /^Bearer ([A-Za-z0-9._~-]{10,8192})$/.exec(header ?? '')
  return match ? match[1]! : null
}

async function countSince(db: Db, action: string, since: number, credentialName?: string): Promise<number> {
  const conditions = [orm.eq(schema.credentialAudit.action, action), orm.gte(schema.credentialAudit.at, since)]
  if (credentialName) conditions.push(orm.eq(schema.credentialAudit.credentialName, credentialName))
  const [row] = await db.select({ n: orm.count() }).from(schema.credentialAudit).where(orm.and(...conditions))
  return row?.n ?? 0
}

// ── POST /api/runner/session ───────────────────────────────────────

export async function createSession(deps: RunnerDeps, authorization: string | null) {
  const token = bearer(authorization)
  if (!token) return fail(401, 'missing_token')
  const verified = await verifyGithubOidc(token, deps.policy, deps.jwks, deps.now)
  if (!verified.ok) {
    await audit(deps.db, { action: 'session_denied', actor: 'runner', result: 'denied', detail: verified.error, now: deps.now })
    return fail(401, 'unauthorized')
  }
  if (await countSince(deps.db, 'session_issued', deps.now - 3600_000) >= SESSION_LIMIT_PER_HOUR) {
    return fail(429, 'rate_limited')
  }
  const issued = await issueRunnerSession(deps.sessionKey, verified.identity, deps.now)
  await audit(deps.db, {
    action: 'session_issued', actor: issued.session.sub, result: 'ok',
    detail: `${verified.identity.event} ${verified.identity.ref} run ${verified.identity.runId}`, now: deps.now,
  })
  return { status: 200, body: { token: issued.token, expiresAt: issued.expiresAt } }
}

async function authenticate(deps: RunnerDeps, authorization: string | null): Promise<{ ok: true; session: RunnerSession } | { ok: false; res: CoreResult<{ error: string }> }> {
  const token = bearer(authorization)
  if (!token) return { ok: false, res: fail(401, 'missing_token') }
  const revokedBefore = await getRunnerRevokedBefore(deps.db)
  const result = await verifyRunnerSession(deps.sessionKey, token, deps.now, revokedBefore)
  if (!result.ok) return { ok: false, res: fail(401, 'unauthorized') }
  return { ok: true, session: result.session }
}

// ── GET /api/runner/registry ───────────────────────────────────────

export async function registry(deps: RunnerDeps, authorization: string | null) {
  const auth = await authenticate(deps, authorization)
  if (!auth.ok) return auth.res
  return { status: 200, body: { credentials: await listRegistryForRunner(deps.db, deps.now) } }
}

// ── POST /api/runner/registrations ────────────────────────────────

export async function requestCredential(
  deps: RunnerDeps,
  authorization: string | null,
  input: { name: unknown; service: unknown; purpose: unknown; doc: unknown },
) {
  const auth = await authenticate(deps, authorization)
  if (!auth.ok) return auth.res
  if (typeof input.name !== 'string' || typeof input.service !== 'string' || typeof input.purpose !== 'string') {
    return fail(400, 'invalid_request')
  }
  if (await countSince(deps.db, 'registration_requested', deps.now - 3600_000) >= REGISTRATION_LIMIT_PER_HOUR) {
    return fail(429, 'rate_limited')
  }
  const result = await requestRegistration(deps.db, {
    name: input.name, service: input.service, purpose: input.purpose, doc: input.doc,
    requestedBy: auth.session.sub, now: deps.now,
  })
  if (!result.ok) return fail(result.error === 'exists' ? 409 : 400, result.error, result.detail ? { detail: result.detail } : {})
  return {
    status: 200,
    body: {
      // Give this link to the owner. It works once, expires, and still needs the owner's login.
      link: `${deps.origin}/vault/register/${result.value.link.token}`,
      expiresAt: result.value.link.expiresAt,
    },
  }
}

// ── POST /api/runner/use ──────────────────────────────────────────

export type UseInput = { name: unknown; method: unknown; url: unknown; headers?: unknown; body?: unknown; purpose?: unknown }

const PROXY_STATUS: Record<ProxyError, number> = {
  bad_method: 400, bad_url: 400, host_not_allowed: 403, bad_header: 400, body_too_large: 413,
  body_not_allowed: 400, upstream_timeout: 504, upstream_error: 502,
}

export async function useCredential(deps: RunnerDeps, authorization: string | null, input: UseInput) {
  const auth = await authenticate(deps, authorization)
  if (!auth.ok) return auth.res
  if (typeof input.name !== 'string' || typeof input.method !== 'string' || typeof input.url !== 'string') return fail(400, 'invalid_request')
  const purpose = typeof input.purpose === 'string' ? input.purpose.slice(0, 500) : ''
  const requestId = crypto.randomUUID()
  const headers: Record<string, string> = {}
  if (input.headers !== undefined) {
    if (typeof input.headers !== 'object' || input.headers === null || Array.isArray(input.headers)) return fail(400, 'invalid_request')
    for (const [k, v] of Object.entries(input.headers)) {
      if (typeof v !== 'string') return fail(400, 'invalid_request')
      headers[k] = v
    }
  }
  if (input.body !== undefined && typeof input.body !== 'string') return fail(400, 'invalid_request')

  const common = { actor: auth.session.sub, credentialName: input.name.slice(0, 80), requestId, purpose, now: deps.now }
  if (await countSince(deps.db, 'proxy_use', deps.now - 60_000, input.name) >= USE_LIMIT_PER_MINUTE) {
    await audit(deps.db, { ...common, action: 'proxy_use', result: 'rate_limited' })
    return fail(429, 'rate_limited')
  }

  const read = await readCredentialValue(deps.db, deps.encryptionKey, input.name, deps.now)
  if (!read.ok) {
    await audit(deps.db, { ...common, action: 'proxy_use', result: 'unavailable', detail: read.reason })
    // Same answer for missing, hidden, disabled and expired: no probing for hidden names.
    return fail(404, 'unavailable')
  }
  if (read.credential.delivery !== 'proxy') {
    await audit(deps.db, { ...common, credentialId: read.credential.id, action: 'proxy_use', result: 'wrong_delivery' })
    return fail(400, 'not_a_proxy_credential')
  }

  const result = await runProxy({
    credential: read.credential, value: read.value, method: input.method, url: input.url, headers, body: input.body as string | undefined,
  }, deps.fetchFn)

  if (!result.ok) {
    await audit(deps.db, { ...common, credentialId: read.credential.id, action: 'proxy_use', result: result.error, detail: result.detail })
    return fail(PROXY_STATUS[result.error], result.error)
  }
  await db_touch(deps, read.credential.id)
  await audit(deps.db, {
    ...common, credentialId: read.credential.id, action: 'proxy_use', result: 'ok',
    detail: `${result.method} ${result.host}${result.path} -> ${result.status}${result.redactions ? ` (${result.redactions} redacted)` : ''}`,
  })
  return {
    status: 200,
    body: { status: result.status, headers: result.headers, body: result.body, truncated: result.truncated, redacted: result.redactions > 0 },
  }
}

async function db_touch(deps: RunnerDeps, id: string) {
  await deps.db.update(schema.credential).set({ lastUsedAt: deps.now }).where(orm.eq(schema.credential.id, id))
}
