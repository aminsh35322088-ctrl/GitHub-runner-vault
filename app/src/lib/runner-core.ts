// Runner-facing operations, written as plain functions with injected dependencies so
// they can be tested without HTTP. runner-api.ts maps them onto routes.

import * as orm from 'drizzle-orm'
import { getDb, schema } from 'db'
import { audit, listRegistryForRunner, readCredentialValue, requestRegistration } from './credential-service.ts'
import { verifyGithubOidc, type JwksSource, type OidcPolicy } from './oidc.ts'
import { issueRunnerSession, verifyRunnerSessionSignature, getRunnerRevokedBefore, type RunnerSession } from './runner-session.ts'
import { runProxy, type ProxyError } from './proxy.ts'
import { BOOTSTRAP_WORKFLOW_FILE, DEFAULT_EVENTS, pinRunnerPolicy } from './runner-policy.ts'
import { createNotification, listRunnerIntegrationMetadata, recordCredentialUsage, type VaultPreferences } from './vault-observability.ts'
import { reserveRunnerRateLimit, releaseRunnerRateLimitReservation } from './runner-rate-limit.ts'

type Db = ReturnType<typeof getDb>

export const USE_LIMIT_PER_MINUTE = 30
export const SESSION_LIMIT_PER_HOUR = 20
export const REGISTRATION_LIMIT_PER_HOUR = 10

export type RunnerDeps = {
  db: Db
  encryptionKey: CryptoKey
  sessionKey: CryptoKey
  policy?: OidcPolicy
  jwks: JwksSource
  origin: string
  fetchFn: typeof fetch
  now: number
  proxyTimeoutMs?: number
  getProxyTimeoutMs?: () => Promise<number>
  getVaultPreferences?: () => Promise<VaultPreferences>
  /** Schedule non-response-critical writes after the HTTP response (Cloudflare waitUntil). */
  waitUntil?: (promise: Promise<unknown>) => void
}

export type CoreResult<T> = { status: number; body: T }
const fail = (status: number, error: string, extra: Record<string, unknown> = {}): CoreResult<{ error: string } & Record<string, unknown>> =>
  ({ status, body: { error, ...extra } })

export function bearer(header: string | null | undefined): string | null {
  const match = /^Bearer ([A-Za-z0-9._~-]{10,8192})$/.exec(header ?? '')
  return match ? match[1]! : null
}


// ── POST /api/runner/session ───────────────────────────────────────

export async function createSession(deps: RunnerDeps, authorization: string | null) {
  const token = bearer(authorization)
  if (!token) return fail(401, 'missing_token')
  if (!deps.policy) return fail(503, 'vault_not_configured')
  const verified = await verifyGithubOidc(token, deps.policy, deps.jwks, deps.now)
  if (!verified.ok) {
    await audit(deps.db, { action: 'session_denied', actor: 'runner', result: 'denied', detail: verified.error, now: deps.now })
    return fail(401, 'unauthorized')
  }
  if (deps.policy.bootstrap) {
    const branchPrefix = 'refs/heads/'
    const branch = verified.identity.ref.startsWith(branchPrefix)
      ? verified.identity.ref.slice(branchPrefix.length) : ''
    try {
      await pinRunnerPolicy(deps.db, {
        repository: verified.identity.repository,
        repositoryId: verified.identity.repositoryId,
        repositoryOwnerId: verified.identity.repositoryOwnerId,
        branch,
        workflowFile: BOOTSTRAP_WORKFLOW_FILE,
        events: DEFAULT_EVENTS,
      }, deps.policy.audience)
    } catch {
      await audit(deps.db, {
        action: 'session_denied', actor: `runner:${verified.identity.repository}`,
        result: 'denied', detail: 'automatic_repository_pin_conflict', now: deps.now,
      })
      return fail(403, 'runner_not_allowed')
    }
  }
  const preferences = await deps.getVaultPreferences?.()
  const reservation = await reserveRunnerRateLimit(deps.db, {
    scope: 'session', subject: 'global', now: deps.now, windowMs: 3600_000,
    limit: preferences?.runnerSessionsPerHour ?? SESSION_LIMIT_PER_HOUR,
  })
  if (!reservation) return fail(429, 'rate_limited')

  const issued = await issueRunnerSession(deps.sessionKey, verified.identity, deps.now)
  await scheduleBackgroundWrites(deps, [audit(deps.db, {
    action: 'session_issued', actor: issued.session.sub, result: 'ok',
    detail: `${verified.identity.event} ${verified.identity.ref} run ${verified.identity.runId}`, now: deps.now,
  })])
  return { status: 200, body: { token: issued.token, expiresAt: issued.expiresAt } }
}

async function authenticate(deps: RunnerDeps, authorization: string | null): Promise<{ ok: true; session: RunnerSession } | { ok: false; res: CoreResult<{ error: string }> }> {
  const token = bearer(authorization)
  if (!token) return { ok: false, res: fail(401, 'missing_token') }
  // HMAC verification is CPU-local; the revocation cutoff is a D1 read. Run both
  // concurrently, but await both so neither a D1 rejection nor a crypto failure
  // leaves a floating promise. Revocation remains checked on every request.
  const [revokedBefore, result] = await Promise.all([
    getRunnerRevokedBefore(deps.db),
    verifyRunnerSessionSignature(deps.sessionKey, token, deps.now),
  ])
  if (!result.ok || result.session.iat <= revokedBefore) return { ok: false, res: fail(401, 'unauthorized') }
  return { ok: true, session: result.session }
}

// ── GET /api/runner/registry ───────────────────────────────────────

export async function registry(deps: RunnerDeps, authorization: string | null) {
  const auth = await authenticate(deps, authorization)
  if (!auth.ok) return auth.res
  return { status: 200, body: { credentials: await listRegistryForRunner(deps.db, deps.now) } }
}

/** A separate, opt-in capability endpoint for local CLI adapters. */
export async function integrations(deps: RunnerDeps, authorization: string | null) {
  const auth = await authenticate(deps, authorization)
  if (!auth.ok) return auth.res
  return { status: 200, body: { integrations: await listRunnerIntegrationMetadata(deps.db, deps.now) } }
}

// ── POST /api/runner/registrations ────────────────────────────────

export async function requestCredential(
  deps: RunnerDeps,
  authorization: string | null,
  input: { name: unknown; service: unknown; purpose?: unknown; doc: unknown },
) {
  const auth = await authenticate(deps, authorization)
  if (!auth.ok) return auth.res
  if (typeof input.name !== 'string' || typeof input.service !== 'string') {
    return fail(400, 'invalid_request')
  }
  const preferences = await deps.getVaultPreferences?.()
  const reservation = await reserveRunnerRateLimit(deps.db, {
    scope: 'registration', subject: 'global', now: deps.now, windowMs: 3600_000,
    limit: preferences?.runnerRegistrationsPerHour ?? REGISTRATION_LIMIT_PER_HOUR,
  })
  if (!reservation) return fail(429, 'rate_limited')

  // A thrown D1 error may happen after the credential/link has already been
  // created (for example, when its trailing audit write fails). Keep the slot
  // reserved on exceptions; only structured pre-acceptance errors release it.
  const result = await requestRegistration(deps.db, {
    name: input.name, service: input.service, purpose: typeof input.purpose === 'string' ? input.purpose : undefined, doc: input.doc,
    requestedBy: auth.session.sub, now: deps.now,
  })
  if (!result.ok) {
    await releaseRunnerRateLimitReservation(deps.db, reservation)
    return fail(result.error === 'exists' ? 409 : 400, result.error, result.detail ? { detail: result.detail } : {})
  }
  await scheduleBackgroundWrites(deps, [createNotification(deps.db, {
    dedupeKey: `registration-request:${result.value.credentialId}:${result.value.link.expiresAt}`,
    kind: 'credential_registration_requested',
    severity: 'info',
    title: 'Runner requested a credential',
    message: `${input.name} (${input.service}) is waiting for owner review and a secret value.`,
    credentialId: result.value.credentialId,
    credentialName: input.name,
    now: deps.now,
  }).catch(() => {
    // The request and one-time owner link remain valid if the optional notification fails.
    console.warn('[vault] registration notification could not be persisted')
  })])
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

export type UseInput = { name: unknown; method: unknown; url: unknown; headers?: unknown; body?: unknown; purpose?: unknown; consumer?: unknown }

const PROXY_STATUS: Record<ProxyError, number> = {
  bad_method: 400, bad_url: 400, host_not_allowed: 403, bad_header: 400, body_too_large: 413,
  body_not_allowed: 400, upstream_timeout: 504, upstream_error: 502,
}

export async function useCredential(deps: RunnerDeps, authorization: string | null, input: UseInput) {
  const auth = await authenticate(deps, authorization)
  if (!auth.ok) return auth.res
  if (typeof input.name !== 'string' || typeof input.method !== 'string' || typeof input.url !== 'string') return fail(400, 'invalid_request')
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

  const safeName = /^[A-Z][A-Z0-9_]{0,79}$/.test(input.name) ? input.name : ''
  const common = { actor: auth.session.sub, credentialName: safeName, requestId, now: deps.now }
  const [preferences, read] = await Promise.all([
    deps.getVaultPreferences?.() ?? Promise.resolve(null),
    readCredentialValue(deps.db, deps.encryptionKey, input.name, deps.now),
  ])
  if (!read.ok) {
    await scheduleBackgroundWrites(deps, [audit(deps.db, { ...common, action: 'proxy_use', result: 'unavailable', detail: read.reason })])
    // Same answer for missing, hidden, disabled and expired: no probing for hidden names.
    return fail(404, 'unavailable')
  }
  if (read.credential.delivery !== 'proxy') {
    await scheduleBackgroundWrites(deps, [audit(deps.db, { ...common, credentialId: read.credential.id, action: 'proxy_use', result: 'wrong_delivery' })])
    return fail(400, 'not_a_proxy_credential')
  }

  const reservation = await reserveRunnerRateLimit(deps.db, {
    scope: 'proxy', subject: read.credential.id, credentialId: read.credential.id,
    now: deps.now, windowMs: 60_000,
    limit: preferences?.proxyRequestsPerMinute ?? USE_LIMIT_PER_MINUTE,
  })
  if (!reservation) {
    await scheduleBackgroundWrites(deps, [audit(deps.db, { ...common, credentialId: read.credential.id, action: 'proxy_use', result: 'rate_limited' })])
    return fail(429, 'rate_limited')
  }

  const startedAt = Date.now()
  const consumer = typeof input.consumer === 'string' && /^cli:[a-z0-9._-]{1,40}$/i.test(input.consumer)
    ? input.consumer.toLowerCase() : 'runner'
  // Proxy policy is read only for actual upstream requests. Registry/session and
  // rejected credential attempts do not need a settings-table round trip.
  const proxyTimeoutMs = preferences?.proxyTimeoutMs ?? (deps.getProxyTimeoutMs
    ? await deps.getProxyTimeoutMs()
    : deps.proxyTimeoutMs)
  const result = await runProxy({
    credential: read.credential, value: read.value, method: input.method, url: input.url, headers, body: input.body as string | undefined,
  }, deps.fetchFn, proxyTimeoutMs)

  if (!result.ok) {
    // A D1 reservation is the authoritative quota counter; audit and aggregates
    // are now best-effort background metadata and never hold the API response open.
    await scheduleBackgroundWrites(deps, [
      audit(deps.db, { ...common, credentialId: read.credential.id, action: 'proxy_use', result: result.error, detail: result.detail }),
      recordCredentialUsage(deps.db, { credentialId: read.credential.id, consumer, success: false, latencyMs: Date.now() - startedAt, now: deps.now }),
    ])
    return fail(PROXY_STATUS[result.error], result.error)
  }
  await scheduleBackgroundWrites(deps, [
    audit(deps.db, {
      ...common, credentialId: read.credential.id, action: 'proxy_use', result: 'ok',
      detail: `${result.method} ${result.host}${result.path} -> ${result.status}${result.redactions ? ` (${result.redactions} redacted)` : ''}`,
    }),
    recordCredentialUsage(deps.db, { credentialId: read.credential.id, consumer, success: result.status < 400, latencyMs: Date.now() - startedAt, now: deps.now }),
    db_touch(deps, read.credential.id),
  ])
  return {
    status: 200,
    body: { status: result.status, headers: result.headers, body: result.body, truncated: result.truncated, redacted: result.redactions > 0 },
  }
}

/**
 * Persist non-critical audit and analytics metadata without holding the Runner
 * response open. Quotas are reserved atomically in D1 before any provider call.
 * Cloudflare waitUntil keeps writes alive after response; tests and other hosts await.
 */
function scheduleBackgroundWrites(deps: RunnerDeps, writes: Promise<unknown>[]): Promise<void> {
  const pending = Promise.allSettled(writes).then(() => undefined)
  if (deps.waitUntil) {
    try {
      deps.waitUntil(pending)
      return Promise.resolve()
    } catch {
      // Preserve audit/usage completion when a host exposes a broken lifecycle hook.
    }
  }
  return pending
}

async function db_touch(deps: RunnerDeps, id: string) {
  await deps.db.update(schema.credential).set({ lastUsedAt: deps.now }).where(orm.eq(schema.credential.id, id))
}
