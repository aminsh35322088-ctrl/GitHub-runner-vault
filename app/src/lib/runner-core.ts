// Runner-facing operations, written as plain functions with injected dependencies so
// they can be tested without HTTP. runner-api.ts maps them onto routes.

import * as orm from 'drizzle-orm'
import { getDb, schema } from 'db'
import { audit, listRegistryForRunner, readCredentialValue, requestRegistration } from './credential-service.ts'
import { verifyGithubOidc, type JwksSource, type OidcPolicy } from './oidc.ts'
import { issueRunnerSession, verifyRunnerSessionSignature, getRunnerRevokedBefore, type RunnerSession } from './runner-session.ts'
import { MAX_REQUEST_BODY, runProxy, type ProxyError, type ProxyResult } from './proxy.ts'
import { BOOTSTRAP_WORKFLOW_FILE, DEFAULT_EVENTS, pinRunnerPolicy } from './runner-policy.ts'
import { createNotification, listRunnerIntegrationMetadata, recordCredentialUsage, recordRuntimeCredentialEvidence, type VaultPreferences } from './vault-observability.ts'
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

export type UseInput = {
  name: unknown
  method: unknown
  url: unknown
  headers?: unknown
  body?: unknown
  /** Raw request stream used by the local CLI bridge for byte-preserving uploads. */
  bodyStream?: ReadableStream<Uint8Array> | null
  /** Content-Length when the HTTP transport supplied a valid declaration. */
  bodyLength?: number
  purpose?: unknown
  consumer?: unknown
}

type BoundedRequestBody =
  | { ok: true; body?: Uint8Array<ArrayBuffer> }
  | { ok: false; error: 'body_too_large' | 'invalid_body' }

export async function readBoundedRequestBody(
  stream: ReadableStream<Uint8Array>,
  maxBytes: number,
  declaredLength?: number,
): Promise<BoundedRequestBody> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) return { ok: false, error: 'invalid_body' }
  if (declaredLength !== undefined && (!Number.isSafeInteger(declaredLength) || declaredLength < 0)) {
    return { ok: false, error: 'invalid_body' }
  }
  // Content-Length is only a hint: never allocate from an untrusted declared length.
  if (declaredLength !== undefined && declaredLength > maxBytes) return { ok: false, error: 'body_too_large' }

  let buffer: Uint8Array<ArrayBuffer> = new Uint8Array(Math.min(64 * 1024, maxBytes))
  let total = 0
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined
  try {
    reader = stream.getReader()
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      const nextTotal = total + value.byteLength
      if (nextTotal > maxBytes) {
        await reader.cancel().catch(() => undefined)
        return { ok: false, error: 'body_too_large' }
      }
      if (declaredLength !== undefined && nextTotal > declaredLength) {
        await reader.cancel().catch(() => undefined)
        return { ok: false, error: 'invalid_body' }
      }
      if (nextTotal > buffer.byteLength) {
        let capacity = Math.max(1, buffer.byteLength)
        while (capacity < nextTotal) capacity = Math.min(maxBytes, capacity * 2)
        const grown = new Uint8Array(capacity)
        grown.set(buffer.subarray(0, total))
        buffer = grown
      }
      buffer.set(value, total)
      total = nextTotal
    }
  } catch {
    return { ok: false, error: 'invalid_body' }
  } finally {
    reader?.releaseLock()
  }

  if (declaredLength !== undefined && total !== declaredLength) return { ok: false, error: 'invalid_body' }
  if (total === 0) return { ok: true }
  return { ok: true, body: buffer.subarray(0, total) }
}

// Keep raw uploads below the per-isolate memory ceiling under concurrent load.
export const MAX_CONCURRENT_PROXY_UPLOADS_PER_ISOLATE = 3
let activeProxyUploads = 0

export function tryAcquireProxyUploadSlot(): (() => void) | null {
  if (activeProxyUploads >= MAX_CONCURRENT_PROXY_UPLOADS_PER_ISOLATE) return null
  activeProxyUploads += 1
  let released = false
  return () => {
    if (released) return
    released = true
    activeProxyUploads = Math.max(0, activeProxyUploads - 1)
  }
}

const PROXY_STATUS: Record<ProxyError, number> = {
  bad_method: 400, bad_url: 400, host_not_allowed: 403, bad_header: 400, body_too_large: 413,
  body_not_allowed: 400, invalid_body: 400, upstream_timeout: 504, upstream_error: 502,
}

function runtimeCredentialEvidence(
  service: string,
  status: number,
  body: string,
  headers: Record<string, string>,
): { status: 'valid' | 'invalid' | 'insufficient_permissions'; message: string } | null {
  const normalized = service.trim().toLowerCase().replace(/[^a-z0-9]/g, '')

  if (normalized === 'telegrambotapi' || normalized === 'telegram') {
    let response: { ok?: unknown; error_code?: unknown }
    try { response = JSON.parse(body) as typeof response } catch { return null }
    if (status >= 200 && status < 300 && response.ok === true) {
      return { status: 'valid', message: 'Telegram Bot API returned ok=true for an authenticated method call.' }
    }
    if (response.error_code === 401 || response.error_code === 404 || status === 401) {
      return { status: 'invalid', message: 'Telegram Bot API rejected the stored Bot Token.' }
    }
    if (response.error_code === 403) {
      return { status: 'insufficient_permissions', message: 'Telegram Bot API accepted the token but denied this operation.' }
    }
    return null
  }

  if (normalized === 'slack') {
    try {
      const response = JSON.parse(body) as { ok?: unknown; error?: unknown }
      if (status >= 200 && status < 300 && response.ok === true) {
        return { status: 'valid', message: 'Slack Web API returned ok=true for an authenticated method call.' }
      }
      if (['invalid_auth', 'token_revoked', 'not_authed'].includes(String(response.error ?? ''))) {
        return { status: 'invalid', message: 'Slack Web API rejected the stored token.' }
      }
      if (response.error === 'missing_scope') {
        return { status: 'insufficient_permissions', message: 'Slack accepted the token but the requested method needs additional scopes.' }
      }
    } catch { return null }
    return null
  }

  if (normalized === 'cloudflare') {
    try {
      const response = JSON.parse(body) as { success?: unknown }
      if (status >= 200 && status < 300 && response.success === true) {
        return { status: 'valid', message: 'Cloudflare API returned success=true for an authenticated request.' }
      }
    } catch { /* An unreadable body is not verification evidence. */ }
    return null
  }

  if (normalized === 'github') {
    if (headers['x-github-sso'] || headers['x-ratelimit-remaining'] === '0') return null
    if (status >= 200 && status < 300 &&
        (headers['x-oauth-scopes'] !== undefined || headers['x-accepted-github-permissions'] !== undefined)) {
      return { status: 'valid', message: 'GitHub returned authenticated-token scope/permission metadata for the API request.' }
    }
    if (status === 403 && headers['x-accepted-github-permissions'] !== undefined) {
      return { status: 'insufficient_permissions', message: 'GitHub accepted the token but reported that the requested operation needs additional permissions.' }
    }
    if (status === 401) return { status: 'invalid', message: 'GitHub rejected the stored token with HTTP 401.' }
    return null
  }

  // Unknown providers do not get promoted by generic HTTP 2xx/4xx responses.
  return null
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
  if (input.bodyStream && input.body !== undefined) return fail(400, 'invalid_request')
  if (input.bodyStream !== undefined && input.bodyStream !== null && typeof input.bodyStream.getReader !== 'function') {
    return fail(400, 'invalid_request')
  }
  if (input.bodyLength !== undefined && (!Number.isSafeInteger(input.bodyLength) || input.bodyLength < 0)) {
    return fail(400, 'invalid_request')
  }
  if (input.bodyLength !== undefined && input.bodyLength > 0 && !input.bodyStream) {
    return fail(400, 'invalid_request')
  }

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
  // Audits record the credential's owner-approved purpose (never the
  // request-supplied one, which is untrusted runner input).
  const identified = { ...common, credentialId: read.credential.id, purpose: read.credential.purpose }
  if (read.credential.delivery !== 'proxy') {
    await scheduleBackgroundWrites(deps, [audit(deps.db, { ...identified, action: 'proxy_use', result: 'wrong_delivery' })])
    return fail(400, 'not_a_proxy_credential')
  }

  const reservation = await reserveRunnerRateLimit(deps.db, {
    scope: 'proxy', subject: read.credential.id, credentialId: read.credential.id,
    now: deps.now, windowMs: 60_000,
    limit: preferences?.proxyRequestsPerMinute ?? USE_LIMIT_PER_MINUTE,
  })
  if (!reservation) {
    await scheduleBackgroundWrites(deps, [audit(deps.db, { ...identified, action: 'proxy_use', result: 'rate_limited' })])
    return fail(429, 'rate_limited')
  }

  const startedAt = Date.now()
  const consumer = typeof input.consumer === 'string' && /^cli:[a-z0-9._-]{1,40}$/i.test(input.consumer)
    ? input.consumer.toLowerCase() : 'runner'

  let proxyBody: string | Uint8Array<ArrayBuffer> | undefined = input.body as string | undefined
  let releaseUploadSlot: (() => void) | null = null
  if (input.bodyStream) {
    releaseUploadSlot = tryAcquireProxyUploadSlot()
    if (!releaseUploadSlot) {
      try { await releaseRunnerRateLimitReservation(deps.db, reservation) } catch { /* Keep the request failure generic. */ }
      await scheduleBackgroundWrites(deps, [
        audit(deps.db, { ...identified, action: 'proxy_use', result: 'proxy_busy' }),
        recordCredentialUsage(deps.db, { credentialId: read.credential.id, consumer, success: false, latencyMs: Date.now() - startedAt, now: deps.now }),
      ])
      return fail(503, 'proxy_busy')
    }
  }

  let result: ProxyResult
  try {
    if (input.bodyStream) {
      const streamed = await readBoundedRequestBody(input.bodyStream, MAX_REQUEST_BODY, input.bodyLength)
      if (!streamed.ok) {
        try { await releaseRunnerRateLimitReservation(deps.db, reservation) } catch { /* Keep the request failure generic. */ }
        await scheduleBackgroundWrites(deps, [
          audit(deps.db, { ...identified, action: 'proxy_use', result: streamed.error }),
          recordCredentialUsage(deps.db, { credentialId: read.credential.id, consumer, success: false, latencyMs: Date.now() - startedAt, now: deps.now }),
        ])
        return fail(streamed.error === 'body_too_large' ? 413 : 400, streamed.error)
      }
      proxyBody = streamed.body
    }

    // Proxy policy is read only for actual upstream requests. Registry/session and
    // rejected credential attempts do not need a settings-table round trip.
    const proxyTimeoutMs = preferences?.proxyTimeoutMs ?? (deps.getProxyTimeoutMs
      ? await deps.getProxyTimeoutMs()
      : deps.proxyTimeoutMs)
    result = await runProxy({
      credential: read.credential, value: read.value, authFields: read.authFields, method: input.method, url: input.url, headers, body: proxyBody,
    }, deps.fetchFn, proxyTimeoutMs)
  } finally {
    releaseUploadSlot?.()
  }

  if (!result.ok) {
    // A D1 reservation is the authoritative quota counter; audit and aggregates
    // are now best-effort background metadata and never hold the API response open.
    await scheduleBackgroundWrites(deps, [
      audit(deps.db, { ...identified, action: 'proxy_use', result: result.error, detail: result.detail }),
      recordCredentialUsage(deps.db, { credentialId: read.credential.id, consumer, success: false, latencyMs: Date.now() - startedAt, now: deps.now }),
    ])
    return fail(PROXY_STATUS[result.error], result.error)
  }
  const evidence = runtimeCredentialEvidence(read.credential.service, result.status, result.body, result.headers)
  const writes: Promise<unknown>[] = [
    audit(deps.db, {
      ...identified, action: 'proxy_use', result: 'ok',
      detail: `${result.method} ${result.host}${result.path} -> ${result.status}${result.redactions ? ` (${result.redactions} redacted)` : ''}`,
    }),
    recordCredentialUsage(deps.db, { credentialId: read.credential.id, consumer, success: result.status < 400, latencyMs: Date.now() - startedAt, now: deps.now }),
    db_touch(deps, read.credential.id),
  ]
  if (evidence) writes.push(recordRuntimeCredentialEvidence(deps.db, {
    credentialId: read.credential.id, valueIv: read.credential.valueIv,
    provider: read.credential.service, ...evidence, now: deps.now,
  }))
  await scheduleBackgroundWrites(deps, writes)
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
