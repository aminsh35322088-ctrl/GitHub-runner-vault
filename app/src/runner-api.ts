// HTTP surface for runners. All logic lives in lib/runner-core.ts.
// Mounted in app.tsx via .use(runnerApp).

import { Spiceflow, json } from 'spiceflow'
import { MAX_REQUEST_BODY } from './lib/proxy.ts'
import { env } from 'cloudflare:workers'
import { getDb } from 'db'
import { loadVaultKeys, type VaultEnv } from './lib/vault-config.ts'
import { cachedJwksSource } from './lib/oidc.ts'
import { loadRunnerPolicy } from './lib/runner-policy.ts'
import { deriveSessionKey } from './lib/runner-session.ts'
import { createSession, registry, integrations, requestCredential, useCredential, type RunnerDeps } from './lib/runner-core.ts'
import { CLOUDFLARE_IP_ADDRESS_HEADERS } from './lib/auth-config.ts'
import { getRequestOrigin } from './db.ts'
import { loadVaultPreferences } from './lib/vault-observability.ts'

const jwks = cachedJwksSource()

/**
 * Client IP for pre-verification rate limiting. Cloudflare sets
 * cf-connecting-ip at the edge, so it is not client-spoofable; anything that
 * is not shaped like an IPv4/IPv6 address is treated as unknown and the core
 * falls back to a single shared budget.
 */
function clientIp(request: Request): string | undefined {
  for (const header of CLOUDFLARE_IP_ADDRESS_HEADERS) {
    const value = request.headers.get(header)?.trim()
    if (value && value.length <= 45 && /^[0-9a-fA-F.:]+$/.test(value)) return value
  }
  return undefined
}

async function buildDeps(request: Request, includeOidcPolicy = false, waitUntil?: RunnerDeps['waitUntil']): Promise<RunnerDeps> {
  const e = env as unknown as Record<string, unknown>
  const origin = getRequestOrigin(request)
  const db = getDb()
  const keys = await loadVaultKeys(db, e as VaultEnv)
  const ip = clientIp(request)
  return {
    db,
    encryptionKey: keys.encryptionKey,
    sessionKey: await deriveSessionKey(keys.authSecret),
    ...(includeOidcPolicy ? { policy: await loadRunnerPolicy(db, e, origin) } : {}),
    jwks,
    origin,
    fetchFn: fetch,
    now: Date.now(),
    ...(ip ? { clientIp: ip } : {}),
    getVaultPreferences: () => loadVaultPreferences(db),
    ...(waitUntil ? { waitUntil } : {}),
  }
}

// Misconfiguration must fail closed with a generic answer, never a stack trace.
async function run(
  request: Request,
  fn: (deps: RunnerDeps) => Promise<{ status: number; body: unknown }>,
  options: { includeOidcPolicy?: boolean } = {},
  waitUntil?: RunnerDeps['waitUntil'],
) {
  let deps: RunnerDeps
  try {
    deps = await buildDeps(request, options.includeOidcPolicy === true, waitUntil)
  } catch {
    return json({ error: 'vault_not_configured' }, { status: 503, headers: { 'Cache-Control': 'no-store' } })
  }
  try {
    const result = await fn(deps)
    return json(result.body, { status: result.status, headers: { 'Cache-Control': 'no-store' } })
  } catch {
    return json({ error: 'internal_error' }, { status: 500, headers: { 'Cache-Control': 'no-store' } })
  }
}

const MAX_RUNNER_JSON_BODY = 512 * 1024
const MAX_PROXY_METADATA_HEADER = 8 * 1024

type RunnerBodyParseResult =
  | { ok: true; body: Record<string, unknown> }
  | { ok: false; error: 'invalid_request' | 'body_too_large' }

function contentLength(request: Request, maxBytes: number):
  | { ok: true; length?: number }
  | { ok: false; error: 'invalid_request' | 'body_too_large' } {
  const raw = request.headers.get('content-length')
  if (raw === null) return { ok: true }
  if (!/^\d+$/.test(raw)) return { ok: false, error: 'invalid_request' }
  const length = Number(raw)
  if (!Number.isSafeInteger(length)) return { ok: false, error: 'invalid_request' }
  if (length > maxBytes) return { ok: false, error: 'body_too_large' }
  return { ok: true, length }
}

export async function parseRunnerBody(request: Request, maxBytes = MAX_RUNNER_JSON_BODY): Promise<RunnerBodyParseResult> {
  const declared = contentLength(request, maxBytes)
  if (!declared.ok) return declared
  if (!request.body) return { ok: false, error: 'invalid_request' }

  const reader = request.body.getReader()
  const decoder = new TextDecoder('utf-8', { fatal: true })
  let total = 0
  let text = ''
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      total += value.byteLength
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined)
        return { ok: false, error: 'body_too_large' }
      }
      text += decoder.decode(value, { stream: true })
    }
    text += decoder.decode()
    if (declared.length !== undefined && total !== declared.length) return { ok: false, error: 'invalid_request' }
    const body: unknown = JSON.parse(text)
    return typeof body === 'object' && body !== null && !Array.isArray(body)
      ? { ok: true, body: body as Record<string, unknown> }
      : { ok: false, error: 'invalid_request' }
  } catch {
    return { ok: false, error: 'invalid_request' }
  } finally {
    reader.releaseLock()
  }
}

function parseProxyMetadata(request: Request): Record<string, unknown> | null {
  const encoded = request.headers.get('x-vault-proxy-metadata')
  if (!encoded || encoded.length > MAX_PROXY_METADATA_HEADER || encoded.length % 4 === 1 || !/^[A-Za-z0-9_-]+$/.test(encoded)) {
    return null
  }
  try {
    const base64 = encoded.replace(/-/g, '+').replace(/_/g, '/')
    const binary = atob(base64 + '='.repeat((4 - encoded.length % 4) % 4))
    const bytes = new Uint8Array(binary.length)
    for (let index = 0; index < binary.length; index++) bytes[index] = binary.charCodeAt(index)
    const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
    return typeof value === 'object' && value !== null && !Array.isArray(value)
      ? value as Record<string, unknown>
      : null
  } catch {
    return null
  }
}

function invalidRequest() {
  return json({ error: 'invalid_request' }, { status: 400, headers: { 'Cache-Control': 'no-store' } })
}

function requestTooLarge() {
  return json({ error: 'body_too_large' }, { status: 413, headers: { 'Cache-Control': 'no-store' } })
}

export const runnerApp = new Spiceflow()
  .route({
    method: 'POST',
    path: '/api/runner/session',
    detail: { tags: ['Runner'], summary: 'Exchange a GitHub Actions OIDC token for a short session' },
    async handler({ request }) {
      return run(request, (deps) => createSession(deps, request.headers.get('authorization')), { includeOidcPolicy: true })
    },
  })
  .route({
    method: 'GET',
    path: '/api/runner/registry',
    detail: { tags: ['Runner'], summary: 'List credentials this runner may use (metadata only)' },
    async handler({ request }) {
      return run(request, (deps) => registry(deps, request.headers.get('authorization')))
    },
  })
  .route({
    method: 'GET',
    path: '/api/runner/integrations',
    detail: { tags: ['Runner'], summary: 'List verified CLI integration adapters for credentials available to this runner' },
    async handler({ request }) {
      return run(request, (deps) => integrations(deps, request.headers.get('authorization')))
    },
  })
  .route({
    method: 'POST',
    path: '/api/runner/registrations',
    detail: { tags: ['Runner'], summary: 'Ask the owner to register a credential; returns a one-time owner link' },
    async handler({ request }) {
      const parsed = await parseRunnerBody(request)
      if (!parsed.ok) return parsed.error === 'body_too_large' ? requestTooLarge() : invalidRequest()
      const body = parsed.body
      return run(request, (deps) => requestCredential(deps, request.headers.get('authorization'), {
        name: body.name, service: body.service, purpose: body.purpose, doc: body.doc,
      }))
    },
  })
  .route({
    method: 'POST',
    path: '/api/runner/use',
    detail: { tags: ['Runner'], summary: 'Make an HTTPS call with a stored credential; the token is never returned' },
    async handler({ request, waitUntil }) {
      const contentType = request.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase()
      if (contentType === 'application/octet-stream') {
        const declared = contentLength(request, MAX_REQUEST_BODY)
        if (!declared.ok) return declared.error === 'body_too_large' ? requestTooLarge() : invalidRequest()
        const metadata = parseProxyMetadata(request)
        if (!metadata) return invalidRequest()
        return run(request, (deps) => useCredential(deps, request.headers.get('authorization'), {
          name: metadata.name,
          method: metadata.method,
          url: metadata.url,
          headers: metadata.headers,
          purpose: metadata.purpose,
          consumer: metadata.consumer,
          bodyStream: request.body,
          bodyLength: declared.length,
        }), {}, waitUntil)
      }

      const parsed = await parseRunnerBody(request)
      if (!parsed.ok) return parsed.error === 'body_too_large' ? requestTooLarge() : invalidRequest()
      const body = parsed.body
      return run(request, (deps) => useCredential(deps, request.headers.get('authorization'), {
        name: body.name, method: body.method, url: body.url, headers: body.headers, body: body.body, purpose: body.purpose, consumer: body.consumer,
      }), {}, waitUntil)
    },
  })
