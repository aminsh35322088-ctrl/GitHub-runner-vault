// HTTP surface for runners. All logic lives in lib/runner-core.ts.
// Mounted in app.tsx via .use(runnerApp).

import { Spiceflow, json } from 'spiceflow'
import { z } from 'zod'
import { env } from 'cloudflare:workers'
import { getDb } from 'db'
import { importEncryptionKey } from './lib/credential-crypto.ts'
import { cachedJwksSource, policyFromEnv } from './lib/oidc.ts'
import { deriveSessionKey } from './lib/runner-session.ts'
import { createSession, registry, requestCredential, useCredential, type RunnerDeps } from './lib/runner-core.ts'
import { pinnedOrigin } from './db.ts'

const jwks = cachedJwksSource()

async function buildDeps(): Promise<RunnerDeps> {
  const e = env as unknown as Record<string, unknown>
  const origin = pinnedOrigin()
  if (!origin) throw new Error('PUBLIC_ORIGIN is not configured')
  return {
    db: getDb(),
    encryptionKey: await importEncryptionKey(e.ENCRYPTION_KEY),
    sessionKey: await deriveSessionKey(e.BETTER_AUTH_SECRET),
    policy: policyFromEnv(e, origin),
    jwks,
    origin,
    fetchFn: fetch,
    now: Date.now(),
  }
}

// Misconfiguration must fail closed with a generic answer, never a stack trace.
async function run(fn: (deps: RunnerDeps) => Promise<{ status: number; body: unknown }>) {
  let deps: RunnerDeps
  try {
    deps = await buildDeps()
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

const anyBody = z.record(z.string(), z.unknown())

async function parseRunnerBody(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const body: unknown = await request.json()
    return typeof body === 'object' && body !== null && !Array.isArray(body)
      ? body as Record<string, unknown>
      : null
  } catch {
    return null
  }
}

function invalidRequest() {
  return json({ error: 'invalid_request' }, { status: 400, headers: { 'Cache-Control': 'no-store' } })
}

export const runnerApp = new Spiceflow()
  .route({
    method: 'POST',
    path: '/api/runner/session',
    detail: { tags: ['Runner'], summary: 'Exchange a GitHub Actions OIDC token for a short session' },
    async handler({ request }) {
      return run((deps) => createSession(deps, request.headers.get('authorization')))
    },
  })
  .route({
    method: 'GET',
    path: '/api/runner/registry',
    detail: { tags: ['Runner'], summary: 'List credentials this runner may use (metadata only)' },
    async handler({ request }) {
      return run((deps) => registry(deps, request.headers.get('authorization')))
    },
  })
  .route({
    method: 'POST',
    path: '/api/runner/registrations',
    detail: { tags: ['Runner'], summary: 'Ask the owner to register a credential; returns a one-time owner link' },
    request: anyBody,
    async handler({ request }) {
      const body = await parseRunnerBody(request)
      if (!body) return invalidRequest()
      return run((deps) => requestCredential(deps, request.headers.get('authorization'), {
        name: body.name, service: body.service, purpose: body.purpose, doc: body.doc,
      }))
    },
  })
  .route({
    method: 'POST',
    path: '/api/runner/use',
    detail: { tags: ['Runner'], summary: 'Make an HTTPS call with a stored credential; the token is never returned' },
    request: anyBody,
    async handler({ request }) {
      const body = await parseRunnerBody(request)
      if (!body) return invalidRequest()
      return run((deps) => useCredential(deps, request.headers.get('authorization'), {
        name: body.name, method: body.method, url: body.url, headers: body.headers, body: body.body, purpose: body.purpose,
      }))
    },
  })
