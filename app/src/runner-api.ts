// HTTP surface for runners. All logic lives in lib/runner-core.ts.
// Mounted in app.tsx via .use(runnerApp).

import { Spiceflow, json } from 'spiceflow'
import { z } from 'zod'
import { env } from 'cloudflare:workers'
import { getDb } from 'db'
import { loadVaultKeys, type VaultEnv } from './lib/vault-config.ts'
import { cachedJwksSource } from './lib/oidc.ts'
import { loadRunnerPolicy } from './lib/runner-policy.ts'
import { deriveSessionKey } from './lib/runner-session.ts'
import { createSession, registry, requestCredential, useCredential, type RunnerDeps } from './lib/runner-core.ts'
import { getRequestOrigin } from './db.ts'

const jwks = cachedJwksSource()

async function buildDeps(request: Request): Promise<RunnerDeps> {
  const e = env as unknown as Record<string, unknown>
  const origin = getRequestOrigin(request)
  const db = getDb()
  const keys = await loadVaultKeys(db, e as VaultEnv)
  return {
    db,
    encryptionKey: keys.encryptionKey,
    sessionKey: await deriveSessionKey(keys.authSecret),
    policy: await loadRunnerPolicy(db, e, origin),
    jwks,
    origin,
    fetchFn: fetch,
    now: Date.now(),
  }
}

// Misconfiguration must fail closed with a generic answer, never a stack trace.
async function run(request: Request, fn: (deps: RunnerDeps) => Promise<{ status: number; body: unknown }>) {
  let deps: RunnerDeps
  try {
    deps = await buildDeps(request)
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
      return run(request, (deps) => createSession(deps, request.headers.get('authorization')))
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
    method: 'POST',
    path: '/api/runner/registrations',
    detail: { tags: ['Runner'], summary: 'Ask the owner to register a credential; returns a one-time owner link' },
    request: anyBody,
    async handler({ request }) {
      const body = await parseRunnerBody(request)
      if (!body) return invalidRequest()
      return run(request, (deps) => requestCredential(deps, request.headers.get('authorization'), {
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
      return run(request, (deps) => useCredential(deps, request.headers.get('authorization'), {
        name: body.name, method: body.method, url: body.url, headers: body.headers, body: body.body, purpose: body.purpose,
      }))
    },
  })
