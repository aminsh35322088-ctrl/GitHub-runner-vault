import { describe, expect, test } from 'vitest'
import { getDb } from 'db'
import {
  cachedJwksSource, GITHUB_OIDC_ISSUER, policyFromEnv, verifyGithubOidc, type JwksSource, type OidcPolicy, resetOidcVerificationKeyCache,
} from './oidc.ts'
import {
  deriveSessionKey, getRunnerRevokedBefore, issueRunnerSession, revokeRunnerSessions, SESSION_TTL_MS, verifyRunnerSession, resetRunnerSessionKeyCache,
} from './runner-session.ts'
import { MAX_REQUEST_BODY, MAX_RESPONSE_BODY, redact, runProxy, secretForms, validateTarget } from './proxy.ts'

// ── OIDC ──────────────────────────────────────────────────────────

function b64url(input: Uint8Array | string): string {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function makeKeyPair() {
  const pair = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true, ['sign', 'verify'],
  ) as CryptoKeyPair
  const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey)
  return { privateKey: pair.privateKey, jwk: { kty: 'RSA', n: jwk.n!, e: jwk.e!, kid: 'k1', alg: 'RS256' } }
}

const NOW = 1_800_000_000_000
const policy: OidcPolicy = {
  audience: 'https://vault.example.workers.dev',
  repository: 'example-org/runner-project',
  repositoryId: '999',
  allowedRefs: ['refs/heads/main'],
  allowedEvents: ['workflow_dispatch', 'schedule', 'push'],
  allowedWorkflowRefs: ['example-org/runner-project/.github/workflows/runner.yml@refs/heads/main'],
}

function goodClaims(overrides: Record<string, unknown> = {}) {
  const s = Math.floor(NOW / 1000)
  return {
    iss: GITHUB_OIDC_ISSUER, aud: policy.audience, iat: s, nbf: s - 5, exp: s + 300,
    repository: 'example-org/runner-project', repository_id: '999', repository_owner: 'example-org',
    repository_owner_id: '65', ref: 'refs/heads/main',
    event_name: 'workflow_dispatch', run_id: '12345', run_attempt: '1', sha: 'abc', jti: 'j1',
    sub: 'repo:example-org/runner-project:ref:refs/heads/main',
    workflow_ref: 'example-org/runner-project/.github/workflows/runner.yml@refs/heads/main',
    ...overrides,
  }
}

async function sign(privateKey: CryptoKey, claims: Record<string, unknown>, header: Record<string, unknown> = { alg: 'RS256', kid: 'k1', typ: 'JWT' }) {
  const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`
  const sig = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKey, new TextEncoder().encode(input)))
  return `${input}.${b64url(sig)}`
}

describe('GitHub OIDC verification', () => {
  test('accepts a valid token and extracts the run identity', async () => {
    const { privateKey, jwk } = await makeKeyPair()
    const jwks: JwksSource = async () => ({ keys: [jwk] })
    const result = await verifyGithubOidc(await sign(privateKey, goodClaims()), policy, jwks, NOW)
    expect(result).toMatchObject({ ok: true, identity: { runId: '12345', repository: 'example-org/runner-project', ref: 'refs/heads/main' } })
  })

  test('automatically bootstraps only an owner-owned main-branch Lab workflow', async () => {
    const { privateKey, jwk } = await makeKeyPair()
    const bootstrap: OidcPolicy = {
      audience: policy.audience, repository: '', repositoryId: '', allowedRefs: ['refs/heads/main'],
      allowedEvents: ['workflow_dispatch', 'schedule', 'push'], allowedWorkflowRefs: [],
      bootstrap: { ownerId: '65', branch: 'main', workflowFile: 'rdc-lab.yml', allowedEvents: ['workflow_dispatch', 'schedule', 'push'] },
    }
    const claims = goodClaims({ workflow_ref: 'example-org/runner-project/.github/workflows/rdc-lab.yml@refs/heads/main' })
    const result = await verifyGithubOidc(await sign(privateKey, claims), bootstrap, async () => ({ keys: [jwk] }), NOW)
    expect(result).toMatchObject({
      ok: true,
      identity: {
        repository: 'example-org/runner-project', repositoryId: '999', repositoryOwnerId: '65',
        workflowRef: 'example-org/runner-project/.github/workflows/rdc-lab.yml@refs/heads/main',
      },
    })
  })

  test.each([
    ['different owner', { repository_owner_id: '66' }, 'wrong repository owner'],
    ['different branch', { ref: 'refs/heads/feature' }, 'ref not allowed'],
    ['pull request event', { event_name: 'pull_request' }, 'event not allowed'],
    ['different workflow', { workflow_ref: 'example-org/runner-project/.github/workflows/untrusted.yml@refs/heads/main' }, 'workflow not allowed'],
    ['missing workflow_ref', { workflow_ref: undefined }, 'workflow not allowed'],
    ['external reusable workflow', { job_workflow_ref: 'attacker/repo/.github/workflows/evil.yml@refs/heads/main' }, 'workflow not allowed'],
  ])('rejects automatic bootstrap with %s', async (_label, overrides, error) => {
    const { privateKey, jwk } = await makeKeyPair()
    const bootstrap: OidcPolicy = {
      audience: policy.audience, repository: '', repositoryId: '', allowedRefs: ['refs/heads/main'],
      allowedEvents: ['workflow_dispatch', 'schedule', 'push'], allowedWorkflowRefs: [],
      bootstrap: { ownerId: '65', branch: 'main', workflowFile: 'rdc-lab.yml', allowedEvents: ['workflow_dispatch', 'schedule', 'push'] },
    }
    const claims = goodClaims({
      workflow_ref: 'example-org/runner-project/.github/workflows/rdc-lab.yml@refs/heads/main',
      ...overrides,
    })
    expect(await verifyGithubOidc(await sign(privateKey, claims), bootstrap, async () => ({ keys: [jwk] }), NOW))
      .toEqual({ ok: false, error })
  })

  const bad: Array<[string, Record<string, unknown>, string]> = [
    ['wrong issuer', { iss: 'https://evil.example' }, 'wrong issuer'],
    ['wrong audience', { aud: 'https://other.example' }, 'wrong audience'],
    ['expired', { exp: Math.floor(NOW / 1000) - 600 }, 'token expired'],
    ['not yet valid', { nbf: Math.floor(NOW / 1000) + 3600 }, 'token not yet valid'],
    ['issued in the future', { iat: Math.floor(NOW / 1000) + 3600 }, 'token issued in the future'],
    ['wrong repository', { repository: 'someone/else' }, 'wrong repository'],
    ['wrong repository id', { repository_id: '1' }, 'wrong repository'],
    ['missing repository id', { repository_id: undefined }, 'wrong repository'],
    ['missing workflow binding', { workflow_ref: undefined }, 'workflow not allowed'],
    ['wrong workflow binding', { workflow_ref: 'example-org/runner-project/.github/workflows/other.yml@refs/heads/main' }, 'workflow not allowed'],
    ['pull request ref', { ref: 'refs/pull/7/merge' }, 'ref not allowed'],
    ['other branch', { ref: 'refs/heads/feature' }, 'ref not allowed'],
    ['pull_request event', { event_name: 'pull_request' }, 'event not allowed'],
    ['missing run id', { run_id: undefined }, 'missing run id'],
    ['non-numeric run id', { run_id: 'abc' }, 'missing run id'],
    ['subject names a different repository', { sub: 'repo:attacker/other:ref:refs/heads/main' }, 'subject mismatch'],
    ['missing subject', { sub: undefined }, 'subject mismatch'],
    ['missing token id', { jti: undefined }, 'missing token id'],
  ]
  test.each(bad)('rejects %s', async (_label, overrides, error) => {
    const { privateKey, jwk } = await makeKeyPair()
    const result = await verifyGithubOidc(await sign(privateKey, goodClaims(overrides)), policy, async () => ({ keys: [jwk] }), NOW)
    expect(result).toEqual({ ok: false, error })
  })

  test('allows a main push from the exact approved workflow', async () => {
    const { privateKey, jwk } = await makeKeyPair()
    const token = await sign(privateKey, goodClaims({ event_name: 'push' }))
    expect((await verifyGithubOidc(token, policy, async () => ({ keys: [jwk] }), NOW)).ok).toBe(true)
    const wrong = await sign(privateKey, goodClaims({ event_name: 'push', ref: 'refs/heads/feature' }))
    expect(await verifyGithubOidc(wrong, policy, async () => ({ keys: [jwk] }), NOW)).toEqual({ ok: false, error: 'ref not allowed' })
  })

  test('audience may be a list that contains ours', async () => {
    const { privateKey, jwk } = await makeKeyPair()
    const token = await sign(privateKey, goodClaims({ aud: ['other', policy.audience] }))
    expect((await verifyGithubOidc(token, policy, async () => ({ keys: [jwk] }), NOW)).ok).toBe(true)
  })

  test('rejects a token signed by a different key', async () => {
    const real = await makeKeyPair()
    const attacker = await makeKeyPair()
    const token = await sign(attacker.privateKey, goodClaims())
    expect(await verifyGithubOidc(token, policy, async () => ({ keys: [real.jwk] }), NOW)).toEqual({ ok: false, error: 'bad signature' })
  })

  test('rejects tampered claims', async () => {
    const { privateKey, jwk } = await makeKeyPair()
    const token = await sign(privateKey, goodClaims())
    const [h, , s] = token.split('.')
    const forged = `${h}.${b64url(JSON.stringify(goodClaims({ ref: 'refs/heads/main', run_id: '777' })))}.${s}`
    expect(await verifyGithubOidc(forged, policy, async () => ({ keys: [jwk] }), NOW)).toEqual({ ok: false, error: 'bad signature' })
  })

  test.each([
    ['alg none', { alg: 'none', kid: 'k1' }],
    ['HMAC confusion', { alg: 'HS256', kid: 'k1' }],
    ['ES256', { alg: 'ES256', kid: 'k1' }],
    ['no kid', { alg: 'RS256' }],
  ])('rejects %s before any key lookup', async (_label, header) => {
    const { privateKey } = await makeKeyPair()
    let lookedUp = false
    const result = await verifyGithubOidc(await sign(privateKey, goodClaims(), header), policy, async () => { lookedUp = true; return { keys: [] } }, NOW)
    expect(result).toEqual({ ok: false, error: 'unsupported algorithm' })
    expect(lookedUp).toBe(false)
  })

  test.each(['', 'a.b', 'a.b.c.d', 'x'.repeat(9000), 'not.a.jwt'])('rejects malformed token %#', async (token) => {
    const result = await verifyGithubOidc(token, policy, async () => ({ keys: [] }), NOW)
    expect(result.ok).toBe(false)
  })

  test('an unknown key id forces one JWKS refresh, then fails', async () => {
    const { privateKey, jwk } = await makeKeyPair()
    const calls: boolean[] = []
    const jwks: JwksSource = async (force) => { calls.push(force); return { keys: [{ ...jwk, kid: 'other' }] } }
    const result = await verifyGithubOidc(await sign(privateKey, goodClaims()), policy, jwks, NOW)
    expect(result).toEqual({ ok: false, error: 'unknown signing key' })
    expect(calls).toEqual([false, true])
  })

  test('a rotated key is picked up after a refresh', async () => {
    const { privateKey, jwk } = await makeKeyPair()
    const jwks: JwksSource = async (force) => ({ keys: force ? [jwk] : [] })
    expect((await verifyGithubOidc(await sign(privateKey, goodClaims()), policy, jwks, NOW)).ok).toBe(true)
  })

  test('replaces a cached verification key when the same key id has new key material', async () => {
    resetOidcVerificationKeyCache()
    const first = await makeKeyPair()
    const rotated = await makeKeyPair()
    const firstToken = await sign(first.privateKey, goodClaims())
    const rotatedToken = await sign(rotated.privateKey, goodClaims())
    expect((await verifyGithubOidc(firstToken, policy, async () => ({ keys: [first.jwk] }), NOW)).ok).toBe(true)
    expect((await verifyGithubOidc(rotatedToken, policy, async () => ({ keys: [rotated.jwk] }), NOW)).ok).toBe(true)
    resetOidcVerificationKeyCache()
  })

  test('JWKS outage fails closed', async () => {
    const { privateKey } = await makeKeyPair()
    const jwks: JwksSource = async () => { throw new Error('down') }
    expect(await verifyGithubOidc(await sign(privateKey, goodClaims()), policy, jwks, NOW)).toEqual({ ok: false, error: 'signing keys unavailable' })
  })

  test('bounds stale JWKS fallback during an outage, then fails closed', async () => {
    let fetches = 0
    let clock = 0
    let unavailable = false
    const source = cachedJwksSource((async () => {
      fetches += 1
      return unavailable ? new Response('', { status: 503 }) : Response.json({ keys: [] })
    }) as typeof fetch, () => clock)

    const initial = await source(false)
    unavailable = true
    clock = 11 * 60_000
    expect(await source(false)).toEqual(initial)
    clock = 16 * 60_000
    await expect(source(false)).rejects.toThrow('could not fetch GitHub JWKS')
    expect(fetches).toBe(3)
  })

  test('the cached JWKS source limits refreshes to once a minute', async () => {
    let fetches = 0
    let clock = 0
    const source = cachedJwksSource((async () => { fetches += 1; return Response.json({ keys: [] }) }) as typeof fetch, () => clock)
    await source(false)
    await source(true)
    await source(true)
    expect(fetches).toBe(1)
    clock = 61_000
    await source(true)
    expect(fetches).toBe(2)
  })

  test('policy is instance-configured and fails closed when any required binding is missing', () => {
    const configured = {
      RUNNER_REPOSITORY: 'example-org/runner-project',
      RUNNER_REPOSITORY_ID: '42',
      RUNNER_ALLOWED_REFS: 'refs/heads/main,refs/heads/release',
      RUNNER_ALLOWED_EVENTS: 'workflow_dispatch,push',
      RUNNER_ALLOWED_WORKFLOW_REFS: 'example-org/runner-project/.github/workflows/runner.yml@refs/heads/main',
    }
    expect(policyFromEnv(configured, 'https://vault.example.test')).toEqual({
      audience: 'https://vault.example.test',
      repository: 'example-org/runner-project',
      repositoryId: '42',
      allowedRefs: ['refs/heads/main', 'refs/heads/release'],
      allowedEvents: ['workflow_dispatch', 'push'],
      allowedWorkflowRefs: ['example-org/runner-project/.github/workflows/runner.yml@refs/heads/main'],
    })
    for (const key of Object.keys(configured)) {
      const incomplete = { ...configured }
      delete incomplete[key as keyof typeof configured]
      expect(() => policyFromEnv(incomplete, 'https://vault.example.test')).toThrow()
    }
    expect(() => policyFromEnv({ ...configured, RUNNER_REPOSITORY: 'not a repo' }, 'https://x')).toThrow()
    expect(() => policyFromEnv({ ...configured, RUNNER_ALLOWED_EVENTS: 'pull_request' }, 'https://x')).toThrow(/Pull-request/)
  })
})

// ── Runner sessions ─────────────────────────────────────────────────

const identity = { repository: 'a/b', repositoryId: '1', repositoryOwnerId: '2', runId: '55', runAttempt: '2', ref: 'refs/heads/main', event: 'workflow_dispatch', workflow: 'w', workflowRef: 'a/b/.github/workflows/w.yml@refs/heads/main', sha: 's', jti: 'j', sub: 'repo:a/b:ref:refs/heads/main', expiresAt: NOW + 300_000 }
const SECRET_32 = 'test-secret-at-least-32-characters-long!!'

describe('runner sessions', () => {
  test('issue and verify round trip', async () => {
    const key = await deriveSessionKey(SECRET_32)
    const { token, expiresAt } = await issueRunnerSession(key, identity, NOW)
    expect(expiresAt).toBe(NOW + SESSION_TTL_MS)
    const verified = await verifyRunnerSession(key, token, NOW + 1000, 0)
    expect(verified).toMatchObject({ ok: true, session: { repository: 'a/b', runId: '55', sub: 'runner:a/b#55.2' } })
  })

  test('expires after the ttl', async () => {
    const key = await deriveSessionKey(SECRET_32)
    const { token } = await issueRunnerSession(key, identity, NOW)
    expect(await verifyRunnerSession(key, token, NOW + SESSION_TTL_MS, 0)).toEqual({ ok: false, error: 'session expired' })
  })

  test('tampering and a different secret are rejected', async () => {
    const key = await deriveSessionKey(SECRET_32)
    const other = await deriveSessionKey('another-secret-that-is-also-32-chars-long!!')
    const { token } = await issueRunnerSession(key, identity, NOW)
    expect((await verifyRunnerSession(other, token, NOW, 0)).ok).toBe(false)
    const [prefix, payload, sig] = token.split('.')
    const forgedPayload = b64url(JSON.stringify({ ...JSON.parse(atob(payload!.replace(/-/g, '+').replace(/_/g, '/'))), exp: NOW + 1e12 }))
    expect((await verifyRunnerSession(key, `${prefix}.${forgedPayload}.${sig}`, NOW, 0)).ok).toBe(false)
    for (const bad of ['', 'rs1.x', 'rs2.a.b', `rs1.${payload}.`, 'x'.repeat(3000)]) {
      expect((await verifyRunnerSession(key, bad, NOW, 0)).ok).toBe(false)
    }
  })

  test('revocation invalidates sessions issued before it, not after', async () => {
    const key = await deriveSessionKey(SECRET_32)
    const db = getDb()
    const old = await issueRunnerSession(key, identity, NOW)
    await revokeRunnerSessions(db, NOW + 10)
    const revokedBefore = await getRunnerRevokedBefore(db)
    expect(revokedBefore).toBe(NOW + 10)
    expect(await verifyRunnerSession(key, old.token, NOW + 20, revokedBefore)).toEqual({ ok: false, error: 'session revoked' })
    const fresh = await issueRunnerSession(key, identity, NOW + 11)
    expect((await verifyRunnerSession(key, fresh.token, NOW + 20, revokedBefore)).ok).toBe(true)
  })

  test('the signing secret must be long enough', async () => {
    await expect(deriveSessionKey('short')).rejects.toThrow()
    await expect(deriveSessionKey(undefined)).rejects.toThrow()
  })

  test('reuses the derived key per isolate and rotates when the secret changes', async () => {
    resetRunnerSessionKeyCache()
    const firstPromise = deriveSessionKey(SECRET_32)
    expect(deriveSessionKey(SECRET_32)).toBe(firstPromise)
    const first = await firstPromise
    const rotatedSecret = SECRET_32 + '-rotated'
    const rotated = await deriveSessionKey(rotatedSecret)
    expect(rotated).not.toBe(first)
    expect(deriveSessionKey(rotatedSecret)).toBeInstanceOf(Promise)
    expect(await deriveSessionKey(rotatedSecret)).toBe(rotated)
    resetRunnerSessionKeyCache()
  })
})

// ── Proxy ─────────────────────────────────────────────────────────

const credential = { allowedHosts: ['api.cloudflare.com'], authHeader: 'Authorization', authScheme: 'Bearer' as const }
const SECRET = 'cfut_TOPSECRET_0123456789abcdef'

type Seen = { url: string; init: RequestInit }
function stubFetch(respond: (seen: Seen) => Response | Promise<Response>, seen: Seen[] = []): typeof fetch {
  return (async (url: string, init: RequestInit) => {
    const entry = { url: String(url), init }
    seen.push(entry)
    return respond(entry)
  }) as unknown as typeof fetch
}

describe('proxy target validation', () => {
  test.each([
    'http://api.cloudflare.com/x', 'https://api.cloudflare.com:8443/x', 'https://user:pw@api.cloudflare.com/x',
    'https://evil.com/x', 'https://api.cloudflare.com.evil.com/x', 'https://evilapi.cloudflare.com/x', 'https://127.0.0.1/x',
    'https://169.254.169.254/latest/meta-data', 'ftp://api.cloudflare.com/x', 'not a url', '', `https://api.cloudflare.com/${'a'.repeat(2100)}`,
  ])('refuses %s', (url) => {
    expect(validateTarget(url, credential.allowedHosts).ok).toBe(false)
  })

  test('allows the exact host, case-insensitively', () => {
    expect(validateTarget('https://API.cloudflare.com/client/v4/user/tokens/verify', credential.allowedHosts).ok).toBe(true)
  })
})

describe('proxy requests', () => {
  test('injects the credential and returns the upstream response', async () => {
    const seen: Seen[] = []
    const fetchFn = stubFetch(() => Response.json({ success: true }), seen)
    const result = await runProxy({ credential, value: SECRET, method: 'get', url: 'https://api.cloudflare.com/client/v4/user/tokens/verify' }, fetchFn)
    expect(result).toMatchObject({ ok: true, status: 200, host: 'api.cloudflare.com', method: 'GET' })
    const headers = new Headers(seen[0]!.init.headers)
    expect(headers.get('authorization')).toBe(`Bearer ${SECRET}`)
    expect(seen[0]!.init.redirect).toBe('manual')
  })

  test('the runner cannot override the auth header or set forbidden headers', async () => {
    const fetchFn = stubFetch(() => new Response('ok'))
    for (const header of ['Authorization', 'authorization', 'Host', 'Cookie', 'X-Forwarded-For', 'Proxy-Authorization', 'Content-Length', 'X-Custom']) {
      const result = await runProxy({ credential, value: SECRET, method: 'GET', url: 'https://api.cloudflare.com/x', headers: { [header]: 'evil' } }, fetchFn)
      expect(result).toMatchObject({ ok: false, error: 'bad_header' })
    }
  })

  test('safe headers pass through; header injection is refused', async () => {
    const seen: Seen[] = []
    const fetchFn = stubFetch(() => new Response('ok'), seen)
    await runProxy({ credential, value: SECRET, method: 'POST', url: 'https://api.cloudflare.com/x', headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'anthropic-version': '2026-10-21', 'x-pinecone-api-version': '2025-10' }, body: '{}' }, fetchFn)
    const headers = new Headers(seen[0]!.init.headers)
    expect(headers.get('content-type')).toBe('application/json')
    expect(headers.get('anthropic-version')).toBe('2026-10-21')
    expect(headers.get('x-pinecone-api-version')).toBe('2025-10')
    expect(await runProxy({ credential, value: SECRET, method: 'GET', url: 'https://api.cloudflare.com/x', headers: { accept: 'a\r\nX-Evil: 1' } }, fetchFn)).toMatchObject({ ok: false, error: 'bad_header' })
  })

  test('injects only declared secondary auth fields and redacts every mapped secret from responses', async () => {
    const secondary = 'secondary-proxy-secret-value'
    const seen: Seen[] = []
    const result = await runProxy({
      credential: {
        ...credential,
        authFieldHeaders: [{ field: 'client_secret', header: 'X-Client-Secret', scheme: 'Raw', required: true }],
      },
      value: SECRET,
      authFields: { client_secret: secondary, undeclared: 'not-forwarded-secret-value' },
      method: 'GET',
      url: 'https://api.cloudflare.com/x',
    }, stubFetch(() => new Response('echo ' + SECRET + ' and ' + secondary), seen))
    expect(result).toMatchObject({ ok: true, body: 'echo [REDACTED] and [REDACTED]' })
    const headers = new Headers(seen[0]!.init.headers)
    expect(headers.get('authorization')).toBe('Bearer ' + SECRET)
    expect(headers.get('x-client-secret')).toBe(secondary)
    expect(headers.get('undeclared')).toBeNull()
    expect(JSON.stringify(result)).not.toContain(SECRET)
    expect(JSON.stringify(result)).not.toContain(secondary)
  })

  test('refuses a missing required secondary auth field before making the upstream request', async () => {
    const seen: Seen[] = []
    const result = await runProxy({
      credential: {
        ...credential,
        authFieldHeaders: [{ field: 'client_secret', header: 'X-Client-Secret', scheme: 'Raw', required: true }],
      },
      value: SECRET,
      authFields: {},
      method: 'GET',
      url: 'https://api.cloudflare.com/x',
    }, stubFetch(() => new Response('should-not-run'), seen))
    expect(result).toMatchObject({ ok: false, error: 'bad_header' })
    expect(seen).toHaveLength(0)
  })

  test('custom auth header and raw scheme', async () => {
    const seen: Seen[] = []
    await runProxy({ credential: { ...credential, authHeader: 'X-Auth-Key', authScheme: 'Raw' }, value: SECRET, method: 'GET', url: 'https://api.cloudflare.com/x' }, stubFetch(() => new Response('ok'), seen))
    const headers = new Headers(seen[0]!.init.headers)
    expect(headers.get('x-auth-key')).toBe(SECRET)
    expect(headers.get('authorization')).toBeNull()
  })

  test.each(['CONNECT', 'TRACE', 'OPTIONS', '', 'GET /x HTTP/1.1'])('refuses method %s', async (method) => {
    expect(await runProxy({ credential, value: SECRET, method, url: 'https://api.cloudflare.com/x' }, stubFetch(() => new Response('ok')))).toMatchObject({ ok: false, error: 'bad_method' })
  })

  test('bodies: refuses GET bodies, forwards deployment-sized payloads, and enforces the hard cap', async () => {
    const seen: Seen[] = []
    const fetchFn = stubFetch(() => new Response('ok'), seen)
    expect(await runProxy({ credential, value: SECRET, method: 'GET', url: 'https://api.cloudflare.com/x', body: 'x' }, fetchFn)).toMatchObject({ ok: false, error: 'body_not_allowed' })
    const deploymentPayload = 'x'.repeat(512 * 1024)
    expect(await runProxy({ credential, value: SECRET, method: 'POST', url: 'https://api.cloudflare.com/x', body: deploymentPayload }, fetchFn)).toMatchObject({ ok: true, status: 200 })
    expect(seen[0]?.init.body).toBe(deploymentPayload)
    expect(await runProxy({ credential, value: SECRET, method: 'POST', url: 'https://api.cloudflare.com/x', body: 'x'.repeat(MAX_REQUEST_BODY + 1) }, fetchFn)).toMatchObject({ ok: false, error: 'body_too_large' })
  })

  test('forwards raw binary request bytes unchanged and enforces the byte cap', async () => {
    const seen: Seen[] = []
    const fetchFn = stubFetch(() => new Response('ok'), seen)
    const payload = new Uint8Array([0x00, 0xff, 0xc3, 0x28, 0x7b, 0x7d, 0x0d, 0x0a])
    const result = await runProxy({
      credential, value: SECRET, method: 'POST', url: 'https://api.cloudflare.com/upload', body: payload,
    }, fetchFn)
    expect(result).toMatchObject({ ok: true, status: 200 })
    expect(seen[0]?.init.body).toBeInstanceOf(Uint8Array)
    expect(new Uint8Array(seen[0]?.init.body as Uint8Array)).toEqual(payload)

    const oversized = new Uint8Array(MAX_REQUEST_BODY + 1)
    expect(await runProxy({
      credential, value: SECRET, method: 'POST', url: 'https://api.cloudflare.com/upload', body: oversized,
    }, fetchFn)).toMatchObject({ ok: false, error: 'body_too_large' })
    expect(seen).toHaveLength(1)
  })

  test('never follows a redirect and does not forward the secret elsewhere', async () => {
    const seen: Seen[] = []
    const fetchFn = stubFetch(() => new Response(null, { status: 302, headers: { Location: 'https://evil.example/steal' } }), seen)
    const result = await runProxy({ credential, value: SECRET, method: 'GET', url: 'https://api.cloudflare.com/x' }, fetchFn)
    expect(result).toMatchObject({ ok: true, status: 302 })
    expect(seen).toHaveLength(1)
    expect(seen[0]!.url).toBe('https://api.cloudflare.com/x')
  })

  test('redacts the secret from the body and headers in every common encoding', async () => {
    const encoded = encodeURIComponent(SECRET)
    const fetchFn = stubFetch(() => new Response(
      JSON.stringify({ echo: SECRET, url: `https://x/?t=${encoded}`, b64: btoa(SECRET), nested: JSON.stringify({ k: SECRET }) }),
      { headers: { 'Content-Type': 'application/json', Link: `<https://x/?t=${SECRET}>; rel="next"`, 'Set-Cookie': `s=${SECRET}`, 'X-Secret-Echo': SECRET } },
    ))
    const result = await runProxy({ credential, value: SECRET, method: 'GET', url: 'https://api.cloudflare.com/x' }, fetchFn)
    if (!result.ok) throw new Error('unexpected')
    const everything = JSON.stringify(result)
    expect(everything).not.toContain(SECRET)
    expect(everything).not.toContain(encoded)
    expect(everything).not.toContain(btoa(SECRET))
    expect(result.redactions).toBeGreaterThanOrEqual(5)
    expect(result.headers['set-cookie']).toBeUndefined()
    expect(result.headers['x-secret-echo']).toBeUndefined()
  })

  test('caps the response size and says so', async () => {
    const fetchFn = stubFetch(() => new Response('a'.repeat(MAX_RESPONSE_BODY + 500)))
    const result = await runProxy({ credential, value: SECRET, method: 'GET', url: 'https://api.cloudflare.com/x' }, fetchFn)
    if (!result.ok) throw new Error('unexpected')
    expect(result.truncated).toBe(true)
    expect(result.body.length).toBe(MAX_RESPONSE_BODY)
  })

  test('upstream failures and timeouts are reported without detail', async () => {
    const boom = stubFetch(() => { throw new Error(`connection to ${SECRET} failed`) })
    const failed = await runProxy({ credential, value: SECRET, method: 'GET', url: 'https://api.cloudflare.com/x' }, boom)
    expect(failed).toEqual({ ok: false, error: 'upstream_error' })
    const slow = stubFetch(() => { const e = new Error('t'); e.name = 'TimeoutError'; throw e })
    expect(await runProxy({ credential, value: SECRET, method: 'GET', url: 'https://api.cloudflare.com/x' }, slow)).toEqual({ ok: false, error: 'upstream_timeout' })
  })

  test('upstream error statuses are returned as they are (not classified as bad tokens)', async () => {
    const fetchFn = stubFetch(() => Response.json({ errors: [{ message: 'Authentication error' }] }, { status: 403 }))
    expect(await runProxy({ credential, value: SECRET, method: 'GET', url: 'https://api.cloudflare.com/x' }, fetchFn)).toMatchObject({ ok: true, status: 403 })
  })
})

describe('redaction helpers', () => {
  test('forms include raw, url, json and base64 variants but skip trivial ones', () => {
    expect(secretForms('ab')).toEqual([])
    const forms = secretForms('p@ss"word/1')
    expect(forms).toContain('p@ss"word/1')
    expect(forms).toContain(encodeURIComponent('p@ss"word/1'))
    expect(forms).toContain('p@ss\\"word/1')
    expect(forms).toContain(btoa('p@ss"word/1'))
  })
  test('redact counts replacements', () => {
    expect(redact('a SECRET1234 b SECRET1234', 'SECRET1234')).toEqual({ text: 'a [REDACTED] b [REDACTED]', count: 2 })
  })
})

describe('Telegram Bot API proxy authentication', () => {
  const botToken = '123456789:' + 'A'.repeat(35)
  const telegramCredential = {
    allowedHosts: ['api.telegram.org'],
    authHeader: 'X-Telegram-Bot-Api-Token',
    authScheme: 'Raw' as const,
  }

  test('injects the token only into the official /bot<TOKEN>/METHOD path and redacts it from results', async () => {
    const seen: Seen[] = []
    const result = await runProxy({
      credential: telegramCredential,
      value: botToken,
      method: 'GET',
      url: 'https://api.telegram.org/getMe',
    }, stubFetch(() => Response.json({ ok: true, result: { id: 123456789 } }), seen))

    expect(seen).toHaveLength(1)
    expect(seen[0]!.url).toBe('https://api.telegram.org/bot' + botToken + '/getMe')
    expect(new Headers(seen[0]!.init.headers).has('x-telegram-bot-api-token')).toBe(false)
    expect(result).toMatchObject({ ok: true, status: 200, path: '/getMe' })
    expect(JSON.stringify(result)).not.toContain(botToken)
  })

  test('rejects paths that could inject another token or method segment', async () => {
    const seen: Seen[] = []
    for (const url of [
      'https://api.telegram.org/bot123:some-secret/getMe',
      'https://api.telegram.org/getMe/extra',
      'https://api.telegram.org/%2Fbot123/getMe',
    ]) {
      expect(await runProxy({ credential: telegramCredential, value: botToken, method: 'GET', url }, stubFetch(() => new Response('ok'), seen)))
        .toMatchObject({ ok: false, error: 'bad_url' })
    }
    expect(seen).toHaveLength(0)
  })
})
