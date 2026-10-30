import { describe, expect, test } from 'vitest'
import { getDb } from 'db'
import {
  cachedJwksSource, GITHUB_OIDC_ISSUER, policyFromEnv, verifyGithubOidc, type JwksSource, type OidcPolicy,
} from './oidc.ts'
import {
  deriveSessionKey, getRunnerRevokedBefore, issueRunnerSession, revokeRunnerSessions, SESSION_TTL_MS, verifyRunnerSession,
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
  repository: 'aminsh35322088-ctrl/GitHub-Runner-Lab',
  repositoryId: '999',
  allowedRefs: ['refs/heads/main'],
  allowedEvents: ['workflow_dispatch', 'schedule'],
}

function goodClaims(overrides: Record<string, unknown> = {}) {
  const s = Math.floor(NOW / 1000)
  return {
    iss: GITHUB_OIDC_ISSUER, aud: policy.audience, iat: s, nbf: s - 5, exp: s + 300,
    repository: 'aminsh35322088-ctrl/GitHub-Runner-Lab', repository_id: '999', ref: 'refs/heads/main',
    event_name: 'workflow_dispatch', run_id: '12345', run_attempt: '1', sha: 'abc', jti: 'j1',
    job_workflow_ref: 'aminsh35322088-ctrl/GitHub-Runner-Lab/.github/workflows/rdc-lab.yml@refs/heads/main',
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
    expect(result).toMatchObject({ ok: true, identity: { runId: '12345', repository: 'aminsh35322088-ctrl/GitHub-Runner-Lab', ref: 'refs/heads/main' } })
  })

  const bad: Array<[string, Record<string, unknown>, string]> = [
    ['wrong issuer', { iss: 'https://evil.example' }, 'wrong issuer'],
    ['wrong audience', { aud: 'https://other.example' }, 'wrong audience'],
    ['expired', { exp: Math.floor(NOW / 1000) - 600 }, 'token expired'],
    ['not yet valid', { nbf: Math.floor(NOW / 1000) + 3600 }, 'token not yet valid'],
    ['issued in the future', { iat: Math.floor(NOW / 1000) + 3600 }, 'token issued in the future'],
    ['wrong repository', { repository: 'someone/else' }, 'wrong repository'],
    ['wrong repository id', { repository_id: '1' }, 'wrong repository'],
    ['pull request ref', { ref: 'refs/pull/7/merge' }, 'ref not allowed'],
    ['other branch', { ref: 'refs/heads/feature' }, 'ref not allowed'],
    ['pull_request event', { event_name: 'pull_request' }, 'event not allowed'],
    ['missing run id', { run_id: undefined }, 'missing run id'],
    ['non-numeric run id', { run_id: 'abc' }, 'missing run id'],
  ]
  test.each(bad)('rejects %s', async (_label, overrides, error) => {
    const { privateKey, jwk } = await makeKeyPair()
    const result = await verifyGithubOidc(await sign(privateKey, goodClaims(overrides)), policy, async () => ({ keys: [jwk] }), NOW)
    expect(result).toEqual({ ok: false, error })
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

  test('JWKS outage fails closed', async () => {
    const { privateKey } = await makeKeyPair()
    const jwks: JwksSource = async () => { throw new Error('down') }
    expect(await verifyGithubOidc(await sign(privateKey, goodClaims()), policy, jwks, NOW)).toEqual({ ok: false, error: 'signing keys unavailable' })
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

  test('policy comes from bindings and fails closed on a bad repository', () => {
    expect(() => policyFromEnv({}, 'https://x')).toThrow()
    expect(() => policyFromEnv({ RUNNER_REPOSITORY: 'not a repo' }, 'https://x')).toThrow()
    expect(policyFromEnv({ RUNNER_REPOSITORY: 'a/b', RUNNER_REPOSITORY_ID: '42' }, 'https://x')).toEqual({
      audience: 'https://x', repository: 'a/b', repositoryId: '42', allowedRefs: ['refs/heads/main'], allowedEvents: ['workflow_dispatch', 'schedule'],
    })
    expect(policyFromEnv({ RUNNER_REPOSITORY: 'a/b', RUNNER_ALLOWED_REFS: 'refs/heads/x, refs/heads/y' }, 'https://x').allowedRefs).toEqual(['refs/heads/x', 'refs/heads/y'])
  })
})

// ── Runner sessions ─────────────────────────────────────────────────

const identity = { repository: 'a/b', repositoryId: '1', runId: '55', runAttempt: '2', ref: 'refs/heads/main', event: 'workflow_dispatch', workflow: 'w', sha: 's', jti: 'j' }
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
    await runProxy({ credential, value: SECRET, method: 'POST', url: 'https://api.cloudflare.com/x', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: '{}' }, fetchFn)
    const headers = new Headers(seen[0]!.init.headers)
    expect(headers.get('content-type')).toBe('application/json')
    expect(await runProxy({ credential, value: SECRET, method: 'GET', url: 'https://api.cloudflare.com/x', headers: { accept: 'a\r\nX-Evil: 1' } }, fetchFn)).toMatchObject({ ok: false, error: 'bad_header' })
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

  test('bodies: refused on GET, capped in size', async () => {
    const fetchFn = stubFetch(() => new Response('ok'))
    expect(await runProxy({ credential, value: SECRET, method: 'GET', url: 'https://api.cloudflare.com/x', body: 'x' }, fetchFn)).toMatchObject({ ok: false, error: 'body_not_allowed' })
    expect(await runProxy({ credential, value: SECRET, method: 'POST', url: 'https://api.cloudflare.com/x', body: 'x'.repeat(MAX_REQUEST_BODY + 1) }, fetchFn)).toMatchObject({ ok: false, error: 'body_too_large' })
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
