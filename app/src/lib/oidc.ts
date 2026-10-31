// Verification of GitHub Actions OIDC tokens.
//
// A runner proves which workflow run it belongs to by presenting the OIDC JWT that
// GitHub issues to a job (`permissions: id-token: write`). There is no long-lived key
// on the runner. The vault checks:
//   - RS256 signature against GitHub's published JWKS (only RS256 is accepted, so an
//     `alg: none` or HMAC-confusion token is rejected before any key lookup),
//   - issuer, audience (this vault's origin), expiry and not-before,
//   - that the token comes from the configured repository, from an allowed ref and
//     event (so pull-request and fork runs cannot enroll).
//
// Honest limit: any process on the runner that can read the job's OIDC request
// variables can obtain such a token. This authenticates the *workflow run*, not the
// individual process; the vault compensates with scoped operations, short sessions,
// rate limits and an audit trail.

export const GITHUB_OIDC_ISSUER = 'https://token.actions.githubusercontent.com'
export const GITHUB_JWKS_URL = `${GITHUB_OIDC_ISSUER}/.well-known/jwks`

export type OidcPolicy = {
  audience: string
  /** `owner/name`, compared exactly (case-insensitively, as GitHub treats names). */
  repository: string
  /** Numeric repository id; strongest binding because names can be renamed or re-created. */
  repositoryId: string
  allowedRefs: string[]
  allowedEvents: string[]
  allowedWorkflowRefs: string[]
}

export type RunnerIdentity = {
  repository: string
  repositoryId: string
  runId: string
  runAttempt: string
  ref: string
  event: string
  workflow: string
  sha: string
  jti: string
}

export type OidcResult = { ok: true; identity: RunnerIdentity } | { ok: false; error: string }

type Jwk = { kty: string; kid: string; n: string; e: string; alg?: string; use?: string }
type Jwks = { keys: Jwk[] }

export type JwksSource = (forceRefresh: boolean) => Promise<Jwks>

const CLOCK_SKEW_S = 60

function b64urlToBytes(value: string): Uint8Array<ArrayBuffer> {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=')
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0))
}

function decodeJson(value: string): unknown {
  return JSON.parse(new TextDecoder().decode(b64urlToBytes(value)))
}

function str(claims: Record<string, unknown>, name: string): string {
  const value = claims[name]
  return typeof value === 'string' ? value : ''
}

/** JWKS source with a small in-memory cache. A refresh is forced at most once a minute. */
export function cachedJwksSource(fetchFn: typeof fetch = fetch, now: () => number = Date.now): JwksSource {
  let cached: { jwks: Jwks; fetchedAt: number } | null = null
  const TTL_MS = 10 * 60_000
  const MIN_REFRESH_MS = 60_000
  return async (forceRefresh) => {
    const t = now()
    const fresh = cached && t - cached.fetchedAt < TTL_MS
    const tooSoon = cached && t - cached.fetchedAt < MIN_REFRESH_MS
    if (cached && fresh && !forceRefresh) return cached.jwks
    if (cached && forceRefresh && tooSoon) return cached.jwks
    const res = await fetchFn(GITHUB_JWKS_URL, { headers: { Accept: 'application/json' } })
    if (!res.ok) {
      if (cached) return cached.jwks
      throw new Error('could not fetch GitHub JWKS')
    }
    const jwks = await res.json() as Jwks
    if (!Array.isArray(jwks?.keys)) throw new Error('unexpected JWKS shape')
    cached = { jwks, fetchedAt: t }
    return jwks
  }
}

async function verifySignature(jwk: Jwk, signingInput: string, signature: Uint8Array<ArrayBuffer>): Promise<boolean> {
  if (jwk.kty !== 'RSA' || typeof jwk.n !== 'string' || typeof jwk.e !== 'string') return false
  const key = await crypto.subtle.importKey(
    'jwk',
    { kty: 'RSA', n: jwk.n, e: jwk.e, alg: 'RS256', ext: true },
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify'],
  )
  return crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature, new TextEncoder().encode(signingInput))
}

export function sameRepository(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase()
}

export async function verifyGithubOidc(
  token: string,
  policy: OidcPolicy,
  jwks: JwksSource,
  nowMs: number,
): Promise<OidcResult> {
  const parts = token.split('.')
  if (parts.length !== 3 || token.length > 8192) return { ok: false, error: 'malformed token' }

  let header: Record<string, unknown>
  let claims: Record<string, unknown>
  let signature: Uint8Array<ArrayBuffer>
  try {
    header = decodeJson(parts[0]!) as Record<string, unknown>
    claims = decodeJson(parts[1]!) as Record<string, unknown>
    signature = b64urlToBytes(parts[2]!)
  } catch {
    return { ok: false, error: 'malformed token' }
  }
  if (!header || !claims || typeof header !== 'object' || typeof claims !== 'object') return { ok: false, error: 'malformed token' }
  if (header.alg !== 'RS256' || typeof header.kid !== 'string' || !header.kid) return { ok: false, error: 'unsupported algorithm' }

  const signingInput = `${parts[0]}.${parts[1]}`
  let keys: Jwks
  try {
    keys = await jwks(false)
  } catch {
    return { ok: false, error: 'signing keys unavailable' }
  }
  let jwk = keys.keys.find((k) => k.kid === header.kid)
  if (!jwk) {
    try {
      jwk = (await jwks(true)).keys.find((k) => k.kid === header.kid)
    } catch {
      return { ok: false, error: 'signing keys unavailable' }
    }
  }
  if (!jwk) return { ok: false, error: 'unknown signing key' }
  let valid = false
  try {
    valid = await verifySignature(jwk, signingInput, signature)
  } catch {
    valid = false
  }
  if (!valid) return { ok: false, error: 'bad signature' }

  const nowS = Math.floor(nowMs / 1000)
  if (claims.iss !== GITHUB_OIDC_ISSUER) return { ok: false, error: 'wrong issuer' }
  const aud = claims.aud
  const audiences = Array.isArray(aud) ? aud : [aud]
  if (!audiences.includes(policy.audience)) return { ok: false, error: 'wrong audience' }
  if (typeof claims.exp !== 'number' || claims.exp <= nowS - CLOCK_SKEW_S) return { ok: false, error: 'token expired' }
  if (typeof claims.nbf === 'number' && claims.nbf > nowS + CLOCK_SKEW_S) return { ok: false, error: 'token not yet valid' }
  if (typeof claims.iat === 'number' && claims.iat > nowS + CLOCK_SKEW_S) return { ok: false, error: 'token issued in the future' }

  const repository = str(claims, 'repository')
  if (!repository || !sameRepository(repository, policy.repository)) return { ok: false, error: 'wrong repository' }
  const repositoryId = str(claims, 'repository_id')
  if (!repositoryId || repositoryId !== policy.repositoryId) return { ok: false, error: 'wrong repository' }
  const ref = str(claims, 'ref')
  if (!policy.allowedRefs.includes(ref)) return { ok: false, error: 'ref not allowed' }
  const event = str(claims, 'event_name')
  if (!policy.allowedEvents.includes(event)) return { ok: false, error: 'event not allowed' }
  const workflow = str(claims, 'job_workflow_ref')
  if (!workflow || !policy.allowedWorkflowRefs.includes(workflow)) return { ok: false, error: 'workflow not allowed' }

  const runId = str(claims, 'run_id')
  if (!/^\d{1,20}$/.test(runId)) return { ok: false, error: 'missing run id' }

  return {
    ok: true,
    identity: {
      repository,
      repositoryId,
      runId,
      runAttempt: str(claims, 'run_attempt') || '1',
      ref,
      event,
      workflow: workflow.slice(0, 200),
      sha: str(claims, 'sha').slice(0, 64),
      jti: str(claims, 'jti').slice(0, 100),
    },
  }
}

/** Parse the policy from Worker bindings. Throws (fails closed) when required values are missing. */
export function policyFromEnv(env: Record<string, unknown>, audience: string): OidcPolicy {
  const repository = typeof env.RUNNER_REPOSITORY === 'string' ? env.RUNNER_REPOSITORY.trim() : ''
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)) throw new Error('RUNNER_REPOSITORY must be owner/name')
  const requiredList = (name: string): string[] => {
    const value = env[name]
    if (typeof value !== 'string' || !value.trim()) throw new Error(name + ' is required')
    const items = value.split(',').map((item) => item.trim()).filter(Boolean)
    if (items.length === 0 || items.some((item) => item.length > 300)) throw new Error(name + ' is invalid')
    return [...new Set(items)]
  }
  const repositoryId = typeof env.RUNNER_REPOSITORY_ID === 'string' && /^\d{1,20}$/.test(env.RUNNER_REPOSITORY_ID.trim())
    ? env.RUNNER_REPOSITORY_ID.trim() : ''
  if (!repositoryId) throw new Error('RUNNER_REPOSITORY_ID must be the numeric repository id')
  const allowedRefs = requiredList('RUNNER_ALLOWED_REFS')
  const allowedEvents = requiredList('RUNNER_ALLOWED_EVENTS')
  if (allowedEvents.some((event) => event === 'pull_request' || event === 'pull_request_target')) {
    throw new Error('Pull-request events are not allowed')
  }
  const allowedWorkflowRefs = requiredList('RUNNER_ALLOWED_WORKFLOW_REFS')
  if (allowedWorkflowRefs.some((item) => !item.includes('/.github/workflows/') || !item.includes('@'))) {
    throw new Error('RUNNER_ALLOWED_WORKFLOW_REFS must contain exact workflow refs')
  }
  return { audience, repository, repositoryId, allowedRefs, allowedEvents, allowedWorkflowRefs }
}
