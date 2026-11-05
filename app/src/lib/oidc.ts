// Verification of GitHub Actions OIDC tokens.
//
// A runner proves which workflow run it belongs to by presenting the OIDC JWT that
// GitHub issues to a job (`permissions: id-token: write`). There is no long-lived key
// on the runner. The vault checks:
//   - RS256 signature against GitHub's published JWKS (only RS256 is accepted, so an
//     `alg: none` or HMAC-confusion token is rejected before any key lookup),
//   - issuer, audience (this vault's origin), expiry and not-before,
//   - that the token comes from the configured repository, from an allowed ref and
//     event (so pull-request and fork runs cannot enroll),
//   - that the subject claim binds the exact repository and context, accepting
//     both GitHub's legacy name-only and immutable owner/repository-ID formats,
//     and that the token id (jti) is present. Verification alone does not stop replay: the caller
//     consumes the jti (see createSession in runner-core.ts) so each token can
//     be exchanged exactly once.
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
  /** Numeric owner id. Required outside bootstrap (verification fails closed
   * without it); bootstrap policies carry the owner id in `bootstrap`. */
  repositoryOwnerId?: string
  bootstrap?: {
    ownerId: string
    branch: string
    workflowFile: string
    allowedEvents: string[]
  }
}

export type RunnerIdentity = {
  repository: string
  repositoryId: string
  repositoryOwnerId: string
  runId: string
  runAttempt: string
  ref: string
  event: string
  workflow: string
  workflowRef: string
  sha: string
  jti: string
  /** The token's `sub` claim, already checked to name `repository`. */
  sub: string
  /** The OIDC token's own expiry (epoch ms), not the issued session's. */
  expiresAt: number
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

/** JWKS source with a bounded stale cache. A refresh is forced at most once a minute. */
export function cachedJwksSource(fetchFn: typeof fetch = fetch, now: () => number = Date.now): JwksSource {
  let cached: { jwks: Jwks; fetchedAt: number } | null = null
  const TTL_MS = 10 * 60_000
  const MAX_CACHE_AGE_MS = 15 * 60_000
  const MIN_REFRESH_MS = 60_000
  return async (forceRefresh) => {
    const t = now()
    const ageMs = cached ? Math.max(0, t - cached.fetchedAt) : Number.POSITIVE_INFINITY
    const fresh = cached && ageMs < TTL_MS
    const tooSoon = cached && ageMs < MIN_REFRESH_MS
    if (cached && fresh && !forceRefresh) return cached.jwks
    if (cached && forceRefresh && tooSoon) return cached.jwks

    try {
      const res = await fetchFn(GITHUB_JWKS_URL, {
        headers: { Accept: 'application/json' },
        signal: AbortSignal.timeout(5_000),
      })
      if (!res.ok) throw new Error('GitHub JWKS endpoint returned an error')
      const jwks = await res.json() as Jwks
      if (!Array.isArray(jwks?.keys)) throw new Error('unexpected JWKS shape')
      cached = { jwks, fetchedAt: t }
      return jwks
    } catch {
      // Preserve availability during a short GitHub outage, but never trust an
      // arbitrarily old signing-key set. GitHub OIDC tokens are short-lived.
      if (cached && ageMs <= MAX_CACHE_AGE_MS) return cached.jwks
      throw new Error('could not fetch GitHub JWKS')
    }
  }
}

const verificationKeys = new Map<string, { fingerprint: string; key: Promise<CryptoKey> }>()
const MAX_CACHED_VERIFICATION_KEYS = 32

async function importVerificationKey(jwk: Jwk): Promise<CryptoKey> {
  const fingerprint = String(jwk.kty) + ':' + jwk.n + ':' + jwk.e
  const cached = verificationKeys.get(jwk.kid)
  if (cached?.fingerprint === fingerprint) {
    verificationKeys.delete(jwk.kid)
    verificationKeys.set(jwk.kid, cached)
    return cached.key
  }
  let key: Promise<CryptoKey>
  key = crypto.subtle.importKey(
    'jwk',
    { kty: 'RSA', n: jwk.n, e: jwk.e, alg: 'RS256', ext: true },
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify'],
  ).catch((error) => {
    if (verificationKeys.get(jwk.kid)?.key === key) verificationKeys.delete(jwk.kid)
    throw error
  })
  verificationKeys.delete(jwk.kid)
  verificationKeys.set(jwk.kid, { fingerprint, key })
  while (verificationKeys.size > MAX_CACHED_VERIFICATION_KEYS) {
    const oldest = verificationKeys.keys().next().value
    if (oldest === undefined) break
    verificationKeys.delete(oldest)
  }
  return key
}

async function verifySignature(jwk: Jwk, signingInput: string, signature: Uint8Array<ArrayBuffer>): Promise<boolean> {
  if (jwk.kty !== 'RSA' || typeof jwk.n !== 'string' || typeof jwk.e !== 'string') return false
  const key = await importVerificationKey(jwk)
  return crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature, new TextEncoder().encode(signingInput))
}

/** Test helper; production key cache is naturally isolate-scoped. */
export function resetOidcVerificationKeyCache() {
  verificationKeys.clear()
}

export function sameRepository(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase()
}

/**
 * GitHub's default `sub` has two supported forms:
 *   repo:OWNER/REPO:ref:refs/heads/main
 *   repo:OWNER@OWNER-ID/REPO@REPO-ID:ref:refs/heads/main
 *
 * Do not use a prefix-only comparison here. Bind the repository segment to the
 * independently signed repository claims and require the subject context to
 * match the signed ref/environment claim exactly.
 */
function subjectMatchesRepository(
  sub: string,
  repository: string,
  repositoryOwnerId: string,
  repositoryId: string,
  ref: string,
  environment: string,
  event: string,
): boolean {
  const separator = sub.indexOf(':', 5)
  if (!sub.startsWith('repo:') || separator < 0) return false

  const subjectRepository = sub.slice(5, separator)
  const subjectContext = sub.slice(separator + 1)
  const [owner, name] = repository.split('/')
  if (!owner || !name) return false

  const legacyRepository = repository
  const immutableRepository = `${owner}@${repositoryOwnerId}/${name}@${repositoryId}`
  const repositoryMatches = sameRepository(subjectRepository, legacyRepository) ||
    sameRepository(subjectRepository, immutableRepository)
  if (!repositoryMatches) return false

  let expectedContext = ''
  if (environment) expectedContext = `environment:${environment.replace(/:/g, '%3A')}`
  else if (event === 'pull_request' || event === 'pull_request_target') expectedContext = 'pull_request'
  else if (ref) expectedContext = `ref:${ref}`
  return subjectContext === expectedContext
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
  const repositoryId = str(claims, 'repository_id')
  const repositoryOwnerId = str(claims, 'repository_owner_id')
  const repositoryOwner = str(claims, 'repository_owner')
  const ref = str(claims, 'ref')
  const event = str(claims, 'event_name')
  const environment = str(claims, 'environment')
  const workflowRef = str(claims, 'workflow_ref')
  const reusableWorkflowRef = str(claims, 'job_workflow_ref')
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository) ||
      !/^\d{1,20}$/.test(repositoryId) || !/^\d{1,20}$/.test(repositoryOwnerId)) {
    return { ok: false, error: 'wrong repository' }
  }
  if (policy.bootstrap) {
    const bootstrap = policy.bootstrap
    const expectedRef = `refs/heads/${bootstrap.branch}`
    const expectedWorkflow = `${repository}/.github/workflows/${bootstrap.workflowFile}@${expectedRef}`
    if (repositoryOwnerId !== bootstrap.ownerId || !repositoryOwner ||
        repository.split('/')[0]!.toLowerCase() !== repositoryOwner.toLowerCase()) {
      return { ok: false, error: 'wrong repository owner' }
    }
    if (ref !== expectedRef || !policy.allowedRefs.includes(ref)) return { ok: false, error: 'ref not allowed' }
    if (!bootstrap.allowedEvents.includes(event) || !policy.allowedEvents.includes(event)) return { ok: false, error: 'event not allowed' }
    if (!workflowRef || workflowRef !== expectedWorkflow ||
        (reusableWorkflowRef && reusableWorkflowRef !== expectedWorkflow)) {
      return { ok: false, error: 'workflow not allowed' }
    }
  } else {
    if (!sameRepository(repository, policy.repository) || repositoryId !== policy.repositoryId) {
      return { ok: false, error: 'wrong repository' }
    }
    if (!repositoryOwner || !sameRepository(repository.split('/')[0]!, repositoryOwner)) {
      return { ok: false, error: 'wrong repository owner' }
    }
    if (!policy.repositoryOwnerId || repositoryOwnerId !== policy.repositoryOwnerId) {
      return { ok: false, error: 'wrong repository owner' }
    }
    if (!policy.allowedRefs.includes(ref)) return { ok: false, error: 'ref not allowed' }
    if (!policy.allowedEvents.includes(event)) return { ok: false, error: 'event not allowed' }
    const workflow = workflowRef || reusableWorkflowRef
    if (!workflow || !policy.allowedWorkflowRefs.includes(workflow)) return { ok: false, error: 'workflow not allowed' }
    if (reusableWorkflowRef && !policy.allowedWorkflowRefs.includes(reusableWorkflowRef)) {
      return { ok: false, error: 'workflow not allowed' }
    }
  }

  const workflow = workflowRef || reusableWorkflowRef
  const runId = str(claims, 'run_id')
  if (!/^\d{1,20}$/.test(runId)) return { ok: false, error: 'missing run id' }

  // Defence in depth: verify the complete repository identity and context. For
  // immutable subjects, this also proves the IDs embedded in `sub` match the
  // separately signed owner/repository ID claims above.
  const sub = str(claims, 'sub')
  if (!subjectMatchesRepository(sub, repository, repositoryOwnerId, repositoryId, ref, environment, event)) {
    return { ok: false, error: 'subject mismatch' }
  }
  // The caller consumes the jti to make the token single-use; without one
  // there is nothing to consume, so fail closed.
  const jti = str(claims, 'jti')
  if (!jti) return { ok: false, error: 'missing token id' }

  return {
    ok: true,
    identity: {
      repository,
      repositoryId,
      repositoryOwnerId,
      runId,
      runAttempt: str(claims, 'run_attempt') || '1',
      ref,
      event,
      workflow: workflow.slice(0, 200),
      workflowRef: workflowRef.slice(0, 300),
      sha: str(claims, 'sha').slice(0, 64),
      jti: jti.slice(0, 100),
      sub: sub.slice(0, 300),
      expiresAt: typeof claims.exp === 'number' ? claims.exp * 1000 : 0,
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
  const repositoryOwnerId = typeof env.RUNNER_REPOSITORY_OWNER_ID === 'string' && /^\d{1,20}$/.test(env.RUNNER_REPOSITORY_OWNER_ID.trim())
    ? env.RUNNER_REPOSITORY_OWNER_ID.trim() : ''
  if (!repositoryOwnerId) throw new Error('RUNNER_REPOSITORY_OWNER_ID must be the numeric owner id')
  if (allowedWorkflowRefs.some((item) => !item.includes('/.github/workflows/') || !item.includes('@'))) {
    throw new Error('RUNNER_ALLOWED_WORKFLOW_REFS must contain exact workflow refs')
  }
  return { audience, repository, repositoryId, repositoryOwnerId, allowedRefs, allowedEvents, allowedWorkflowRefs }
}
