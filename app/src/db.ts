// Worker-level database client, auth, encryption, and authorization guards.
//
// getDb() creates a drizzle-orm/d1 client bound to env.DB. The schema uses
// epochMs custom columns that accept both Date and number inputs, so
// BetterAuth's Date params are converted to epoch ms before reaching D1.
// getAuth(request) creates a BetterAuth instance backed by the same drizzle
// client for the current request host. Credential encryption requires a
// dedicated ENCRYPTION_KEY and never derives one from BETTER_AUTH_SECRET.

import { env } from 'cloudflare:workers'
import * as orm from 'drizzle-orm'
import { getDb, schema } from 'db'
import { betterAuth } from 'better-auth/minimal'
import { drizzleAdapter } from 'better-auth-drizzle-adapter'
import { redirect } from 'spiceflow'
import { GITHUB_PROVIDER_ID, isOwnerAccount, normalizeOwnerId, userHasOwnerAccount } from './lib/owner.ts'
import { CLOUDFLARE_IP_ADDRESS_HEADERS, hasGithubOAuthConfig } from './lib/auth-config.ts'

// ── Drizzle client via D1 ───────────────────────────────────────────
export { getDb }

// ── Request origin ──────────────────────────────────────────────────
// PUBLIC_ORIGIN is an optional canonical-origin override (useful for custom
// domains). By default, use the origin of the request actually received by the
// Worker. Forwarded headers are only considered for localhost development.

export function pinnedOrigin(): string | null {
  const raw = (env as { PUBLIC_ORIGIN?: string }).PUBLIC_ORIGIN
  if (!raw) return null
  const url = new URL(raw)
  if (url.protocol !== 'https:' && url.hostname !== 'localhost' && !url.hostname.endsWith('.localhost')) {
    throw new Error('PUBLIC_ORIGIN must be https (or a localhost address for development)')
  }
  return url.origin
}

export function getRequestOrigin(request: Request): string {
  const pinned = pinnedOrigin()
  if (pinned) return pinned
  const publicOrigin = getPublicOriginOverride(request)
  if (publicOrigin) {
    return publicOrigin
  }

  return new URL(request.url).origin
}

function getRequestHost(request: Request): string {
  const pinned = pinnedOrigin()
  if (pinned) return new URL(pinned).host.toLowerCase()
  const publicOrigin = getPublicOriginOverride(request)
  if (publicOrigin) {
    return new URL(publicOrigin).host.toLowerCase()
  }

  return new URL(request.url).host.toLowerCase()
}

function isLocalHost(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '127.0.0.1'
}

function originFromHost(host: string, protocol = 'https'): string {
  const hostname = host.split(':')[0] ?? host
  const safeProtocol = protocol === 'http' || protocol === 'https' ? protocol : 'https'
  const scheme = isLocalHost(hostname) ? 'http' : safeProtocol
  return `${scheme}://${host}`
}

// IMPORTANT: This function MUST only run when request.url is localhost.
// The isLocalHost guard below is critical for security. In production,
// Cloudflare Workers set request.url to the real hostname (e.g. sigillo.dev),
// so this function returns null immediately and never reads forwarded headers.
//
// If this guard were removed, an attacker could inject X-Forwarded-Host: evil.com
// to make BetterAuth set baseURL and trustedOrigins to evil.com, redirecting
// the OAuth callback there and stealing the user's auth code/credentials.
//
// This override only exists for local dev behind a tunnel (e.g. traforo),
// where request.url is localhost but the real public URL is the tunnel domain.
function getPublicOriginOverride(request: Request): string | null {
  const requestUrl = new URL(request.url)
  if (!isLocalHost(requestUrl.hostname)) {
    return null
  }

  const forwardedHost = request.headers.get('x-forwarded-host')
  if (forwardedHost) {
    const host = forwardedHost.split(',')[0]!.trim().toLowerCase()
    const protocol = request.headers.get('x-forwarded-proto')?.split(',')[0]?.trim().toLowerCase()
    return originFromHost(host, protocol)
  }

  const origin = request.headers.get('origin')
  if (origin) {
    const originUrl = new URL(origin)
    if (!isLocalHost(originUrl.hostname)) {
      return originUrl.origin
    }
  }

  const referer = request.headers.get('referer')
  if (referer) {
    const refererUrl = new URL(referer)
    if (!isLocalHost(refererUrl.hostname)) {
      return refererUrl.origin
    }
  }

  const traforoUrl = process.env.TRAFORO_URL
  if (!traforoUrl) {
    return null
  }

  return traforoUrl
}

// ── BetterAuth ──────────────────────────────────────────────────────

export async function getAuth(request: Request) {
  const db = getDb()
  const origin = getRequestOrigin(request)
  const githubId = (env as { GITHUB_CLIENT_ID?: string }).GITHUB_CLIENT_ID
  const githubSecret = (env as { GITHUB_CLIENT_SECRET?: string }).GITHUB_CLIENT_SECRET
  const ownerId = normalizeOwnerId((env as { OWNER_GITHUB_ID?: string }).OWNER_GITHUB_ID)
  return betterAuth({
    baseURL: origin,
    secret: env.BETTER_AUTH_SECRET,
    database: drizzleAdapter(db, { provider: 'sqlite' }),
    // Only the origin of this deployment. No registered-host list, no wildcard.
    trustedOrigins: [origin],
    // Cloudflare sets this edge-controlled header on incoming visitor requests.
    // Do not trust client-supplied X-Forwarded-For or X-Real-IP values here.
    advanced: {
      ipAddress: { ipAddressHeaders: [...CLOUDFLARE_IP_ADDRESS_HEADERS] },
    },
    // Enable email/password signup in tests so tests can create users via
    // auth.api.signUpEmail() and get bearer tokens without needing GitHub.
    // VITEST var is set in wrangler.test.jsonc, propagated to process.env by nodejs_compat.
    emailAndPassword: { enabled: !!process.env.VITEST },
    // Without a configured GitHub OAuth app there is simply no provider, so
    // sign-in fails closed instead of falling back to anything weaker.
    socialProviders: hasGithubOAuthConfig({ GITHUB_CLIENT_ID: githubId, GITHUB_CLIENT_SECRET: githubSecret })
      ? { github: { clientId: githubId!, clientSecret: githubSecret! } }
      : {},
    // The GitHub access token is only needed to read the profile once at sign-in.
    account: { encryptOAuthTokens: true },
    // Refuse to even link a GitHub account that is not the owner. resolveSession
    // enforces the same rule again on every request (defence in depth).
    databaseHooks: {
      account: {
        create: {
          before: async (account) => {
            if (account.providerId === GITHUB_PROVIDER_ID && !isOwnerAccount(
              { providerId: account.providerId, accountId: String(account.accountId) },
              ownerId,
            )) {
              throw new Error('This vault only accepts its owner')
            }
            return { data: account }
          },
        },
      },
    },
    session: {
      cookieCache: {
        enabled: true,
        maxAge: 5 * 60, // 5 minutes — avoids a D1 round-trip on every request
      },
    },
  })
}

// ── Session helpers ─────────────────────────────────────────────────

type Session = { userId: string; user: { id: string; name: string; email: string; emailVerified: boolean } }

// Spiceflow passes the SAME request instance to every matched loader/layout in
// a single navigation (verified against the framework source). Several loaders
// call getSession concurrently for one navigation, so without deduping each
// would rebuild a BetterAuth instance and re-validate the session — and on a
// cold cookie cache, each would hit D1 for the same session. Memoizing the
// resolution per request collapses those into one. The WeakMap lets entries be
// GC'd once the request is gone, so it never leaks across requests.
const sessionByRequest = new WeakMap<Request, Promise<Session | null>>()

export function getSession(request: Request): Promise<Session | null> {
  const cached = sessionByRequest.get(request)
  if (cached) return cached
  const promise = resolveSession(request)
  sessionByRequest.set(request, promise)
  return promise
}

// Every session must belong to
// a user with the owner's GitHub account linked. The vitest environment has no
// GitHub accounts, so it is exempt (see owner.ts).
async function sessionUserIsOwner(userId: string): Promise<boolean> {
  if (process.env.VITEST) return true
  const accounts = await getDb()
    .select({ providerId: schema.account.providerId, accountId: schema.account.accountId })
    .from(schema.account)
    .where(orm.eq(schema.account.userId, userId))
  return userHasOwnerAccount(accounts, (env as { OWNER_GITHUB_ID?: string }).OWNER_GITHUB_ID)
}

async function resolveSession(request: Request): Promise<Session | null> {
  // Browser cookie sessions only. There is no bearer or device flow in the vault.
  if (!request.headers.has('cookie')) return null

  const auth = await getAuth(request)
  const session = await auth.api.getSession({ headers: request.headers })
  if (!session) return null
  if (!(await sessionUserIsOwner(session.user.id))) return null
  return { userId: session.user.id, user: { id: session.user.id, name: session.user.name, email: session.user.email, emailVerified: session.user.emailVerified } }
}

export async function requirePageSession(request: Request): Promise<Session> {
  const session = await getSession(request)
  if (!session) {
    const url = new URL(request.url)
    throw redirect(`/login?redirect=${encodeURIComponent(url.pathname)}`)
  }
  return session
}
