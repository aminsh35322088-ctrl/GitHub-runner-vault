// Memoize async functions via Cloudflare Cache API (caches.default).
// Cache keys include the deployment id so stale entries are never served across deploys.
// Requires a custom domain; does NOT work on *.workers.dev.
//
// Supports stale-while-revalidate (SWR): within the SWR window, stale values
// are returned immediately while a background refresh runs via waitUntil().
// The Cache API itself doesn't support SWR, so we store createdAt alongside
// the value and check age ourselves. s-maxage is set to ttl + swr so the
// Cache API keeps the entry alive for the full window.
//
// IMPORTANT: null, undefined, and Error results are NEVER cached. This prevents
// caching "not found" or "unauthorized" responses that would lock users out
// until the TTL expires. Memoized functions that indicate absence or failure
// MUST return null/undefined or throw. Never return a truthy sentinel for
// missing data, or it will be cached and served for the full TTL window.

import superjson from 'superjson'
import { waitUntil } from 'cloudflare:workers'
import { getDeploymentId } from 'spiceflow'
import { captureException } from '@strada.sh/sdk'

// Cache keys are full URLs and the hostname is part of the key. Cloudflare
// associates each entry with the zone the key's hostname belongs to:
//
//   "The asset will be cached under the hostname specified within the Worker's
//    subrequest — not the Worker's own hostname."
//   https://developers.cloudflare.com/workers/reference/how-the-cache-works/
//
// So Cloudflare's own Cache API example builds the key from the incoming
// request URL, keeping it inside the zone the Worker serves:
// https://developers.cloudflare.com/workers/examples/cache-api/
//
// We do the same. app.tsx calls rememberCacheOrigin() on every request and
// keys hang off that origin, which also separates preview from production and
// gives each self-hosted instance its own keyspace for free.
//
// This used to be a hardcoded `https://0.0.0.0/`, on the theory that a
// non-routable IP avoided DNS lookups. Cache keys never resolve DNS, and an IP
// literal belongs to no zone, so that was undocumented territory. Note that
// cache.put() "resolves to undefined regardless of whether the cache
// successfully stored the response", so a bad key produces a 100% miss rate
// with no error anywhere — do not guess at hostnames here.
//
// The `/__memoize/` path prefix matters because caches.default is the same
// cache fetch() uses, so keys share a namespace with real URLs on this origin.
// If that ever feels too close for comfort, the documented alternative is a
// separate namespace via caches.open(), which is isolated from the fetch cache.
const FALLBACK_CACHE_ORIGIN = 'https://memoize.sigillo.dev'

let cacheOrigin: string | undefined

/**
 * Records the origin this Worker is being served from, so cache keys stay
 * inside its own zone. Idempotent and safe to call per request: the value is
 * constant for a given deployment + custom domain.
 */
export function rememberCacheOrigin(requestUrl: string): void {
  if (cacheOrigin) return
  cacheOrigin = new URL(requestUrl).origin
}

interface CacheEnvelope<T> {
  value: T
  createdAt: number
}

export interface MemoizeOptions<Args extends unknown[], T> {
  namespace: string
  fn: (...args: Args) => Promise<T>
  /** Fresh window in seconds. Default: 300 (5 min) */
  ttl?: number
  /** Stale-while-revalidate window in seconds. Default: 600 (10 min) */
  swr?: number
}

function shouldCache<T>(value: T): boolean {
  if (value == null) return false
  if (value instanceof Error) return false
  return true
}

export function memoize<Args extends unknown[], T>(
  options: MemoizeOptions<Args, T>,
): (...args: Args) => Promise<T> {
  const { namespace, fn, ttl = 300, swr = 600 } = options

  return async (...args: Args): Promise<T> => {
    const cache = (caches as any).default as Cache
    const key = await buildCacheKey(namespace, args)
    const req = new Request(key)

    const hit = await cache.match(req)
    if (hit) {
      const envelope = superjson.parse<CacheEnvelope<T>>(await hit.text())
      const age = (Date.now() - envelope.createdAt) / 1000

      if (age < ttl) {
        return envelope.value
      }

      if (swr > 0 && age < ttl + swr) {
        waitUntil(refreshCache({ cache, req, fn, args, maxAge: ttl + swr, namespace }))
        return envelope.value
      }
    }

    const value = await fn(...args)
    if (shouldCache(value)) {
      waitUntil(putCache({ cache, req, value, maxAge: ttl + swr, namespace }))
    }
    return value
  }
}

// Background work runs in waitUntil(), so nothing above it can observe a
// failure. Every catch here reports to Strada instead of swallowing —
// otherwise a permanently broken SWR refresh is completely invisible and
// users just keep getting stale data until the entry expires.
async function refreshCache<Args extends unknown[], T>({ cache, req, fn, args, maxAge, namespace }: {
  cache: Cache
  req: Request
  fn: (...args: Args) => Promise<T>
  args: Args
  maxAge: number
  namespace: string
}): Promise<void> {
  try {
    const value = await fn(...args)
    if (shouldCache(value)) {
      await putCache({ cache, req, value, maxAge, namespace })
    } else {
      await cache.delete(req)
    }
  } catch (error) {
    // Stale entry stays until it expires naturally.
    captureException(error, { tags: { handler: 'memoize.refreshCache', namespace } })
  }
}

async function putCache<T>({ cache, req, value, maxAge, namespace }: {
  cache: Cache
  req: Request
  value: T
  maxAge: number
  namespace: string
}): Promise<void> {
  const envelope: CacheEnvelope<T> = { value, createdAt: Date.now() }
  const response = new Response(superjson.stringify(envelope), {
    headers: {
      'content-type': 'application/json',
      'cache-control': `s-maxage=${maxAge}`,
    },
  })
  await cache.put(req, response).catch((error) => {
    captureException(error, { tags: { handler: 'memoize.putCache', namespace } })
  })
}

export async function invalidate(namespace: string, ...args: unknown[]): Promise<boolean> {
  const cache = (caches as any).default as Cache
  const key = await buildCacheKey(namespace, args)
  return cache.delete(new Request(key))
}

async function buildCacheKey(namespace: string, args: unknown[]): Promise<string> {
  const id = await getDeploymentId()
  const origin = cacheOrigin ?? FALLBACK_CACHE_ORIGIN
  const prefix = id ? `${origin}/__memoize/${id}/` : `${origin}/__memoize/`
  const serialized = superjson.stringify(args)
  const hash = await sha256(serialized)
  return `${prefix}${namespace}/${hash}`
}

async function sha256(input: string): Promise<string> {
  const encoded = new TextEncoder().encode(input)
  const digest = await crypto.subtle.digest('SHA-256', encoded)
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}
