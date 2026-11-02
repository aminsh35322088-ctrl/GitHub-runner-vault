// Worker-side API execution. The runner describes a request; the vault checks it against
// the credential's owner-approved hosts, adds the credential itself, performs the call, and
// returns a filtered response. The secret never leaves the Worker.
//
// Defences, each covered by tests:
//  - https only, exact allow-listed hostname, default port, no embedded credentials,
//  - redirects are never followed (a redirect cannot carry the secret to another host),
//  - the runner may only set a short allow-list of harmless headers, so it cannot override
//    the auth header, Host, cookies or hop-by-hop headers,
//  - request and response sizes are capped and the call has a timeout,
//  - the response goes through an allow-list of headers and any occurrence of the secret
//    (raw, URL-encoded, base64, JSON-escaped) is replaced before it is returned.

import { formatAuthValue, normalizeHost, type AuthScheme } from './credential-input.ts'

export const MAX_REQUEST_BODY = 256 * 1024
export const MAX_RESPONSE_BODY = 1024 * 1024
export const UPSTREAM_TIMEOUT_MS = 20_000
export const MAX_URL_LENGTH = 2000

const METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'])
const REQUEST_HEADERS = new Set([
  'accept', 'accept-language', 'content-type', 'if-match', 'if-none-match',
  'x-github-api-version', 'x-api-version', 'anthropic-version', 'anthropic-workspace-id',
  'x-pinecone-api-version',
])
const RESPONSE_HEADERS = new Set(['content-type', 'etag', 'link', 'retry-after', 'location', 'last-modified', 'cache-control', 'x-github-request-id', 'cf-ray'])

export type ProxyCredential = { allowedHosts: string[]; authHeader: string; authScheme: AuthScheme }

export type ProxyInput = {
  credential: ProxyCredential
  value: string
  method: string
  url: string
  headers?: Record<string, string>
  body?: string
}

export type ProxyError =
  | 'bad_method' | 'bad_url' | 'host_not_allowed' | 'bad_header' | 'body_too_large'
  | 'body_not_allowed' | 'upstream_timeout' | 'upstream_error'

export type ProxyResult =
  | { ok: true; status: number; headers: Record<string, string>; body: string; truncated: boolean; redactions: number; host: string; method: string; path: string }
  | { ok: false; error: ProxyError; detail?: string }

export function validateTarget(raw: string, allowedHosts: string[]): { ok: true; url: URL } | { ok: false; error: ProxyError } {
  if (typeof raw !== 'string' || raw.length > MAX_URL_LENGTH) return { ok: false, error: 'bad_url' }
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    return { ok: false, error: 'bad_url' }
  }
  if (url.protocol !== 'https:' || url.username || url.password) return { ok: false, error: 'bad_url' }
  if (url.port && url.port !== '443') return { ok: false, error: 'bad_url' }
  const host = normalizeHost(url.hostname)
  if (!host || !allowedHosts.includes(host)) return { ok: false, error: 'host_not_allowed' }
  return { ok: true, url }
}

/** Every form in which the value could plausibly be echoed back by an upstream service. */
export function secretForms(value: string): string[] {
  if (value.length < 4) return []
  const forms = new Set<string>([value])
  forms.add(encodeURIComponent(value))
  forms.add(JSON.stringify(value).slice(1, -1))
  try {
    forms.add(btoa(value))
  } catch {
    // value contains non-latin1 characters; base64 of its UTF-8 bytes instead
    forms.add(btoa(String.fromCharCode(...new TextEncoder().encode(value))))
  }
  return [...forms].filter((f) => f.length >= 4)
}

export function redact(text: string, value: string): { text: string; count: number } {
  let count = 0
  let out = text
  for (const form of secretForms(value)) {
    const parts = out.split(form)
    if (parts.length > 1) {
      count += parts.length - 1
      out = parts.join('[REDACTED]')
    }
  }
  return { text: out, count }
}

async function readCapped(response: Response, max: number): Promise<{ bytes: Uint8Array; truncated: boolean }> {
  if (!response.body) return { bytes: new Uint8Array(), truncated: false }
  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  let truncated = false
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    if (total + value.byteLength > max) {
      chunks.push(value.subarray(0, max - total))
      total = max
      truncated = true
      await reader.cancel()
      break
    }
    chunks.push(value)
    total += value.byteLength
  }
  const bytes = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.byteLength
  }
  return { bytes, truncated }
}

export async function runProxy(input: ProxyInput, fetchFn: typeof fetch = fetch): Promise<ProxyResult> {
  const method = String(input.method ?? '').toUpperCase()
  if (!METHODS.has(method)) return { ok: false, error: 'bad_method' }
  const target = validateTarget(input.url, input.credential.allowedHosts)
  if (!target.ok) return target

  const headers = new Headers()
  for (const [name, value] of Object.entries(input.headers ?? {})) {
    const lower = name.toLowerCase()
    if (!REQUEST_HEADERS.has(lower) || typeof value !== 'string' || value.length > 500 || /[\r\n]/.test(value)) {
      return { ok: false, error: 'bad_header', detail: lower }
    }
    headers.set(lower, value)
  }
  // Set last so nothing the runner sent can have come first or override it.
  headers.set(input.credential.authHeader, formatAuthValue(input.credential.authScheme, input.value))
  headers.set('user-agent', 'runner-vault/1')

  let body: string | undefined
  if (input.body !== undefined && input.body !== '') {
    if (method === 'GET' || method === 'HEAD') return { ok: false, error: 'body_not_allowed' }
    if (typeof input.body !== 'string' || new TextEncoder().encode(input.body).byteLength > MAX_REQUEST_BODY) return { ok: false, error: 'body_too_large' }
    body = input.body
  }

  let response: Response
  try {
    response = await fetchFn(target.url.toString(), {
      method,
      headers,
      body,
      redirect: 'manual',
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
    })
  } catch (error) {
    const timedOut = error instanceof Error && (error.name === 'TimeoutError' || error.name === 'AbortError')
    return { ok: false, error: timedOut ? 'upstream_timeout' : 'upstream_error' }
  }

  const { bytes, truncated } = await readCapped(response, MAX_RESPONSE_BODY)
  const decoded = new TextDecoder().decode(bytes)
  let redactions = 0
  const outHeaders: Record<string, string> = {}
  response.headers.forEach((value, name) => {
    if (!RESPONSE_HEADERS.has(name.toLowerCase())) return
    const cleaned = redact(value, input.value)
    redactions += cleaned.count
    outHeaders[name.toLowerCase()] = cleaned.text
  })
  const cleanedBody = redact(decoded, input.value)
  redactions += cleanedBody.count

  return {
    ok: true,
    status: response.status,
    headers: outHeaders,
    body: cleanedBody.text,
    truncated,
    redactions,
    host: target.url.hostname,
    method,
    path: target.url.pathname,
  }
}
