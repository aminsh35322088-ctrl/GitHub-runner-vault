// Baseline security headers for every response the Worker sends.
//
// The CSP is deliberately pragmatic rather than maximally strict:
// - script-src needs 'unsafe-inline': the Shell injects an inline theme
//   bootstrap script, and Spiceflow injects the React flight payload as
//   inline <script> tags. Without it every page loses hydration.
// - style-src needs 'unsafe-inline' for React inline style attributes and
//   the utility classes the UI toggles at runtime.
// Everything else stays locked to 'self', framing is denied outright, and
// form posts may only target this origin.

export const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self' data:",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
].join('; ')

export const SECURITY_HEADERS: Readonly<Record<string, string>> = {
  'Content-Security-Policy': CONTENT_SECURITY_POLICY,
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
}

/** Sets the baseline headers without overwriting a value a route already chose. */
export function applySecurityHeaders(response: Response): Response {
  // Response.redirect() returns immutable headers in Workers. Work on a copy
  // and rebuild only when a baseline header is missing; this preserves route
  // headers, status, status text and streaming bodies without mutating the
  // original response.
  const headers = new Headers(response.headers)
  let changed = false

  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    if (!headers.has(name)) {
      headers.set(name, value)
      changed = true
    }
  }

  if (!changed) return response

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  })
}
