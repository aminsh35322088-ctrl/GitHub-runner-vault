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
  const missing = Object.entries(SECURITY_HEADERS).filter(([name]) => !response.headers.has(name))
  if (missing.length === 0) return response

  // Response.redirect() and some upstream responses have immutable headers.
  // Cloudflare's supported clone pattern creates a mutable response while
  // preserving response metadata (including Workers-specific ResponseInit fields).
  const secured = new Response(response.body, response)
  for (const [name, value] of missing) {
    secured.headers.set(name, value)
  }
  return secured
}
