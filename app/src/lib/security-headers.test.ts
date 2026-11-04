import { describe, expect, test } from 'vitest'
import { applySecurityHeaders, CONTENT_SECURITY_POLICY, SECURITY_HEADERS } from './security-headers.ts'

describe('security headers', () => {
  test('the CSP locks the document to this origin and denies framing', () => {
    expect(CONTENT_SECURITY_POLICY).toContain("default-src 'self'")
    expect(CONTENT_SECURITY_POLICY).toContain("frame-ancestors 'none'")
    expect(CONTENT_SECURITY_POLICY).toContain("form-action 'self'")
    expect(CONTENT_SECURITY_POLICY).toContain("connect-src 'self'")
    // Spiceflow injects the flight payload and the Shell injects the theme
    // bootstrap as inline scripts; blocking them would break every page.
    expect(CONTENT_SECURITY_POLICY).toContain("script-src 'self' 'unsafe-inline'")
  })

  test('applies every baseline header to a response', () => {
    const res = applySecurityHeaders(new Response('ok'))
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
      expect(res.headers.get(name)).toBe(value)
    }
    expect(res.headers.get('x-content-type-options')).toBe('nosniff')
    expect(res.headers.get('referrer-policy')).toBe('no-referrer')
    expect(res.headers.get('x-frame-options')).toBe('DENY')
    expect(res.headers.get('strict-transport-security')).toBe('max-age=31536000; includeSubDomains')
  })

  test('never overwrites a header a route set explicitly', () => {
    const res = new Response(null, { headers: { 'Referrer-Policy': 'same-origin' } })
    applySecurityHeaders(res)
    expect(res.headers.get('referrer-policy')).toBe('same-origin')
    expect(res.headers.get('content-security-policy')).toBe(CONTENT_SECURITY_POLICY)
  })
})
