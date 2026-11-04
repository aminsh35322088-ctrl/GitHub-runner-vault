import { describe, expect, test } from 'vitest'
import { app } from './app.tsx'
import { parseRunnerBody } from './runner-api.ts'
import { MAX_REQUEST_BODY } from './lib/proxy.ts'

const call = (method: string, path: string, body?: unknown) =>
  app.handle(new Request(`https://vault.test${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer aaaaaaaaaa.bbbbbbbbbb.cccccccccc' },
    body: body === undefined ? undefined : JSON.stringify(body),
  }))

describe('runner HTTP surface', () => {
  test('session exchange fails closed (503, no-store) when OIDC policy is not configured', async () => {
    const res = await call('POST', '/api/runner/session')
    expect(res.status).toBe(503)
    expect(res.headers.get('cache-control')).toBe('no-store')
    expect(await res.json()).toEqual({ error: 'vault_not_configured' })
  })

  test.each([
    ['GET', '/api/runner/registry', undefined],
    ['GET', '/api/runner/integrations', undefined],
    ['POST', '/api/runner/registrations', { name: 'X' }],
    ['POST', '/api/runner/use', { name: 'X', method: 'GET', url: 'https://example.com' }],
  ])('%s %s does not require OIDC policy to reject an invalid runner session', async (method, path, body) => {
    const res = await call(method, path, body)
    expect(res.status).toBe(401)
    expect(res.headers.get('cache-control')).toBe('no-store')
    expect(await res.json()).toEqual({ error: 'unauthorized' })
  })

  test('malformed and non-object JSON bodies return a generic 400', async () => {
    for (const body of ['{', '[]', 'null', '"secret-value"']) {
      const res = await app.handle(new Request('https://vault.test/api/runner/use', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer aaaaaaaaaa.bbbbbbbbbb.cccccccccc' },
        body,
      }))
      expect(res.status).toBe(400)
      expect(res.headers.get('cache-control')).toBe('no-store')
      expect(await res.json()).toEqual({ error: 'invalid_request' })
    }
  })

  test('JSON parser enforces its byte limit before parsing', async () => {
    const request = new Request('https://vault.test/api/runner/use', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': '1025' },
      body: '{}',
    })
    expect(await parseRunnerBody(request, 1024)).toEqual({ ok: false, error: 'body_too_large' })
  })

  test('raw proxy transport rejects an oversized declared payload before reading it', async () => {
    const metadata = btoa(JSON.stringify({ name: 'X', method: 'POST', url: 'https://api.example.com/upload' }))
      .replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
    const res = await app.handle(new Request('https://vault.test/api/runner/use', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-Vault-Proxy-Metadata': metadata,
        'Content-Length': String(MAX_REQUEST_BODY + 1),
        Authorization: 'Bearer aaaaaaaaaa.bbbbbbbbbb.cccccccccc',
      },
      body: 'x',
    }))
    expect(res.status).toBe(413)
    expect(await res.json()).toEqual({ error: 'body_too_large' })
  })

  test('raw proxy transport rejects malformed metadata', async () => {
    const res = await app.handle(new Request('https://vault.test/api/runner/use', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-Vault-Proxy-Metadata': 'not-base64!',
        Authorization: 'Bearer aaaaaaaaaa.bbbbbbbbbb.cccccccccc',
      },
      body: 'x',
    }))
    expect(res.status).toBe(400)
    expect(await res.json()).toEqual({ error: 'invalid_request' })
  })

  test('no route returns a credential value endpoint of the old secrets API shape', async () => {
    const res = await call('GET', '/api/runner/secrets')
    expect([404, 405]).toContain(res.status)
  })
})
