import { describe, expect, test } from 'vitest'
import { app } from './app.tsx'

const call = (method: string, path: string, body?: unknown) =>
  app.handle(new Request(`https://vault.test${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer aaaaaaaaaa.bbbbbbbbbb.cccccccccc' },
    body: body === undefined ? undefined : JSON.stringify(body),
  }))

describe('runner HTTP surface', () => {
  test.each([
    ['POST', '/api/runner/session', undefined],
    ['GET', '/api/runner/registry', undefined],
    ['POST', '/api/runner/registrations', { name: 'X' }],
    ['POST', '/api/runner/use', { name: 'X', method: 'GET', url: 'https://example.com' }],
  ])('%s %s fails closed (503, no-store) when the runner policy is not configured', async (method, path, body) => {
    const res = await call(method, path, body)
    expect(res.status).toBe(503)
    expect(res.headers.get('cache-control')).toBe('no-store')
    expect(await res.json()).toEqual({ error: 'vault_not_configured' })
  })

  test('no route returns a credential value endpoint of the old secrets API shape', async () => {
    const res = await call('GET', '/api/runner/secrets')
    expect([404, 405]).toContain(res.status)
  })
})
