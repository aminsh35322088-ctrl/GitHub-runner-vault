import assert from 'node:assert/strict'
import test from 'node:test'
import { readFileSync } from 'node:fs'
import relay from './oauth-relay-worker.js'

const WIZARD_ORIGIN = 'https://wizard.example'

test('fails closed when ALLOWED_ORIGINS is missing or invalid', async () => {
  const request = new Request('https://relay.example/token', { method: 'POST', headers: { Origin: WIZARD_ORIGIN } })
  const missing = await relay.fetch(request, {})
  assert.equal(missing.status, 503)

  const invalid = await relay.fetch(request, { ALLOWED_ORIGINS: 'https://wizard.example/path, http://insecure.example' })
  assert.equal(invalid.status, 503)
})

test('rejects an origin that is not explicitly allowlisted', async () => {
  const request = new Request('https://relay.example/token', { method: 'POST', headers: { Origin: 'https://attacker.example' } })
  const response = await relay.fetch(request, { ALLOWED_ORIGINS: WIZARD_ORIGIN })
  assert.equal(response.status, 403)
  assert.equal(await response.text(), 'Origin not allowed')
})

test('allows only the configured origin and forwards the PKCE exchange', async (t) => {
  const originalFetch = globalThis.fetch
  let observedUrl
  let observedBody
  globalThis.fetch = async (url, init) => {
    observedUrl = String(url)
    observedBody = new URLSearchParams(init.body)
    return new Response('{"access_token":"test-token"}', {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })
  }
  t.after(() => { globalThis.fetch = originalFetch })

  const form = new FormData()
  form.set('code', 'single-use-code')
  form.set('redirect_uri', WIZARD_ORIGIN + '/callback')
  form.set('client_id', 'public-client-id')
  form.set('code_verifier', 'pkce-verifier')
  const request = new Request('https://relay.example/token', {
    method: 'POST',
    headers: { Origin: WIZARD_ORIGIN },
    body: form,
  })
  const response = await relay.fetch(request, { ALLOWED_ORIGINS: 'https://other.example, ' + WIZARD_ORIGIN })

  assert.equal(response.status, 200)
  assert.equal(response.headers.get('access-control-allow-origin'), WIZARD_ORIGIN)
  assert.equal(observedUrl, 'https://dash.cloudflare.com/oauth2/token')
  assert.equal(observedBody.get('code'), 'single-use-code')
  assert.equal(observedBody.get('code_verifier'), 'pkce-verifier')
  assert.equal(observedBody.get('grant_type'), 'authorization_code')
  assert.equal(await response.json().then((body) => body.access_token), 'test-token')
})

test('returns a CORS preflight only to an allowed origin', async () => {
  const allowed = await relay.fetch(new Request('https://relay.example/token', {
    method: 'OPTIONS', headers: { Origin: WIZARD_ORIGIN },
  }), { ALLOWED_ORIGINS: WIZARD_ORIGIN })
  assert.equal(allowed.status, 204)
  assert.equal(allowed.headers.get('access-control-allow-origin'), WIZARD_ORIGIN)

  const denied = await relay.fetch(new Request('https://relay.example/token', {
    method: 'OPTIONS', headers: { Origin: 'https://other.example' },
  }), { ALLOWED_ORIGINS: WIZARD_ORIGIN })
  assert.equal(denied.status, 403)
})


test('wizard OAuth configuration is scoped to the exact GitHub Pages path', () => {
  const config = JSON.parse(readFileSync(new URL('./wizard-config.json', import.meta.url), 'utf8'))
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8')
  const site = new URL(config.siteUrl)
  assert.equal(site.protocol, 'https:')
  assert.ok(site.pathname.length > 1, 'project Pages config must include its repository path')
  assert.match(html, /configuredSite\.origin === location\.origin && configuredPath === currentPath/)
  assert.match(html, /!configuredSite\.username/)
  assert.match(html, /safeHttpsOrigin\(cfg\.cloudflareOAuthRelayUrl\)/)
  assert.match(html, /var clientId = '';/)
  assert.match(html, /var relayUrl = '';/)
  assert.doesNotMatch(html, /qs\.get\(['"]relay['"]\)/)
  assert.doesNotMatch(html, /qs\.get\(['"]client_id['"]\)/)
})
