import { test } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import {
  api, apiProxy, parseArgs, parseHeaders, mapLocalProxyTarget, fetchWithTimeout,
  runnerSession, resetClientSessionForTests, startLocalProxy,
} from './vault.mjs'

const SECRET = 'must-never-appear-anywhere'
const realFetch = globalThis.fetch
const OIDC_TOKEN = 'eyJ' + 'a'.repeat(180)
const REQUESTER_TOKEN = 'github-actions-requester-token-for-tests'

function configureEnv(extra = {}) {
  const keys = ['VAULT_URL', 'ACTIONS_ID_TOKEN_REQUEST_URL', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'VAULT_REQUEST_TIMEOUT_MS']
  const previous = Object.fromEntries(keys.map((key) => [key, process.env[key]]))
  for (const key of keys) delete process.env[key]
  Object.assign(process.env, {
    VAULT_URL: 'https://vault.example',
    ACTIONS_ID_TOKEN_REQUEST_URL: 'https://pipelines.actions.githubusercontent.com/oidc/token?foo=bar',
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: REQUESTER_TOKEN,
    ...extra,
  })
  resetClientSessionForTests()
  return () => {
    for (const key of keys) {
      if (previous[key] === undefined) delete process.env[key]
      else process.env[key] = previous[key]
    }
    resetClientSessionForTests()
  }
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
}

function createVaultFetch({ credentials, integrations, useResult, unauthorizedOnce = false, expireFirstSession = false } = {}) {
  const seen = []
  let oidcCount = 0
  let sessionCount = 0
  let rejected = false
  const fetchFn = async (input, init = {}) => {
    const url = new URL(String(input))
    const headers = new Headers(init.headers ?? {})
    seen.push({ url: url.toString(), method: init.method ?? 'GET', headers, body: init.body })
    if (url.hostname === '127.0.0.1' || url.hostname === 'localhost') return realFetch(input, init)
    if (url.hostname.endsWith('.actions.githubusercontent.com')) {
      assert.equal(headers.get('authorization'), 'Bearer ' + REQUESTER_TOKEN)
      assert.equal(url.searchParams.get('audience'), 'https://vault.example')
      oidcCount++
      return json({ value: OIDC_TOKEN })
    }
    assert.equal(url.origin, 'https://vault.example')
    if (url.pathname === '/api/runner/session') {
      assert.equal(init.method, 'POST')
      assert.equal(headers.get('authorization'), 'Bearer ' + OIDC_TOKEN)
      sessionCount++
      return json({ token: 'runner-session-token-' + sessionCount, expiresAt: Date.now() + (expireFirstSession && sessionCount === 1 ? 45_000 : 1_800_000) })
    }
    if (headers.get('authorization')?.startsWith('Bearer runner-session-') !== true) {
      return json({ error: 'unauthorized' }, 401)
    }
    if (url.pathname === '/api/runner/registry') {
      if (unauthorizedOnce && !rejected) {
        rejected = true
        return json({ error: 'unauthorized' }, 401)
      }
      return json({ credentials: credentials ?? [{ name: 'CF_TOKEN', service: 'Cloudflare' }] })
    }
    if (url.pathname === '/api/runner/integrations') return json({ integrations: integrations ?? [] })
    if (url.pathname === '/api/runner/registrations') {
      return json({ link: 'https://vault.example/vault/register/once', ownerInbox: 'https://vault.example/vault/requests', expiresAt: Date.now() + 900_000 })
    }
    if (url.pathname === '/api/runner/use') {
      const metadata = JSON.parse(Buffer.from(headers.get('x-vault-proxy-metadata'), 'base64url').toString('utf8'))
      const body = init.body ? Buffer.from(init.body) : Buffer.alloc(0)
      seen[seen.length - 1].metadata = metadata
      seen[seen.length - 1].decodedBody = body
      return json(useResult ?? { status: 200, headers: { 'content-type': 'application/json' }, body: '{"ok":true}', truncated: false })
    }
    return json({ error: 'not_found' }, 404)
  }
  return { fetchFn, seen, get oidcCount() { return oidcCount }, get sessionCount() { return sessionCount } }
}

test('parsing', () => {
  assert.deepEqual(parseArgs(['a', '--x', '1', '--header', 'A: b', 'c']), { positional: ['a', 'c'], flags: { x: '1' }, headers: ['A: b'] })
  assert.deepEqual(parseHeaders(['Accept: application/json', 'X-A:b:c']), { Accept: 'application/json', 'X-A': 'b:c' })
})

test('local API proxy preserves provider base paths without allowing an absolute target host', () => {
  assert.equal(mapLocalProxyTarget('https://api.northflank.com/v1', '/v1/projects?limit=10').toString(), 'https://api.northflank.com/v1/projects?limit=10')
  assert.equal(mapLocalProxyTarget('https://api.northflank.com/v1', '/projects').toString(), 'https://api.northflank.com/v1/projects')
  assert.throws(() => mapLocalProxyTarget('https://api.northflank.com/v1', 'https://attacker.example/collect'))
  assert.throws(() => mapLocalProxyTarget('http://api.northflank.com/v1', '/projects'))
  assert.throws(() => mapLocalProxyTarget('https://user:pass@api.northflank.com/v1', '/projects'))
  assert.throws(() => mapLocalProxyTarget('https://api.northflank.com:8443/v1', '/projects'))
})

test('direct HTTPS bootstrap exchanges GitHub OIDC for an in-memory session and authenticates API calls', async () => {
  const restore = configureEnv()
  const stub = createVaultFetch()
  globalThis.fetch = stub.fetchFn
  try {
    const session = await runnerSession()
    assert.equal(session.token, 'runner-session-token-1')
    const result = await api(null, 'GET', '/api/runner/registry')
    assert.deepEqual(result.body.credentials, [{ name: 'CF_TOKEN', service: 'Cloudflare' }])
    assert.equal(stub.oidcCount, 1)
    assert.equal(stub.sessionCount, 1)
    const registryCall = stub.seen.find((item) => item.url.endsWith('/api/runner/registry'))
    assert.equal(registryCall.headers.get('authorization'), 'Bearer runner-session-token-1')
    assert.ok(!JSON.stringify(stub.seen).includes(SECRET))
  } finally {
    globalThis.fetch = realFetch
    restore()
  }
})

test('an expiring in-memory session is renewed before the next request', async () => {
  const restore = configureEnv()
  const stub = createVaultFetch({ expireFirstSession: true })
  globalThis.fetch = stub.fetchFn
  try {
    const first = await runnerSession()
    const second = await runnerSession()
    assert.equal(first.token, 'runner-session-token-1')
    assert.equal(second.token, 'runner-session-token-2')
    assert.equal(stub.oidcCount, 2)
    assert.equal(stub.sessionCount, 2)
  } finally {
    globalThis.fetch = realFetch
    restore()
  }
})

test('registration is sent directly to the Worker and returns only the one-time owner link', async () => {
  const restore = configureEnv()
  const stub = createVaultFetch()
  globalThis.fetch = stub.fetchFn
  const doc = { overview: 'Deploy a Worker', required_permissions: [], verification: 'unverified' }
  try {
    const result = await api(null, 'POST', '/api/runner/registrations', { name: 'CF_NEW_TOKEN', service: 'Cloudflare', doc })
    assert.equal(result.status, 200)
    assert.match(result.body.link, /register\/once/)
    const call = stub.seen.find((item) => item.url.endsWith('/api/runner/registrations'))
    assert.deepEqual(JSON.parse(call.body), { name: 'CF_NEW_TOKEN', service: 'Cloudflare', doc })
    assert.equal(call.headers.get('content-type'), 'application/json')
  } finally {
    globalThis.fetch = realFetch
    restore()
  }
})

test('credential use sends only metadata and request bytes; provider secret never reaches the client', async () => {
  const restore = configureEnv()
  const stub = createVaultFetch()
  globalThis.fetch = stub.fetchFn
  const requestBody = Buffer.from('binary-deploy-payload')
  const metadata = { name: 'CF_TOKEN', method: 'POST', url: 'https://api.cloudflare.com/client/v4/deploy', purpose: 'deploy', headers: { accept: 'application/json' } }
  try {
    const result = await apiProxy(null, metadata, requestBody)
    assert.equal(result.status, 200)
    assert.deepEqual(result.body, { status: 200, headers: { 'content-type': 'application/json' }, body: '{"ok":true}', truncated: false })
    const call = stub.seen.find((item) => item.url.endsWith('/api/runner/use'))
    assert.deepEqual(call.metadata, metadata)
    assert.deepEqual(call.decodedBody, requestBody)
    assert.equal(call.headers.get('authorization'), 'Bearer runner-session-token-1')
    assert.ok(!JSON.stringify(stub.seen).includes(SECRET))
  } finally {
    globalThis.fetch = realFetch
    restore()
  }
})

test('a long-running local proxy refreshes a rejected in-memory session once', async () => {
  const restore = configureEnv()
  const stub = createVaultFetch({ unauthorizedOnce: true })
  globalThis.fetch = stub.fetchFn
  try {
    const result = await api(null, 'GET', '/api/runner/registry')
    assert.equal(result.status, 200)
    assert.equal(stub.oidcCount, 2)
    assert.equal(stub.sessionCount, 2)
    const registryCalls = stub.seen.filter((item) => item.url.endsWith('/api/runner/registry'))
    assert.equal(registryCalls.length, 2)
    assert.equal(registryCalls[0].headers.get('authorization'), 'Bearer runner-session-token-1')
    assert.equal(registryCalls[1].headers.get('authorization'), 'Bearer runner-session-token-2')
  } finally {
    globalThis.fetch = realFetch
    restore()
  }
})

test('serve runs a loopback-only provider bridge with Vault-injected credentials', async () => {
  const restore = configureEnv()
  const stub = createVaultFetch({
    integrations: [{
      name: 'NORTHFLANK_API_TOKEN', service: 'Northflank',
      adapter: {
        apiBaseUrl: 'https://api.northflank.com/v1',
        defaultHeaders: { 'x-api-version': '2026-01-01' },
        cliTools: [{ id: 'northflank', label: 'Northflank CLI', binary: 'nf', integration: 'base-url-env', variable: 'NF_API_BASE_URL' }],
      },
    }],
    useResult: { status: 200, headers: { 'content-type': 'application/json' }, body: '{"projects":[{"id":"project-1"}]}', truncated: false },
  })
  globalThis.fetch = stub.fetchFn
  let server
  try {
    server = await startLocalProxy(null, 'NORTHFLANK_API_TOKEN', undefined, 0)
    const port = server.address().port
    const response = await fetch('http://127.0.0.1:' + port + '/v1/projects?limit=5', {
      headers: { Authorization: 'Bearer vault-local-placeholder', Accept: 'application/json', 'x-api-version': 'attacker-value' },
    })
    assert.equal(response.status, 200)
    assert.deepEqual(await response.json(), { projects: [{ id: 'project-1' }] })
    const use = stub.seen.find((item) => item.url.endsWith('/api/runner/use'))
    assert.deepEqual(use.metadata, {
      name: 'NORTHFLANK_API_TOKEN', method: 'GET', url: 'https://api.northflank.com/v1/projects?limit=5',
      headers: { accept: 'application/json', 'x-api-version': '2026-01-01' },
      consumer: 'cli:northflank', purpose: 'CLI integration: Northflank CLI',
    })
    assert.ok(!JSON.stringify(stub.seen).includes(SECRET))
  } finally {
    if (server) await new Promise((resolve) => server.close(resolve))
    globalThis.fetch = realFetch
    restore()
  }
})

test('OIDC bootstrap accepts the regional GitHub-hosted runner requester endpoint', async () => {
  const restore = configureEnv({
    ACTIONS_ID_TOKEN_REQUEST_URL: 'https://run-actions-2-azure-eastus.actions.githubusercontent.com/oidc/token?api-version=2.0',
  })
  const stub = createVaultFetch()
  globalThis.fetch = stub.fetchFn
  try {
    const session = await runnerSession()
    assert.equal(session.token, 'runner-session-token-1')
    assert.equal(stub.seen.some((item) => new URL(item.url).hostname === 'run-actions-2-azure-eastus.actions.githubusercontent.com'), true)
  } finally {
    globalThis.fetch = realFetch
    restore()
  }
})

test('OIDC bootstrap still accepts the legacy pipelines requester endpoint', async () => {
  const restore = configureEnv()
  const stub = createVaultFetch()
  globalThis.fetch = stub.fetchFn
  try {
    const session = await runnerSession()
    assert.equal(session.token, 'runner-session-token-1')
  } finally {
    globalThis.fetch = realFetch
    restore()
  }
})

test('OIDC bootstrap fails closed for hosts outside the direct GitHub Actions suffix', async () => {
  const untrustedUrls = [
    'https://attacker.example/steal',
    'https://actions.githubusercontent.com/oidc/token',
    'https://nested.run-actions-2-azure-eastus.actions.githubusercontent.com/oidc/token',
    'https://run-actions-2-azure-eastus.actions.githubusercontent.com.evil.example/oidc/token',
    'https://run-actions-2-azure-eastus.actions.githubusercontent.com:8443/oidc/token',
    'http://run-actions-2-azure-eastus.actions.githubusercontent.com/oidc/token',
    'https://user:pass@run-actions-2-azure-eastus.actions.githubusercontent.com/oidc/token',
  ]
  for (const endpoint of untrustedUrls) {
    const restore = configureEnv({ ACTIONS_ID_TOKEN_REQUEST_URL: endpoint })
    let called = false
    globalThis.fetch = async () => { called = true; throw new Error('must not be called') }
    try {
      await assert.rejects(runnerSession(), /OIDC endpoint is not trusted/, endpoint)
      assert.equal(called, false, 'untrusted endpoint must be rejected before network access')
    } finally {
      globalThis.fetch = realFetch
      restore()
    }
  }
})

test('Vault HTTP utility still aborts on timeout and exposes no URL or token details', async () => {
  const server = http.createServer((_req, res) => {
    setTimeout(() => {
      if (!res.destroyed) { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{}') }
    }, 500)
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const url = 'http://127.0.0.1:' + server.address().port + '/sensitive-path?token=' + SECRET
  const started = Date.now()
  try {
    await assert.rejects(fetchWithTimeout(url, { headers: { Authorization: 'Bearer ' + SECRET } }, 'Vault test request', 60), (error) => {
      assert.equal(error.message, 'Vault test request timed out')
      assert.ok(!error.message.includes(SECRET)); assert.ok(!error.message.includes(url)); return true
    })
    assert.ok(Date.now() - started < 400)
  } finally {
    await new Promise((resolve) => server.close(resolve))
  }
})
