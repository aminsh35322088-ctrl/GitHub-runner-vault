import { test } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { spawn } from 'node:child_process'
import os from 'node:os'
import path from 'node:path'
import fs from 'node:fs'
import { parseArgs, parseHeaders, mapLocalProxyTarget } from './vault.mjs'

const SECRET = 'must-never-appear-anywhere'

function startStub() {
  const seen = []
  const server = http.createServer((req, res) => {
    let raw = ''
    req.on('data', (c) => (raw += c))
    req.on('end', () => {
      seen.push({ method: req.method, url: req.url, auth: req.headers.authorization, body: raw })
      const json = (status, body) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)) }
      if (req.url.startsWith('/oidc')) return json(200, { value: 'oidc-token-value' })
      if (req.url === '/api/runner/session') return json(200, { token: 'rs1.session.token', expiresAt: Date.now() + 1_800_000 })
      if (req.url === '/api/runner/registry') return json(200, { credentials: [{ name: 'CF_TOKEN', service: 'Cloudflare' }] })
      if (req.url === '/api/runner/use') {
        const body = JSON.parse(raw)
        if (body.name === 'MISSING') return json(404, { error: 'unavailable' })
        return json(200, { status: 200, headers: {}, body: '{"ok":true}', truncated: false, redacted: false })
      }
      json(404, { error: 'nope' })
    })
  })
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, seen, port: server.address().port })))
}

function run(args, env, script = new URL('./vault.mjs', import.meta.url).pathname) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [script, ...args], { env: { PATH: process.env.PATH, ...env } })
    let stdout = '', stderr = ''
    child.stdout.on('data', (c) => (stdout += c))
    child.stderr.on('data', (c) => (stderr += c))
    child.on('close', (code) => resolve({ code, stdout, stderr }))
  })
}

test('parsing', () => {
  assert.deepEqual(parseArgs(['a', '--x', '1', '--header', 'A: b', 'c']), { positional: ['a', 'c'], flags: { x: '1' }, headers: ['A: b'] })
  assert.deepEqual(parseHeaders(['Accept: application/json', 'X-A:b:c']), { Accept: 'application/json', 'X-A': 'b:c' })
})

test('local API proxy preserves provider base paths without allowing an absolute target host', () => {
  assert.equal(
    mapLocalProxyTarget('https://api.northflank.com/v1', '/v1/projects?limit=10').toString(),
    'https://api.northflank.com/v1/projects?limit=10',
  )
  assert.equal(
    mapLocalProxyTarget('https://api.northflank.com/v1', '/projects').toString(),
    'https://api.northflank.com/v1/projects',
  )
  assert.throws(() => mapLocalProxyTarget('https://api.northflank.com/v1', 'https://attacker.example/collect'))
  assert.throws(() => mapLocalProxyTarget('http://api.northflank.com/v1', '/projects'))
  assert.throws(() => mapLocalProxyTarget('https://user:pass@api.northflank.com/v1', '/projects'))
  assert.throws(() => mapLocalProxyTarget('https://api.northflank.com:8443/v1', '/projects'))
})

test('serve runs a Northflank loopback bridge without forwarding a CLI placeholder as a secret', async () => {
  const seen = []
  const worker = http.createServer(async (req, res) => {
    let raw = ''
    for await (const chunk of req) raw += chunk
    const json = (status, body) => {
      res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' })
      res.end(JSON.stringify(body))
    }
    if (req.url.startsWith('/oidc')) return json(200, { value: 'oidc-token-value' })
    if (req.url === '/api/runner/session') return json(200, { token: 'rs1.test.session.token', expiresAt: Date.now() + 1_800_000 })
    if (req.url === '/api/runner/integrations') return json(200, { integrations: [{
      name: 'NORTHFLANK_API_TOKEN',
      service: 'Northflank',
      adapter: {
        apiBaseUrl: 'https://api.northflank.com/v1',
        defaultHeaders: { 'x-api-version': '2026-01-01' },
        cliTools: [{
          id: 'northflank', label: 'Northflank CLI', binary: 'nf',
          integration: 'base-url-env', variable: 'NF_API_BASE_URL',
          setupHint: 'Use the local proxy.',
        }],
      },
    }] })
    if (req.url === '/api/runner/use') {
      const body = JSON.parse(raw)
      seen.push({ body, authorization: req.headers.authorization })
      return json(200, {
        status: 200,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ projects: [{ id: 'project-1' }] }),
        truncated: false,
        redacted: false,
      })
    }
    return json(404, { error: 'not_found' })
  })
  await new Promise((resolve) => worker.listen(0, '127.0.0.1', resolve))
  const workerPort = worker.address().port
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-serve-e2e-'))
  const child = spawn(process.execPath, [new URL('./vault.mjs', import.meta.url).pathname, 'serve', 'NORTHFLANK_API_TOKEN'], {
    env: {
      PATH: process.env.PATH,
      VAULT_URL: `http://localhost:${workerPort}`,
      ACTIONS_ID_TOKEN_REQUEST_URL: `http://127.0.0.1:${workerPort}/oidc`,
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'oidc-request-token',
      VAULT_SESSION_FILE: path.join(dir, 'session.json'),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  let stdout = ''
  let stderr = ''
  let port = null
  let resolveReady
  let rejectReady
  const ready = new Promise((resolve, reject) => { resolveReady = resolve; rejectReady = reject })
  child.stdout.on('data', (chunk) => {
    stdout += chunk.toString()
    const match = stdout.match(/Listening only on 127\.0\.0\.1:(\d+)/)
    if (match && stdout.includes('NF_API_BASE_URL') && !port) { port = Number(match[1]); resolveReady() }
  })
  child.stderr.on('data', (chunk) => { stderr += chunk.toString() })
  const close = new Promise((resolve) => child.once('close', resolve))
  try {
    await Promise.race([
      ready,
      new Promise((_, reject) => setTimeout(() => reject(new Error(`bridge did not start: ${stderr}`)), 5_000)),
    ])
    assert.match(stdout, /NF_API_BASE_URL=/)
    assert.match(stdout, /NF_API_TOKEN="vault-local-placeholder"/)
    const response = await fetch(`http://127.0.0.1:${port}/v1/projects?limit=5`, {
      headers: {
        Authorization: 'Bearer vault-local-placeholder',
        Accept: 'application/json',
        'x-api-version': 'attacker-value',
      },
    })
    assert.equal(response.status, 200)
    assert.deepEqual(await response.json(), { projects: [{ id: 'project-1' }] })
    assert.equal(seen.length, 1)
    assert.equal(seen[0].authorization, 'Bearer rs1.test.session.token')
    assert.deepEqual(seen[0].body, {
      name: 'NORTHFLANK_API_TOKEN',
      method: 'GET',
      url: 'https://api.northflank.com/v1/projects?limit=5',
      headers: { accept: 'application/json', 'x-api-version': '2026-01-01' },
      consumer: 'cli:northflank',
      purpose: 'CLI integration: Northflank CLI',
    })
    assert.ok(!stdout.includes(SECRET))
    assert.ok(!stderr.includes(SECRET))
  } finally {
    child.kill('SIGTERM')
    await close
    await new Promise((resolve) => worker.close(resolve))
    fs.rmSync(dir, { recursive: true, force: true })
  }
})

test('serve runs a Cloudflare Wrangler loopback bridge and keeps the real API token in Vault', async () => {
  const seen = []
  const worker = http.createServer(async (req, res) => {
    let raw = ''
    for await (const chunk of req) raw += chunk
    const json = (status, body) => {
      res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' })
      res.end(JSON.stringify(body))
    }
    if (req.url.startsWith('/oidc')) return json(200, { value: 'oidc-token-value' })
    if (req.url === '/api/runner/session') return json(200, { token: 'rs1.cloudflare.session.token', expiresAt: Date.now() + 1_800_000 })
    if (req.url === '/api/runner/integrations') return json(200, { integrations: [{
      name: 'CLOUDFLARE_API_TOKEN',
      service: 'Cloudflare',
      adapter: {
        apiBaseUrl: 'https://api.cloudflare.com/client/v4',
        cliTools: [{
          id: 'wrangler', label: 'Wrangler CLI', binary: 'wrangler',
          integration: 'base-url-env', variable: 'CLOUDFLARE_API_BASE_URL',
          tokenVariable: 'CLOUDFLARE_API_TOKEN',
          setupHint: 'Use the Cloudflare Wrangler environment overrides.',
        }],
      },
    }] })
    if (req.url === '/api/runner/use') {
      const body = JSON.parse(raw)
      seen.push({ body, authorization: req.headers.authorization })
      return json(200, {
        status: 200,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ success: true, result: { id: 'account-id' } }),
        truncated: false,
        redacted: false,
      })
    }
    return json(404, { error: 'not_found' })
  })
  await new Promise((resolve) => worker.listen(0, '127.0.0.1', resolve))
  const workerPort = worker.address().port
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-wrangler-serve-'))
  const child = spawn(process.execPath, [new URL('./vault.mjs', import.meta.url).pathname, 'serve', 'CLOUDFLARE_API_TOKEN'], {
    env: {
      PATH: process.env.PATH,
      VAULT_URL: 'http://localhost:' + workerPort,
      ACTIONS_ID_TOKEN_REQUEST_URL: 'http://127.0.0.1:' + workerPort + '/oidc',
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'oidc-request-token',
      VAULT_SESSION_FILE: path.join(dir, 'session.json'),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  let stdout = ''
  let stderr = ''
  let port = null
  let resolveReady
  const ready = new Promise((resolve) => { resolveReady = resolve })
  child.stdout.on('data', (chunk) => {
    stdout += chunk.toString()
    const match = stdout.match(/Listening only on 127\.0\.0\.1:(\d+)/)
    if (match && stdout.includes('CLOUDFLARE_API_BASE_URL') && stdout.includes('CLOUDFLARE_API_TOKEN') && !port) {
      port = Number(match[1])
      resolveReady()
    }
  })
  child.stderr.on('data', (chunk) => { stderr += chunk.toString() })
  const close = new Promise((resolve) => child.once('close', resolve))
  try {
    await Promise.race([
      ready,
      new Promise((_, reject) => setTimeout(() => reject(new Error('Wrangler bridge did not start: ' + stderr)), 5_000)),
    ])
    assert.match(stdout, /CLOUDFLARE_API_BASE_URL=/)
    assert.match(stdout, /CLOUDFLARE_API_TOKEN="vault-local-placeholder"/)
    const response = await fetch('http://127.0.0.1:' + port + '/client/v4/user', {
      headers: { Authorization: 'Bearer vault-local-placeholder', Accept: 'application/json' },
    })
    assert.equal(response.status, 200)
    assert.deepEqual(await response.json(), { success: true, result: { id: 'account-id' } })
    assert.equal(seen.length, 1)
    assert.equal(seen[0].authorization, 'Bearer rs1.cloudflare.session.token')
    assert.deepEqual(seen[0].body, {
      name: 'CLOUDFLARE_API_TOKEN',
      method: 'GET',
      url: 'https://api.cloudflare.com/client/v4/user',
      headers: { accept: 'application/json' },
      consumer: 'cli:wrangler',
      purpose: 'CLI integration: Wrangler CLI',
    })
    assert.ok(!stdout.includes(SECRET))
    assert.ok(!stderr.includes(SECRET))
  } finally {
    child.kill('SIGTERM')
    await close
    await new Promise((resolve) => worker.close(resolve))
    fs.rmSync(dir, { recursive: true, force: true })
  }
})

test('list and use work end to end, caching one session', async () => {
  const { server, seen, port } = await startStub()
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-test-'))
  const sessionFile = path.join(dir, 'session.json')
  const env = {
    VAULT_URL: `http://localhost:${port}`.replace('localhost', 'localhost'),
    ACTIONS_ID_TOKEN_REQUEST_URL: `http://127.0.0.1:${port}/oidc`,
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'req-token',
    VAULT_SESSION_FILE: sessionFile,
  }
  try {
    const list = await run(['list'], env)
    assert.equal(list.code, 0, list.stderr)
    assert.match(list.stdout, /CF_TOKEN/)
    const use = await run(['use', 'CF_TOKEN', 'GET', 'https://api.cloudflare.com/x', '--purpose', 'check', '--header', 'Accept: application/json'], env)
    assert.equal(use.code, 0, use.stderr)
    assert.equal(use.stdout, '{"ok":true}')
    assert.equal(seen.filter((r) => r.url === '/api/runner/session').length, 1, 'session is reused')
    assert.equal(seen.find((r) => r.url.startsWith('/oidc')).auth, 'Bearer req-token')
    assert.match(seen.find((r) => r.url.startsWith('/oidc')).url, /audience=/)
    assert.equal(fs.statSync(sessionFile).mode & 0o777, 0o600)
    fs.chmodSync(sessionFile, 0o644)
    const safeRead = await run(['list'], env)
    assert.equal(safeRead.code, 0, safeRead.stderr)
    assert.equal(fs.statSync(sessionFile).mode & 0o777, 0o600)

    // A malicious pre-created symlink must not let the client overwrite its target.
    const targetFile = path.join(dir, 'do-not-overwrite.txt')
    fs.writeFileSync(targetFile, 'keep-me')
    fs.unlinkSync(sessionFile)
    fs.symlinkSync(targetFile, sessionFile)
    const symlinkRun = await run(['list'], env)
    assert.equal(symlinkRun.code, 0, symlinkRun.stderr)
    assert.equal(fs.readFileSync(targetFile, 'utf8'), 'keep-me')
    assert.equal(fs.lstatSync(sessionFile).isSymbolicLink(), true)

    const missing = await run(['use', 'MISSING', 'GET', 'https://api.cloudflare.com/x'], env)
    assert.equal(missing.code, 2)
    assert.match(missing.stderr, /unavailable/)
    assert.ok(!(list.stdout + use.stdout + use.stderr).includes(SECRET))
  } finally {
    server.close()
    fs.rmSync(dir, { recursive: true, force: true })
  }
})

test('refuses plain http for non-local hosts and missing OIDC variables', async () => {
  assert.match((await run(['list'], { VAULT_URL: 'http://vault.example.com' })).stderr, /https/)
  const r = await run(['list'], { VAULT_URL: 'http://localhost:9', VAULT_SESSION_FILE: '/nonexistent/x' })
  assert.match(r.stderr, /id-token: write/)
})

test('works when invoked through a symlink (how the runner installs it)', async () => {
  const { server, port } = await startStub()
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-link-'))
  const link = path.join(dir, 'vault')
  fs.symlinkSync(new URL('./vault.mjs', import.meta.url).pathname, link)
  try {
    const out = await run(['list'], {
      VAULT_URL: `http://localhost:${port}`,
      ACTIONS_ID_TOKEN_REQUEST_URL: `http://127.0.0.1:${port}/oidc`,
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'req-token',
      VAULT_SESSION_FILE: path.join(dir, 'session.json'),
    }, link)
    assert.equal(out.code, 0, out.stderr)
    assert.match(out.stdout, /CF_TOKEN/)
  } finally {
    server.close()
    fs.rmSync(dir, { recursive: true, force: true })
  }
})
