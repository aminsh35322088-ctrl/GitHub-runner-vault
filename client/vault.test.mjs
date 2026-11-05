import { test } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import net from 'node:net'
import { spawn } from 'node:child_process'
import os from 'node:os'
import path from 'node:path'
import fs from 'node:fs'
import { parseArgs, parseHeaders, mapLocalProxyTarget, fetchWithTimeout } from './vault.mjs'

const SECRET = 'must-never-appear-anywhere'

function startBrokerStub({ credentials, integrations, useResult } = {}) {
  const seen = []
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-broker-socket-'))
  const socketPath = path.join(dir, 'broker.sock')
  const server = net.createServer((socket) => {
    let input = Buffer.alloc(0)
    socket.on('data', (chunk) => {
      input = Buffer.concat([input, chunk])
      if (input.length > 15 * 1024 * 1024) socket.destroy()
    })
    socket.on('end', () => {
      let request
      try { request = JSON.parse(input.toString('utf8').trim()) } catch { socket.destroy(); return }
      seen.push(request)
      let result
      let error
      switch (request.operation) {
        case 'status':
          result = { connected: true, sessionExpiresAt: Date.now() + 1_800_000, brokerProtocol: 1,
            operations: ['tokens.list', 'integrations.list', 'registrations.create', 'credential.use'] }
          break
        case 'tokens.list':
          result = { credentials: credentials ?? [{ name: 'CF_TOKEN', service: 'Cloudflare' }] }
          break
        case 'integrations.list':
          result = { integrations: integrations ?? [] }
          break
        case 'registrations.create':
          result = { link: `http://localhost/vault/register/lnk_${'a'.repeat(43)}`, ownerInbox: 'https://vault.example/vault/requests', expiresAt: Date.now() + 900_000 }
          break
        case 'credential.use':
          if (request.payload?.name === 'MISSING') {
            error = { code: 'CREDENTIAL_UNAVAILABLE', message: 'Credential is unavailable', retryable: false }
          } else {
            result = useResult ?? { status: 200, headers: {}, body: '{"ok":true}', truncated: false }
            seen[seen.length - 1].decodedBody = request.payload?.body
              ? Buffer.from(request.payload.body, 'base64') : Buffer.alloc(0)
          }
          break
        default:
          error = { code: 'OPERATION_NOT_ALLOWED', message: 'Operation is not available', retryable: false }
      }
      socket.end(JSON.stringify({ version: 1, id: request.id, ok: !error, ...(error ? { error } : { result }) }) + '\n')
    })
  })
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(socketPath, () => resolve({ server, seen, socketPath, dir }))
  })
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

async function closeBrokerStub(stub) {
  await new Promise((resolve) => stub.server.close(resolve))
  fs.rmSync(stub.dir, { recursive: true, force: true })
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

test('request uses only the broker registration operation and prints the one-time owner link', async () => {
  const stub = await startBrokerStub()
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-request-e2e-'))
  const docPath = path.join(dir, 'service-doc.json')
  const doc = { overview: 'Deploy a Worker', task: 'Deploy a Worker', token_type: 'API token', creation_steps: [],
    required_permissions: [], unnecessary_permissions: [], security_notes: [], expiration_guidance: [],
    official_documentation_links: [], verification: 'unverified', unverified_note: 'Not yet checked' }
  fs.writeFileSync(docPath, JSON.stringify(doc))
  try {
    const result = await run(['request', '--name', 'CF_NEW_TOKEN', '--service', 'Cloudflare', '--doc', docPath], {
      VAULT_BROKER_SOCKET: stub.socketPath,
    })
    assert.equal(result.code, 0, result.stderr)
    assert.match(result.stdout, /Credential request created: CF_NEW_TOKEN \(Cloudflare\)/)
    assert.match(result.stdout, /Owner inbox: https:\/\/vault\.example\/vault\/requests/)
    assert.match(result.stdout, /One-time owner form .*works once/)
    assert.match(result.stdout, /\/vault\/register\/lnk_/)
    assert.equal(stub.seen.length, 1)
    assert.equal(stub.seen[0].operation, 'registrations.create')
    assert.deepEqual(stub.seen[0].payload, { name: 'CF_NEW_TOKEN', service: 'Cloudflare', doc })
    assert.ok(!result.stdout.includes(SECRET) && !result.stderr.includes(SECRET))
  } finally {
    fs.rmSync(dir, { recursive: true, force: true })
    await closeBrokerStub(stub)
  }
})

test('serve runs a Northflank loopback bridge without forwarding a CLI placeholder as a secret', async () => {
  const stub = await startBrokerStub({ integrations: [{
    name: 'NORTHFLANK_API_TOKEN', service: 'Northflank',
    adapter: {
      apiBaseUrl: 'https://api.northflank.com/v1',
      defaultHeaders: { 'x-api-version': '2026-01-01' },
      cliTools: [{ id: 'northflank', label: 'Northflank CLI', binary: 'nf', integration: 'base-url-env', variable: 'NF_API_BASE_URL' }],
    },
  }], useResult: { status: 200, headers: { 'content-type': 'application/json' }, body: '{"projects":[{"id":"project-1"}]}', truncated: false } })
  const child = spawn(process.execPath, [new URL('./vault.mjs', import.meta.url).pathname, 'serve', 'NORTHFLANK_API_TOKEN'], {
    env: { PATH: process.env.PATH, VAULT_BROKER_SOCKET: stub.socketPath }, stdio: ['ignore', 'pipe', 'pipe'],
  })
  let stdout = '', stderr = '', port = null
  let resolveReady
  const ready = new Promise((resolve) => { resolveReady = resolve })
  child.stdout.on('data', (chunk) => {
    stdout += chunk.toString()
    const match = stdout.match(/Listening only on 127\.0\.0\.1:(\d+)/)
    if (match && stdout.includes('Use: export NF_API_BASE_URL=') && !port) { port = Number(match[1]); resolveReady() }
  })
  child.stderr.on('data', (chunk) => { stderr += chunk.toString() })
  const close = new Promise((resolve) => child.once('close', resolve))
  try {
    await Promise.race([ready, new Promise((_, reject) => setTimeout(() => reject(new Error(`bridge did not start: ${stderr}`)), 5000))])
    assert.match(stdout, /NF_API_BASE_URL=/)
    assert.match(stdout, /NF_API_TOKEN="vault-local-placeholder"/)
    const response = await fetch(`http://127.0.0.1:${port}/v1/projects?limit=5`, {
      headers: { Authorization: 'Bearer vault-local-placeholder', Accept: 'application/json', 'x-api-version': 'attacker-value' },
    })
    assert.equal(response.status, 200)
    assert.deepEqual(await response.json(), { projects: [{ id: 'project-1' }] })
    const use = stub.seen.find((item) => item.operation === 'credential.use')
    assert.ok(use)
    assert.equal(use.payload.name, 'NORTHFLANK_API_TOKEN')
    assert.equal(use.payload.method, 'GET')
    assert.equal(use.payload.url, 'https://api.northflank.com/v1/projects?limit=5')
    assert.deepEqual(use.payload.headers, { accept: 'application/json', 'x-api-version': '2026-01-01' })
    assert.equal(use.payload.consumer, 'cli:northflank')
    assert.ok(!stdout.includes(SECRET) && !stderr.includes(SECRET))
  } finally {
    child.kill('SIGTERM'); await close; await closeBrokerStub(stub)
  }
})

test('serve runs a Cloudflare Wrangler loopback bridge using broker-approved integration metadata', async () => {
  const stub = await startBrokerStub({ integrations: [{
    name: 'CLOUDFLARE_API_TOKEN', service: 'Cloudflare',
    adapter: {
      apiBaseUrl: 'https://api.cloudflare.com/client/v4',
      cliTools: [{ id: 'wrangler', label: 'Wrangler CLI', binary: 'wrangler', integration: 'base-url-env',
        variable: 'CLOUDFLARE_API_BASE_URL', tokenVariable: 'CLOUDFLARE_API_TOKEN' }],
    },
  }], useResult: { status: 200, headers: { 'content-type': 'application/json' }, body: '{"success":true}', truncated: false } })
  const child = spawn(process.execPath, [new URL('./vault.mjs', import.meta.url).pathname, 'serve', 'CLOUDFLARE_API_TOKEN'], {
    env: { PATH: process.env.PATH, VAULT_BROKER_SOCKET: stub.socketPath }, stdio: ['ignore', 'pipe', 'pipe'],
  })
  let stdout = '', stderr = '', port = null
  let resolveReady
  const ready = new Promise((resolve) => { resolveReady = resolve })
  child.stdout.on('data', (chunk) => {
    stdout += chunk.toString()
    const match = stdout.match(/Listening only on 127\.0\.0\.1:(\d+)/)
    if (match && stdout.includes('Use: export CLOUDFLARE_API_BASE_URL=') && !port) { port = Number(match[1]); resolveReady() }
  })
  child.stderr.on('data', (chunk) => { stderr += chunk.toString() })
  const close = new Promise((resolve) => child.once('close', resolve))
  try {
    await Promise.race([ready, new Promise((_, reject) => setTimeout(() => reject(new Error(`bridge did not start: ${stderr}`)), 5000))])
    assert.match(stdout, /CLOUDFLARE_API_TOKEN="vault-local-placeholder"/)
    const response = await fetch(`http://127.0.0.1:${port}/client/v4/user`, { headers: { Authorization: 'Bearer vault-local-placeholder', Accept: 'application/json' } })
    assert.equal(response.status, 200)
    assert.deepEqual(await response.json(), { success: true })
    const use = stub.seen.find((item) => item.operation === 'credential.use')
    assert.equal(use.payload.url, 'https://api.cloudflare.com/client/v4/user')
    assert.equal(use.payload.consumer, 'cli:wrangler')
    const uploadBody = Buffer.alloc(300 * 1024, 0xff)
    const upload = await fetch(`http://127.0.0.1:${port}/v1/deploy`, { method: 'POST', headers: { 'content-type': 'application/octet-stream' }, body: uploadBody })
    assert.equal(upload.status, 200)
    const post = stub.seen.filter((item) => item.operation === 'credential.use')[1]
    assert.ok(post)
    assert.deepEqual(Buffer.from(post.payload.body, 'base64'), uploadBody)
    assert.ok(!stdout.includes(SECRET) && !stderr.includes(SECRET))
  } finally {
    child.kill('SIGTERM'); await close; await closeBrokerStub(stub)
  }
})

test('list and use use the broker protocol without OIDC variables or a Runner Session cache', async () => {
  const stub = await startBrokerStub()
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-broker-cli-'))
  const legacySessionFile = path.join(dir, 'session.json')
  const env = { VAULT_BROKER_SOCKET: stub.socketPath, VAULT_SESSION_FILE: legacySessionFile }
  try {
    const list = await run(['list'], env)
    assert.equal(list.code, 0, list.stderr)
    assert.match(list.stdout, /CF_TOKEN/)
    const use = await run(['use', 'CF_TOKEN', 'GET', 'https://api.cloudflare.com/client/v4/user', '--purpose', 'check', '--header', 'Accept: application/json'], env)
    assert.equal(use.code, 0, use.stderr)
    assert.equal(use.stdout, '{"ok":true}')
    assert.equal(stub.seen[0].operation, 'tokens.list')
    assert.equal(stub.seen[1].operation, 'credential.use')
    assert.equal(stub.seen[1].payload.name, 'CF_TOKEN')
    assert.equal(stub.seen[1].payload.purpose, 'check')
    assert.deepEqual(stub.seen[1].payload.headers, { Accept: 'application/json' })
    assert.equal(fs.existsSync(legacySessionFile), false)
    const missing = await run(['use', 'MISSING', 'GET', 'https://api.cloudflare.com/client/v4/user'], env)
    assert.equal(missing.code, 2)
    assert.match(missing.stderr, /credential_unavailable/)
    assert.ok(!(list.stdout + use.stdout + use.stderr).includes(SECRET))
  } finally {
    fs.rmSync(dir, { recursive: true, force: true })
    await closeBrokerStub(stub)
  }
})

test('missing broker socket fails closed without asking for OIDC requester variables', async () => {
  const result = await run(['list'], { VAULT_BROKER_SOCKET: '/tmp/nonexistent-vault-broker.sock' })
  assert.notEqual(result.code, 0)
  assert.match(result.stderr, /broker_unavailable/)
  assert.doesNotMatch(result.stderr, /id-token: write|OIDC/)
})

test('works when invoked through a symlink (how the runner installs it)', async () => {
  const stub = await startBrokerStub()
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-link-'))
  const link = path.join(dir, 'vault')
  fs.symlinkSync(new URL('./vault.mjs', import.meta.url).pathname, link)
  try {
    const out = await run(['list'], { VAULT_BROKER_SOCKET: stub.socketPath }, link)
    assert.equal(out.code, 0, out.stderr)
    assert.match(out.stdout, /CF_TOKEN/)
  } finally {
    fs.rmSync(dir, { recursive: true, force: true })
    await closeBrokerStub(stub)
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
