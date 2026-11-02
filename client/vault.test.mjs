import { test } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { spawn } from 'node:child_process'
import os from 'node:os'
import path from 'node:path'
import fs from 'node:fs'
import { parseArgs, parseHeaders } from './vault.mjs'

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
