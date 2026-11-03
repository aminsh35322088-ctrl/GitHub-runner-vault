#!/usr/bin/env node
// Runner client for the Runner Credential Vault. Zero dependencies (Node 18+).
//
//   vault list                                  credentials this runner may use (metadata only)
//   vault request --name N --service S --doc doc.json
//                                               ask the owner to register a credential; prints the
//                                               owner inbox and one-time link. Prints no secret.
//   vault use NAME METHOD URL [--purpose P] [--header 'K: V']... [--data BODY | --data-file F]
//                                               make an HTTPS call with the stored credential.
//                                               The Worker adds the token; it is never returned.
//   vault serve NAME [--tool ID] [--port PORT]
//                                               expose one reviewed CLI adapter through a
//                                               loopback-only proxy; prints placeholder config,
//                                               never the stored token.
//
// Environment:
//   VAULT_URL                  vault origin, e.g. https://runner-vault.example.workers.dev
//   ACTIONS_ID_TOKEN_REQUEST_URL / ACTIONS_ID_TOKEN_REQUEST_TOKEN
//                              set by GitHub Actions when the job has `permissions: id-token: write`
//   VAULT_SESSION_FILE         optional cache path for the 30 minute session (default under $XDG_RUNTIME_DIR or /tmp)

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { createServer } from 'node:http'

const env = process.env

function die(message, code = 1) {
  process.stderr.write(`vault: ${message}\n`)
  process.exit(code)
}

function origin() {
  const raw = env.VAULT_URL
  if (!raw) die('VAULT_URL is not set')
  let url
  try { url = new URL(raw) } catch { die('VAULT_URL is not a valid URL') }
  const local = url.hostname === 'localhost' || url.hostname.endsWith('.localhost')
  if (url.protocol !== 'https:' && !local) die('VAULT_URL must be https')
  return url.origin
}

function sessionFile() {
  const uid = os.userInfo().uid
  const privateDir = env.XDG_RUNTIME_DIR || path.join(os.tmpdir(), 'runner-vault-' + uid)
  return env.VAULT_SESSION_FILE || path.join(privateDir, 'session-' + uid + '.json')
}

function openNoFollow(file, flags, mode) {
  const noFollow = fs.constants.O_NOFOLLOW ?? 0
  return fs.openSync(file, flags | noFollow, mode)
}

function readCachedSession(base) {
  let fd
  try {
    fd = openNoFollow(sessionFile(), fs.constants.O_RDONLY)
    const stat = fs.fstatSync(fd)
    if (!stat.isFile() || stat.uid !== os.userInfo().uid) return null
    if ((stat.mode & 0o077) !== 0) fs.fchmodSync(fd, 0o600)
    const cached = JSON.parse(fs.readFileSync(fd, 'utf8'))
    if (
      cached.origin === base &&
      typeof cached.token === 'string' &&
      cached.token.length >= 10 &&
      Number.isFinite(cached.expiresAt) &&
      cached.expiresAt - Date.now() > 60_000
    ) return cached
  } catch { /* no cache; symlinks and unsafe files are ignored */ }
  finally { if (fd !== undefined) fs.closeSync(fd) }
  return null
}

function writeCachedSession(base, token, expiresAt) {
  let fd
  try {
    const file = sessionFile()
    const directory = path.dirname(file)
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 })
    const dirStat = fs.lstatSync(directory)
    if (!dirStat.isDirectory() || dirStat.isSymbolicLink() || dirStat.uid !== os.userInfo().uid) return
    if ((dirStat.mode & 0o077) !== 0) fs.chmodSync(directory, 0o700)

    fd = openNoFollow(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_TRUNC, 0o600)
    const stat = fs.fstatSync(fd)
    if (!stat.isFile() || stat.uid !== os.userInfo().uid) return
    fs.fchmodSync(fd, 0o600)
    fs.writeFileSync(fd, JSON.stringify({ origin: base, token, expiresAt }))
  } catch { /* cache is optional; never follow a pre-existing symlink */ }
  finally { if (fd !== undefined) fs.closeSync(fd) }
}

async function getOidcToken(base) {
  const url = env.ACTIONS_ID_TOKEN_REQUEST_URL
  const bearer = env.ACTIONS_ID_TOKEN_REQUEST_TOKEN
  if (!url || !bearer) die('no GitHub Actions OIDC variables; the job needs `permissions: id-token: write`')
  const res = await fetch(`${url}${url.includes('?') ? '&' : '?'}audience=${encodeURIComponent(base)}`, {
    headers: { Authorization: `Bearer ${bearer}`, Accept: 'application/json' },
  })
  if (!res.ok) die(`could not get an OIDC token (HTTP ${res.status})`)
  const body = await res.json()
  if (typeof body.value !== 'string') die('unexpected OIDC response')
  return body.value
}

let memorySession = null
let memorySessionExpiresAt = 0
let sessionInFlight = null

async function session(base) {
  if (memorySession && memorySessionExpiresAt - Date.now() > 60_000) return memorySession
  if (sessionInFlight) return sessionInFlight
  sessionInFlight = (async () => {
    const cached = readCachedSession(base)
    if (cached) {
      memorySession = cached.token
      memorySessionExpiresAt = cached.expiresAt
      return cached.token
    }
    const oidc = await getOidcToken(base)
    const res = await fetch(`${base}/api/runner/session`, { method: 'POST', headers: { Authorization: `Bearer ${oidc}` } })
    const body = await res.json().catch(() => ({}))
    if (!res.ok) die(`vault refused the session (${body.error ?? res.status})`)
    memorySession = body.token
    memorySessionExpiresAt = Number(body.expiresAt) || Date.now() + 25 * 60_000
    writeCachedSession(base, body.token, body.expiresAt)
    return body.token
  })()
  try { return await sessionInFlight } finally { sessionInFlight = null }
}

async function api(base, method, route, payload) {
  const token = await session(base)
  const res = await fetch(`${base}${route}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, ...(payload ? { 'Content-Type': 'application/json' } : {}) },
    body: payload ? JSON.stringify(payload) : undefined,
  })
  const body = await res.json().catch(() => ({ error: `HTTP ${res.status}` }))
  return { status: res.status, body }
}

export function parseArgs(argv) {
  const positional = []
  const flags = {}
  const headers = []
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg.startsWith('--')) {
      const key = arg.slice(2)
      const value = argv[++i]
      if (value === undefined) die(`--${key} needs a value`)
      if (key === 'header') headers.push(value)
      else flags[key] = value
    } else positional.push(arg)
  }
  return { positional, flags, headers }
}

export function parseHeaders(list) {
  const out = {}
  for (const line of list) {
    const idx = line.indexOf(':')
    if (idx < 1) die(`bad header: ${line}`)
    out[line.slice(0, idx).trim()] = line.slice(idx + 1).trim()
  }
  return out
}

const LOCAL_PROXY_BODY_LIMIT = 256 * 1024
const LOCAL_PROXY_RESPONSE_LIMIT = 1_100 * 1024
const LOCAL_PROXY_REQUEST_HEADERS = new Set([
  'accept', 'content-type', 'if-match', 'if-none-match',
  'if-modified-since', 'if-unmodified-since', 'range', 'x-api-version',
  'x-github-api-version', 'anthropic-version', 'x-pinecone-api-version',
])
const LOCAL_PROXY_RESPONSE_HEADERS = new Set([
  'content-type', 'content-language', 'etag', 'last-modified', 'retry-after',
  'x-request-id', 'cf-ray', 'link', 'www-authenticate', 'content-range',
])

function loopbackAddress(address) {
  return address === '127.0.0.1' || address === '::1' || address === '::ffff:127.0.0.1'
}

export function mapLocalProxyTarget(apiBaseUrl, requestTarget) {
  const base = new URL(apiBaseUrl)
  if (base.protocol !== 'https:' || base.username || base.password || (base.port && base.port !== '443') || base.search || base.hash) {
    throw new Error('The registered adapter does not contain a safe HTTPS API base URL.')
  }
  if (base.hostname.includes(':') || base.hostname === 'localhost' || /^\d/.test(base.hostname)) {
    throw new Error('The registered API host is not a public DNS hostname.')
  }
  const incoming = new URL(requestTarget, 'http://127.0.0.1')
  if (incoming.origin !== 'http://127.0.0.1' || incoming.pathname.includes('\\') || incoming.pathname.split('/').includes('..')) {
    throw new Error('Invalid local proxy path.')
  }
  const basePath = base.pathname.replace(/\/$/, '')
  const incomingPath = incoming.pathname
  const pathname = basePath && (incomingPath === basePath || incomingPath.startsWith(basePath + '/'))
    ? incomingPath : `${basePath}${incomingPath.startsWith('/') ? incomingPath : `/${incomingPath}`}`
  return new URL(`${pathname}${incoming.search}`, base.origin)
}

async function startLocalProxy(vaultOrigin, credentialName, toolId, requestedPort) {
  const registry = await api(vaultOrigin, 'GET', '/api/runner/integrations')
  if (registry.status !== 200 || !Array.isArray(registry.body.integrations)) die(`could not read CLI integration registry (${registry.body.error ?? registry.status})`)
  const credential = registry.body.integrations.find((item) => item.name === credentialName)
  if (!credential) die('credential is unavailable, hidden, disabled, expired or not in the runner registry')
  if (credential.externallyManaged) die('externally managed credentials cannot be proxied by the vault')
  const adapter = credential.adapter
  if (!adapter || typeof adapter.apiBaseUrl !== 'string' || !Array.isArray(adapter.cliTools)) {
    die('this credential has no reviewed CLI integration adapter')
  }
  const tools = adapter.cliTools
  const tool = toolId ? tools.find((entry) => entry.id === toolId) : tools.length === 1 ? tools[0] : null
  if (!tool) {
    const names = tools.map((entry) => entry.id).join(', ')
    die(tools.length ? `choose a CLI consumer with --tool (${names})` : 'this service has no supported CLI consumer')
  }
  if (!['base-url-env', 'host-flag'].includes(tool.integration)) die('the CLI integration type is not supported')
  if (tool.integration === 'base-url-env' && !/^[A-Z][A-Z0-9_]{0,63}$/.test(tool.variable ?? '')) die('the CLI environment variable is not safe')
  if (tool.tokenVariable && (!/^[A-Z][A-Z0-9_]{0,63}$/.test(tool.tokenVariable) || tool.tokenVariable === tool.variable)) die('the CLI token environment variable is not safe')
  if (tool.integration === 'host-flag' && !/^--[a-z][a-z-]{0,30}$/.test(tool.flag ?? '')) die('the CLI host flag is not safe')

  let upstreamBase
  try {
    upstreamBase = new URL(adapter.apiBaseUrl)
    if (upstreamBase.protocol !== 'https:' || upstreamBase.username || upstreamBase.password || (upstreamBase.port && upstreamBase.port !== '443')) throw new Error()
  } catch { die('the registered API origin is invalid') }

  const server = createServer(async (request, response) => {
    const reject = (status, message) => {
      const body = JSON.stringify({ error: message })
      response.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body), 'cache-control': 'no-store' })
      response.end(body)
    }
    if (!loopbackAddress(request.socket.remoteAddress)) return reject(403, 'loopback_only')
    const localPort = server.address()?.port
    const host = String(request.headers.host ?? '').toLowerCase()
    if (![ `127.0.0.1:${localPort}`, `localhost:${localPort}` ].includes(host)) return reject(403, 'invalid_host')
    if (request.headers.origin) {
      try {
        const source = new URL(request.headers.origin)
        if (!['127.0.0.1', 'localhost'].includes(source.hostname) || source.port !== String(localPort)) return reject(403, 'invalid_origin')
      } catch { return reject(403, 'invalid_origin') }
    }
    if (request.method === 'CONNECT' || request.method === 'TRACE') return reject(405, 'method_not_allowed')
    let target
    try { target = mapLocalProxyTarget(adapter.apiBaseUrl, request.url ?? '/') } catch { return reject(400, 'invalid_path') }
    let total = 0
    const chunks = []
    try {
      for await (const chunk of request) {
        total += chunk.byteLength
        if (total > LOCAL_PROXY_BODY_LIMIT) return reject(413, 'body_too_large')
        chunks.push(chunk)
      }
    } catch { return reject(400, 'invalid_body') }
    const bodyText = total ? Buffer.concat(chunks).toString('utf8') : undefined
    // Adapter-supplied headers are part of the reviewed provider contract.
    // CLI-provided values may add harmless headers but cannot override them.
    const headers = {}
    for (const [key, value] of Object.entries(adapter.defaultHeaders ?? {})) {
      const normalized = key.toLowerCase()
      if (LOCAL_PROXY_REQUEST_HEADERS.has(normalized) && typeof value === 'string') headers[normalized] = value
    }
    for (const [key, value] of Object.entries(request.headers)) {
      if (LOCAL_PROXY_REQUEST_HEADERS.has(key) && typeof value === 'string' && headers[key] === undefined) headers[key] = value
    }

    try {
      const proxied = await api(vaultOrigin, 'POST', '/api/runner/use', {
        name: credentialName,
        method: request.method ?? 'GET',
        url: target.toString(),
        headers,
        body: bodyText,
        consumer: `cli:${tool.id}`,
        purpose: `CLI integration: ${tool.label}`,
      })
      if (proxied.status !== 200) return reject(proxied.status, proxied.body.error ?? 'vault_proxy_failed')
      const upstreamStatus = Number(proxied.body.status)
      if (!Number.isInteger(upstreamStatus) || upstreamStatus < 100 || upstreamStatus > 599 || typeof proxied.body.body !== 'string') {
        return reject(502, 'invalid_vault_response')
      }
      if (Buffer.byteLength(proxied.body.body) > LOCAL_PROXY_RESPONSE_LIMIT) return reject(502, 'response_too_large')
      const outHeaders = { 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' }
      for (const [key, value] of Object.entries(proxied.body.headers ?? {})) {
        if (LOCAL_PROXY_RESPONSE_HEADERS.has(key.toLowerCase()) && typeof value === 'string' && value.length <= 2000) outHeaders[key.toLowerCase()] = value
      }
      response.writeHead(upstreamStatus, outHeaders)
      response.end(proxied.body.body)
    } catch {
      reject(502, 'vault_proxy_failed')
    }
  })

  server.requestTimeout = 30_000
  server.headersTimeout = 10_000
  server.keepAliveTimeout = 5_000
  server.maxHeadersCount = 50
  server.on('clientError', (_error, socket) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n')
  })
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(requestedPort, '127.0.0.1', resolve)
  })
  const address = server.address()
  if (!address || typeof address === 'string') die('could not start the loopback proxy')
  const localOrigin = `http://127.0.0.1:${address.port}`
  process.stdout.write(`Vault local proxy ready for ${credentialName} → ${tool.label}\n`)
  process.stdout.write(`Listening only on 127.0.0.1:${address.port}. Keep this process running while the CLI is in use.\n`)
  if (tool.integration === 'base-url-env') {
    const mount = upstreamBase.pathname.replace(/\/$/, '')
    process.stdout.write('Use: export ' + tool.variable + '="' + localOrigin + mount + '"\n')
    const tokenVariable = tool.tokenVariable ?? (tool.id === 'northflank' ? 'NF_API_TOKEN' : undefined)
    if (tokenVariable) {
      process.stdout.write('export ' + tokenVariable + '="vault-local-placeholder"\n')
      process.stdout.write('The placeholder is intercepted locally and is never sent upstream; the Vault injects the stored token at the provider boundary.\n')
    }
    process.stdout.write('Then run: ' + tool.binary + ' …\n')
  } else {
    process.stdout.write(`Use: ${tool.binary} login --token-login --token "vault-local-placeholder" ${tool.flag} "${localOrigin}" --name "vault-local"\n`)
    process.stdout.write(`The placeholder is not a credential; Vault injects the stored token at the upstream boundary.\n`)
  }
  process.stdout.write('Stop the proxy with Ctrl+C. No API token is displayed or written by this command.\n')
  return server
}

async function main() {
  const [command, ...rest] = process.argv.slice(2)
  const { positional, flags, headers } = parseArgs(rest)
  const base = origin()

  if (command === 'list') {
    const { status, body } = await api(base, 'GET', '/api/runner/registry')
    if (status !== 200) die(`list failed (${body.error})`)
    console.log(JSON.stringify(body.credentials, null, 2))
    return
  }

  if (command === 'serve') {
    const [name] = positional
    if (!name) die('usage: vault serve NAME [--tool TOOL] [--port PORT]')
    const port = flags.port === undefined ? 0 : Number(flags.port)
    if (!Number.isInteger(port) || port < 0 || port > 65535) die('--port must be an integer between 0 and 65535')
    await startLocalProxy(base, name, flags.tool, port)
    return
  }

  if (command === 'request') {
    for (const k of ['name', 'service', 'doc']) if (!flags[k]) die(`--${k} is required`)
    let doc
    try { doc = JSON.parse(fs.readFileSync(flags.doc, 'utf8')) } catch { die('--doc must be a JSON file') }
    const { status, body } = await api(base, 'POST', '/api/runner/registrations', { name: flags.name, service: flags.service, doc })
    if (status !== 200) die(`registration refused (${body.error}${body.detail ? `: ${body.detail}` : ''})`)
    console.log(`Credential request created: ${flags.name} (${flags.service})`)
    console.log(`Owner inbox: ${base}/vault/requests`)
    console.log(`One-time owner form (expires ${new Date(body.expiresAt).toISOString()}, works once):\n${body.link}`)
    return
  }

  if (command === 'use') {
    const [name, method, url] = positional
    if (!name || !method || !url) die('usage: vault use NAME METHOD URL [--purpose P] [--header "K: V"] [--data BODY | --data-file F]')
    const data = flags['data-file'] ? fs.readFileSync(flags['data-file'], 'utf8') : flags.data
    const consumer = flags.consumer && /^cli:[a-z0-9._-]{1,40}$/i.test(flags.consumer) ? flags.consumer.toLowerCase() : undefined
    const { status, body } = await api(base, 'POST', '/api/runner/use', {
      name, method, url, purpose: flags.purpose, headers: parseHeaders(headers), body: data, consumer,
    })
    if (status !== 200) die(`call refused (${body.error})`, 2)
    if (body.truncated) process.stderr.write('vault: response was truncated\n')
    process.stderr.write(`vault: upstream status ${body.status}\n`)
    process.stdout.write(body.body)
    if (body.status >= 400) process.exit(3)
    return
  }

  die('commands: list | request | use | serve')
}

// Resolve symlinks: the runner installs this file behind a `vault` symlink, so argv[1] is the link path.
const invokedDirectly = (() => {
  try { return fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url)) } catch { return false }
})()

if (invokedDirectly) main().catch((e) => die(e instanceof Error ? e.message : String(e)))
