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
//   VAULT_BROKER_SOCKET        trusted local Unix socket (default /run/runner-vault/broker.sock)
//   The Agent never receives GitHub OIDC requester values or a Runner Session.

import fs from 'node:fs'
import net from 'node:net'
import { randomBytes } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { createServer } from 'node:http'

const env = process.env

const DEFAULT_REQUEST_TIMEOUT_MS = 8_000
const MIN_REQUEST_TIMEOUT_MS = 100
const MAX_REQUEST_TIMEOUT_MS = 30_000

function requestTimeoutMs() {
  const configured = Number(env.VAULT_REQUEST_TIMEOUT_MS)
  return Number.isInteger(configured) && configured >= MIN_REQUEST_TIMEOUT_MS && configured <= MAX_REQUEST_TIMEOUT_MS
    ? configured
    : DEFAULT_REQUEST_TIMEOUT_MS
}

/** Bounded HTTP requests with sanitized errors; never include URLs or headers in failures. */
export async function fetchWithTimeout(url, init = {}, label = 'Vault request', timeoutMs = requestTimeoutMs()) {
  try {
    return await fetch(url, { ...init, signal: AbortSignal.timeout(timeoutMs) })
  } catch (error) {
    const timedOut = error && (error.name === 'TimeoutError' || error.name === 'AbortError')
    throw new Error(timedOut ? label + ' timed out' : label + ' failed')
  }
}

function die(message, code = 1) {
  process.stderr.write(`vault: ${message}\n`)
  process.exit(code)
}

const BROKER_PROTOCOL_VERSION = 1
const BROKER_FRAME_LIMIT = 15 * 1024 * 1024
const BROKER_TIMEOUT_MS = 30_000

function brokerSocketPath() {
  const value = env.VAULT_BROKER_SOCKET || '/run/runner-vault/broker.sock'
  if (typeof value !== 'string' || value.length < 1 || value.length > 100 || value.includes('\0')) {
    die('VAULT_BROKER_SOCKET is invalid', 2)
  }
  return value
}

/** One bounded JSON frame per AF_UNIX connection; no HTTP/OIDC capability lives in the Agent. */
export async function brokerRequest(operation, payload = undefined) {
  const id = randomBytes(16).toString('hex')
  const request = { version: BROKER_PROTOCOL_VERSION, id, operation, ...(payload === undefined ? {} : { payload }) }
  const frame = Buffer.from(JSON.stringify(request) + '\n', 'utf8')
  if (frame.byteLength > BROKER_FRAME_LIMIT) throw new Error('Vault broker request exceeds the size limit')
  const socketPath = brokerSocketPath()
  return await new Promise((resolve, reject) => {
    let settled = false
    let received = Buffer.alloc(0)
    const socket = net.createConnection(socketPath)
    const finish = (error, value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      socket.destroy()
      if (error) reject(error)
      else resolve(value)
    }
    const timer = setTimeout(() => {
      const error = new Error('Vault broker request timed out')
      error.code = 'BROKER_TIMEOUT'
      finish(error)
    }, BROKER_TIMEOUT_MS)
    socket.once('connect', () => socket.end(frame))
    socket.on('data', (chunk) => {
      received = Buffer.concat([received, chunk])
      if (received.byteLength > BROKER_FRAME_LIMIT) {
        const error = new Error('Vault broker response exceeds the size limit')
        error.code = 'BROKER_PROTOCOL_ERROR'
        finish(error)
        return
      }
      const newline = received.indexOf(0x0a)
      if (newline < 0) return
      if (newline !== received.byteLength - 1) {
        const error = new Error('Vault broker returned multiple response frames')
        error.code = 'BROKER_PROTOCOL_ERROR'
        finish(error)
        return
      }
      let response
      try { response = JSON.parse(received.subarray(0, newline).toString('utf8')) } catch {
        const error = new Error('Vault broker returned an invalid response')
        error.code = 'BROKER_PROTOCOL_ERROR'
        finish(error)
        return
      }
      if (!response || response.version !== BROKER_PROTOCOL_VERSION || response.id !== id || typeof response.ok !== 'boolean') {
        const error = new Error('Vault broker response did not match the request')
        error.code = 'BROKER_PROTOCOL_ERROR'
        finish(error)
        return
      }
      if (response.ok && response.result && typeof response.result === 'object') {
        finish(null, response.result)
        return
      }
      const brokerError = response.error && typeof response.error === 'object' ? response.error : {}
      const error = new Error(typeof brokerError.message === 'string' ? brokerError.message : 'Vault broker refused the operation')
      error.code = typeof brokerError.code === 'string' ? brokerError.code : 'BROKER_REFUSED'
      error.retryable = brokerError.retryable === true
      finish(error)
    })
    socket.once('error', (cause) => {
      const error = new Error(cause?.code === 'EACCES' ? 'Vault broker access was denied' : 'Vault broker is unavailable')
      error.code = cause?.code === 'EACCES' ? 'BROKER_ACCESS_DENIED' : 'BROKER_UNAVAILABLE'
      finish(error)
    })
    socket.once('end', () => {
      if (!settled) {
        const error = new Error('Vault broker closed without a complete response')
        error.code = 'BROKER_PROTOCOL_ERROR'
        finish(error)
      }
    })
  })
}

const BROKER_ERROR_STATUS = {
  INVALID_REQUEST: 400,
  OPERATION_NOT_ALLOWED: 403,
  PEER_DENIED: 403,
  POLICY_DENIED: 403,
  SESSION_EXPIRED: 401,
  SESSION_REJECTED: 401,
  RATE_LIMITED: 429,
  BROKER_ACCESS_DENIED: 403,
  BROKER_UNAVAILABLE: 503,
  BROKER_TIMEOUT: 504,
  VAULT_UNAVAILABLE: 503,
  UPSTREAM_UNAVAILABLE: 503,
  UPSTREAM_REDIRECT: 502,
}

async function brokerApi(operation, payload) {
  try {
    return { status: 200, body: await brokerRequest(operation, payload) }
  } catch (error) {
    const code = typeof error?.code === 'string' ? error.code : 'BROKER_ERROR'
    return { status: BROKER_ERROR_STATUS[code] ?? 502, body: { error: code.toLowerCase(), detail: error.message } }
  }
}

async function api(_base, method, route, payload) {
  if (method === 'GET' && route === '/api/runner/registry') {
    const result = await brokerApi('tokens.list')
    return result.status === 200
      ? { status: 200, body: { credentials: result.body.credentials } }
      : result
  }
  if (method === 'GET' && route === '/api/runner/integrations') {
    const result = await brokerApi('integrations.list')
    return result.status === 200
      ? { status: 200, body: { integrations: result.body.integrations } }
      : result
  }
  if (method === 'POST' && route === '/api/runner/registrations') {
    return brokerApi('registrations.create', payload)
  }
  return { status: 400, body: { error: 'unsupported_broker_route' } }
}

async function apiProxy(_base, metadata, requestBody) {
  const payload = { ...metadata }
  if (requestBody && requestBody.byteLength > 0) payload.body = Buffer.from(requestBody).toString('base64')
  return brokerApi('credential.use', payload)
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

// Match the Worker-side cap; this is a bounded buffer, not an unbounded upload path.
const LOCAL_PROXY_BODY_LIMIT = 10 * 1024 * 1024
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
  const registry = await api(null, 'GET', '/api/runner/integrations')
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
    const reject = (status, message, close = false) => {
      const body = JSON.stringify({ error: message })
      response.writeHead(status, {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(body),
        'cache-control': 'no-store',
        ...(close ? { connection: 'close' } : {}),
      })
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
    const rawDeclaredLength = request.headers['content-length']
    let declaredLength
    if (rawDeclaredLength !== undefined) {
      const value = String(rawDeclaredLength)
      if (!/^\d+$/.test(value) || !Number.isSafeInteger(Number(value))) return reject(400, 'invalid_content_length', true)
      declaredLength = Number(value)
      if (declaredLength > LOCAL_PROXY_BODY_LIMIT) return reject(413, 'body_too_large', true)
    }
    let total = 0
    let tooLarge = false
    const chunks = []
    try {
      for await (const chunk of request) {
        if (tooLarge) continue
        total += chunk.byteLength
        if (total > LOCAL_PROXY_BODY_LIMIT) {
          tooLarge = true
          chunks.length = 0
          continue
        }
        chunks.push(chunk)
      }
    } catch { return reject(400, 'invalid_body', true) }
    if (tooLarge) return reject(413, 'body_too_large', true)
    if (declaredLength !== undefined && total !== declaredLength) return reject(400, 'invalid_body', true)
    const bodyBytes = total ? Buffer.concat(chunks, total) : undefined
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
      const proxied = await apiProxy(vaultOrigin, {
        name: credentialName,
        method: request.method ?? 'GET',
        url: target.toString(),
        headers,
        consumer: 'cli:' + tool.id,
        purpose: 'CLI integration: ' + tool.label,
      }, bodyBytes)
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
  const base = null

  if (command === 'status') {
    const { status, body } = await brokerApi('status')
    if (status !== 200) die(`broker status failed (${body.error})`, 4)
    console.log(JSON.stringify(body, null, 2))
    return
  }

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
    console.log(`Owner inbox: ${body.ownerInbox}`)
    console.log(`One-time owner form (expires ${new Date(body.expiresAt).toISOString()}, works once):\n${body.link}`)
    return
  }

  if (command === 'use') {
    const [name, method, url] = positional
    if (!name || !method || !url) die('usage: vault use NAME METHOD URL [--purpose P] [--header "K: V"] [--data BODY | --data-file F]')
    let data
    if (flags['data-file']) {
      let fileStat
      try { fileStat = fs.statSync(flags['data-file']) } catch { die('--data-file could not be read') }
      if (!fileStat.isFile()) die('--data-file must be a regular file')
      if (fileStat.size > LOCAL_PROXY_BODY_LIMIT) die('request body exceeds the 10 MiB limit')
      data = fs.readFileSync(flags['data-file'])
    } else {
      data = flags.data === undefined ? undefined : Buffer.from(flags.data, 'utf8')
    }
    if (data && data.byteLength > LOCAL_PROXY_BODY_LIMIT) die('request body exceeds the 10 MiB limit')
    const consumer = flags.consumer && /^cli:[a-z0-9._-]{1,40}$/i.test(flags.consumer) ? flags.consumer.toLowerCase() : undefined
    const { status, body } = await apiProxy(base, {
      name, method, url, purpose: flags.purpose, headers: parseHeaders(headers), consumer,
    }, data)
    if (status !== 200) die(`call refused (${body.error})`, 2)
    if (body.truncated) process.stderr.write('vault: response was truncated\n')
    process.stderr.write(`vault: upstream status ${body.status}\n`)
    process.stdout.write(body.body)
    if (body.status >= 400) process.exit(3)
    return
  }

  die('commands: status | list | request | use | serve')
}

// Resolve symlinks: the runner installs this file behind a `vault` symlink, so argv[1] is the link path.
const invokedDirectly = (() => {
  try { return fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url)) } catch { return false }
})()

if (invokedDirectly) main().catch((e) => die(e instanceof Error ? e.message : String(e)))
