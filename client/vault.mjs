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
//   VAULT_URL                  HTTPS origin of the Vault Worker
//   GitHub Actions OIDC requester variables (id-token: write) authenticate this run.
//   A short-lived Runner Session is held only in this process memory; no session file.

import fs from 'node:fs'
import { fileURLToPath } from 'node:url'
import { createServer } from 'node:http'

const env = process.env
const fetchImpl = (...args) => globalThis.fetch(...args)

const DEFAULT_REQUEST_TIMEOUT_MS = 8_000
const MIN_REQUEST_TIMEOUT_MS = 100
const MAX_REQUEST_TIMEOUT_MS = 30_000
const MAX_API_RESPONSE_BYTES = 12 * 1024 * 1024
const LOCAL_PROXY_BODY_LIMIT = 10 * 1024 * 1024
const LOCAL_PROXY_RESPONSE_LIMIT = 1_100 * 1024

function requestTimeoutMs() {
  const configured = Number(env.VAULT_REQUEST_TIMEOUT_MS)
  return Number.isInteger(configured) && configured >= MIN_REQUEST_TIMEOUT_MS && configured <= MAX_REQUEST_TIMEOUT_MS
    ? configured
    : DEFAULT_REQUEST_TIMEOUT_MS
}

/** Bounded HTTP requests with sanitized errors; never include URLs or headers in failures. */
export async function fetchWithTimeout(url, init = {}, label = 'Vault request', timeoutMs = requestTimeoutMs()) {
  try {
    return await fetchImpl(url, { ...init, redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) })
  } catch (error) {
    const timedOut = error && (error.name === 'TimeoutError' || error.name === 'AbortError')
    throw new Error(timedOut ? label + ' timed out' : label + ' failed')
  }
}

function die(message, code = 1) {
  process.stderr.write(`vault: ${message}\n`)
  process.exit(code)
}

function vaultOrigin() {
  const configured = env.VAULT_URL
  if (typeof configured !== 'string' || configured.length > 2048) die('VAULT_URL must be configured', 2)
  let url
  try { url = new URL(configured) } catch { die('VAULT_URL is invalid', 2) }
  if (url.protocol !== 'https:' || !url.hostname || url.username || url.password || url.port
    || url.search || url.hash || (url.pathname !== '/' && url.pathname !== '')) {
    die('VAULT_URL must be an HTTPS origin without credentials, query or fragment', 2)
  }
  return url.origin
}

function oidcRequester() {
  const requestUrl = env.ACTIONS_ID_TOKEN_REQUEST_URL
  const requestToken = env.ACTIONS_ID_TOKEN_REQUEST_TOKEN
  if (typeof requestUrl !== 'string' || requestUrl.length > 4096
    || typeof requestToken !== 'string' || requestToken.length < 20 || requestToken.length > 8192) {
    throw new Error('GitHub Actions OIDC is unavailable; run this command in an authorized workflow with id-token: write')
  }
  let url
  try { url = new URL(requestUrl) } catch { throw new Error('GitHub Actions OIDC configuration is invalid') }
  if (url.origin !== 'https://pipelines.actions.githubusercontent.com'
    || url.username || url.password || url.hash) {
    throw new Error('GitHub Actions OIDC endpoint is not trusted')
  }
  return { url, requestToken }
}

let sessionPromise
export function resetClientSessionForTests() {
  sessionPromise = undefined
}
export async function runnerSession() {
  if (sessionPromise) {
    const current = await sessionPromise
    if (current.expiresAt > Date.now() + 60_000) return current
    sessionPromise = undefined
  }
  sessionPromise = (async () => {
    const origin = vaultOrigin()
    const { url, requestToken } = oidcRequester()
    url.searchParams.set('audience', origin)
    const oidcResponse = await fetchWithTimeout(url, {
      headers: { Authorization: 'Bearer ' + requestToken, Accept: 'application/json' },
    }, 'GitHub OIDC token request')
    if (oidcResponse.status !== 200) throw new Error('GitHub Actions refused the OIDC token request')
    const oidcBody = await readJson(oidcResponse, 'GitHub OIDC token response')
    if (typeof oidcBody.value !== 'string' || oidcBody.value.length < 100 || oidcBody.value.length > 8192) {
      throw new Error('GitHub Actions returned an invalid OIDC token')
    }
    const response = await fetchWithTimeout(origin + '/api/runner/session', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + oidcBody.value, Accept: 'application/json' },
    }, 'Vault session exchange')
    const body = await readJson(response, 'Vault session response')
    if (response.status !== 200 || typeof body.token !== 'string' || body.token.length < 20
      || !Number.isFinite(body.expiresAt) || body.expiresAt <= Date.now() + 30_000) {
      throw new Error(typeof body.error === 'string' ? body.error : 'Vault session exchange was refused')
    }
    return { token: body.token, expiresAt: body.expiresAt }
  })().catch((error) => {
    sessionPromise = undefined
    throw error
  })
  return sessionPromise
}

async function readJson(response, label) {
  const declared = Number(response.headers.get('content-length'))
  if (Number.isFinite(declared) && declared > MAX_API_RESPONSE_BYTES) throw new Error(label + ' is too large')
  if (!response.body) throw new Error(label + ' is empty')
  const reader = response.body.getReader()
  const chunks = []
  let total = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      total += value.byteLength
      if (total > MAX_API_RESPONSE_BYTES) {
        await reader.cancel().catch(() => undefined)
        throw new Error(label + ' is too large')
      }
      chunks.push(Buffer.from(value))
    }
  } finally {
    reader.releaseLock()
  }
  const text = Buffer.concat(chunks, total).toString('utf8')
  try {
    const value = JSON.parse(text)
    return value && typeof value === 'object' && !Array.isArray(value) ? value : {}
  } catch {
    throw new Error(label + ' is invalid')
  }
}

async function authenticatedFetch(url, init, label, timeoutMs = requestTimeoutMs()) {
  const perform = async () => {
    const session = await runnerSession()
    const headers = new Headers(init.headers ?? {})
    headers.set('Authorization', 'Bearer ' + session.token)
    return fetchWithTimeout(url, { ...init, headers }, label, timeoutMs)
  }
  let response = await perform()
  if (response.status === 401) {
    // A long-running local CLI bridge can outlive its in-memory session. Re-exchange
    // a fresh, single-use GitHub OIDC token once; never persist the session to disk.
    await response.body?.cancel().catch(() => undefined)
    sessionPromise = undefined
    response = await perform()
  }
  return response
}

export async function api(_base, method, route, payload) {
  const headers = { Accept: 'application/json' }
  const init = { method, headers }
  if (payload !== undefined) {
    headers['Content-Type'] = 'application/json'
    init.body = JSON.stringify(payload)
  }
  const response = await authenticatedFetch(vaultOrigin() + route, init, 'Vault API request')
  const body = await readJson(response, 'Vault API response')
  return { status: response.status, body }
}

export async function apiProxy(_base, metadata, requestBody) {
  const encoded = Buffer.from(JSON.stringify(metadata)).toString('base64url')
  const headers = {
    Accept: 'application/json',
    'Content-Type': 'application/octet-stream',
    'X-Vault-Proxy-Metadata': encoded,
  }
  const init = { method: 'POST', headers }
  if (requestBody && requestBody.byteLength > 0) init.body = requestBody
  const response = await authenticatedFetch(vaultOrigin() + '/api/runner/use', init, 'Vault credential request', 30_000)
  const body = await readJson(response, 'Vault proxy response')
  return { status: response.status, body }
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

export async function startLocalProxy(vaultOrigin, credentialName, toolId, requestedPort) {
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
    const session = await runnerSession()
    console.log(JSON.stringify({ connected: true, sessionExpiresAt: session.expiresAt, transport: 'https' }, null, 2))
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
    if (status !== 200) die(`registration refused (${body.error})`)
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
