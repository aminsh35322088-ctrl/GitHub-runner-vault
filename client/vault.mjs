#!/usr/bin/env node
// Runner client for the Runner Credential Vault. Zero dependencies (Node 18+).
//
//   vault list                                  credentials this runner may use (metadata only)
//   vault request --name N --service S --purpose P --doc doc.json
//                                               ask the owner to register a credential; prints a
//                                               one-time link for the owner. Prints no secret.
//   vault use NAME METHOD URL [--purpose P] [--header 'K: V']... [--data BODY | --data-file F]
//                                               make an HTTPS call with the stored credential.
//                                               The Worker adds the token; it is never returned.
//
// Environment:
//   VAULT_URL                  vault origin, e.g. https://runner-vault.example.workers.dev
//   ACTIONS_ID_TOKEN_REQUEST_URL / ACTIONS_ID_TOKEN_REQUEST_TOKEN
//                              set by GitHub Actions when the job has `permissions: id-token: write`
//   VAULT_SESSION_FILE         optional cache path for the 30 minute session (default under $XDG_RUNTIME_DIR or /tmp)

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

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
  return env.VAULT_SESSION_FILE || path.join(env.XDG_RUNTIME_DIR || os.tmpdir(), `runner-vault-session-${os.userInfo().uid}.json`)
}

function readCachedSession(base) {
  try {
    const cached = JSON.parse(fs.readFileSync(sessionFile(), 'utf8'))
    if (cached.origin === base && typeof cached.token === 'string' && cached.expiresAt - Date.now() > 60_000) return cached.token
  } catch { /* no cache */ }
  return null
}

function writeCachedSession(base, token, expiresAt) {
  try {
    fs.writeFileSync(sessionFile(), JSON.stringify({ origin: base, token, expiresAt }), { mode: 0o600 })
  } catch { /* cache is optional */ }
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

async function session(base) {
  const cached = readCachedSession(base)
  if (cached) return cached
  const oidc = await getOidcToken(base)
  const res = await fetch(`${base}/api/runner/session`, { method: 'POST', headers: { Authorization: `Bearer ${oidc}` } })
  const body = await res.json().catch(() => ({}))
  if (!res.ok) die(`vault refused the session (${body.error ?? res.status})`)
  writeCachedSession(base, body.token, body.expiresAt)
  return body.token
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

  if (command === 'request') {
    for (const k of ['name', 'service', 'purpose', 'doc']) if (!flags[k]) die(`--${k} is required`)
    let doc
    try { doc = JSON.parse(fs.readFileSync(flags.doc, 'utf8')) } catch { die('--doc must be a JSON file') }
    const { status, body } = await api(base, 'POST', '/api/runner/registrations', { name: flags.name, service: flags.service, purpose: flags.purpose, doc })
    if (status !== 200) die(`registration refused (${body.error}${body.detail ? `: ${body.detail}` : ''})`)
    console.log(`Give this one-time link to the owner (expires ${new Date(body.expiresAt).toISOString()}):\n${body.link}`)
    return
  }

  if (command === 'use') {
    const [name, method, url] = positional
    if (!name || !method || !url) die('usage: vault use NAME METHOD URL [--purpose P] [--header "K: V"] [--data BODY | --data-file F]')
    const data = flags['data-file'] ? fs.readFileSync(flags['data-file'], 'utf8') : flags.data
    const { status, body } = await api(base, 'POST', '/api/runner/use', {
      name, method, url, purpose: flags.purpose, headers: parseHeaders(headers), body: data,
    })
    if (status !== 200) die(`call refused (${body.error})`, 2)
    if (body.truncated) process.stderr.write('vault: response was truncated\n')
    process.stderr.write(`vault: upstream status ${body.status}\n`)
    process.stdout.write(body.body)
    if (body.status >= 400) process.exit(3)
    return
  }

  die('commands: list | request | use')
}

if (import.meta.url === `file://${process.argv[1]}`) main().catch((e) => die(e instanceof Error ? e.message : String(e)))
