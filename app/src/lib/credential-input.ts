// Validation for the owner-controlled fields of a credential. These are the fields
// a prompt-injected model must never be able to choose silently: the name that
// becomes the environment variable, and the hosts the proxy may call.

export const CREDENTIAL_NAME = /^[A-Z][A-Z0-9_]{1,63}$/

export function validCredentialName(name: unknown): name is string {
  return typeof name === 'string' && CREDENTIAL_NAME.test(name)
}

// Names that would change how a process starts if injected as an environment
// variable. Refused outright, regardless of delivery mode.
const RESERVED_NAMES = new Set([
  'PATH', 'HOME', 'USER', 'SHELL', 'PWD', 'IFS', 'TERM', 'LANG', 'TZ', 'TMPDIR',
  'LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT', 'DYLD_INSERT_LIBRARIES',
  'PYTHONPATH', 'PYTHONSTARTUP', 'NODE_OPTIONS', 'NODE_PATH', 'RUBYOPT', 'PERL5OPT',
  'GIT_SSH_COMMAND', 'GIT_ASKPASS', 'GIT_CONFIG_GLOBAL', 'GIT_DIR', 'BASH_ENV', 'ENV',
  'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'SSL_CERT_FILE', 'CURL_CA_BUNDLE',
])

export function reservedName(name: string): boolean {
  return RESERVED_NAMES.has(name) || name.startsWith('LD_') || name.startsWith('BASH_FUNC_')
}

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/
const LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/
const INTERNAL_SUFFIX = /\.(local|localhost|internal|lan|home|corp|intranet|test|invalid|example)$/

/** Exact public hostname, lowercase, no scheme/port/path/wildcard. Null when unacceptable. */
export function normalizeHost(raw: unknown): string | null {
  if (typeof raw !== 'string') return null
  const host = raw.trim().toLowerCase().replace(/\.$/, '')
  if (host.length === 0 || host.length > 253) return null
  if (host.includes('*') || host.includes('/') || host.includes(':') || host.includes('@')) return null
  if (IPV4.test(host) || INTERNAL_SUFFIX.test(host)) return null
  const labels = host.split('.')
  if (labels.length < 2) return null
  if (!labels.every((label) => LABEL.test(label))) return null
  return host
}

export type HostsResult = { ok: true; hosts: string[] } | { ok: false; error: string }

export function normalizeAllowedHosts(raw: unknown, max = 10): HostsResult {
  if (!Array.isArray(raw)) return { ok: false, error: 'allowed hosts must be a list' }
  if (raw.length > max) return { ok: false, error: `at most ${max} hosts` }
  const hosts: string[] = []
  for (const entry of raw) {
    const host = normalizeHost(entry)
    if (!host) return { ok: false, error: 'each host must be an exact public hostname' }
    if (!hosts.includes(host)) hosts.push(host)
  }
  return { ok: true, hosts }
}

/** Parse the JSON column. A corrupt value yields an empty list, i.e. "calls nothing". */
export function readAllowedHosts(json: string): string[] {
  try {
    const parsed = normalizeAllowedHosts(JSON.parse(json), 50)
    return parsed.ok ? parsed.hosts : []
  } catch {
    return []
  }
}

// ── How the proxy presents the value upstream ───────────────────────────

export const AUTH_SCHEMES = ['Bearer', 'Token', 'Raw'] as const
export type AuthScheme = (typeof AUTH_SCHEMES)[number]

const HEADER_NAME = /^[A-Za-z][A-Za-z0-9-]{0,63}$/
// Headers that control framing, routing or identity of the proxied request. The value
// may only ever go into an authentication-style header, never one of these.
const FORBIDDEN_AUTH_HEADERS = new Set([
  'host', 'content-length', 'content-type', 'content-encoding', 'cookie', 'set-cookie', 'connection',
  'transfer-encoding', 'upgrade', 'te', 'trailer', 'proxy-authorization', 'proxy-authenticate',
  'expect', 'forwarded', 'via', 'origin', 'referer', 'user-agent', 'accept', 'range',
])

export type AuthStyleResult = { ok: true; header: string; scheme: AuthScheme } | { ok: false; error: string }

export function normalizeAuthStyle(header: unknown, scheme: unknown): AuthStyleResult {
  if (typeof header !== 'string' || !HEADER_NAME.test(header.trim())) return { ok: false, error: 'invalid header name' }
  const name = header.trim()
  const lower = name.toLowerCase()
  if (FORBIDDEN_AUTH_HEADERS.has(lower) || lower.startsWith('x-forwarded-') || lower.startsWith('cf-') || lower.startsWith('proxy-') || lower.startsWith('sec-')) {
    return { ok: false, error: 'header not allowed for credentials' }
  }
  if (typeof scheme !== 'string' || !(AUTH_SCHEMES as readonly string[]).includes(scheme)) return { ok: false, error: 'invalid scheme' }
  return { ok: true, header: name, scheme: scheme as AuthScheme }
}

export function formatAuthValue(scheme: AuthScheme, value: string): string {
  return scheme === 'Raw' ? value : `${scheme} ${value}`
}
