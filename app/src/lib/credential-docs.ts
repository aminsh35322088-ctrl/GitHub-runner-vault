// Setup documentation that a model attaches to a registration request.
//
// The text is written by a model that may have been prompt-injected, then shown to
// the owner on a trusted page right above the secret input. So it is treated as
// hostile input:
//  - strict schema with hard size and count limits (unknown keys are rejected),
//  - plain text only: control characters are stripped and the UI renders values as
//    text nodes, never as HTML or Markdown,
//  - links must be https with a real DNS hostname (no IPs, no credentials in the URL,
//    no odd ports) and the UI always shows the actual hostname next to the title,
//  - the document says whether the model verified it against official documentation.

import { z } from 'zod'
import { reservedName } from './credential-input.ts'
const CONTROL_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F​-‏‪-‮⁦-⁩]/g

/** Strip control and bidi-override characters so text cannot visually spoof the UI. */
export function cleanText(value: string): string {
  return value.replace(CONTROL_CHARS, '').trim()
}

function text(max: number) {
  return z.string().transform(cleanText).pipe(z.string().min(1).max(max))
}

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/

/** Returns a normalized https URL string, or null when the link is not acceptable. */
export function safeLink(raw: string): string | null {
  if (raw.length > 300) return null
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    return null
  }
  if (url.protocol !== 'https:') return null
  if (url.username || url.password) return null
  if (url.port && url.port !== '443') return null
  const host = url.hostname.toLowerCase()
  if (!host.includes('.') || host.startsWith('[') || IPV4.test(host)) return null
  if (/\.(local|localhost|internal|lan|home|corp)$/.test(host)) return null
  url.hash = ''
  return url.toString()
}

const link = z.object({
  title: text(120),
  url: z.string().transform((value, ctx) => {
    const safe = safeLink(value)
    if (!safe) {
      ctx.addIssue({ code: 'custom', message: 'link must be a plain https URL with a public hostname' })
      return z.NEVER
    }
    return safe
  }),
}).strict()

const permission = z.object({
  name: text(120),
  level: text(60),
  why: text(400),
}).strict()

const serviceAdapterSchema = z.object({
  api_base_url: z.string().trim().max(300).transform((value, ctx) => {
    let url: URL
    try { url = new URL(value) } catch {
      ctx.addIssue({ code: 'custom', message: 'service adapter API base URL must be HTTPS' })
      return z.NEVER
    }
    if (url.protocol !== 'https:' || url.username || url.password || (url.port && url.port !== '443') || url.search || url.hash) {
      ctx.addIssue({ code: 'custom', message: 'service adapter API base URL must be a plain HTTPS URL' })
      return z.NEVER
    }
    if (!normalizeServiceHost(url.hostname)) {
      ctx.addIssue({ code: 'custom', message: 'service adapter API host must be a public DNS hostname' })
      return z.NEVER
    }
    return url.toString().replace(/\/$/, '')
  }),
  auth_header: z.string().trim().regex(/^[A-Za-z][A-Za-z0-9-]{0,63}$/),
  auth_scheme: z.enum(['Bearer', 'Token', 'Raw']),
  default_headers: z.partialRecord(z.enum(['anthropic-version', 'x-api-version', 'x-github-api-version']), z.string().trim().min(1).max(100)).optional(),
  validation: z.object({
    method: z.enum(['GET', 'HEAD']),
    path: z.string().min(1).max(200).regex(/^\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$/),
    identity_pointer: z.string().max(160).optional(),
    permissions_pointer: z.string().max(160).optional(),
    success_pointer: z.string().max(160).optional(),
    success_value: z.union([z.string().max(120), z.number(), z.boolean()]).optional(),
  }).strict().superRefine((value, ctx) => {
    if (Boolean(value.success_pointer) !== (value.success_value !== undefined)) {
      ctx.addIssue({ code: 'custom', path: ['success_pointer'], message: 'success_pointer and success_value must be supplied together' })
    }
    if (value.method === 'HEAD' && value.success_pointer) {
      ctx.addIssue({ code: 'custom', path: ['success_pointer'], message: 'a HEAD check cannot inspect a response body' })
    }
    if (value.path.split('/').includes('..')) {
      ctx.addIssue({ code: 'custom', path: ['path'], message: 'validation path cannot traverse parent segments' })
    }
  }).optional(),
  cli_tools: z.array(z.object({
    id: z.string().trim().regex(/^[a-z0-9][a-z0-9._-]{0,39}$/),
    label: text(80),
    binary: z.string().trim().regex(/^[a-zA-Z0-9._-]{1,60}$/),
    integration: z.enum(['base-url-env', 'host-flag']),
    variable: z.string().regex(/^[A-Z][A-Z0-9_]{0,63}$/).optional(),
    token_variable: z.string().regex(/^[A-Z][A-Z0-9_]{0,63}$/).optional(),
    flag: z.string().regex(/^--[a-z][a-z-]{0,30}$/).optional(),
    setup_hint: text(300),
  }).strict()).max(8).default([]),
}).strict()

function normalizeServiceHost(host: string): string | null {
  const value = host.toLowerCase().replace(/\.$/, '')
  if (value.length > 253 || value.includes(':') || value.includes('*') || value.startsWith('[')) return null
  const labels = value.split('.')
  if (labels.length < 2 || !labels.every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) return null
  if (/\.(local|localhost|internal|lan|home|corp|test|invalid|example)$/.test(value)) return null
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) return null
  return value
}

function documentationOwnsApiHost(documentationHost: string, apiHost: string): boolean {
  const docs = documentationHost.toLowerCase().replace(/\.$/, '')
  const api = apiHost.toLowerCase().replace(/\.$/, '')
  // Never infer a registrable domain by taking the last two labels: that
  // incorrectly treats unrelated tenants on public suffixes such as co.uk as siblings.
  return docs === api || api.endsWith(`.${docs}`)
}

export const credentialDocSchema = z.object({
  overview: text(2000),
  task: text(500),
  token_type: text(120),
  creation_link: link.optional(),
  creation_steps: z.array(text(500)).max(20),
  required_permissions: z.array(permission).max(30),
  unnecessary_permissions: z.array(text(200)).max(30),
  security_notes: z.array(text(400)).max(15),
  expiration_guidance: z.array(text(400)).max(10),
  official_documentation_links: z.array(link).max(10),
  service_adapter: serviceAdapterSchema.optional(),
  // The model must say honestly whether it checked official documentation.
  verification: z.enum(['verified', 'unverified']),
  unverified_note: text(400).optional(),
}).strict().superRefine((doc, ctx) => {
  if (doc.verification === 'unverified' && !doc.unverified_note) {
    ctx.addIssue({ code: 'custom', path: ['unverified_note'], message: 'explain what could not be verified' })
  }
  if (doc.verification === 'verified' && doc.official_documentation_links.length === 0) {
    ctx.addIssue({ code: 'custom', path: ['official_documentation_links'], message: 'verified documentation needs at least one official link' })
  }
  if (doc.service_adapter) {
    if (doc.verification !== 'verified' || doc.official_documentation_links.length === 0) {
      ctx.addIssue({ code: 'custom', path: ['service_adapter'], message: 'a service adapter requires verified official documentation' })
    } else {
      const apiHost = new URL(doc.service_adapter.api_base_url).hostname.toLowerCase()
      const docsHosts = doc.official_documentation_links.map((item) => new URL(item.url).hostname.toLowerCase())
      if (!docsHosts.some((host) => documentationOwnsApiHost(host, apiHost))) {
        ctx.addIssue({ code: 'custom', path: ['service_adapter', 'api_base_url'], message: 'API host must exactly match an official documentation host or be its subdomain' })
      }
    }
    if (doc.service_adapter.cli_tools.some((tool) => tool.integration === 'base-url-env' && (!tool.variable || !tool.variable.endsWith('_API_BASE_URL')))) {
      ctx.addIssue({ code: 'custom', path: ['service_adapter', 'cli_tools'], message: 'base URL integration must use a documented *_API_BASE_URL variable' })
    }
    if (doc.service_adapter.cli_tools.some((tool) => tool.token_variable && reservedName(tool.token_variable))) {
      ctx.addIssue({ code: 'custom', path: ['service_adapter', 'cli_tools'], message: 'token environment variable is reserved by the local process' })
    }
    if (doc.service_adapter.cli_tools.some((tool) => tool.variable && tool.variable === tool.token_variable)) {
      ctx.addIssue({ code: 'custom', path: ['service_adapter', 'cli_tools'], message: 'API base URL and token environment variables must be different' })
    }
    if (doc.service_adapter.cli_tools.some((tool) => tool.integration === 'host-flag' && !tool.flag)) {
      ctx.addIssue({ code: 'custom', path: ['service_adapter', 'cli_tools'], message: 'host-flag integration needs a documented flag' })
    }
  }
})

export type CredentialDoc = z.infer<typeof credentialDocSchema>

export const MAX_DOC_JSON_BYTES = 32 * 1024

export type ParsedDoc = { ok: true; doc: CredentialDoc; json: string } | { ok: false; error: string }

export function parseCredentialDoc(input: unknown): ParsedDoc {
  const result = credentialDocSchema.safeParse(input)
  if (!result.success) {
    const first = result.error.issues[0]
    const where = first?.path.length ? first.path.join('.') : 'document'
    return { ok: false, error: `${where}: ${first?.message ?? 'invalid'}` }
  }
  const json = JSON.stringify(result.data)
  if (new TextEncoder().encode(json).byteLength > MAX_DOC_JSON_BYTES) {
    return { ok: false, error: 'document is too large' }
  }
  return { ok: true, doc: result.data, json }
}

/** Parse a stored document, falling back to null (never throws) for rows with `{}`. */
export function readStoredDoc(json: string): CredentialDoc | null {
  try {
    const parsed = credentialDocSchema.safeParse(JSON.parse(json))
    return parsed.success ? parsed.data : null
  } catch {
    return null
  }
}

/** Hostname to display next to a link title so the real destination is always visible. */
export function linkHost(url: string): string {
  try {
    return new URL(url).hostname
  } catch {
    return ''
  }
}
