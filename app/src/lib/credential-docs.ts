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
