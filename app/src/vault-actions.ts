'use server'
// Directive stays on line 1: spiceflow strips it in vitest only when it is the first statement.

// Owner-only server actions for the vault UI. getSession() only resolves for the
// configured owner (see db.ts), so a session here already means "the owner".
// Every action validates its input with zod; none returns a secret value.

import { z } from 'zod'
import { getActionRequest } from 'spiceflow'
import { env } from 'cloudflare:workers'
import { getDb, getSession } from './db.ts'
import { importEncryptionKey } from './lib/credential-crypto.ts'
import {
  deleteCredential, getCredentialForOwner, registerExternallyManaged, setEnabled, setVisibility, storeCredentialValue, validateStoreInput,
} from './lib/credential-service.ts'
import { consumeEnrollmentLink, peekEnrollmentLink, releaseEnrollmentLink } from './lib/enrollment.ts'
import { revokeRunnerSessions } from './lib/runner-session.ts'

async function requireOwner() {
  const session = await getSession(getActionRequest())
  if (!session) throw new Error('Unauthorized')
  return session
}

function fail(result: { ok: false; error: string; detail?: string }): never {
  throw new Error(result.detail ? `${result.error}: ${result.detail}` : result.error)
}

const idSchema = z.string().uuid()

const storeSchema = z.object({
  value: z.string().min(1).max(10_000),
  lifetime: z.enum(['permanent', 'temporary']),
  /** hours from now; required for temporary, optional for permanent */
  expiresInHours: z.number().positive().max(24 * 365 * 3).nullable(),
  visible: z.boolean(),
  delivery: z.enum(['proxy']),
  allowedHosts: z.string().max(2000),
  authHeader: z.string().max(60),
  authScheme: z.enum(['Bearer', 'Token', 'Raw']),
})
export type StoreForm = z.input<typeof storeSchema>

function toStoreInput(form: z.output<typeof storeSchema>, now: number) {
  return {
    value: form.value,
    lifetime: form.lifetime,
    expiresAt: form.expiresInHours === null ? null : now + Math.round(form.expiresInHours * 3600_000),
    visible: form.visible,
    delivery: form.delivery,
    allowedHosts: form.allowedHosts.split(/[\s,]+/).filter(Boolean),
    authHeader: form.authHeader || 'Authorization',
    authScheme: form.authScheme,
    now,
  }
}

async function key() {
  return importEncryptionKey((env as unknown as Record<string, unknown>).ENCRYPTION_KEY)
}

/** Registration page submit: uses the one-time link, then stores the value. */
export async function submitRegistrationAction(token: string, form: StoreForm) {
  await requireOwner()
  const parsed = storeSchema.parse(form)
  const db = getDb()
  const now = Date.now()
  // Validate the inputs before burning the link, so a typo does not waste it.
  const parsedToken = z.string().max(100).parse(token)
  const info = await peekEnrollmentLink(db, parsedToken, now)
  if (!info || info.kind !== 'register') throw new Error('This link is invalid, expired or already used')
  const credential = await getCredentialForOwner(db, info.credentialId)
  if (!credential || credential.status !== 'pending' || credential.externallyManaged) {
    throw new Error('This registration is no longer available')
  }
  const storeInput = { credentialId: info.credentialId, ...toStoreInput(parsed, now) }
  const validation = validateStoreInput(storeInput)
  if (!validation.ok) fail(validation)
  const encryptionKey = await key()

  const link = await consumeEnrollmentLink(db, parsedToken, now)
  if (!link || link.id !== info.id || link.credentialId !== info.credentialId || link.kind !== 'register') {
    throw new Error('This link is invalid, expired or already used')
  }
  try {
    const result = await storeCredentialValue(db, encryptionKey, storeInput)
    if (!result.ok) {
      await releaseEnrollmentLink(db, link.id, now)
      fail(result)
    }
    return { ok: true as const, name: result.value.name }
  } catch (error) {
    await releaseEnrollmentLink(db, link.id, now).catch(() => false)
    throw error
  }
}

/** Replace the value / rules of an existing credential (owner is signed in; no link needed). */
export async function replaceCredentialAction(id: string, form: StoreForm) {
  await requireOwner()
  const parsed = storeSchema.parse(form)
  const result = await storeCredentialValue(getDb(), await key(), { credentialId: idSchema.parse(id), ...toStoreInput(parsed, Date.now()) })
  if (!result.ok) fail(result)
  return { ok: true as const, name: result.value.name }
}

export async function setVisibleAction(id: string, visible: boolean) {
  await requireOwner()
  const r = await setVisibility(getDb(), idSchema.parse(id), z.boolean().parse(visible), Date.now())
  if (!r.ok) fail(r)
  return { ok: true as const }
}

export async function setEnabledAction(id: string, enabled: boolean) {
  await requireOwner()
  const r = await setEnabled(getDb(), idSchema.parse(id), z.boolean().parse(enabled), Date.now())
  if (!r.ok) fail(r)
  return { ok: true as const }
}

export async function deleteCredentialAction(id: string) {
  await requireOwner()
  const r = await deleteCredential(getDb(), idSchema.parse(id), Date.now())
  if (!r.ok) fail(r)
  return { ok: true as const }
}

export async function addExternalAction(input: { name: string; service: string; purpose: string }) {
  await requireOwner()
  const parsed = z.object({ name: z.string().max(80), service: z.string().max(80), purpose: z.string().max(500) }).parse(input)
  const r = await registerExternallyManaged(getDb(), { ...parsed, now: Date.now() })
  if (!r.ok) fail(r)
  return { ok: true as const }
}

export async function revokeRunnerSessionsAction() {
  await requireOwner()
  await revokeRunnerSessions(getDb(), Date.now())
  return { ok: true as const }
}
