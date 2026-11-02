'use server'
// Directive stays on line 1: spiceflow strips it in vitest only when it is the first statement.

// Owner-only server actions for the vault UI. getSession() only resolves for the
// configured owner (see db.ts), so a session here already means "the owner".
// Every action validates its input with zod; none returns a secret value.

import { z } from 'zod'
import { getActionRequest } from 'spiceflow'
import { env } from 'cloudflare:workers'
import { getDb, getRequestOrigin, getSession } from './db.ts'
import { loadVaultKeys, type VaultEnv } from './lib/vault-config.ts'
import {
  createCredential, deleteCredential, getCredentialForOwner, registerExternallyManaged, setEnabled, setVisibility, storeCredentialValue, validateStoreInput,
} from './lib/credential-service.ts'
import { consumeEnrollmentLink, peekEnrollmentLink, releaseEnrollmentLink } from './lib/enrollment.ts'
import { revokeRunnerSessions } from './lib/runner-session.ts'
import { DEFAULT_EVENTS, resolveRepositoryId, saveRunnerPolicy } from './lib/runner-policy.ts'
import { normalizeCredentialName } from './lib/credential-input.ts'
import { defaultPurposeForService } from './lib/presets.ts'
import { validateProviderToken, type CredentialValidationReport } from './lib/credential-validation.ts'
import { publicCredentialActionError } from './lib/public-action-error.ts'

type CredentialActionResult<T> = { ok: true; value: T } | { ok: false; error: string }

async function captureCredentialAction<T>(action: () => Promise<T>): Promise<CredentialActionResult<T>> {
  try {
    return { ok: true, value: await action() }
  } catch (error) {
    console.error('[vault-action] credential action failed:', error instanceof Error ? error.name : 'unknown error')
    return { ok: false, error: publicCredentialActionError(error) }
  }
}

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
  cloudflareAccountId: z.string().trim().regex(/^[a-f0-9]{32}$/i, 'شناسه Account Cloudflare باید دقیقاً ۳۲ کاراکتر هگزادسیمال باشد.').or(z.literal('')).optional(),
})
export type StoreForm = z.input<typeof storeSchema>

const createCredentialSchema = z.object({
  name: z.string().trim().min(1).max(120),
  service: z.string().trim().min(1).max(80),
  form: storeSchema,
})

function toStoreInput(form: z.output<typeof storeSchema>, now: number, validation?: CredentialValidationReport) {
  return {
    value: form.value,
    lifetime: form.lifetime,
    expiresAt: form.expiresInHours === null ? null : now + Math.round(form.expiresInHours * 3600_000),
    visible: form.visible,
    delivery: form.delivery,
    allowedHosts: form.allowedHosts.split(/[\s,]+/).filter(Boolean),
    authHeader: form.authHeader || 'Authorization',
    authScheme: form.authScheme,
    validation: validation?.status === 'valid' ? 'valid' as const : 'not_tested' as const,
    validationDetails: validation ? JSON.stringify(validation).slice(0, 32_000) : null,
    now,
  }
}

async function key() {
  return (await loadVaultKeys(getDb(), env as unknown as VaultEnv)).encryptionKey
}

/** Validate a provider token on demand; the submitted value is never returned. */
export async function validateCredentialTokenAction(service: string, value: string, cloudflareAccountId?: string) {
  return captureCredentialAction(async () => {
    await requireOwner()
    const parsed = z.object({
      service: z.string().trim().min(1).max(80),
      value: z.string().min(1).max(10_000),
      cloudflareAccountId: z.string().trim().regex(/^[a-f0-9]{32}$/i, 'شناسه Account Cloudflare باید دقیقاً ۳۲ کاراکتر هگزادسیمال باشد.').optional(),
    }).parse({ service, value, cloudflareAccountId: cloudflareAccountId || undefined })
    return validateProviderToken(parsed.service, parsed.value, fetch, Date.now(), parsed.cloudflareAccountId)
  })
}

function ensureSaveable(validation: CredentialValidationReport) {
  if (validation.status === 'invalid' || validation.status === 'unavailable') {
    throw new Error(validation.message)
  }
}

/** Create a credential directly from the authenticated owner dashboard. */
export async function createCredentialAction(input: { name: string; service: string; form: StoreForm }) {
  return captureCredentialAction(async () => {
    await requireOwner()
    const parsed = createCredentialSchema.parse(input)
    const name = normalizeCredentialName(parsed.name)
    const validation = await validateProviderToken(parsed.service, parsed.form.value, fetch, Date.now(), parsed.form.cloudflareAccountId || undefined)
    ensureSaveable(validation)
    const now = Date.now()
    const result = await createCredential(getDb(), await key(), {
      name, service: parsed.service, purpose: defaultPurposeForService(parsed.service),
      ...toStoreInput(parsed.form, now, validation),
    })
    if (!result.ok) fail(result)
    return { id: result.value.id, name: result.value.name }
  })
}

/** Registration page submit: uses the one-time link, then stores the value. */
export async function submitRegistrationAction(token: string, form: StoreForm) {
  return captureCredentialAction(async () => {
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
    const tokenReport = await validateProviderToken(credential.service, parsed.value, fetch, Date.now(), parsed.cloudflareAccountId || undefined)
    ensureSaveable(tokenReport)
    const storeInput = { credentialId: info.credentialId, ...toStoreInput(parsed, now, tokenReport) }
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
      return { name: result.value.name }
    } catch (error) {
      await releaseEnrollmentLink(db, link.id, now).catch(() => false)
      throw error
    }
  })
}

/** Replace the value / rules of an existing credential (owner is signed in; no link needed). */
export async function replaceCredentialAction(id: string, form: StoreForm) {
  return captureCredentialAction(async () => {
    await requireOwner()
    const parsed = storeSchema.parse(form)
    const db = getDb()
    const credential = await getCredentialForOwner(db, idSchema.parse(id))
    if (!credential || credential.externallyManaged) throw new Error('Credential not found or is externally managed')
    const tokenReport = await validateProviderToken(credential.service, parsed.value, fetch, Date.now(), parsed.cloudflareAccountId || undefined)
    ensureSaveable(tokenReport)
    const result = await storeCredentialValue(db, await key(), {
      credentialId: credential.id, ...toStoreInput(parsed, Date.now(), tokenReport),
    })
    if (!result.ok) fail(result)
    return { name: result.value.name }
  })
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

export async function addExternalAction(input: { name: string; service: string }) {
  await requireOwner()
  const parsed = z.object({ name: z.string().max(120), service: z.string().trim().min(1).max(80) }).parse(input)
  const r = await registerExternallyManaged(getDb(), {
    ...parsed, name: normalizeCredentialName(parsed.name), purpose: defaultPurposeForService(parsed.service), now: Date.now(),
  })
  if (!r.ok) fail(r)
  return { ok: true as const }
}

export async function revokeRunnerSessionsAction() {
  await requireOwner()
  await revokeRunnerSessions(getDb(), Date.now())
  return { ok: true as const }
}

const runnerSchema = z.object({
  repository: z.string().trim().max(140),
  branch: z.string().trim().max(100),
  workflowFile: z.string().trim().max(100),
  /** Only needed for a private repository; public ones are looked up. */
  repositoryId: z.string().trim().max(20).optional(),
})
export type RunnerForm = z.input<typeof runnerSchema>

/** Settings: which repository/workflow the runner API trusts. */
export async function saveRunnerPolicyAction(form: RunnerForm) {
  await requireOwner()
  const parsed = runnerSchema.parse(form)
  const repositoryId = parsed.repositoryId || (await resolveRepositoryId(parsed.repository))
  if (!repositoryId) {
    throw new Error('Could not look up that repository. Check the name, or enter its numeric id (needed for private repositories).')
  }
  const audience = getRequestOrigin(getActionRequest())
  await saveRunnerPolicy(getDb(), {
    repository: parsed.repository, repositoryId, branch: parsed.branch, workflowFile: parsed.workflowFile, events: DEFAULT_EVENTS,
  }, audience)
}
