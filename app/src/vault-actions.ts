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
  createCredential, deleteCredential, dismissPendingRegistrationRequest, getCredentialForOwner, MAX_TEMPORARY_MS, readCredentialValue, registerExternallyManaged, renewRegistrationLink, setEnabled, setVisibility, storeCredentialValue, validateStoreInput,
} from './lib/credential-service.ts'
import { consumeEnrollmentLink, peekEnrollmentLink, releaseEnrollmentLink } from './lib/enrollment.ts'
import { revokeRunnerSessions } from './lib/runner-session.ts'
import { DEFAULT_EVENTS, resolveRepositoryId, saveRunnerPolicy } from './lib/runner-policy.ts'
import { normalizeCredentialName } from './lib/credential-input.ts'
import { defaultPurposeForService, presetForService } from './lib/presets.ts'
import { adapterHost, effectiveServiceAdapter, serviceAdapterFor, serviceAdapterFromDocument } from './lib/service-adapter.ts'
import { validateProviderToken, type CredentialValidationReport } from './lib/credential-validation.ts'
import { publicCredentialActionError } from './lib/public-action-error.ts'
import { listUnreadRegistrationNotificationIds, loadVaultPreferences, markAllNotificationsRead, markNotificationIdsRead, markNotificationRead, markRegistrationNotificationsRead, saveVaultPreferences, validateStoredCredentialNow, type VaultPreferences } from './lib/vault-observability.ts'

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
  connectionLabel: z.string().max(120).default(''),
  providerAccountId: z.string().max(160).default(''),
  authFields: z.record(z.string().regex(/^[a-z][a-z0-9_]{0,31}$/), z.string().max(4096)).refine((fields) => Object.keys(fields).length <= 12).default({}),
  validationRequested: z.boolean().default(false),
}).superRefine((form, ctx) => {
  // The service layer caps temporary credentials at MAX_TEMPORARY_MS; enforce
  // the same bound here so the form fails fast instead of after submission.
  if (form.lifetime !== 'temporary') return
  if (form.expiresInHours === null) {
    ctx.addIssue({ code: 'custom', path: ['expiresInHours'], message: 'Temporary credentials need an expiry.' })
  } else if (form.expiresInHours * 3600_000 > MAX_TEMPORARY_MS) {
    ctx.addIssue({ code: 'custom', path: ['expiresInHours'], message: `Temporary credentials can live at most ${MAX_TEMPORARY_MS / 3600_000} hours.` })
  }
})
export type StoreForm = z.input<typeof storeSchema>

const createCredentialSchema = z.object({
  name: z.string().trim().min(1).max(120),
  service: z.string().trim().min(1).max(80),
  form: storeSchema,
})

type CredentialPolicy = {
  allowedHosts: string[]
  authHeader: string
  authScheme: 'Bearer' | 'Token' | 'Raw'
}

function credentialPolicy(service: string, document?: unknown): CredentialPolicy {
  const preset = presetForService(service)
  const documentAdapter = serviceAdapterFromDocument(document)
  if (preset && documentAdapter) {
    const documentHost = adapterHost(documentAdapter)
    if (!documentHost || !preset.hosts.includes(documentHost)) {
      throw new Error('Service Adapter این سند با Host رسمی سرویس تطابق ندارد؛ Credential ذخیره نشد.')
    }
  }
  const adapter = effectiveServiceAdapter(service, document)
  const host = adapter ? adapterHost(adapter) : preset?.hosts[0] ?? null
  if (!adapter && !preset) {
    throw new Error('این سرویس Adapter امن و مستند ندارد؛ از Runner یک لینک ثبت جدید با Service Adapter بساز.')
  }
  if (!host) throw new Error('آدرس API سرویس قابل‌تأیید نیست؛ Credential ذخیره نشد.')
  return {
    allowedHosts: [host],
    authHeader: adapter?.authHeader ?? preset?.authHeader ?? 'Authorization',
    authScheme: adapter?.authScheme ?? preset?.authScheme ?? 'Bearer',
  }
}

function toStoreInput(form: z.output<typeof storeSchema>, now: number, policy: CredentialPolicy, validation?: CredentialValidationReport, validationIntervalHours = 6, adapter = null as ReturnType<typeof serviceAdapterFor>) {
  return {
    value: form.value,
    lifetime: form.lifetime,
    expiresAt: form.expiresInHours === null ? null : now + Math.round(form.expiresInHours * 3600_000),
    visible: form.visible,
    delivery: 'proxy' as const,
    allowedHosts: policy.allowedHosts,
    authHeader: policy.authHeader,
    authScheme: policy.authScheme,
    connectionLabel: form.connectionLabel,
    providerAccountId: form.providerAccountId,
    authFields: form.authFields,
    authFieldIds: adapter?.credentialFields?.map((field) => field.id) ?? [],
    requiredAuthFields: adapter?.credentialFields?.filter((field) => field.required).map((field) => field.id) ?? [],
    validation: validation?.status === 'valid' ? 'valid' as const
      : (validation?.status === 'invalid' || validation?.status === 'expired') ? 'invalid' as const
        : validation?.status === 'insufficient_permissions' ? 'insufficient_permissions' as const : 'not_tested' as const,
    validationStatus: validation?.status ?? 'not_tested',
    validationDetails: validation ? JSON.stringify(validation).slice(0, 32_000) : null,
    validationIntervalHours,
    now,
  }
}

async function optionalSaveValidation(
  service: string,
  form: z.output<typeof storeSchema>,
  policy: CredentialPolicy,
  adapter: ReturnType<typeof serviceAdapterFor>,
): Promise<CredentialValidationReport | undefined> {
  if (!form.validationRequested) return undefined
  try {
    return await validateProviderToken(
      service, form.value, fetch, Date.now(), undefined, adapter,
      policy.allowedHosts, form.authFields,
    )
  } catch {
    return {
      provider: service, status: 'unavailable', permissions: [], permissionsComplete: false,
      permissionSource: 'not-supported', checkedAt: Date.now(),
      message: 'Validation could not be completed. The credential can still be saved and checked again later.',
    }
  }
}

async function key() {
  return (await loadVaultKeys(getDb(), env as unknown as VaultEnv)).encryptionKey
}

async function mergeStoredAuthFieldsForValidation(
  db: ReturnType<typeof getDb>,
  credentialName: string,
  incoming: Record<string, string>,
  adapter: ReturnType<typeof serviceAdapterFor>,
): Promise<Record<string, string>> {
  const allowed = new Set(adapter?.credentialFields?.map((field) => field.id) ?? [])
  const stored = await readCredentialValue(db, await key(), credentialName, Date.now(), { validation: true })
  const merged = {
    ...(stored.ok ? stored.authFields : {}),
    ...incoming,
  }
  return Object.fromEntries(Object.entries(merged).filter(([field]) => allowed.has(field)))
}

/** Validate a provider token on demand; the submitted value is never returned. */
export async function validateCredentialTokenAction(service: string, value: string, credentialId?: string, authFields: Record<string, string> = {}) {
  return captureCredentialAction(async () => {
    await requireOwner()
    const parsed = z.object({
      service: z.string().trim().min(1).max(80),
      value: z.string().min(1).max(10_000),
      credentialId: idSchema.optional(),
      authFields: z.record(z.string().regex(/^[a-z][a-z0-9_]{0,31}$/), z.string().max(4096)).refine((fields) => Object.keys(fields).length <= 12),
    }).parse({ service, value, credentialId, authFields })
    const existing = parsed.credentialId ? await getCredentialForOwner(getDb(), parsed.credentialId) : null
    if (parsed.credentialId && !existing) throw new Error('Credential not found')
    const document = existing?.doc
    const adapter = effectiveServiceAdapter(parsed.service, document)
    const policy = credentialPolicy(parsed.service, document)
    const declaredFields = new Set(adapter?.credentialFields?.map((field) => field.id) ?? [])
    if (Object.keys(parsed.authFields).some((field) => !declaredFields.has(field))) throw new Error('Undeclared credential field')
    const effectiveFields = existing
      ? await mergeStoredAuthFieldsForValidation(getDb(), existing.name, parsed.authFields, adapter)
      : parsed.authFields
    return validateProviderToken(parsed.service, parsed.value, fetch, Date.now(), undefined, adapter, policy.allowedHosts, effectiveFields)
  })
}

/** Recheck a stored credential without returning or logging its decrypted value. */
export async function validateStoredCredentialAction(id: string) {
  return captureCredentialAction(async () => {
    await requireOwner()
    const credentialId = idSchema.parse(id)
    const report = await validateStoredCredentialNow(getDb(), await key(), credentialId, Date.now(), fetch)
    return { status: report.status, message: report.message, checkedAt: report.checkedAt }
  })
}


/** Create a credential directly from the authenticated owner dashboard. */
export async function createCredentialAction(input: { name: string; service: string; form: StoreForm }) {
  return captureCredentialAction(async () => {
    await requireOwner()
    const parsed = createCredentialSchema.parse(input)
    const name = normalizeCredentialName(parsed.name)
    const policy = credentialPolicy(parsed.service)
    const adapter = serviceAdapterFor(parsed.service)
    const validation = await optionalSaveValidation(parsed.service, parsed.form, policy, adapter)
    const now = Date.now()
    const db = getDb()
    const preferences = await loadVaultPreferences(db)
    const result = await createCredential(db, await key(), {
      name, service: parsed.service, purpose: defaultPurposeForService(parsed.service),
      ...toStoreInput(parsed.form, now, policy, validation, preferences.validationIntervalHours, adapter),
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
    const policy = credentialPolicy(credential.service, credential.doc)
    const adapter = effectiveServiceAdapter(credential.service, credential.doc)
    const validationReport = await optionalSaveValidation(credential.service, parsed, policy, adapter)
    const preferences = await loadVaultPreferences(db)
    const storeInput = {
      credentialId: info.credentialId,
      ...toStoreInput(parsed, now, policy, validationReport, preferences.validationIntervalHours, adapter),
    }
    const validation = validateStoreInput(storeInput)
    if (!validation.ok) fail(validation)
    const encryptionKey = await key()

    const link = await consumeEnrollmentLink(db, parsedToken, now)
    if (!link || link.id !== info.id || link.credentialId !== info.credentialId || link.kind !== 'register') {
      throw new Error('This link is invalid, expired or already used')
    }
    try {
      const result = await storeCredentialValue(db, encryptionKey, storeInput, { requirePending: true })
      if (!result.ok) {
        await releaseEnrollmentLink(db, link.id, now)
        fail(result)
      }
      try {
        await markRegistrationNotificationsRead(db, info.credentialId, Date.now())
      } catch {
        // Notification cleanup is best-effort; a stored credential must still report success.
        console.warn('[vault] registration notification could not be marked as resolved')
      }
      return { name: result.value.name }
    } catch (error) {
      await releaseEnrollmentLink(db, link.id, now).catch(() => false)
      throw error
    }
  })
}

/** Dismiss a pending request without making active or filled credentials eligible. */
export async function dismissRegistrationRequestAction(id: string) {
  await requireOwner()
  const credentialId = idSchema.parse(id)
  const now = Date.now()
  const db = getDb()
  const notificationIds = await listUnreadRegistrationNotificationIds(db, credentialId)
  const r = await dismissPendingRegistrationRequest(db, credentialId, now)
  if (!r.ok) throw new Error('This Runner request is no longer pending. Refresh the request inbox.')
  try {
    // The credential FK is ON DELETE SET NULL, so resolve the captured IDs.
    await markNotificationIdsRead(db, notificationIds, now)
  } catch {
    console.warn('[vault] dismissed registration notification could not be marked as resolved')
  }
  return { ok: true as const }
}

/** Reissue a one-time owner form for an unchanged pending Runner request. */
export async function renewRegistrationLinkAction(id: string) {
  await requireOwner()
  const credentialId = idSchema.parse(id)
  const now = Date.now()
  const renewed = await renewRegistrationLink(getDb(), credentialId, 'owner:manual-reissue', now)
  if (!renewed.ok) throw new Error('This Runner request is no longer pending. Refresh the request inbox.')
  const url = new URL(`/vault/register/${renewed.value.link.token}`, getRequestOrigin(getActionRequest())).toString()
  return { url, expiresAt: renewed.value.link.expiresAt }
}

/** Replace the value / rules of an existing credential (owner is signed in; no link needed). */
export async function replaceCredentialAction(id: string, form: StoreForm) {
  return captureCredentialAction(async () => {
    await requireOwner()
    const parsed = storeSchema.parse(form)
    const db = getDb()
    const credential = await getCredentialForOwner(db, idSchema.parse(id))
    if (!credential || credential.externallyManaged) throw new Error('Credential not found or is externally managed')
    const policy = credentialPolicy(credential.service, credential.doc)
    const adapter = effectiveServiceAdapter(credential.service, credential.doc)
    const validationForm = parsed.validationRequested
      ? { ...parsed, authFields: await mergeStoredAuthFieldsForValidation(db, credential.name, parsed.authFields, adapter) }
      : parsed
    const validation = await optionalSaveValidation(credential.service, validationForm, policy, adapter)
    const preferences = await loadVaultPreferences(db)
    const result = await storeCredentialValue(db, await key(), {
      credentialId: credential.id,
      ...toStoreInput(parsed, Date.now(), policy, validation, preferences.validationIntervalHours, adapter),
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

const vaultPreferencesSchema = z.object({
  validationIntervalHours: z.number().int().min(1).max(24),
  analyticsRetentionDays: z.number().int().min(7).max(365),
  notificationRetentionDays: z.number().int().min(7).max(365),
  defaultVisible: z.boolean(),
  defaultLifetime: z.enum(['permanent', 'temporary']),
  proxyTimeoutMs: z.number().int().min(5_000).max(30_000),
  proxyRequestsPerMinute: z.number().int().min(1).max(600),
  runnerSessionsPerHour: z.number().int().min(1).max(120),
  runnerRegistrationsPerHour: z.number().int().min(1).max(60),
})

export async function saveVaultPreferencesAction(input: VaultPreferences) {
  await requireOwner()
  const preferences = vaultPreferencesSchema.parse(input)
  await saveVaultPreferences(getDb(), preferences, Date.now())
  return { ok: true as const }
}

export async function markNotificationReadAction(id: string) {
  await requireOwner()
  await markNotificationRead(getDb(), idSchema.parse(id))
  return { ok: true as const }
}

export async function markAllNotificationsReadAction() {
  await requireOwner()
  await markAllNotificationsRead(getDb())
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
