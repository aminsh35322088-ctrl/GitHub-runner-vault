// Credential registry operations. All database access for credentials goes through
// here so the rules live in one place:
//  - listing queries name their columns explicitly and never select the value columns,
//  - the only function that reads a value is `readCredentialValue` (used by the proxy /
//    it re-checks availability itself for every proxy call,
//  - every state change writes an audit row written by the Worker, never by a runner.

import * as orm from 'drizzle-orm'
import { getDb, schema } from 'db'
import {
  decryptCredentialValue, encryptCredentialValue,
} from './credential-crypto.ts'
import { parseCredentialDoc, readStoredDoc } from './credential-docs.ts'
import { normalizeAllowedHosts, normalizeAuthStyle, readAllowedHosts, reservedName, validCredentialName, type AuthScheme } from './credential-input.ts'
import { availability, publicReason } from './credential-policy.ts'
import { createEnrollmentLink, type CreatedLink } from './enrollment.ts'
import { defaultPurposeForService } from './presets.ts'
import { adapterHost, serviceAdapterFor, serviceAdapterFromDocument } from './service-adapter.ts'

type Db = ReturnType<typeof getDb>

export const KEY_VERSION = 1
export const MAX_VALUE_BYTES = 8 * 1024
export const MAX_TEMPORARY_MS = 24 * 3600_000
const MAX_PERMANENT_MS = 3 * 365 * 24 * 3600_000

export type ServiceError =
  | 'invalid_name' | 'reserved_name' | 'invalid_doc' | 'exists' | 'not_found'
  | 'invalid_value' | 'invalid_hosts' | 'invalid_auth_style' | 'invalid_expiry' | 'hosts_required' | 'unavailable'

export type Result<T> = { ok: true; value: T } | { ok: false; error: ServiceError; detail?: string }

// ── Audit ──────────────────────────────────────────────────────────

export async function audit(db: Db, entry: {
  action: string
  actor: string
  credentialId?: string | null
  credentialName?: string
  requestId?: string
  result?: string
  detail?: string
  now: number
}) {
  await db.insert(schema.credentialAudit).values({
    at: entry.now,
    action: entry.action.slice(0, 60),
    actor: entry.actor.slice(0, 200),
    credentialId: entry.credentialId ?? null,
    credentialName: entry.credentialName ?? '',
    requestId: entry.requestId ?? '',
    purpose: '',
    result: (entry.result ?? '').slice(0, 60),
    reportedResult: '',
    detail: (entry.detail ?? '').slice(0, 500),
  })
}

// ── Registration requests (made through the runner API by a model) ─────────

export type RegistrationRequest = {
  name: string
  service: string
  purpose?: string
  doc: unknown
  requestedBy: string
  now: number
}

/**
 * A model asks for a credential that does not exist. This creates (or reuses) a
 * pending, invisible entry that holds only the proposed metadata and documentation,
 * plus a one-time link for the owner. Nothing here is trusted: the owner confirms
 * name, hosts and delivery on the registration page.
 */
export async function requestRegistration(db: Db, req: RegistrationRequest): Promise<Result<{ credentialId: string; link: CreatedLink }>> {
  if (!validCredentialName(req.name)) return { ok: false, error: 'invalid_name' }
  if (reservedName(req.name)) return { ok: false, error: 'reserved_name' }
  const doc = parseCredentialDoc(req.doc)
  if (!doc.ok) return { ok: false, error: 'invalid_doc', detail: doc.error }

  const [existing] = await db.select({ id: schema.credential.id, status: schema.credential.status, externallyManaged: schema.credential.externallyManaged })
    .from(schema.credential).where(orm.eq(schema.credential.name, req.name)).limit(1)
  if (existing && existing.status !== 'pending') return { ok: false, error: 'exists' }

  const service = req.service.trim().slice(0, 80)
  const purpose = defaultPurposeForService(service)

  let credentialId = existing?.id
  if (credentialId) {
    await db.update(schema.credential)
      .set({ service, purpose, docJson: doc.json, tokenType: doc.doc.token_type, updatedAt: req.now })
      .where(orm.eq(schema.credential.id, credentialId))
  } else {
    credentialId = crypto.randomUUID()
    await db.insert(schema.credential).values({
      id: credentialId, name: req.name, service, purpose, docJson: doc.json, tokenType: doc.doc.token_type,
      createdAt: req.now, updatedAt: req.now,
    })
  }
  const link = await createEnrollmentLink(db, { credentialId, kind: 'register', requestedBy: req.requestedBy, now: req.now })
  await audit(db, { action: 'registration_requested', actor: req.requestedBy, credentialId, credentialName: req.name, result: 'ok', now: req.now })
  return { ok: true, value: { credentialId, link } }
}

// ── Owner: create directly from the dashboard ──────────────────────────

export async function createCredential(
  db: Db,
  key: CryptoKey,
  input: Omit<StoreInput, 'credentialId'> & { name: string; service: string; purpose?: string },
): Promise<Result<{ id: string; name: string }>> {
  if (!validCredentialName(input.name)) return { ok: false, error: 'invalid_name' }
  if (reservedName(input.name)) return { ok: false, error: 'reserved_name' }
  const service = input.service.trim().slice(0, 80)
  const purpose = defaultPurposeForService(service)
  if (!service) return { ok: false, error: 'invalid_doc', detail: 'service is required' }
  const validated = validateStoreInput(input)
  if (!validated.ok) return validated
  const [existing] = await db.select({ id: schema.credential.id })
    .from(schema.credential).where(orm.eq(schema.credential.name, input.name)).limit(1)
  if (existing) return { ok: false, error: 'exists' }

  const id = crypto.randomUUID()
  const sealed = await encryptCredentialValue(key, id, KEY_VERSION, validated.value.value)
  await db.insert(schema.credential).values({
    id, name: input.name, service, purpose, tokenType: '', status: 'active',
    visible: input.visible, lifetime: input.lifetime, delivery: input.delivery,
    allowedHosts: JSON.stringify(validated.value.hosts),
    authHeader: validated.value.style.header, authScheme: validated.value.style.scheme,
    externallyManaged: false, validation: input.validation ?? 'not_tested', validationDetails: input.validationDetails ?? null,
    validationStatus: input.validationStatus ?? input.validation ?? 'not_tested', lastValidatedAt: input.validationStatus ? input.now : null,
    nextValidationAt: input.now + Math.max(1, Math.min(24, Math.trunc(input.validationIntervalHours ?? 6))) * 3600_000, docJson: '{}',
    valueEncrypted: sealed.encrypted, valueIv: sealed.iv, keyVersion: KEY_VERSION,
    expiresAt: validated.value.expiresAt, createdAt: input.now, updatedAt: input.now,
  })
  await audit(db, { action: 'credential_created', actor: 'owner', credentialId: id, credentialName: input.name, result: 'ok', detail: input.lifetime + '/proxy', now: input.now })
  return { ok: true, value: { id, name: input.name } }
}

// ── Owner: store / replace the value ───────────────────────────────────

export type StoreInput = {
  credentialId: string
  value: string
  lifetime: 'permanent' | 'temporary'
  /** epoch ms; required for temporary, optional for permanent */
  expiresAt: number | null
  visible: boolean
  delivery: 'proxy'
  allowedHosts: unknown
  /** Header and scheme the proxy uses upstream. Defaults to `Authorization: Bearer`. */
  authHeader?: string
  authScheme?: AuthScheme
  now: number
  validation?: 'not_tested' | 'valid' | 'invalid' | 'insufficient_permissions'
  validationDetails?: string | null
  validationStatus?: string
  validationIntervalHours?: number
}

export type ValidatedStoreInput = {
  value: string
  expiresAt: number | null
  hosts: string[]
  style: { header: string; scheme: AuthScheme }
}

/** Validate every owner-controlled value before a one-time registration link is consumed. */
export function validateStoreInput(input: Omit<StoreInput, 'credentialId'> & { credentialId?: string }): Result<ValidatedStoreInput> {
  if ((input as { delivery: string }).delivery !== 'proxy') {
    return { ok: false, error: 'invalid_value', detail: 'only proxy delivery is supported' }
  }
  const value = input.value.trim()
  if (!value || new TextEncoder().encode(value).byteLength > MAX_VALUE_BYTES || /[\r\n\u0000]/.test(value)) {
    return { ok: false, error: 'invalid_value' }
  }
  let expiresAt = input.expiresAt
  if (input.lifetime === 'temporary') {
    expiresAt = expiresAt === null ? input.now + MAX_TEMPORARY_MS : expiresAt
    if (expiresAt <= input.now || expiresAt > input.now + MAX_TEMPORARY_MS) return { ok: false, error: 'invalid_expiry' }
  } else if (expiresAt !== null && (expiresAt <= input.now || expiresAt > input.now + MAX_PERMANENT_MS)) {
    return { ok: false, error: 'invalid_expiry' }
  }
  const hosts = normalizeAllowedHosts(input.allowedHosts)
  if (!hosts.ok) return { ok: false, error: 'invalid_hosts', detail: hosts.error }
  if (hosts.hosts.length === 0) return { ok: false, error: 'hosts_required' }
  const style = normalizeAuthStyle(input.authHeader ?? 'Authorization', input.authScheme ?? 'Bearer')
  if (!style.ok) return { ok: false, error: 'invalid_auth_style', detail: style.error }
  return { ok: true, value: { value, expiresAt, hosts: hosts.hosts, style: { header: style.header, scheme: style.scheme } } }
}

export async function storeCredentialValue(db: Db, key: CryptoKey, input: StoreInput): Promise<Result<{ name: string }>> {
  const [row] = await db.select({ id: schema.credential.id, name: schema.credential.name, externallyManaged: schema.credential.externallyManaged })
    .from(schema.credential).where(orm.eq(schema.credential.id, input.credentialId)).limit(1)
  if (!row) return { ok: false, error: 'not_found' }
  if (row.externallyManaged) return { ok: false, error: 'invalid_value', detail: 'externally managed credentials hold no value' }

  const validated = validateStoreInput(input)
  if (!validated.ok) return validated
  const { value, expiresAt, hosts, style } = validated.value
  const { encrypted, iv } = await encryptCredentialValue(key, row.id, KEY_VERSION, value)
  await db.update(schema.credential).set({
    authHeader: style.header,
    authScheme: style.scheme,
    valueEncrypted: encrypted,
    valueIv: iv,
    keyVersion: KEY_VERSION,
    status: 'active',
    visible: input.visible,
    lifetime: input.lifetime,
    delivery: input.delivery,
    allowedHosts: JSON.stringify(hosts),
    expiresAt,
    validation: input.validation ?? 'not_tested',
    validationDetails: input.validationDetails ?? null,
    validationStatus: input.validationStatus ?? input.validation ?? 'not_tested',
    lastValidatedAt: input.validationStatus ? input.now : null,
    nextValidationAt: input.now + Math.max(1, Math.min(24, Math.trunc(input.validationIntervalHours ?? 6))) * 3600_000,
    updatedAt: input.now,
  }).where(orm.eq(schema.credential.id, row.id))
  await audit(db, { action: 'value_stored', actor: 'owner', credentialId: row.id, credentialName: row.name, result: 'ok', detail: input.lifetime + '/proxy', now: input.now })
  return { ok: true, value: { name: row.name } }
}

// ── Listings: metadata only ──────────────────────────────────────────

const METADATA_COLUMNS = {
  id: schema.credential.id,
  name: schema.credential.name,
  service: schema.credential.service,
  purpose: schema.credential.purpose,
  tokenType: schema.credential.tokenType,
  status: schema.credential.status,
  visible: schema.credential.visible,
  lifetime: schema.credential.lifetime,
  delivery: schema.credential.delivery,
  allowedHosts: schema.credential.allowedHosts,
  authHeader: schema.credential.authHeader,
  authScheme: schema.credential.authScheme,
  externallyManaged: schema.credential.externallyManaged,
  validation: schema.credential.validation,
  validationStatus: schema.credential.validationStatus,
  lastValidatedAt: schema.credential.lastValidatedAt,
  nextValidationAt: schema.credential.nextValidationAt,
  expiresAt: schema.credential.expiresAt,
  lastUsedAt: schema.credential.lastUsedAt,
  createdAt: schema.credential.createdAt,
  updatedAt: schema.credential.updatedAt,
  hasValue: orm.sql<number>`(${schema.credential.valueEncrypted} IS NOT NULL)`,
} as const

export async function listCredentialsForOwner(db: Db) {
  const rows = await db.select(METADATA_COLUMNS).from(schema.credential).orderBy(schema.credential.name)
  return rows.map((row) => ({ ...row, hasValue: Boolean(row.hasValue), allowedHosts: readAllowedHosts(row.allowedHosts) }))
}

export async function getCredentialForOwner(db: Db, id: string) {
  const [row] = await db.select({ ...METADATA_COLUMNS, docJson: schema.credential.docJson, validationDetails: schema.credential.validationDetails })
    .from(schema.credential).where(orm.eq(schema.credential.id, id)).limit(1)
  if (!row) return null
  return { ...row, hasValue: Boolean(row.hasValue), allowedHosts: readAllowedHosts(row.allowedHosts), doc: readStoredDoc(row.docJson) }
}

/** What a runner (and through it, a model) may know. Only Active + Visible entries. */
export async function listRegistryForRunner(db: Db, now: number) {
  const rows = await db.select(METADATA_COLUMNS).from(schema.credential)
    .where(orm.and(orm.eq(schema.credential.status, 'active'), orm.eq(schema.credential.visible, true)))
    .orderBy(schema.credential.name)
  return rows
    .filter((row) => availability({
      status: row.status, visible: row.visible, expiresAt: row.expiresAt,
      externallyManaged: row.externallyManaged, hasValue: Boolean(row.hasValue),
    }, now).available)
    .map((row) => ({
      name: row.name,
      service: row.service,
      purpose: row.purpose,
      lifetime: row.lifetime,
      delivery: row.delivery,
      validation: row.validation,
      expiresAt: row.expiresAt,
      externallyManaged: row.externallyManaged,
    }))
}

// ── Owner: lifecycle changes ───────────────────────────────────────────

async function mutate(db: Db, id: string, now: number, action: string, set: Partial<typeof schema.credential.$inferInsert>, detail = ''): Promise<Result<{ name: string }>> {
  const [row] = await db.select({ name: schema.credential.name }).from(schema.credential).where(orm.eq(schema.credential.id, id)).limit(1)
  if (!row) return { ok: false, error: 'not_found' }
  await db.update(schema.credential).set({ ...set, updatedAt: now }).where(orm.eq(schema.credential.id, id))
  await audit(db, { action, actor: 'owner', credentialId: id, credentialName: row.name, result: 'ok', detail, now })
  return { ok: true, value: { name: row.name } }
}

export const setVisibility = (db: Db, id: string, visible: boolean, now: number) =>
  mutate(db, id, now, visible ? 'made_visible' : 'made_hidden', { visible })

export async function setEnabled(db: Db, id: string, enabled: boolean, now: number): Promise<Result<{ name: string }>> {
  const [row] = await db.select({ hasValue: orm.sql<number>`(${schema.credential.valueEncrypted} IS NOT NULL)`, externallyManaged: schema.credential.externallyManaged, status: schema.credential.status })
    .from(schema.credential).where(orm.eq(schema.credential.id, id)).limit(1)
  if (!row) return { ok: false, error: 'not_found' }
  if (enabled && !row.hasValue && !row.externallyManaged) return { ok: false, error: 'invalid_value', detail: 'no value stored yet' }
  return mutate(db, id, now, enabled ? 'enabled' : 'disabled', { status: enabled ? 'active' : 'disabled' })
}

export async function deleteCredential(db: Db, id: string, now: number): Promise<Result<{ name: string }>> {
  const [row] = await db.select({ name: schema.credential.name }).from(schema.credential).where(orm.eq(schema.credential.id, id)).limit(1)
  if (!row) return { ok: false, error: 'not_found' }
  await db.delete(schema.credential).where(orm.eq(schema.credential.id, id))
  await audit(db, { action: 'deleted', actor: 'owner', credentialId: id, credentialName: row.name, result: 'ok', now })
  return { ok: true, value: { name: row.name } }
}

/** Register a metadata-only entry for access that is managed elsewhere (e.g. GitHub). */
export async function registerExternallyManaged(db: Db, input: { name: string; service: string; purpose?: string; now: number }): Promise<Result<{ id: string }>> {
  if (!validCredentialName(input.name)) return { ok: false, error: 'invalid_name' }
  if (reservedName(input.name)) return { ok: false, error: 'reserved_name' }
  const [existing] = await db.select({ id: schema.credential.id }).from(schema.credential).where(orm.eq(schema.credential.name, input.name)).limit(1)
  if (existing) return { ok: false, error: 'exists' }
  const id = crypto.randomUUID()
  await db.insert(schema.credential).values({
    id, name: input.name, service: input.service.slice(0, 80), purpose: defaultPurposeForService(input.service),
    status: 'active', visible: true, lifetime: 'permanent', delivery: 'proxy', externallyManaged: true,
    createdAt: input.now, updatedAt: input.now,
  })
  await audit(db, { action: 'registered_external', actor: 'owner', credentialId: id, credentialName: input.name, result: 'ok', now: input.now })
  return { ok: true, value: { id } }
}

// ── The only place a value is decrypted ───────────────────────────────

export type ValueResult =
  | { ok: true; value: string; credential: { id: string; name: string; delivery: 'proxy'; allowedHosts: string[]; authHeader: string; authScheme: AuthScheme } }
  | { ok: false; reason: string }

/**
 * Decrypts a value for a proxy call. Re-checks availability against the
 * stored row at the moment of use, so disabling, hiding, deleting or expiry take
 * effect on the very next request. The caller must never return `value` to a runner
 * in `proxy` mode.
 */
export async function readCredentialValue(
  db: Db,
  key: CryptoKey,
  name: string,
  now: number,
  options: { validation?: boolean } = {},
): Promise<ValueResult> {
  const [row] = await db.select({
    id: schema.credential.id, name: schema.credential.name, status: schema.credential.status, visible: schema.credential.visible,
    expiresAt: schema.credential.expiresAt, externallyManaged: schema.credential.externallyManaged,
    delivery: schema.credential.delivery, allowedHosts: schema.credential.allowedHosts,
    authHeader: schema.credential.authHeader, authScheme: schema.credential.authScheme,
    valueEncrypted: schema.credential.valueEncrypted, valueIv: schema.credential.valueIv, keyVersion: schema.credential.keyVersion,
  }).from(schema.credential).where(orm.eq(schema.credential.name, name)).limit(1)
  if (!row) return { ok: false, reason: 'unavailable' }
  const state = availability({
    status: options.validation ? 'active' : row.status,
    visible: options.validation ? true : row.visible,
    expiresAt: options.validation ? null : row.expiresAt,
    externallyManaged: row.externallyManaged, hasValue: row.valueEncrypted !== null,
  }, now)
  if (!state.available) return { ok: false, reason: publicReason(state.reason) }
  if (row.externallyManaged || row.valueEncrypted === null || row.valueIv === null) return { ok: false, reason: 'unavailable' }
  const value = await decryptCredentialValue(key, row.id, row.keyVersion, row.valueEncrypted, row.valueIv)
  return {
    ok: true,
    value,
    credential: {
      id: row.id, name: row.name, delivery: row.delivery, allowedHosts: readAllowedHosts(row.allowedHosts),
      authHeader: row.authHeader, authScheme: row.authScheme,
    },
  }
}

// ── Audit listing (owner) ─────────────────────────────────────────────

export async function listAudit(db: Db, opts: { limit?: number; credentialName?: string } = {}) {
  const limit = Math.min(Math.max(opts.limit ?? 100, 1), 500)
  const q = db.select().from(schema.credentialAudit)
  const rows = await (opts.credentialName ? q.where(orm.eq(schema.credentialAudit.credentialName, opts.credentialName)) : q)
    .orderBy(orm.desc(schema.credentialAudit.at)).limit(limit)
  return rows
}
