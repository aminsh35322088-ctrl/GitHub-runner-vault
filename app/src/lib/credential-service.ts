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
import { createEnrollmentLink, discardEnrollmentLink, type CreatedLink } from './enrollment.ts'
import { defaultPurposeForService } from './presets.ts'
import { adapterHost, effectiveServiceAdapter, serviceAdapterFor } from './service-adapter.ts'

type Db = ReturnType<typeof getDb>

export const KEY_VERSION = 1
const CREDENTIAL_BUNDLE_PREFIX = 'vault-credential-bundle:v1:'

type CredentialBundle = { value: string; authFields: Record<string, string> }

function encodeCredentialBundle(value: string, authFields: Record<string, string>) {
  return Object.keys(authFields).length
    ? CREDENTIAL_BUNDLE_PREFIX + JSON.stringify({ version: 1, value, authFields })
    : value
}

/** Existing encrypted single-token rows remain readable without a migration. */
function validProviderTokenSyntax(service: string, value: string) {
  const normalized = service.trim().toLowerCase().replace(/[^a-z0-9]/g, '')
  if (normalized === 'telegrambotapi' || normalized === 'telegram') {
    return /^\d{5,16}:[A-Za-z0-9_-]{20,}$/.test(value)
  }
  return true
}

function decodeCredentialBundle(raw: string): CredentialBundle {
  if (!raw.startsWith(CREDENTIAL_BUNDLE_PREFIX)) return { value: raw, authFields: {} }
  try {
    const parsed = JSON.parse(raw.slice(CREDENTIAL_BUNDLE_PREFIX.length)) as {
      version?: unknown; value?: unknown; authFields?: unknown
    }
    if (parsed.version !== 1 || typeof parsed.value !== 'string' ||
        !parsed.authFields || typeof parsed.authFields !== 'object' || Array.isArray(parsed.authFields)) {
      return { value: raw, authFields: {} }
    }
    const fields: Record<string, string> = {}
    for (const [id, value] of Object.entries(parsed.authFields)) {
      if (/^[a-z][a-z0-9_]{0,31}$/.test(id) && typeof value === 'string') fields[id] = value
    }
    return { value: parsed.value, authFields: fields }
  } catch {
    return { value: raw, authFields: {} }
  }
}
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
  purpose?: string
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
    purpose: (entry.purpose ?? '').slice(0, 300),
    result: (entry.result ?? '').slice(0, 60),
    reportedResult: '',
    detail: (entry.detail ?? '').slice(0, 500),
  })
}

/** A caller-supplied purpose wins over the generated default; blank means default. */
function requestedPurpose(service: string, purpose?: string): string {
  const trimmed = purpose?.trim()
  return trimmed ? trimmed.slice(0, 300) : defaultPurposeForService(service)
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

  const [existing] = await db.select({
    id: schema.credential.id,
    status: schema.credential.status,
    externallyManaged: schema.credential.externallyManaged,
    hasValue: orm.sql<number>`(${schema.credential.valueEncrypted} IS NOT NULL)`,
  }).from(schema.credential).where(orm.eq(schema.credential.name, req.name)).limit(1)
  if (existing && (existing.status !== 'pending' || existing.externallyManaged || Boolean(existing.hasValue))) {
    return { ok: false, error: 'exists' }
  }

  const service = req.service.trim().slice(0, 80)
  const purpose = requestedPurpose(service, req.purpose)

  let credentialId: string
  if (existing) {
    // The initial read is only advisory. Enforce Pending/no-value again in the
    // UPDATE so a concurrently approved or dismissed credential is never
    // modified by a late Runner retry.
    const [updated] = await db.update(schema.credential)
      .set({ service, purpose, docJson: doc.json, tokenType: doc.doc.token_type, updatedAt: req.now })
      .where(orm.and(
        orm.eq(schema.credential.id, existing.id),
        orm.eq(schema.credential.status, 'pending'),
        orm.eq(schema.credential.externallyManaged, false),
        orm.isNull(schema.credential.valueEncrypted),
      ))
      .returning({ id: schema.credential.id })
    if (!updated) return { ok: false, error: 'exists' }
    credentialId = updated.id
  } else {
    const id = crypto.randomUUID()
    const [created] = await db.insert(schema.credential).values({
      id, name: req.name, service, purpose, docJson: doc.json, tokenType: doc.doc.token_type,
      createdAt: req.now, updatedAt: req.now,
    }).onConflictDoNothing({ target: schema.credential.name }).returning({ id: schema.credential.id })
    // Another request may have created this unique name after our initial read.
    // Treat that as a normal conflict rather than returning an unhandled D1 error.
    if (!created) return { ok: false, error: 'exists' }
    credentialId = created.id
  }

  let link: CreatedLink
  try {
    link = await createEnrollmentLink(db, { credentialId, kind: 'register', requestedBy: req.requestedBy, now: req.now })
  } catch (error) {
    const [stillPending] = await db.select({ id: schema.credential.id }).from(schema.credential)
      .where(orm.and(
        orm.eq(schema.credential.id, credentialId),
        orm.eq(schema.credential.status, 'pending'),
        orm.eq(schema.credential.externallyManaged, false),
        orm.isNull(schema.credential.valueEncrypted),
      )).limit(1)
    if (!stillPending) return { ok: false, error: 'exists' }
    throw error
  }

  const [stillPending] = await db.select({ id: schema.credential.id }).from(schema.credential)
    .where(orm.and(
      orm.eq(schema.credential.id, credentialId),
      orm.eq(schema.credential.status, 'pending'),
      orm.eq(schema.credential.externallyManaged, false),
      orm.isNull(schema.credential.valueEncrypted),
    )).limit(1)
  if (!stillPending) {
    await discardEnrollmentLink(db, link.token)
    return { ok: false, error: 'exists' }
  }

  await audit(db, { action: 'registration_requested', actor: req.requestedBy, credentialId, credentialName: req.name, purpose, result: 'ok', now: req.now })
  return { ok: true, value: { credentialId, link } }
}

/** Dismiss only an unfilled Runner request; active credentials are never eligible. */
export async function dismissPendingRegistrationRequest(
  db: Db,
  credentialId: string,
  now: number,
): Promise<Result<{ name: string }>> {
  const [row] = await db.delete(schema.credential).where(orm.and(
    orm.eq(schema.credential.id, credentialId),
    orm.eq(schema.credential.status, 'pending'),
    orm.eq(schema.credential.externallyManaged, false),
    orm.isNull(schema.credential.valueEncrypted),
  )).returning({ id: schema.credential.id, name: schema.credential.name })
  if (!row) return { ok: false, error: 'not_found' }
  await audit(db, {
    action: 'registration_request_dismissed', actor: 'owner', credentialId: row.id,
    credentialName: row.name, result: 'ok', now,
  })
  return { ok: true, value: { name: row.name } }
}

/** The owner can reissue a link for a still-pending request after the original expires. */
export async function renewRegistrationLink(
  db: Db,
  credentialId: string,
  requestedBy: string,
  now: number,
): Promise<Result<{ credentialId: string; name: string; link: CreatedLink }>> {
  const [row] = await db.select({
    id: schema.credential.id,
    name: schema.credential.name,
    status: schema.credential.status,
    externallyManaged: schema.credential.externallyManaged,
    hasValue: orm.sql<number>`(${schema.credential.valueEncrypted} IS NOT NULL)`,
  }).from(schema.credential).where(orm.eq(schema.credential.id, credentialId)).limit(1)
  if (!row || row.status !== 'pending' || row.externallyManaged || Boolean(row.hasValue)) {
    return { ok: false, error: 'not_found' }
  }
  const [originalRequest] = await db.select({ actor: schema.credentialAudit.actor })
    .from(schema.credentialAudit)
    .where(orm.and(
      orm.eq(schema.credentialAudit.credentialId, row.id),
      orm.eq(schema.credentialAudit.action, 'registration_requested'),
    ))
    .orderBy(orm.desc(schema.credentialAudit.at))
    .limit(1)
  const link = await createEnrollmentLink(db, {
    credentialId: row.id, kind: 'register', requestedBy: originalRequest?.actor ?? requestedBy, now,
  })
  await audit(db, {
    action: 'registration_link_renewed', actor: requestedBy, credentialId: row.id,
    credentialName: row.name, result: 'ok', detail: `expires_at:${link.expiresAt}`, now,
  })
  return { ok: true, value: { credentialId: row.id, name: row.name, link } }
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
  if (!validProviderTokenSyntax(service, validated.value.value)) {
    return { ok: false, error: 'invalid_value', detail: 'invalid Telegram Bot API token format' }
  }
  for (const required of input.requiredAuthFields ?? []) {
    if (!validated.value.authFields[required]?.trim()) return { ok: false, error: 'invalid_value', detail: 'missing required credential field' }
  }
  const [existing] = await db.select({ id: schema.credential.id })
    .from(schema.credential).where(orm.eq(schema.credential.name, input.name)).limit(1)
  if (existing) return { ok: false, error: 'exists' }

  const id = crypto.randomUUID()
  const encodedBundle = encodeCredentialBundle(validated.value.value, validated.value.authFields)
  if (new TextEncoder().encode(encodedBundle).byteLength > MAX_VALUE_BYTES) return { ok: false, error: 'invalid_value', detail: 'credential bundle is too large' }
  const sealed = await encryptCredentialValue(key, id, KEY_VERSION, encodedBundle)
  await db.insert(schema.credential).values({
    id, name: input.name, service, connectionLabel: validated.value.connectionLabel, providerAccountId: validated.value.providerAccountId, purpose, tokenType: '', status: 'active',
    visible: input.visible, lifetime: input.lifetime, delivery: input.delivery,
    allowedHosts: JSON.stringify(validated.value.hosts),
    authHeader: validated.value.style.header, authScheme: validated.value.style.scheme,
    externallyManaged: false, validation: input.validation ?? 'not_tested', validationDetails: input.validationDetails ?? null,
    validationStatus: input.validationStatus ?? input.validation ?? 'not_tested', lastValidatedAt: (input.validationStatus ?? input.validation ?? 'not_tested') === 'not_tested' ? null : input.now,
    nextValidationAt: input.now + Math.max(1, Math.min(24, Math.trunc(input.validationIntervalHours ?? 6))) * 3600_000,
    validationFailureCount: 0, firstValidationFailureAt: null, docJson: '{}',
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
  authFields?: Record<string, string>
  /** Allowed schema field IDs. Derived from the reviewed provider adapter on the server. */
  authFieldIds?: string[]
  requiredAuthFields?: string[]
  connectionLabel?: string
  providerAccountId?: string
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
  authFields: Record<string, string>
  connectionLabel: string
  providerAccountId: string
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
  const connectionLabel = (input.connectionLabel ?? '').trim()
  const providerAccountId = (input.providerAccountId ?? '').trim()
  if (connectionLabel.length > 120 || /[\r\n\u0000]/.test(connectionLabel) ||
      providerAccountId.length > 160 || /[\r\n\u0000]/.test(providerAccountId)) {
    return { ok: false, error: 'invalid_value', detail: 'invalid provider connection metadata' }
  }
  const authFields = input.authFields ?? {}
  const allowedFields = input.authFieldIds ?? Object.keys(authFields)
  if (Object.keys(authFields).length > 12 || allowedFields.length > 12) {
    return { ok: false, error: 'invalid_value', detail: 'too many credential fields' }
  }
  let authFieldBytes = 0
  for (const [field, fieldValue] of Object.entries(authFields)) {
    if (!/^[a-z][a-z0-9_]{0,31}$/.test(field) || !allowedFields.includes(field) ||
        typeof fieldValue !== 'string' || fieldValue.trim().length < 4 ||
        /[\r\n\u0000]/.test(fieldValue) || new TextEncoder().encode(fieldValue).byteLength > 4096) {
      return { ok: false, error: 'invalid_value', detail: 'invalid credential field bundle' }
    }
    authFieldBytes += new TextEncoder().encode(field + fieldValue).byteLength
  }
  if (new TextEncoder().encode(value).byteLength + authFieldBytes > MAX_VALUE_BYTES) {
    return { ok: false, error: 'invalid_value', detail: 'credential bundle is too large' }
  }
  return { ok: true, value: {
    value, expiresAt, hosts: hosts.hosts, style: { header: style.header, scheme: style.scheme },
    authFields, connectionLabel, providerAccountId,
  } }
}

export async function storeCredentialValue(
  db: Db,
  key: CryptoKey,
  input: StoreInput,
  options: { requirePending?: boolean } = {},
): Promise<Result<{ name: string }>> {
  const [row] = await db.select({ id: schema.credential.id, name: schema.credential.name, service: schema.credential.service, externallyManaged: schema.credential.externallyManaged, valueEncrypted: schema.credential.valueEncrypted, valueIv: schema.credential.valueIv, keyVersion: schema.credential.keyVersion })
    .from(schema.credential).where(orm.eq(schema.credential.id, input.credentialId)).limit(1)
  if (!row) return { ok: false, error: 'not_found' }
  if (row.externallyManaged) return { ok: false, error: 'invalid_value', detail: 'externally managed credentials hold no value' }

  const validated = validateStoreInput(input)
  if (!validated.ok) return validated
  if (!validProviderTokenSyntax(row.service, validated.value.value)) {
    return { ok: false, error: 'invalid_value', detail: 'invalid Telegram Bot API token format' }
  }
  const { value, expiresAt, hosts, style, connectionLabel, providerAccountId } = validated.value
  let authFields = validated.value.authFields
  // Write-only secondary fields are retained when a primary token is rotated.
  if (!options.requirePending && row.valueEncrypted && row.valueIv) {
    const previous = decodeCredentialBundle(await decryptCredentialValue(key, row.id, row.keyVersion, row.valueEncrypted, row.valueIv))
    const allowed = new Set(input.authFieldIds ?? [])
    const preserved = Object.fromEntries(Object.entries(previous.authFields).filter(([id]) => allowed.has(id)))
    authFields = { ...preserved, ...authFields }
  }
  for (const required of input.requiredAuthFields ?? []) {
    if (!authFields[required]?.trim()) return { ok: false, error: 'invalid_value', detail: 'missing required credential field' }
  }
  if (Object.keys(authFields).length > 12) return { ok: false, error: 'invalid_value', detail: 'too many credential fields' }
  const encodedBundle = encodeCredentialBundle(value, authFields)
  if (new TextEncoder().encode(encodedBundle).byteLength > MAX_VALUE_BYTES) return { ok: false, error: 'invalid_value', detail: 'credential bundle is too large' }
  const { encrypted, iv } = await encryptCredentialValue(key, row.id, KEY_VERSION, encodedBundle)
  const conditions = [
    orm.eq(schema.credential.id, row.id),
    orm.eq(schema.credential.externallyManaged, false),
  ]
  if (options.requirePending) {
    // Registration must win or lose atomically against Dismiss. If another
    // owner action changes/deletes the pending row after the initial read,
    // this conditional UPDATE returns no row and no success is reported.
    conditions.push(
      orm.eq(schema.credential.status, 'pending'),
      orm.isNull(schema.credential.valueEncrypted),
    )
  }
  const [stored] = await db.update(schema.credential).set({
    authHeader: style.header,
    authScheme: style.scheme,
    connectionLabel,
    providerAccountId,
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
    lastValidatedAt: (input.validationStatus ?? input.validation ?? 'not_tested') === 'not_tested' ? null : input.now,
    nextValidationAt: input.now + Math.max(1, Math.min(24, Math.trunc(input.validationIntervalHours ?? 6))) * 3600_000,
    validationFailureCount: 0,
    firstValidationFailureAt: null,
    updatedAt: input.now,
  }).where(orm.and(...conditions)).returning({ id: schema.credential.id, name: schema.credential.name })
  if (!stored) return { ok: false, error: 'not_found' }
  await audit(db, { action: 'value_stored', actor: 'owner', credentialId: stored.id, credentialName: stored.name, result: 'ok', detail: input.lifetime + '/proxy', now: input.now })
  return { ok: true, value: { name: stored.name } }
}

// ── Listings: metadata only ──────────────────────────────────────────

const METADATA_COLUMNS = {
  id: schema.credential.id,
  name: schema.credential.name,
  service: schema.credential.service,
  connectionLabel: schema.credential.connectionLabel,
  providerAccountId: schema.credential.providerAccountId,
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
  validationFailureCount: schema.credential.validationFailureCount,
  firstValidationFailureAt: schema.credential.firstValidationFailureAt,
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

const PENDING_REQUEST_PAGE_SIZE = 50

/** Pending owner requests in a bounded metadata-only page; never selects encrypted values. */
export async function listPendingRegistrationRequestsForOwner(
  db: Db,
  options: { page?: number; pageSize?: number } = {},
) {
  const conditions = orm.and(
    orm.eq(schema.credential.status, 'pending'),
    orm.eq(schema.credential.externallyManaged, false),
    orm.isNull(schema.credential.valueEncrypted),
  )
  const [countRow] = await db.select({ count: orm.count() }).from(schema.credential).where(conditions)
  const total = countRow?.count ?? 0
  const pageSize = Math.max(1, Math.min(100, Math.trunc(options.pageSize ?? PENDING_REQUEST_PAGE_SIZE)))
  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  const page = Math.min(totalPages, Math.max(1, Math.trunc(options.page ?? 1) || 1))
  const rows = await db.select({
    ...METADATA_COLUMNS,
    docJson: schema.credential.docJson,
  }).from(schema.credential)
    .where(conditions)
    .orderBy(orm.desc(schema.credential.updatedAt), orm.desc(schema.credential.name))
    .limit(pageSize)
    .offset((page - 1) * pageSize)
  return {
    rows: rows.map((row) => ({
      ...row,
      hasValue: Boolean(row.hasValue),
      allowedHosts: readAllowedHosts(row.allowedHosts),
      doc: readStoredDoc(row.docJson),
    })),
    total,
    page,
    pageSize,
    totalPages,
  }
}

export async function getCredentialForOwner(db: Db, id: string) {
  const [row] = await db.select({ ...METADATA_COLUMNS, docJson: schema.credential.docJson, validationDetails: schema.credential.validationDetails })
    .from(schema.credential).where(orm.eq(schema.credential.id, id)).limit(1)
  if (!row) return null
  return { ...row, hasValue: Boolean(row.hasValue), allowedHosts: readAllowedHosts(row.allowedHosts), doc: readStoredDoc(row.docJson) }
}

/** What a runner (and through it, a model) may know. Only Active + Visible entries. */
export async function listRegistryForRunner(db: Db, now: number) {
  // Keep the runner hot path narrow: select only fields returned by the API,
  // filter eligibility in D1, and preserve name ordering through its index.
  // The encrypted value is referenced only by IS NOT NULL; it is never selected.
  return db.select({
    name: schema.credential.name,
    service: schema.credential.service,
    connectionLabel: schema.credential.connectionLabel,
    providerAccountId: schema.credential.providerAccountId,
    purpose: schema.credential.purpose,
    lifetime: schema.credential.lifetime,
    delivery: schema.credential.delivery,
    validation: schema.credential.validation,
    expiresAt: schema.credential.expiresAt,
    externallyManaged: schema.credential.externallyManaged,
  }).from(schema.credential)
    .where(orm.and(
      orm.eq(schema.credential.status, 'active'),
      orm.eq(schema.credential.visible, true),
      orm.or(orm.isNull(schema.credential.expiresAt), orm.gt(schema.credential.expiresAt, now)),
      orm.or(
        orm.eq(schema.credential.externallyManaged, true),
        orm.isNotNull(schema.credential.valueEncrypted),
      ),
    ))
    .orderBy(schema.credential.name)
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
    id, name: input.name, service: input.service.slice(0, 80), purpose: requestedPurpose(input.service, input.purpose),
    status: 'active', visible: true, lifetime: 'permanent', delivery: 'proxy', externallyManaged: true,
    createdAt: input.now, updatedAt: input.now,
  })
  await audit(db, { action: 'registered_external', actor: 'owner', credentialId: id, credentialName: input.name, result: 'ok', now: input.now })
  return { ok: true, value: { id } }
}

/**
 * Prepare every credential ciphertext for a master-key change without writing
 * anything. One unreadable row blocks the whole plan; plaintext exists only in
 * this function's stack and is never returned or persisted.
 */
export type PreparedCredentialReencryption = {
  updates: Array<{ id: string; valueEncrypted: string; valueIv: string; updatedAt: number }>
  failedIds: string[]
}

export async function prepareStoredCredentialReencryption(
  db: Db,
  fromKey: CryptoKey,
  toKey: CryptoKey,
  credentialIds?: string[],
): Promise<PreparedCredentialReencryption> {
  const valueFilter = orm.isNotNull(schema.credential.valueEncrypted)
  const rows = await db.select({
    id: schema.credential.id,
    keyVersion: schema.credential.keyVersion,
    valueEncrypted: schema.credential.valueEncrypted,
    valueIv: schema.credential.valueIv,
  }).from(schema.credential).where(
    credentialIds === undefined
      ? valueFilter
      : credentialIds.length === 0
        ? orm.eq(schema.credential.id, '')
        : orm.and(valueFilter, orm.inArray(schema.credential.id, credentialIds)),
  )
  const updates: PreparedCredentialReencryption['updates'] = []
  const failedIds: string[] = []
  const updatedAt = Date.now()
  for (const row of rows) {
    if (row.valueEncrypted === null || row.valueIv === null) {
      failedIds.push(row.id)
      continue
    }
    try {
      const plain = await decryptCredentialValue(fromKey, row.id, row.keyVersion, row.valueEncrypted, row.valueIv)
      const sealed = await encryptCredentialValue(toKey, row.id, row.keyVersion, plain)
      updates.push({ id: row.id, valueEncrypted: sealed.encrypted, valueIv: sealed.iv, updatedAt })
    } catch {
      failedIds.push(row.id)
    }
  }
  return failedIds.length ? { updates: [], failedIds } : { updates, failedIds: [] }
}

/**
 * Re-encrypt all stored credential values in one atomic D1 batch. A failed
 * preflight leaves every existing ciphertext untouched.
 */
export async function reencryptStoredCredentials(
  db: Db,
  fromKey: CryptoKey,
  toKey: CryptoKey,
  credentialIds?: string[],
): Promise<{ migrated: number; failedIds: string[] }> {
  const prepared = await prepareStoredCredentialReencryption(db, fromKey, toKey, credentialIds)
  if (prepared.failedIds.length) return { migrated: 0, failedIds: prepared.failedIds }
  if (prepared.updates.length) {
    await db.batch(prepared.updates.map((row) => db.update(schema.credential)
      .set({ valueEncrypted: row.valueEncrypted, valueIv: row.valueIv, updatedAt: row.updatedAt })
      .where(orm.eq(schema.credential.id, row.id))))
  }
  return { migrated: prepared.updates.length, failedIds: [] }
}
// ── The only place a value is decrypted ───────────────────────────────

export type ValueResult =
  | { ok: true; value: string; authFields: Record<string, string>; credential: {
      id: string; name: string; service: string; purpose: string; connectionLabel: string; providerAccountId: string;
      delivery: 'proxy'; allowedHosts: string[]; authHeader: string; authScheme: AuthScheme; valueIv: string;
      authFieldHeaders: Array<{ field: string; header: string; scheme: AuthScheme; required: boolean }>
    } }
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
    id: schema.credential.id, name: schema.credential.name, service: schema.credential.service, purpose: schema.credential.purpose, connectionLabel: schema.credential.connectionLabel, providerAccountId: schema.credential.providerAccountId, status: schema.credential.status, visible: schema.credential.visible,
    expiresAt: schema.credential.expiresAt, externallyManaged: schema.credential.externallyManaged,
    delivery: schema.credential.delivery, allowedHosts: schema.credential.allowedHosts,
    authHeader: schema.credential.authHeader, authScheme: schema.credential.authScheme, docJson: schema.credential.docJson,
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
  const raw = await decryptCredentialValue(key, row.id, row.keyVersion, row.valueEncrypted, row.valueIv)
  const bundle = decodeCredentialBundle(raw)
  const adapter = effectiveServiceAdapter(row.service, readStoredDoc(row.docJson))
  return {
    ok: true,
    value: bundle.value,
    authFields: bundle.authFields,
    credential: {
      id: row.id, name: row.name, service: row.service, purpose: row.purpose, connectionLabel: row.connectionLabel, providerAccountId: row.providerAccountId,
      delivery: row.delivery, allowedHosts: readAllowedHosts(row.allowedHosts),
      authHeader: row.authHeader, authScheme: row.authScheme, valueIv: row.valueIv,
      authFieldHeaders: adapter?.authFieldHeaders ?? [],
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
