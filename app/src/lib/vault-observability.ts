import * as orm from 'drizzle-orm'
import { getDb, schema } from 'db'
import { readAllowedHosts } from './credential-input.ts'
import { availability } from './credential-policy.ts'
import { readStoredDoc } from './credential-docs.ts'
import { readCredentialValue } from './credential-service.ts'
import { validateProviderToken, type CredentialValidationReport } from './credential-validation.ts'
import { adapterHost, serviceAdapterFor, serviceAdapterFromDocument } from './service-adapter.ts'

type Db = ReturnType<typeof getDb>

export type VaultPreferences = {
  validationIntervalHours: number
  analyticsRetentionDays: number
  notificationRetentionDays: number
  defaultVisible: boolean
  defaultLifetime: 'permanent' | 'temporary'
  proxyTimeoutMs: number
  proxyRequestsPerMinute: number
  runnerSessionsPerHour: number
  runnerRegistrationsPerHour: number
}

export const DEFAULT_VAULT_PREFERENCES: VaultPreferences = {
  validationIntervalHours: 6,
  analyticsRetentionDays: 90,
  notificationRetentionDays: 90,
  defaultVisible: true,
  defaultLifetime: 'permanent',
  proxyTimeoutMs: 20_000,
  proxyRequestsPerMinute: 30,
  runnerSessionsPerHour: 20,
  runnerRegistrationsPerHour: 10,
}

let preferencesCache: { value: VaultPreferences; expiresAt: number } | null = null
let preferencesLoad: Promise<VaultPreferences> | null = null
let preferencesRevision = 0
const PREFERENCES_CACHE_TTL_MS = 15_000

const SETTING_KEYS = {
  validationIntervalHours: 'validation_interval_hours',
  analyticsRetentionDays: 'analytics_retention_days',
  notificationRetentionDays: 'notification_retention_days',
  defaultVisible: 'default_visible',
  defaultLifetime: 'default_lifetime',
  proxyTimeoutMs: 'proxy_timeout_ms',
  proxyRequestsPerMinute: 'proxy_requests_per_minute',
  runnerSessionsPerHour: 'runner_sessions_per_hour',
  runnerRegistrationsPerHour: 'runner_registrations_per_hour',
} as const

function intSetting(value: string | null, fallback: number, min: number, max: number): number {
  if (value === null || !/^\d+$/.test(value)) return fallback
  const n = Number(value)
  return Number.isSafeInteger(n) && n >= min && n <= max ? n : fallback
}

export async function loadVaultPreferences(db: Db, now = Date.now()): Promise<VaultPreferences> {
  if (preferencesCache && preferencesCache.expiresAt > now) return { ...preferencesCache.value }
  if (preferencesLoad) return preferencesLoad.then((value) => ({ ...value }))

  const revision = preferencesRevision
  const pending = (async (): Promise<VaultPreferences> => {
    const keys = Object.values(SETTING_KEYS)
    const rows = await db.select({ key: schema.vaultSetting.key, value: schema.vaultSetting.value })
      .from(schema.vaultSetting).where(orm.inArray(schema.vaultSetting.key, keys))
    const values = new Map(rows.map((row) => [row.key, row.value]))
    const defaults = DEFAULT_VAULT_PREFERENCES
    return {
      validationIntervalHours: intSetting(values.get(SETTING_KEYS.validationIntervalHours) ?? null, defaults.validationIntervalHours, 1, 24),
      analyticsRetentionDays: intSetting(values.get(SETTING_KEYS.analyticsRetentionDays) ?? null, defaults.analyticsRetentionDays, 7, 365),
      notificationRetentionDays: intSetting(values.get(SETTING_KEYS.notificationRetentionDays) ?? null, defaults.notificationRetentionDays, 7, 365),
      defaultVisible: values.get(SETTING_KEYS.defaultVisible) === undefined ? defaults.defaultVisible : values.get(SETTING_KEYS.defaultVisible) === 'true',
      defaultLifetime: values.get(SETTING_KEYS.defaultLifetime) === 'temporary' ? 'temporary' : 'permanent',
      proxyTimeoutMs: intSetting(values.get(SETTING_KEYS.proxyTimeoutMs) ?? null, defaults.proxyTimeoutMs, 5_000, 30_000),
      proxyRequestsPerMinute: intSetting(values.get(SETTING_KEYS.proxyRequestsPerMinute) ?? null, defaults.proxyRequestsPerMinute, 1, 600),
      runnerSessionsPerHour: intSetting(values.get(SETTING_KEYS.runnerSessionsPerHour) ?? null, defaults.runnerSessionsPerHour, 1, 120),
      runnerRegistrationsPerHour: intSetting(values.get(SETTING_KEYS.runnerRegistrationsPerHour) ?? null, defaults.runnerRegistrationsPerHour, 1, 60),
    }
  })()
  preferencesLoad = pending
  try {
    const value = await pending
    // An older in-flight read must never overwrite a newer save's cache.
    if (revision === preferencesRevision) preferencesCache = { value, expiresAt: now + PREFERENCES_CACHE_TTL_MS }
    return { ...value }
  } finally {
    if (preferencesLoad === pending) preferencesLoad = null
  }
}

/** Test helper: clear only the isolate-local preferences cache. */
export function resetVaultPreferencesCache() {
  preferencesRevision++
  preferencesCache = null
  preferencesLoad = null
}

export async function saveVaultPreferences(db: Db, input: VaultPreferences, now = Date.now()): Promise<void> {
  const parsed: VaultPreferences = {
    validationIntervalHours: intSetting(String(input.validationIntervalHours), DEFAULT_VAULT_PREFERENCES.validationIntervalHours, 1, 24),
    analyticsRetentionDays: intSetting(String(input.analyticsRetentionDays), DEFAULT_VAULT_PREFERENCES.analyticsRetentionDays, 7, 365),
    notificationRetentionDays: intSetting(String(input.notificationRetentionDays), DEFAULT_VAULT_PREFERENCES.notificationRetentionDays, 7, 365),
    defaultVisible: Boolean(input.defaultVisible),
    defaultLifetime: input.defaultLifetime === 'temporary' ? 'temporary' : 'permanent',
    proxyTimeoutMs: intSetting(String(input.proxyTimeoutMs), DEFAULT_VAULT_PREFERENCES.proxyTimeoutMs, 5_000, 30_000),
    proxyRequestsPerMinute: intSetting(String(input.proxyRequestsPerMinute), DEFAULT_VAULT_PREFERENCES.proxyRequestsPerMinute, 1, 600),
    runnerSessionsPerHour: intSetting(String(input.runnerSessionsPerHour), DEFAULT_VAULT_PREFERENCES.runnerSessionsPerHour, 1, 120),
    runnerRegistrationsPerHour: intSetting(String(input.runnerRegistrationsPerHour), DEFAULT_VAULT_PREFERENCES.runnerRegistrationsPerHour, 1, 60),
  }
  const writes = Object.entries(SETTING_KEYS).map(([name, key]) =>
    orm.sql`(${key}, ${String(parsed[name as keyof VaultPreferences])}, ${now})`,
  )
  // One parameterized multi-row upsert: one D1 round trip and an atomic update
  // of the whole preferences snapshot (no partially saved settings).
  await db.run(orm.sql`
    INSERT INTO vault_setting (key, value, updated_at)
    VALUES ${orm.sql.join(writes, orm.sql`, `)}
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
  `)
  preferencesRevision++
  preferencesLoad = null
  preferencesCache = { value: parsed, expiresAt: now + PREFERENCES_CACHE_TTL_MS }
}

export async function createNotification(
  db: Db,
  input: {
    dedupeKey: string
    kind: string
    severity: 'info' | 'warning' | 'critical'
    title: string
    message: string
    credentialId?: string
    credentialName?: string
    now: number
  },
): Promise<void> {
  await db.insert(schema.vaultNotification).values({
    id: crypto.randomUUID(),
    dedupeKey: input.dedupeKey.slice(0, 180),
    kind: input.kind.slice(0, 60),
    severity: input.severity,
    title: input.title.slice(0, 160),
    message: input.message.slice(0, 600),
    credentialId: input.credentialId ?? null,
    credentialName: input.credentialName ?? '',
    createdAt: input.now,
  }).onConflictDoNothing({ target: schema.vaultNotification.dedupeKey })
}

export async function unreadNotificationCount(db: Db): Promise<number> {
  const [row] = await db.select({ count: orm.count() }).from(schema.vaultNotification)
    .where(orm.isNull(schema.vaultNotification.readAt))
  return row?.count ?? 0
}

export async function listNotifications(db: Db, limit = 100) {
  return db.select().from(schema.vaultNotification)
    .orderBy(orm.desc(schema.vaultNotification.createdAt)).limit(Math.min(Math.max(limit, 1), 200))
}

export async function markNotificationRead(db: Db, id: string, now = Date.now()) {
  await db.update(schema.vaultNotification).set({ readAt: now })
    .where(orm.and(orm.eq(schema.vaultNotification.id, id), orm.isNull(schema.vaultNotification.readAt)))
}

export async function markAllNotificationsRead(db: Db, now = Date.now()) {
  await db.update(schema.vaultNotification).set({ readAt: now })
    .where(orm.isNull(schema.vaultNotification.readAt))
}

/** Resolve only the in-panel alerts created for a specific Runner registration. */
export async function markRegistrationNotificationsRead(db: Db, credentialId: string, now = Date.now()) {
  await db.update(schema.vaultNotification).set({ readAt: now })
    .where(orm.and(
      orm.eq(schema.vaultNotification.credentialId, credentialId),
      orm.eq(schema.vaultNotification.kind, 'credential_registration_requested'),
      orm.isNull(schema.vaultNotification.readAt),
    ))
}

/** Capture notification IDs before deleting a credential (the FK sets its ID to NULL). */
export async function listUnreadRegistrationNotificationIds(db: Db, credentialId: string) {
  const rows = await db.select({ id: schema.vaultNotification.id }).from(schema.vaultNotification)
    .where(orm.and(
      orm.eq(schema.vaultNotification.credentialId, credentialId),
      orm.eq(schema.vaultNotification.kind, 'credential_registration_requested'),
      orm.isNull(schema.vaultNotification.readAt),
    ))
  return rows.map((row) => row.id)
}

export async function markNotificationIdsRead(db: Db, ids: string[], now = Date.now()) {
  if (ids.length === 0) return
  await db.update(schema.vaultNotification).set({ readAt: now })
    .where(orm.and(
      orm.inArray(schema.vaultNotification.id, ids),
      orm.isNull(schema.vaultNotification.readAt),
    ))
}

export async function recordCredentialUsage(
  db: Db,
  input: { credentialId: string; consumer: string; success: boolean; latencyMs: number; now: number },
): Promise<void> {
  const windowStart = Math.floor(input.now / 3_600_000) * 3_600_000
  const consumer = /^[a-z][a-z0-9:_-]{0,40}$/i.test(input.consumer) ? input.consumer : 'runner'
  const latency = Math.max(0, Math.min(120_000, Math.round(input.latencyMs)))
  await db.insert(schema.credentialUsageHourly).values({
    id: crypto.randomUUID(), credentialId: input.credentialId, windowStart, consumer,
    requestCount: 1, successCount: input.success ? 1 : 0, errorCount: input.success ? 0 : 1,
    latencyTotalMs: latency, latencyMaxMs: latency,
  }).onConflictDoUpdate({
    target: [
      schema.credentialUsageHourly.credentialId,
      schema.credentialUsageHourly.windowStart,
      schema.credentialUsageHourly.consumer,
    ],
    set: {
      requestCount: orm.sql`${schema.credentialUsageHourly.requestCount} + 1`,
      successCount: orm.sql`${schema.credentialUsageHourly.successCount} + ${input.success ? 1 : 0}`,
      errorCount: orm.sql`${schema.credentialUsageHourly.errorCount} + ${input.success ? 0 : 1}`,
      latencyTotalMs: orm.sql`${schema.credentialUsageHourly.latencyTotalMs} + ${latency}`,
      latencyMaxMs: orm.sql`MAX(${schema.credentialUsageHourly.latencyMaxMs}, ${latency})`,
    },
  })
}

function asNumber(value: number | string | null | undefined): number {
  return Number(value ?? 0) || 0
}

export async function getUsageAnalytics(db: Db, now = Date.now()) {
  const since = now - 30 * 24 * 3_600_000
  const rows = await db.select({
    requests: orm.sum(schema.credentialUsageHourly.requestCount),
    successes: orm.sum(schema.credentialUsageHourly.successCount),
    errors: orm.sum(schema.credentialUsageHourly.errorCount),
    latencyTotal: orm.sum(schema.credentialUsageHourly.latencyTotalMs),
    latencyMax: orm.max(schema.credentialUsageHourly.latencyMaxMs),
  }).from(schema.credentialUsageHourly).where(orm.gte(schema.credentialUsageHourly.windowStart, since))
  const totals = rows[0]
  const seriesRows = await db.select({
    windowStart: schema.credentialUsageHourly.windowStart,
    requests: orm.sum(schema.credentialUsageHourly.requestCount),
    successes: orm.sum(schema.credentialUsageHourly.successCount),
    errors: orm.sum(schema.credentialUsageHourly.errorCount),
  }).from(schema.credentialUsageHourly)
    .where(orm.gte(schema.credentialUsageHourly.windowStart, now - 24 * 3_600_000))
    .groupBy(schema.credentialUsageHourly.windowStart)
    .orderBy(schema.credentialUsageHourly.windowStart)
  const credentialRows = await db.select({
    credentialId: schema.credentialUsageHourly.credentialId,
    credentialName: schema.credential.name,
    service: schema.credential.service,
    requests: orm.sum(schema.credentialUsageHourly.requestCount),
    successes: orm.sum(schema.credentialUsageHourly.successCount),
    errors: orm.sum(schema.credentialUsageHourly.errorCount),
    latencyTotal: orm.sum(schema.credentialUsageHourly.latencyTotalMs),
  }).from(schema.credentialUsageHourly)
    .innerJoin(schema.credential, orm.eq(schema.credential.id, schema.credentialUsageHourly.credentialId))
    .where(orm.gte(schema.credentialUsageHourly.windowStart, since))
    .groupBy(schema.credentialUsageHourly.credentialId, schema.credential.name, schema.credential.service)
    .orderBy(orm.desc(orm.sum(schema.credentialUsageHourly.requestCount)))
    .limit(20)
  const consumerRows = await db.select({
    consumer: schema.credentialUsageHourly.consumer,
    requests: orm.sum(schema.credentialUsageHourly.requestCount),
    successes: orm.sum(schema.credentialUsageHourly.successCount),
    errors: orm.sum(schema.credentialUsageHourly.errorCount),
    latencyTotal: orm.sum(schema.credentialUsageHourly.latencyTotalMs),
    latencyMax: orm.max(schema.credentialUsageHourly.latencyMaxMs),
  }).from(schema.credentialUsageHourly)
    .where(orm.gte(schema.credentialUsageHourly.windowStart, since))
    .groupBy(schema.credentialUsageHourly.consumer)
    .orderBy(orm.desc(orm.sum(schema.credentialUsageHourly.requestCount)))
    .limit(30)
  const requestCount = asNumber(totals?.requests)
  const latencyTotal = asNumber(totals?.latencyTotal)
  return {
    periodDays: 30,
    totals: {
      requests: requestCount,
      successes: asNumber(totals?.successes),
      errors: asNumber(totals?.errors),
      averageLatencyMs: requestCount ? Math.round(latencyTotal / requestCount) : 0,
      maxLatencyMs: asNumber(totals?.latencyMax),
    },
    series: seriesRows.map((row) => ({
      windowStart: row.windowStart,
      requests: asNumber(row.requests),
      successes: asNumber(row.successes),
      errors: asNumber(row.errors),
    })),
    credentials: credentialRows.map((row) => {
      const requests = asNumber(row.requests)
      return {
        credentialId: row.credentialId,
        credentialName: row.credentialName,
        service: row.service,
        requests,
        successes: asNumber(row.successes),
        errors: asNumber(row.errors),
        averageLatencyMs: requests ? Math.round(asNumber(row.latencyTotal) / requests) : 0,
      }
    }),
    consumers: consumerRows.map((row) => {
      const requests = asNumber(row.requests)
      return {
        consumer: row.consumer,
        requests,
        successes: asNumber(row.successes),
        errors: asNumber(row.errors),
        averageLatencyMs: requests ? Math.round(asNumber(row.latencyTotal) / requests) : 0,
        maxLatencyMs: asNumber(row.latencyMax),
      }
    }),
  }
}

export async function listCredentialIntegrationMetadata(db: Db) {
  const rows = await db.select({
    id: schema.credential.id,
    name: schema.credential.name,
    service: schema.credential.service,
    status: schema.credential.status,
    docJson: schema.credential.docJson,
    allowedHosts: schema.credential.allowedHosts,
  }).from(schema.credential).orderBy(schema.credential.service, schema.credential.name)
  return rows.map((row) => {
    const doc = readStoredDoc(row.docJson)
    const adapter = serviceAdapterFromDocument(doc) ?? serviceAdapterFor(row.service)
    const baseHost = adapter ? adapterHost(adapter) : readAllowedHosts(row.allowedHosts)[0] ?? null
    return {
      id: row.id,
      name: row.name,
      service: row.service,
      status: row.status,
      host: baseHost,
      tools: adapter?.cliTools ?? [],
    }
  })
}

/**
 * Runner-only CLI metadata. Kept separate from /registry so models do not
 * receive network origins or tool configuration unless they explicitly use
 * the CLI integration capability. Only Active + Visible + unexpired entries
 * are returned; secret columns are never selected.
 */
export async function listRunnerIntegrationMetadata(db: Db, now = Date.now()) {
  const rows = await db.select({
    name: schema.credential.name,
    service: schema.credential.service,
    status: schema.credential.status,
    visible: schema.credential.visible,
    expiresAt: schema.credential.expiresAt,
    externallyManaged: schema.credential.externallyManaged,
    docJson: schema.credential.docJson,
    allowedHosts: schema.credential.allowedHosts,
    hasValue: orm.sql<number>`(${schema.credential.valueEncrypted} IS NOT NULL)`,
  }).from(schema.credential)
    .where(orm.and(
      orm.eq(schema.credential.status, 'active'),
      orm.eq(schema.credential.visible, true),
      orm.eq(schema.credential.externallyManaged, false),
      orm.or(orm.isNull(schema.credential.expiresAt), orm.gt(schema.credential.expiresAt, now)),
    ))
    .orderBy(schema.credential.service, schema.credential.name)

  return rows.flatMap((row) => {
    if (!availability({
      status: row.status, visible: row.visible, expiresAt: row.expiresAt,
      externallyManaged: row.externallyManaged, hasValue: Boolean(row.hasValue),
    }, now).available) return []
    const document = readStoredDoc(row.docJson)
    const adapter = serviceAdapterFromDocument(document) ?? serviceAdapterFor(row.service)
    if (!adapter || adapter.cliTools.length === 0) return []
    const host = adapterHost(adapter)
    if (!host || !readAllowedHosts(row.allowedHosts).includes(host)) return []
    return [{
      name: row.name,
      service: row.service,
      adapter: {
        apiBaseUrl: adapter.apiBaseUrl,
        cliTools: adapter.cliTools,
        ...(adapter.defaultHeaders ? { defaultHeaders: adapter.defaultHeaders } : {}),
      },
    }]
  })
}

export type ValidationHistorySource = 'scheduled' | 'manual'

type ValidationTarget = {
  id: string
  name: string
  service: string
  status: 'active' | 'disabled' | 'pending'
  visible: boolean
  expiresAt: number | null
  updatedAt: number
  valueIv: string | null
  validationStatus: string
  validationFailureCount: number
  firstValidationFailureAt: number | null
  nextValidationAt: number | null
  docJson: string
  allowedHosts: string
  externallyManaged: boolean
  hasValue: number
}

const VALIDATION_TARGET_COLUMNS = {
  id: schema.credential.id,
  name: schema.credential.name,
  service: schema.credential.service,
  status: schema.credential.status,
  visible: schema.credential.visible,
  expiresAt: schema.credential.expiresAt,
  updatedAt: schema.credential.updatedAt,
  valueIv: schema.credential.valueIv,
  validationStatus: schema.credential.validationStatus,
  validationFailureCount: schema.credential.validationFailureCount,
  firstValidationFailureAt: schema.credential.firstValidationFailureAt,
  nextValidationAt: schema.credential.nextValidationAt,
  docJson: schema.credential.docJson,
  allowedHosts: schema.credential.allowedHosts,
  externallyManaged: schema.credential.externallyManaged,
  hasValue: orm.sql<number>`(${schema.credential.valueEncrypted} IS NOT NULL)`,
}

function retryState(
  status: CredentialValidationReport['status'],
  target: ValidationTarget,
  now: number,
  intervalMs: number,
) {
  const countsAsFailure = ['invalid', 'expired', 'insufficient_permissions', 'unavailable'].includes(status)
  if (!countsAsFailure) {
    return {
      validationFailureCount: 0,
      firstValidationFailureAt: null,
      nextValidationAt: now + intervalMs,
    }
  }

  const validationFailureCount = Math.min(1_000, target.validationFailureCount + 1)
  const exponent = Math.min(validationFailureCount - 1, 8)
  const delay = Math.min(intervalMs, 15 * 60_000 * (2 ** exponent))
  return {
    validationFailureCount,
    firstValidationFailureAt: target.firstValidationFailureAt ?? now,
    nextValidationAt: now + delay,
  }
}

async function recordValidationResult(
  db: Db,
  target: ValidationTarget,
  report: CredentialValidationReport,
  source: ValidationHistorySource,
  now: number,
  durationMs: number,
  intervalMs: number,
): Promise<boolean> {
  const legacyStatus = report.status === 'valid' ? 'valid'
    : report.status === 'invalid' ? 'invalid'
      : report.status === 'insufficient_permissions' ? 'insufficient_permissions' : 'not_tested'
  const retry = retryState(report.status, target, now, intervalMs)

  // A provider request can take seconds. Do not let its result overwrite a
  // credential that the owner replaced or changed while validation was in flight.
  // updatedAt protects metadata changes; the freshly randomized AES-GCM IV is a
  // version marker for the secret itself, including same-millisecond rotations.
  const unchanged = [
    orm.eq(schema.credential.id, target.id),
    orm.eq(schema.credential.updatedAt, target.updatedAt),
    orm.eq(schema.credential.status, target.status),
    orm.eq(schema.credential.visible, target.visible),
    orm.eq(schema.credential.service, target.service),
    orm.eq(schema.credential.docJson, target.docJson),
    orm.eq(schema.credential.allowedHosts, target.allowedHosts),
    orm.eq(schema.credential.externallyManaged, target.externallyManaged),
    target.expiresAt === null
      ? orm.isNull(schema.credential.expiresAt)
      : orm.eq(schema.credential.expiresAt, target.expiresAt),
    target.valueIv === null
      ? orm.isNull(schema.credential.valueIv)
      : orm.eq(schema.credential.valueIv, target.valueIv),
    target.nextValidationAt === null
      ? orm.isNull(schema.credential.nextValidationAt)
      : orm.eq(schema.credential.nextValidationAt, target.nextValidationAt),
  ]
  const [updated] = await db.update(schema.credential).set({
    validation: legacyStatus,
    validationStatus: report.status,
    validationDetails: JSON.stringify(report).slice(0, 32_000),
    lastValidatedAt: now,
    ...retry,
  }).where(orm.and(...unchanged)).returning({ id: schema.credential.id })

  // A stale result is not a validation event for the current credential. In
  // particular, do not emit misleading history rows or owner notifications.
  if (!updated) return false

  // History deliberately stores report metadata only. The credential value is
  // never written to the history table, message, permissions, or telemetry.
  await db.insert(schema.credentialValidationHistory).values({
    id: crypto.randomUUID(),
    credentialId: target.id,
    credentialName: target.name,
    provider: report.provider.slice(0, 80),
    source,
    status: report.status,
    message: report.message.slice(0, 600),
    identity: report.identity?.slice(0, 200) ?? null,
    tokenType: report.tokenType?.slice(0, 120) ?? null,
    permissionSource: report.permissionSource,
    permissionsJson: JSON.stringify(report.permissions).slice(0, 16_000),
    permissionsComplete: report.permissionsComplete,
    durationMs: Math.max(0, Math.min(120_000, Math.round(durationMs))),
    checkedAt: now,
  })

  const previous = target.validationStatus
  if (report.status === 'invalid' && previous !== 'invalid') {
    await createNotification(db, {
      dedupeKey: `validation:${target.id}:invalid:${now}`,
      kind: 'validation_invalid', severity: 'critical',
      title: `${target.service} token rejected`,
      message: `The provider rejected the stored token for ${target.name}. Replace it or review its status.`,
      credentialId: target.id, credentialName: target.name, now,
    })
  } else if (report.status === 'expired' && previous !== 'expired') {
    await createNotification(db, {
      dedupeKey: `validation:${target.id}:expired:${target.expiresAt}`,
      kind: 'credential_expired', severity: 'critical',
      title: `${target.service} token expired`,
      message: `${target.name} reached its configured Vault expiry time.`,
      credentialId: target.id, credentialName: target.name, now,
    })
  } else if (report.status === 'unavailable' && previous !== 'unavailable') {
    await createNotification(db, {
      dedupeKey: `validation:${target.id}:unavailable:${now}`,
      kind: 'validation_unavailable', severity: 'warning',
      title: `${target.service} could not be reached`,
      message: `Validation for ${target.name} was inconclusive. The token was not marked invalid.`,
      credentialId: target.id, credentialName: target.name, now,
    })
  } else if (report.status === 'valid' && ['invalid', 'expired', 'unavailable', 'insufficient_permissions'].includes(previous)) {
    await createNotification(db, {
      dedupeKey: `validation:${target.id}:recovered:${now}`,
      kind: 'validation_recovered', severity: 'info',
      title: `${target.service} token verified again`,
      message: `${target.name} passed its latest provider validation.`,
      credentialId: target.id, credentialName: target.name, now,
    })
  }

  if (target.expiresAt !== null && target.expiresAt > now && target.expiresAt <= now + 72 * 3_600_000) {
    await createNotification(db, {
      dedupeKey: `expiry-soon:${target.id}:${target.expiresAt}`,
      kind: 'credential_expiring', severity: 'warning',
      title: `${target.service} token expires soon`,
      message: `${target.name} expires within 72 hours. Update its lifetime or replace the token if needed.`,
      credentialId: target.id, credentialName: target.name, now,
    })
  }
  return true
}

async function validateTarget(
  db: Db,
  encryptionKey: CryptoKey,
  target: ValidationTarget,
  now: number,
  fetchFn: typeof fetch,
  source: ValidationHistorySource,
  intervalMs: number,
): Promise<CredentialValidationReport> {
  const startedAt = Date.now()
  let report: CredentialValidationReport

  if (target.expiresAt !== null && target.expiresAt <= now) {
    report = {
      provider: target.service, status: 'expired', permissions: [], permissionsComplete: false,
      permissionSource: 'not-supported', checkedAt: now,
      message: 'مدت ماندگاری ثبت‌شده در Vault به پایان رسیده است؛ مقدار توکن بدون ارسال به سرویس منقضی محسوب می‌شود.',
    }
  } else {
    const document = readStoredDoc(target.docJson)
    const adapter = serviceAdapterFromDocument(document) ?? serviceAdapterFor(target.service)
    const allowedHosts = readAllowedHosts(target.allowedHosts)
    if (!adapter) {
      report = {
        provider: target.service, status: 'unsupported', permissions: [], permissionsComplete: false,
        permissionSource: 'not-supported', checkedAt: now,
        message: 'برای این سرویس Service Adapter مستند ثبت نشده است؛ Vault وضعیت معتبر را حدس نمی‌زند.',
      }
    } else {
      const host = adapterHost(adapter)
      if (!host || !allowedHosts.includes(host)) {
        report = {
          provider: target.service, status: 'unsupported', permissions: [], permissionsComplete: false,
          permissionSource: 'not-supported', checkedAt: now,
          message: 'Host مربوط به Service Adapter با Hostهای مجاز ذخیره‌شده یکسان نیست.',
        }
      } else {
        const read = await readCredentialValue(db, encryptionKey, target.name, now, { validation: true })
        if (!read.ok) {
          report = {
            provider: target.service, status: 'unavailable', permissions: [], permissionsComplete: false,
            permissionSource: 'not-supported', checkedAt: now,
            message: 'مقدار Credential برای اعتبارسنجی در دسترس نیست؛ وضعیت توکن تغییر داده نشد.',
          }
        } else {
          try {
            report = await validateProviderToken(target.service, read.value, fetchFn, now, undefined, adapter, allowedHosts, read.authFields)
          } catch {
            report = {
              provider: target.service, status: 'unavailable', permissions: [], permissionsComplete: false,
              permissionSource: 'not-exposed', checkedAt: now,
              message: 'بررسی سرویس با خطای موقت مواجه شد؛ Credential نامعتبر علامت‌گذاری نشد.',
            }
          }
        }
      }
    }
  }

  const recorded = await recordValidationResult(db, target, report, source, now, Date.now() - startedAt, intervalMs)
  if (!recorded) {
    return {
      provider: target.service,
      status: 'unavailable',
      permissions: [],
      permissionsComplete: false,
      permissionSource: 'not-supported',
      checkedAt: now,
      message: 'Credential changed during validation; the stale result was discarded. Run validation again.',
    }
  }
  return report
}

/** Record provider-authenticated runtime evidence without trusting generic transport success. */
export async function recordRuntimeCredentialEvidence(
  db: Db,
  input: { credentialId: string; valueIv: string; provider: string; status: 'valid' | 'invalid' | 'insufficient_permissions'; message: string; now: number },
): Promise<boolean> {
  const [target] = await db.select({
    id: schema.credential.id,
    name: schema.credential.name,
    valueIv: schema.credential.valueIv,
    status: schema.credential.status,
  }).from(schema.credential).where(orm.eq(schema.credential.id, input.credentialId)).limit(1)
  if (!target || target.valueIv !== input.valueIv || target.status !== 'active') return false

  const preferences = await loadVaultPreferences(db, input.now)
  const updated = await db.update(schema.credential).set({
    validation: input.status,
    validationStatus: input.status,
    validationDetails: JSON.stringify({ provider: input.provider, status: input.status, source: 'runtime', message: input.message }).slice(0, 32_000),
    lastValidatedAt: input.now,
    validationFailureCount: input.status === 'valid' ? 0 : 1,
    firstValidationFailureAt: input.status === 'valid' ? null : input.now,
    nextValidationAt: input.now + preferences.validationIntervalHours * 3_600_000,
  }).where(orm.and(
    orm.eq(schema.credential.id, target.id),
    orm.eq(schema.credential.valueIv, input.valueIv),
    orm.eq(schema.credential.status, 'active'),
  )).returning({ id: schema.credential.id })
  if (!updated.length) return false

  await db.insert(schema.credentialValidationHistory).values({
    id: crypto.randomUUID(), credentialId: target.id, credentialName: target.name,
    provider: input.provider.slice(0, 80), source: 'runtime', status: input.status,
    message: input.message.slice(0, 600), identity: null, tokenType: null,
    permissionSource: 'capability-probe', permissionsJson: '[]', permissionsComplete: false,
    durationMs: 0, checkedAt: input.now,
  })
  return true
}

export async function validateStoredCredentialNow(
  db: Db,
  encryptionKey: CryptoKey,
  credentialId: string,
  now = Date.now(),
  fetchFn: typeof fetch = fetch,
): Promise<CredentialValidationReport> {
  const [target] = await db.select(VALIDATION_TARGET_COLUMNS).from(schema.credential)
    .where(orm.eq(schema.credential.id, credentialId)).limit(1)
  if (!target) throw new Error('Credential not found')
  if (target.externallyManaged || !target.hasValue) {
    throw new Error('This credential has no stored value to validate')
  }

  const preferences = await loadVaultPreferences(db, now)
  return validateTarget(db, encryptionKey, target as ValidationTarget, now, fetchFn, 'manual', preferences.validationIntervalHours * 3_600_000)
}

export async function listCredentialValidationHistory(db: Db, limit = 100) {
  return db.select().from(schema.credentialValidationHistory)
    .orderBy(orm.desc(schema.credentialValidationHistory.checkedAt))
    .limit(Math.min(Math.max(limit, 1), 200))
}

export async function runScheduledCredentialValidation(
  db: Db,
  encryptionKey: CryptoKey,
  now = Date.now(),
  fetchFn: typeof fetch = fetch,
  maxBatch = 12,
) {
  const preferences = await loadVaultPreferences(db, now)
  const intervalMs = preferences.validationIntervalHours * 3_600_000
  const dueFilter = orm.and(
    orm.eq(schema.credential.status, 'active'),
    orm.eq(schema.credential.externallyManaged, false),
    orm.isNotNull(schema.credential.valueEncrypted),
    orm.or(orm.isNull(schema.credential.nextValidationAt), orm.lte(schema.credential.nextValidationAt, now)),
  )
  const targets = await db.select(VALIDATION_TARGET_COLUMNS).from(schema.credential)
    .where(dueFilter)
    .orderBy(schema.credential.nextValidationAt)
    .limit(Math.min(Math.max(maxBatch, 1), 30))

  let checked = 0
  for (const rawTarget of targets) {
    const target = rawTarget as ValidationTarget
    // Claim the item before contacting the provider. A crashed Worker will make
    // it eligible again after this short lease instead of retrying every cron.
    const claimConditions = [
      orm.eq(schema.credential.id, target.id),
      orm.eq(schema.credential.status, 'active'),
      orm.eq(schema.credential.externallyManaged, false),
      orm.isNotNull(schema.credential.valueEncrypted),
      target.nextValidationAt === null
        ? orm.isNull(schema.credential.nextValidationAt)
        : orm.eq(schema.credential.nextValidationAt, target.nextValidationAt),
    ]
    const claimUntil = now + 15 * 60_000
    const claimed = await db.update(schema.credential).set({ nextValidationAt: claimUntil })
      .where(orm.and(...claimConditions))
      .returning({ id: schema.credential.id })
    // Another cron or a manual owner action may have moved this credential
    // while this batch was being prepared. Only the successful claimant runs it.
    if (!claimed.length) continue
    await validateTarget(db, encryptionKey, { ...target, nextValidationAt: claimUntil }, now, fetchFn, 'scheduled', intervalMs)
    checked++
  }

  // Count the entire remaining queue, not just targets.length (which is capped
  // by maxBatch). The UI/cron summary must expose backlogs larger than one batch.
  const [remainingRow] = await db.select({ count: orm.count() }).from(schema.credential)
    .where(dueFilter)

  await db.delete(schema.credentialUsageHourly).where(orm.lt(schema.credentialUsageHourly.windowStart, now - preferences.analyticsRetentionDays * 86_400_000))
  await db.delete(schema.vaultNotification).where(orm.lt(schema.vaultNotification.createdAt, now - preferences.notificationRetentionDays * 86_400_000))
  await db.delete(schema.credentialValidationHistory).where(orm.lt(
    schema.credentialValidationHistory.checkedAt,
    now - preferences.analyticsRetentionDays * 86_400_000,
  ))
  return { checked, remainingDue: remainingRow?.count ?? 0 }
}
