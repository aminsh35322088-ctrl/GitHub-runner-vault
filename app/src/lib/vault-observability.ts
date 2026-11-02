import * as orm from 'drizzle-orm'
import { getDb, schema } from 'db'
import { readAllowedHosts } from './credential-input.ts'
import { availability } from './credential-policy.ts'
import { readStoredDoc } from './credential-docs.ts'
import { readCredentialValue } from './credential-service.ts'
import { validateProviderToken, type CredentialValidationReport } from './credential-validation.ts'
import { adapterHost, serviceAdapterFor, serviceAdapterFromDocument } from './service-adapter.ts'
import { putSetting } from './vault-config.ts'

type Db = ReturnType<typeof getDb>

export type VaultPreferences = {
  validationIntervalHours: number
  analyticsRetentionDays: number
  notificationRetentionDays: number
  defaultVisible: boolean
  defaultLifetime: 'permanent' | 'temporary'
  proxyTimeoutMs: number
}

export const DEFAULT_VAULT_PREFERENCES: VaultPreferences = {
  validationIntervalHours: 6,
  analyticsRetentionDays: 90,
  notificationRetentionDays: 90,
  defaultVisible: true,
  defaultLifetime: 'permanent',
  proxyTimeoutMs: 20_000,
}

let preferencesCache: { value: VaultPreferences; expiresAt: number } | null = null
const PREFERENCES_CACHE_TTL_MS = 15_000

const SETTING_KEYS = {
  validationIntervalHours: 'validation_interval_hours',
  analyticsRetentionDays: 'analytics_retention_days',
  notificationRetentionDays: 'notification_retention_days',
  defaultVisible: 'default_visible',
  defaultLifetime: 'default_lifetime',
  proxyTimeoutMs: 'proxy_timeout_ms',
} as const

function intSetting(value: string | null, fallback: number, min: number, max: number): number {
  if (value === null || !/^\d+$/.test(value)) return fallback
  const n = Number(value)
  return Number.isSafeInteger(n) && n >= min && n <= max ? n : fallback
}

export async function loadVaultPreferences(db: Db, now = Date.now()): Promise<VaultPreferences> {
  if (preferencesCache && preferencesCache.expiresAt > now) return { ...preferencesCache.value }
  const keys = Object.values(SETTING_KEYS)
  const rows = await db.select({ key: schema.vaultSetting.key, value: schema.vaultSetting.value })
    .from(schema.vaultSetting).where(orm.inArray(schema.vaultSetting.key, keys))
  const values = new Map(rows.map((row) => [row.key, row.value]))
  const defaults = DEFAULT_VAULT_PREFERENCES
  const value: VaultPreferences = {
    validationIntervalHours: intSetting(values.get(SETTING_KEYS.validationIntervalHours) ?? null, defaults.validationIntervalHours, 1, 24),
    analyticsRetentionDays: intSetting(values.get(SETTING_KEYS.analyticsRetentionDays) ?? null, defaults.analyticsRetentionDays, 7, 365),
    notificationRetentionDays: intSetting(values.get(SETTING_KEYS.notificationRetentionDays) ?? null, defaults.notificationRetentionDays, 7, 365),
    defaultVisible: values.get(SETTING_KEYS.defaultVisible) === undefined ? defaults.defaultVisible : values.get(SETTING_KEYS.defaultVisible) === 'true',
    defaultLifetime: values.get(SETTING_KEYS.defaultLifetime) === 'temporary' ? 'temporary' : 'permanent',
    proxyTimeoutMs: intSetting(values.get(SETTING_KEYS.proxyTimeoutMs) ?? null, defaults.proxyTimeoutMs, 5_000, 30_000),
  }
  preferencesCache = { value, expiresAt: now + PREFERENCES_CACHE_TTL_MS }
  return { ...value }
}

export async function saveVaultPreferences(db: Db, input: VaultPreferences, now = Date.now()): Promise<void> {
  const parsed: VaultPreferences = {
    validationIntervalHours: intSetting(String(input.validationIntervalHours), 6, 1, 24),
    analyticsRetentionDays: intSetting(String(input.analyticsRetentionDays), 90, 7, 365),
    notificationRetentionDays: intSetting(String(input.notificationRetentionDays), 90, 7, 365),
    defaultVisible: Boolean(input.defaultVisible),
    defaultLifetime: input.defaultLifetime === 'temporary' ? 'temporary' : 'permanent',
    proxyTimeoutMs: intSetting(String(input.proxyTimeoutMs), 20_000, 5_000, 30_000),
  }
  for (const [name, key] of Object.entries(SETTING_KEYS) as Array<[keyof VaultPreferences, string]>) {
    await putSetting(db, key, String(parsed[name]), now)
  }
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

export async function runScheduledCredentialValidation(
  db: Db,
  encryptionKey: CryptoKey,
  now = Date.now(),
  fetchFn: typeof fetch = fetch,
  maxBatch = 12,
) {
  const preferences = await loadVaultPreferences(db)
  const intervalMs = preferences.validationIntervalHours * 3_600_000
  const targets = await db.select({
    id: schema.credential.id,
    name: schema.credential.name,
    service: schema.credential.service,
    status: schema.credential.status,
    visible: schema.credential.visible,
    expiresAt: schema.credential.expiresAt,
    updatedAt: schema.credential.updatedAt,
    validationStatus: schema.credential.validationStatus,
    docJson: schema.credential.docJson,
    allowedHosts: schema.credential.allowedHosts,
  }).from(schema.credential)
    .where(orm.and(
      orm.eq(schema.credential.status, 'active'),
      orm.eq(schema.credential.externallyManaged, false),
      orm.isNotNull(schema.credential.valueEncrypted),
      orm.or(orm.isNull(schema.credential.nextValidationAt), orm.lte(schema.credential.nextValidationAt, now)),
    ))
    .orderBy(schema.credential.nextValidationAt)
    .limit(Math.min(Math.max(maxBatch, 1), 30))

  let checked = 0
  for (const target of targets) {
    const retryAt = now + Math.max(15 * 60_000, Math.min(intervalMs, 60 * 60_000))
    await db.update(schema.credential).set({ nextValidationAt: retryAt }).where(orm.eq(schema.credential.id, target.id))
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
            report = await validateProviderToken(target.service, read.value, fetchFn, now, undefined, adapter, allowedHosts)
          }
        }
      }
    }

    const legacyStatus = report.status === 'valid' ? 'valid'
      : report.status === 'invalid' ? 'invalid'
        : report.status === 'insufficient_permissions' ? 'insufficient_permissions' : 'not_tested'
    const nextInterval = report.status === 'invalid' ? Math.min(intervalMs, 60 * 60_000)
      : report.status === 'unavailable' ? Math.min(intervalMs, 30 * 60_000) : intervalMs
    await db.update(schema.credential).set({
      validation: legacyStatus,
      validationStatus: report.status,
      validationDetails: JSON.stringify(report).slice(0, 32_000),
      lastValidatedAt: now,
      nextValidationAt: now + nextInterval,
    }).where(orm.eq(schema.credential.id, target.id))

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
    } else if (report.status === 'valid' && ['invalid', 'expired', 'unavailable'].includes(previous)) {
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
    checked++
  }

  await db.delete(schema.credentialUsageHourly).where(orm.lt(schema.credentialUsageHourly.windowStart, now - preferences.analyticsRetentionDays * 86_400_000))
  await db.delete(schema.vaultNotification).where(orm.lt(schema.vaultNotification.createdAt, now - preferences.notificationRetentionDays * 86_400_000))
  return { checked, remainingDue: Math.max(0, targets.length - checked) }
}
