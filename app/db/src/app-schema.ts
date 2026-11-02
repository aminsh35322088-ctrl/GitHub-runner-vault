// Schema for the Runner Credential Vault D1 database.
// BetterAuth core tables (owner sign-in) and the credential registry.


import { defineRelations } from 'drizzle-orm'
import * as sqliteCore from 'drizzle-orm/sqlite-core'
import { ulid } from 'ulid'

// Integer column that stores epoch milliseconds as a plain number.
// Unlike integer({ mode: 'number' }), this accepts Date objects in toDriver
// so BetterAuth's internal Date params don't crash D1's .bind() which only
// accepts string | number | null | ArrayBuffer. TypeScript type stays `number`.
export const epochMs = sqliteCore.customType<{ data: number; driverParam: number }>({
  dataType() { return 'integer' },
  toDriver(value: unknown): number {
    if (value instanceof Date) return value.getTime()
    return value as number
  },
  fromDriver(value: unknown): number { return value as number },
})

// ── BetterAuth core tables ──────────────────────────────────────────

export const user = sqliteCore.sqliteTable('user', {
  id: sqliteCore.text('id').primaryKey().notNull().$defaultFn(() => ulid()),
  name: sqliteCore.text('name').notNull(),
  email: sqliteCore.text('email').notNull().unique(),
  emailVerified: sqliteCore.integer('email_verified', { mode: 'boolean' }).notNull().default(false),
  image: sqliteCore.text('image'),
  createdAt: epochMs('created_at').notNull().$defaultFn(() => Date.now()),
  updatedAt: epochMs('updated_at').notNull().$defaultFn(() => Date.now()),
})

export const session = sqliteCore.sqliteTable('session', {
  id: sqliteCore.text('id').primaryKey().notNull().$defaultFn(() => ulid()),
  userId: sqliteCore.text('user_id').notNull().references(() => user.id, { onDelete: 'cascade' }),
  token: sqliteCore.text('token').notNull().unique(),
  expiresAt: epochMs('expires_at').notNull(),
  ipAddress: sqliteCore.text('ip_address'),
  userAgent: sqliteCore.text('user_agent'),
  createdAt: epochMs('created_at').notNull().$defaultFn(() => Date.now()),
  updatedAt: epochMs('updated_at').notNull().$defaultFn(() => Date.now()),
}, (table) => [
  sqliteCore.index('session_user_id_idx').on(table.userId),
])

export const account = sqliteCore.sqliteTable('account', {
  id: sqliteCore.text('id').primaryKey().notNull().$defaultFn(() => ulid()),
  userId: sqliteCore.text('user_id').notNull().references(() => user.id, { onDelete: 'cascade' }),
  accountId: sqliteCore.text('account_id').notNull(),
  providerId: sqliteCore.text('provider_id').notNull(),
  accessToken: sqliteCore.text('access_token'),
  refreshToken: sqliteCore.text('refresh_token'),
  accessTokenExpiresAt: epochMs('access_token_expires_at'),
  refreshTokenExpiresAt: epochMs('refresh_token_expires_at'),
  scope: sqliteCore.text('scope'),
  idToken: sqliteCore.text('id_token'),
  password: sqliteCore.text('password'),
  createdAt: epochMs('created_at').notNull().$defaultFn(() => Date.now()),
  updatedAt: epochMs('updated_at').notNull().$defaultFn(() => Date.now()),
}, (table) => [
  sqliteCore.index('account_user_id_idx').on(table.userId),
])

export const verification = sqliteCore.sqliteTable('verification', {
  id: sqliteCore.text('id').primaryKey().notNull().$defaultFn(() => ulid()),
  identifier: sqliteCore.text('identifier').notNull(),
  value: sqliteCore.text('value').notNull(),
  expiresAt: epochMs('expires_at').notNull(),
  createdAt: epochMs('created_at').notNull().$defaultFn(() => Date.now()),
  updatedAt: epochMs('updated_at').notNull().$defaultFn(() => Date.now()),
})

// ── Credential registry (runner vault) ─────────────────────────────
// Mirrors migration 0010. The value columns are intentionally nullable: pending
// and externally-managed entries have none. List queries must select the
// metadata columns explicitly and never `value_encrypted` / `value_iv`.

export const credential = sqliteCore.sqliteTable('credential', {
  id: sqliteCore.text('id').primaryKey().notNull().$defaultFn(() => ulid()),
  name: sqliteCore.text('name').notNull().unique(),
  service: sqliteCore.text('service').notNull(),
  purpose: sqliteCore.text('purpose').notNull(),
  tokenType: sqliteCore.text('token_type').notNull().default(''),
  status: sqliteCore.text('status', { enum: ['pending', 'active', 'disabled'] }).notNull().default('pending'),
  visible: sqliteCore.integer('visible', { mode: 'boolean' }).notNull().default(false),
  lifetime: sqliteCore.text('lifetime', { enum: ['permanent', 'temporary'] }).notNull().default('temporary'),
  delivery: sqliteCore.text('delivery', { enum: ['proxy'] }).notNull().default('proxy'),
  allowedHosts: sqliteCore.text('allowed_hosts').notNull().default('[]'),
  // How the proxy presents the value upstream (migration 0011). Owner-controlled.
  authHeader: sqliteCore.text('auth_header').notNull().default('Authorization'),
  authScheme: sqliteCore.text('auth_scheme', { enum: ['Bearer', 'Token', 'Raw'] }).notNull().default('Bearer'),
  externallyManaged: sqliteCore.integer('externally_managed', { mode: 'boolean' }).notNull().default(false),
  validation: sqliteCore.text('validation', {
    enum: ['not_tested', 'valid', 'invalid', 'insufficient_permissions'],
  }).notNull().default('not_tested'),
  validationDetails: sqliteCore.text('validation_details'),
  validationStatus: sqliteCore.text('validation_status').notNull().default('not_tested'),
  lastValidatedAt: epochMs('last_validated_at'),
  nextValidationAt: epochMs('next_validation_at'),
  docJson: sqliteCore.text('doc_json').notNull().default('{}'),
  valueEncrypted: sqliteCore.text('value_encrypted'),
  valueIv: sqliteCore.text('value_iv'),
  keyVersion: sqliteCore.integer('key_version').notNull().default(1),
  expiresAt: epochMs('expires_at'),
  lastUsedAt: epochMs('last_used_at'),
  createdAt: epochMs('created_at').notNull().$defaultFn(() => Date.now()),
  updatedAt: epochMs('updated_at').notNull().$defaultFn(() => Date.now()),
}, (table) => [
  sqliteCore.index('credential_status_idx').on(table.status),
  sqliteCore.index('credential_validation_due_idx').on(table.status, table.nextValidationAt),
])

export const enrollmentLink = sqliteCore.sqliteTable('enrollment_link', {
  id: sqliteCore.text('id').primaryKey().notNull().$defaultFn(() => ulid()),
  credentialId: sqliteCore.text('credential_id').notNull().references(() => credential.id, { onDelete: 'cascade' }),
  kind: sqliteCore.text('kind', { enum: ['register', 'edit'] }).notNull(),
  // SHA-256 hex of the link token. The token itself is never stored.
  tokenHash: sqliteCore.text('token_hash').notNull().unique(),
  expiresAt: epochMs('expires_at').notNull(),
  usedAt: epochMs('used_at'),
  requestedBy: sqliteCore.text('requested_by').notNull().default(''),
  createdAt: epochMs('created_at').notNull().$defaultFn(() => Date.now()),
}, (table) => [
  sqliteCore.index('enrollment_link_credential_id_idx').on(table.credentialId),
])

export const credentialAudit = sqliteCore.sqliteTable('credential_audit', {
  id: sqliteCore.text('id').primaryKey().notNull().$defaultFn(() => ulid()),
  at: epochMs('at').notNull().$defaultFn(() => Date.now()),
  credentialId: sqliteCore.text('credential_id'),
  credentialName: sqliteCore.text('credential_name').notNull().default(''),
  action: sqliteCore.text('action').notNull(),
  actor: sqliteCore.text('actor').notNull(),
  requestId: sqliteCore.text('request_id').notNull().default(''),
  purpose: sqliteCore.text('purpose').notNull().default(''),
  result: sqliteCore.text('result').notNull().default(''),
  // What a runner claimed happened. Informational only; never authoritative.
  reportedResult: sqliteCore.text('reported_result').notNull().default(''),
  detail: sqliteCore.text('detail').notNull().default(''),
}, (table) => [
  sqliteCore.index('credential_audit_at_idx').on(table.at),
  sqliteCore.index('credential_audit_credential_idx').on(table.credentialId),
])

export const vaultSetting = sqliteCore.sqliteTable('vault_setting', {
  key: sqliteCore.text('key').primaryKey().notNull(),
  value: sqliteCore.text('value').notNull(),
  updatedAt: epochMs('updated_at').notNull().$defaultFn(() => Date.now()),
})

export const vaultNotification = sqliteCore.sqliteTable('vault_notification', {
  id: sqliteCore.text('id').primaryKey().notNull(),
  dedupeKey: sqliteCore.text('dedupe_key').notNull().unique(),
  kind: sqliteCore.text('kind').notNull(),
  severity: sqliteCore.text('severity', { enum: ['info', 'warning', 'critical'] }).notNull(),
  title: sqliteCore.text('title').notNull(),
  message: sqliteCore.text('message').notNull(),
  credentialId: sqliteCore.text('credential_id').references(() => credential.id, { onDelete: 'set null' }),
  credentialName: sqliteCore.text('credential_name').notNull().default(''),
  createdAt: epochMs('created_at').notNull(),
  readAt: epochMs('read_at'),
}, (table) => [
  sqliteCore.index('vault_notification_created_idx').on(table.createdAt),
  sqliteCore.index('vault_notification_unread_idx').on(table.readAt, table.createdAt),
])

export const credentialUsageHourly = sqliteCore.sqliteTable('credential_usage_hourly', {
  id: sqliteCore.text('id').primaryKey().notNull(),
  credentialId: sqliteCore.text('credential_id').notNull().references(() => credential.id, { onDelete: 'cascade' }),
  windowStart: epochMs('window_start').notNull(),
  consumer: sqliteCore.text('consumer').notNull().default('runner'),
  requestCount: sqliteCore.integer('request_count').notNull().default(0),
  successCount: sqliteCore.integer('success_count').notNull().default(0),
  errorCount: sqliteCore.integer('error_count').notNull().default(0),
  latencyTotalMs: sqliteCore.integer('latency_total_ms').notNull().default(0),
  latencyMaxMs: sqliteCore.integer('latency_max_ms').notNull().default(0),
}, (table) => [
  sqliteCore.uniqueIndex('credential_usage_hourly_unique_idx').on(table.credentialId, table.windowStart, table.consumer),
  sqliteCore.index('credential_usage_window_idx').on(table.windowStart),
  sqliteCore.index('credential_usage_credential_idx').on(table.credentialId, table.windowStart),
])

export const relations = defineRelations(
  { user, session, account, verification },
  (r) => ({
    user: {
      sessions: r.many.session(),
      accounts: r.many.account(),
    },
    session: {
      user: r.one.user({ from: r.session.userId, to: r.user.id }),
    },
    account: {
      user: r.one.user({ from: r.account.userId, to: r.user.id }),
    },
    verification: {},
  }),
)
