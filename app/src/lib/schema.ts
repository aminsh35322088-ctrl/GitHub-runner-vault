// Creates the vault's tables on first use, so a fresh one-click deployment works
// without running D1 migrations by hand. The baseline is idempotent (so it also
// adopts databases created by earlier `wrangler d1 migrations apply` runs); later
// migrations run once each and are recorded in `vault_migration`.

import { SCHEMA_MIGRATIONS, type SchemaMigration } from './schema-sql.generated.ts'

let ready: Promise<void> | null = null

export function ensureSchema(d1: D1Database, migrations: SchemaMigration[] = SCHEMA_MIGRATIONS): Promise<void> {
  if (!ready) {
    ready = apply(d1, migrations).catch((error) => {
      ready = null
      throw error
    })
  }
  return ready
}

/** Test helper: forget that the schema was already checked in this isolate. */
export function resetSchemaCheck() {
  ready = null
}

async function apply(d1: D1Database, migrations: SchemaMigration[]) {
  await d1.prepare('CREATE TABLE IF NOT EXISTS vault_migration (id TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)').run()
  const done = new Set((await d1.prepare('SELECT id FROM vault_migration').all<{ id: string }>()).results.map((r) => r.id))
  for (const migration of migrations) {
    if (done.has(migration.id)) continue
    // Statements within one migration are idempotent or run once: a batch is atomic.
    await d1.batch([
      ...migration.statements.map((sql) => d1.prepare(sql)),
      d1.prepare('INSERT OR IGNORE INTO vault_migration (id, applied_at) VALUES (?, ?)').bind(migration.id, Date.now()),
    ])
  }
}
