// Cloudflare Workers entrypoint for the shared Sigillo app D1 schema.
// Uses drizzle-orm/sqlite-proxy instead of drizzle-orm/d1 because the D1
// driver crashes in mapGetResult when db.batch() runs findFirst() with no
// results (drizzle-team/drizzle-orm#2721). sqlite-proxy has the guard.
//
// sqlite-proxy expects positional arrays. Non-batch uses raw() directly;
// batch converts D1 object rows via d1ToRawRows.

import { env } from 'cloudflare:workers'
import { drizzle } from 'drizzle-orm/sqlite-proxy'
import * as schema from './app-schema.ts'

export { schema }

function d1ToRawRows(results: Record<string, unknown>[]) {
  return results.map((row) => Object.keys(row).map((k) => row[k]))
}

function createDb() {
  return drizzle(
    async (sql, params, method) => {
      const stmt = env.DB.prepare(sql).bind(...params)
      if (method === 'run') { await stmt.run(); return { rows: [] as any[] } }
      const rows = await stmt.raw()
      // https://github.com/drizzle-team/drizzle-orm/issues/5461
      if (method === 'get') return { rows: rows[0] as any }
      return { rows: rows as any[] }
    },
    async (queries) => {
      const stmts = queries.map((q) => env.DB.prepare(q.sql).bind(...q.params))
      const results = await env.DB.batch(stmts)
      return results.map((r, i) => {
        const rows = d1ToRawRows(r.results as Record<string, unknown>[])
        if (queries[i]!.method === 'get') return { rows: rows[0] as any }
        return { rows: rows as any[] }
      })
    },
    { schema, relations: schema.relations },
  )
}


// D1 is a stable Worker binding for the lifetime of an isolate. Reuse the
// lightweight Drizzle/sqlite-proxy facade instead of rebuilding its callbacks
// and relation metadata on every HTTP request. The cache is isolate-local;
// no request-specific data or transaction state is retained.
type WorkerDb = ReturnType<typeof createDb>
let cachedDb: WorkerDb | null = null

export function getDb(): WorkerDb {
  if (cachedDb) return cachedDb
  cachedDb = createDb()
  return cachedDb
}
