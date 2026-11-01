// Creates the schema in the in-memory test D1 the same way production does:
// through ensureSchema(), so tests exercise the real first-request path.
import { env } from 'cloudflare:workers'
import { ensureSchema } from './lib/schema.ts'

await ensureSchema(env.DB)
