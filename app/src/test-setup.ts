// Setup file that applies D1 migrations and seeds test data before tests run.
// Runs inside workerd via @cloudflare/vitest-pool-workers.
// applyD1Migrations() only applies migrations that haven't already been
// applied, so it is safe to call repeatedly.
//
// Outbound HTTP is handled in vite.config.ts via miniflare's outboundService,
// not here — see testOutboundService for why the OIDC discovery endpoint must
// be answered locally.
import { applyD1Migrations } from 'cloudflare:test'
import { env } from 'cloudflare:workers'
import { ulid } from 'ulid'

await applyD1Migrations(env.DB, env.TEST_MIGRATIONS)

// Pre-populate oauth_domain for the test host so ensureOAuthClient returns
// early without calling the provider. createSpiceflowFetch(app) sends
// requests with host "e.ly", which is not localhost, so ensureOAuthClient
// uses the cached client ID and never re-registers.
await env.DB.prepare(
  'INSERT OR IGNORE INTO oauth_domain (id, host, oauth_client_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?)',
)
  .bind(ulid(), 'e.ly', 'test-client-id', Date.now(), Date.now())
  .run()
