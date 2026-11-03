import { afterEach, describe, expect, test } from 'vitest'
import { env } from 'cloudflare:workers'
import { getDb, schema } from 'db'
import * as orm from 'drizzle-orm'
import { listRegistryForRunner } from './credential-service.ts'

function percentile(samples: number[], ratio: number): number {
  const sorted = [...samples].sort((a, b) => a - b)
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * ratio) - 1)] ?? 0
}

describe('runner hot-path performance diagnostics', () => {
  const db = getDb()
  let insertedNames: string[] = []

  afterEach(async () => {
    if (insertedNames.length > 0) {
      await db.delete(schema.credential).where(orm.inArray(schema.credential.name, insertedNames))
      insertedNames = []
    }
  })

  test('reuses the isolate-local database facade', () => {
    expect(getDb()).toBe(db)
  })

  test('D1 query plans use the registry and rate-limit composite indexes', async () => {
    const registryPlan = await env.DB.prepare(
      'EXPLAIN QUERY PLAN SELECT name, service, purpose, lifetime, delivery, validation, expires_at, externally_managed ' +
      'FROM credential WHERE status = ? AND visible = ? ' +
      'AND (expires_at IS NULL OR expires_at > ?) ' +
      'AND (externally_managed = ? OR value_encrypted IS NOT NULL) ORDER BY name',
    ).bind('active', 1, Date.now(), 1).all()
    expect(JSON.stringify(registryPlan.results)).toContain('credential_runner_registry_idx')

    const ratePlan = await env.DB.prepare(
      'EXPLAIN QUERY PLAN SELECT count(*) FROM credential_audit ' +
      'WHERE action = ? AND credential_name = ? AND at >= ?',
    ).bind('proxy_use', 'PERFORMANCE_PROBE', Date.now() - 60_000).all()
    expect(JSON.stringify(ratePlan.results)).toContain('credential_audit_action_name_at_idx')

    const credentialAuditPlan = await env.DB.prepare(
      'EXPLAIN QUERY PLAN SELECT id, at, action FROM credential_audit ' +
      'WHERE credential_id = ? ORDER BY at DESC LIMIT 50',
    ).bind('PERFORMANCE_PROBE').all()
    expect(JSON.stringify(credentialAuditPlan.results)).toContain('credential_audit_credential_at_idx')

    const namedAuditPlan = await env.DB.prepare(
      'EXPLAIN QUERY PLAN SELECT id, at, action FROM credential_audit ' +
      'WHERE credential_name = ? ORDER BY at DESC LIMIT 50',
    ).bind('PERFORMANCE_PROBE').all()
    expect(JSON.stringify(namedAuditPlan.results)).toContain('credential_audit_name_at_idx')

    const unreadPlan = await env.DB.prepare(
      'EXPLAIN QUERY PLAN SELECT count(*) FROM vault_notification WHERE read_at IS NULL',
    ).all()
    expect(JSON.stringify(unreadPlan.results)).toContain('vault_notification_unread_idx')
  })

  test('reports warm runner registry p50/p95 on local Workerd D1', async () => {
    const now = Date.now()
    const suffix = crypto.randomUUID().replace(/-/g, '').toUpperCase()
    const rows = Array.from({ length: 40 }, (_, index) => {
      const name = 'PERF_' + suffix + '_' + String(index).padStart(2, '0')
      insertedNames.push(name)
      return {
        id: crypto.randomUUID(),
        name,
        service: 'Performance probe',
        purpose: 'Synthetic metadata-only benchmark fixture',
        status: 'active' as const,
        visible: true,
        lifetime: 'permanent' as const,
        delivery: 'proxy' as const,
        externallyManaged: true,
        validation: 'not_tested' as const,
        createdAt: now,
        updatedAt: now,
      }
    })
    // D1 allows at most 100 bound parameters per query. Each row binds 21 values.
    for (let offset = 0; offset < rows.length; offset += 4) {
      await db.insert(schema.credential).values(rows.slice(offset, offset + 4))
    }

    for (let i = 0; i < 5; i += 1) await listRegistryForRunner(db, now)
    const samples: number[] = []
    let visibleCount = 0
    for (let i = 0; i < 40; i += 1) {
      const started = performance.now()
      const result = await listRegistryForRunner(db, now)
      samples.push(performance.now() - started)
      visibleCount = result.filter((entry) => entry.name.startsWith('PERF_' + suffix + '_')).length
    }
    expect(visibleCount).toBe(40)
    const p50 = percentile(samples, 0.50)
    const p95 = percentile(samples, 0.95)
    console.info(
      '[VAULT_PERF_LOCAL_WORKERD] registry rows=40 samples=' + samples.length +
      ' p50_ms=' + p50.toFixed(2) + ' p95_ms=' + p95.toFixed(2),
    )
  })
})
