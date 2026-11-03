import * as orm from 'drizzle-orm'
import { getDb, schema } from 'db'

type Db = ReturnType<typeof getDb>
export type RunnerRateLimitScope = 'session' | 'registration' | 'proxy'

export interface RunnerRateLimitReservation {
  scope: RunnerRateLimitScope
  subject: string
  now: number
  windowMs: number
  limit: number
  credentialId?: string | null
}

const EVENT_RETENTION_MS = 2 * 60 * 60_000

/**
 * Atomically reserve one slot in a sliding window.
 * INSERT..SELECT evaluates the current count and writes the event in a single
 * SQLite statement, so parallel Worker requests cannot all pass a stale count.
 */
export async function reserveRunnerRateLimit(db: Db, input: RunnerRateLimitReservation): Promise<string | null> {
  if (!Number.isSafeInteger(input.now) || !Number.isSafeInteger(input.windowMs) || input.windowMs < 1 ||
      !Number.isSafeInteger(input.limit) || input.limit < 1 || input.subject.length < 1 || input.subject.length > 160 ||
      (input.scope === 'proxy' && !input.credentialId) || (input.scope !== 'proxy' && input.credentialId)) {
    throw new Error('Invalid Runner rate-limit reservation')
  }
  const id = crypto.randomUUID()
  const credentialId = input.credentialId ?? null
  const inserted = await db.all<{ id: string }>(orm.sql`
    INSERT INTO runner_rate_limit_event (id, scope, subject, credential_id, created_at)
    SELECT ${id}, ${input.scope}, ${input.subject}, ${credentialId}, ${input.now}
    WHERE (
      SELECT COUNT(*) FROM runner_rate_limit_event
      WHERE scope = ${input.scope}
        AND subject = ${input.subject}
        AND created_at >= ${input.now - input.windowMs}
    ) < ${input.limit}
    RETURNING id
  `)
  return inserted.length === 1 ? id : null
}

/** Release a reservation when a registration operation fails before it is accepted. */
export async function releaseRunnerRateLimitReservation(db: Db, id: string): Promise<void> {
  await db.delete(schema.runnerRateLimitEvent).where(orm.eq(schema.runnerRateLimitEvent.id, id))
}

/** Keep only the last two hours; the longest supported window is one hour. */
export async function cleanupRunnerRateLimitEvents(db: Db, now = Date.now()): Promise<void> {
  await db.delete(schema.runnerRateLimitEvent)
    .where(orm.lt(schema.runnerRateLimitEvent.createdAt, now - EVENT_RETENTION_MS))
}
