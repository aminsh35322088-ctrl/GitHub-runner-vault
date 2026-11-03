// One-time registration / edit links.
//
// A link only carries a random token. The owner must still be signed in to use it
// (the route checks the owner session), so a leaked link alone is not enough.
// Only the SHA-256 of the token is stored. Opening the page does not consume the
// link (peek); submitting the form does, atomically, so a link works exactly once
// even under concurrent submissions.

import * as orm from 'drizzle-orm'
import { getDb, schema } from 'db'

type Db = ReturnType<typeof getDb>

export const DEFAULT_LINK_TTL_MS = 15 * 60 * 1000
export const MAX_LINK_TTL_MS = 30 * 60 * 1000

export type LinkKind = 'register' | 'edit'

function base64Url(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export async function hashLinkToken(token: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token))
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('')
}

export function newLinkToken(): string {
  return `lnk_${base64Url(crypto.getRandomValues(new Uint8Array(32)))}`
}

const TOKEN_SHAPE = /^lnk_[A-Za-z0-9_-]{43}$/

export type CreatedLink = { token: string; expiresAt: number }

/** Create a link and invalidate any other unused link of the same kind for the credential. */
export async function createEnrollmentLink(
  db: Db,
  input: { credentialId: string; kind: LinkKind; requestedBy: string; now: number; ttlMs?: number },
): Promise<CreatedLink> {
  const ttl = Math.min(Math.max(input.ttlMs ?? DEFAULT_LINK_TTL_MS, 60_000), MAX_LINK_TTL_MS)
  const token = newLinkToken()
  const tokenHash = await hashLinkToken(token)
  const expiresAt = input.now + ttl

  // The invalidation and insert are one D1 batch (one transaction). This avoids
  // the race where parallel callers both retire the old link and collide on insert.
  // The partial unique index is a second, database-enforced line of defence.
  const invalidate = db.update(schema.enrollmentLink)
    .set({ usedAt: input.now })
    .where(orm.and(
      orm.eq(schema.enrollmentLink.credentialId, input.credentialId),
      orm.eq(schema.enrollmentLink.kind, input.kind),
      orm.isNull(schema.enrollmentLink.usedAt),
    ))
  const insert = db.insert(schema.enrollmentLink).values({
    credentialId: input.credentialId,
    kind: input.kind,
    tokenHash,
    expiresAt,
    requestedBy: input.requestedBy.slice(0, 200),
    createdAt: input.now,
  })
  await db.batch([invalidate, insert])
  return { token, expiresAt }
}

export type LinkInfo = { id: string; credentialId: string; kind: LinkKind; expiresAt: number }

/** Undo a consume only when this exact request marked the link used and it has not expired. */
export async function releaseEnrollmentLink(db: Db, id: string, consumedAt: number): Promise<boolean> {
  const rows = await db.update(schema.enrollmentLink)
    .set({ usedAt: null })
    .where(orm.and(
      orm.eq(schema.enrollmentLink.id, id),
      orm.eq(schema.enrollmentLink.usedAt, consumedAt),
      orm.gt(schema.enrollmentLink.expiresAt, consumedAt),
    ))
    .returning({ id: schema.enrollmentLink.id })
  return rows.length === 1
}


/** Look at a link without using it. Returns null for unknown, expired or used links. */
export async function peekEnrollmentLink(db: Db, token: string, now: number): Promise<LinkInfo | null> {
  if (!TOKEN_SHAPE.test(token)) return null
  const tokenHash = await hashLinkToken(token)
  const [row] = await db.select({
    id: schema.enrollmentLink.id,
    credentialId: schema.enrollmentLink.credentialId,
    kind: schema.enrollmentLink.kind,
    expiresAt: schema.enrollmentLink.expiresAt,
    usedAt: schema.enrollmentLink.usedAt,
  }).from(schema.enrollmentLink).where(orm.eq(schema.enrollmentLink.tokenHash, tokenHash)).limit(1)
  if (!row || row.usedAt !== null || row.expiresAt <= now) return null
  return { id: row.id, credentialId: row.credentialId, kind: row.kind, expiresAt: row.expiresAt }
}

/** Owner-facing link metadata only. Token hashes are never selected or returned. */
export async function listLatestRegistrationLinks(db: Db, credentialIds: string[]) {
  if (credentialIds.length === 0) return []
  const latest = new Map<string, {
    credentialId: string; requestedBy: string; expiresAt: number; usedAt: number | null; createdAt: number
  }>()
  // Stay below SQLite's conservative bind-variable limit while covering every
  // pending request, rather than silently omitting older pending credentials.
  for (let offset = 0; offset < credentialIds.length; offset += 750) {
    const chunk = credentialIds.slice(offset, offset + 750)
    const rows = await db.select({
      credentialId: schema.enrollmentLink.credentialId,
      requestedBy: schema.enrollmentLink.requestedBy,
      expiresAt: schema.enrollmentLink.expiresAt,
      usedAt: schema.enrollmentLink.usedAt,
      createdAt: schema.enrollmentLink.createdAt,
    }).from(schema.enrollmentLink)
      .where(orm.and(
        orm.eq(schema.enrollmentLink.kind, 'register'),
        orm.inArray(schema.enrollmentLink.credentialId, chunk),
      ))
      .orderBy(orm.desc(schema.enrollmentLink.createdAt), orm.asc(schema.enrollmentLink.usedAt))
    for (const row of rows) {
      if (!latest.has(row.credentialId)) latest.set(row.credentialId, row)
    }
  }
  return [...latest.values()]
}

/** Atomically use a link. Exactly one concurrent caller gets the link; the rest get null. */
export async function consumeEnrollmentLink(db: Db, token: string, now: number): Promise<LinkInfo | null> {
  if (!TOKEN_SHAPE.test(token)) return null
  const tokenHash = await hashLinkToken(token)
  const [row] = await db.update(schema.enrollmentLink)
    .set({ usedAt: now })
    .where(orm.and(
      orm.eq(schema.enrollmentLink.tokenHash, tokenHash),
      orm.isNull(schema.enrollmentLink.usedAt),
      orm.gt(schema.enrollmentLink.expiresAt, now),
    ))
    .returning({
      id: schema.enrollmentLink.id,
      credentialId: schema.enrollmentLink.credentialId,
      kind: schema.enrollmentLink.kind,
      expiresAt: schema.enrollmentLink.expiresAt,
    })
  return row ?? null
}
