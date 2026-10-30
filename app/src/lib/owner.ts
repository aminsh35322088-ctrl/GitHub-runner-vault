// Single-owner access policy for the credential vault.
//
// The vault has exactly one human owner, identified by the numeric GitHub user
// id (`OWNER_GITHUB_ID`). The id is compared, never the login name: logins can
// be renamed and re-registered by someone else, ids cannot.
//
// Fail closed: with no OWNER_GITHUB_ID configured nobody may sign in. The only
// exception is the vitest environment, which signs users up with
// email/password (see getAuth in db.ts) and has no GitHub accounts.

export const GITHUB_PROVIDER_ID = 'github'

/** GitHub numeric ids are positive integers. Reject anything else outright. */
export function normalizeOwnerId(value: unknown): string | null {
  if (typeof value !== 'string') return null
  const trimmed = value.trim()
  if (!/^[1-9][0-9]{0,15}$/.test(trimmed)) return null
  return trimmed
}

/** True only for a GitHub account whose id equals the configured owner id. */
export function isOwnerAccount(
  account: { providerId: string; accountId: string },
  ownerId: unknown,
): boolean {
  const owner = normalizeOwnerId(ownerId)
  if (!owner) return false
  return account.providerId === GITHUB_PROVIDER_ID && account.accountId === owner
}

/** Whether any of a user's linked accounts is the owner account. */
export function userHasOwnerAccount(
  accounts: ReadonlyArray<{ providerId: string; accountId: string }>,
  ownerId: unknown,
): boolean {
  return accounts.some((account) => isOwnerAccount(account, ownerId))
}
