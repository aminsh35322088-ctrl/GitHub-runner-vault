// Which GitHub Actions workflow may talk to this vault.
//
// A configured Worker policy wins. Otherwise, the first valid OIDC run must prove
// the deployment-pinned owner id, main branch and exact rdc-lab.yml workflow. The
// resulting repository id and owner id are atomically pinned in D1. Later runs use
// that immutable policy; a second repository cannot claim or replace it.

import { policyFromEnv, type OidcPolicy } from './oidc.ts'
import { getDb, schema } from 'db'
import { loadOwnerId } from './vault-config.ts'
import { getSetting, putSetting, type VaultEnv } from './vault-config.ts'

type Db = ReturnType<typeof getDb>

const KEY = 'runner_policy'
export const DEFAULT_EVENTS = 'workflow_dispatch,schedule,push'

export const BOOTSTRAP_BRANCH = 'main'
export const BOOTSTRAP_WORKFLOW_FILE = 'rdc-lab.yml'

export function buildBootstrapPolicy(ownerId: string, audience: string): OidcPolicy {
  if (!/^\d{1,20}$/.test(ownerId)) throw new Error('A pinned numeric vault owner id is required')
  return {
    audience, repository: '', repositoryId: '', allowedRefs: [`refs/heads/${BOOTSTRAP_BRANCH}`],
    allowedEvents: DEFAULT_EVENTS.split(','), allowedWorkflowRefs: [],
    bootstrap: {
      ownerId, branch: BOOTSTRAP_BRANCH, workflowFile: BOOTSTRAP_WORKFLOW_FILE,
      allowedEvents: DEFAULT_EVENTS.split(','),
    },
  }
}

/** Atomically pins the first owner-approved OIDC repository; a racing runner cannot replace it. */
export async function pinRunnerPolicy(db: Db, input: RunnerPolicyInput, audience: string): Promise<RunnerPolicyInput> {
  const policy = buildPolicy(input, audience)
  const value = JSON.stringify(input)
  if (value.length > 480) throw new Error('Runner settings are too long')
  await db.insert(schema.vaultSetting)
    .values({ key: KEY, value, updatedAt: Date.now() })
    .onConflictDoNothing()
  const pinned = await loadRunnerPolicyInput(db)
  if (!pinned ||
      pinned.repositoryId !== policy.repositoryId ||
      pinned.repositoryOwnerId !== input.repositoryOwnerId ||
      !pinned.repository || pinned.repository.toLowerCase() !== input.repository.toLowerCase() ||
      pinned.branch !== input.branch || pinned.workflowFile !== input.workflowFile) {
    throw new Error('A different runner repository is already pinned')
  }
  return pinned
}

export interface RunnerPolicyInput {
  repository: string
  repositoryId: string
  branch: string
  workflowFile: string
  events: string
  repositoryOwnerId?: string
}

function toEnvRecord(p: RunnerPolicyInput): Record<string, string> {
  return {
    RUNNER_REPOSITORY: p.repository,
    RUNNER_REPOSITORY_ID: p.repositoryId,
    RUNNER_ALLOWED_REFS: `refs/heads/${p.branch}`,
    RUNNER_ALLOWED_EVENTS: p.events,
    RUNNER_ALLOWED_WORKFLOW_REFS: `${p.repository}/.github/workflows/${p.workflowFile}@refs/heads/${p.branch}`,
    ...(p.repositoryOwnerId ? { RUNNER_REPOSITORY_OWNER_ID: p.repositoryOwnerId } : {}),
  }
}

function checkParts(p: RunnerPolicyInput) {
  if (!/^[A-Za-z0-9._/-]{1,100}$/.test(p.branch) || p.branch.includes('..') || p.branch.startsWith('/')) throw new Error('Branch name is not valid')
  if (!/^[A-Za-z0-9._-]{1,100}\.ya?ml$/.test(p.workflowFile)) throw new Error('Workflow file must look like name.yml (no folders)')
}

/** Validates (throws a readable Error) and returns the policy for an audience. */
export function buildPolicy(input: RunnerPolicyInput, audience: string): OidcPolicy {
  checkParts(input)
  return policyFromEnv(toEnvRecord(input), audience)
}

export async function saveRunnerPolicy(db: Db, input: RunnerPolicyInput, audience: string): Promise<void> {
  buildPolicy(input, audience)
  const value = JSON.stringify(input)
  if (value.length > 480) throw new Error('Runner settings are too long')
  await putSetting(db, KEY, value)
}

export async function loadRunnerPolicyInput(db: Db): Promise<RunnerPolicyInput | null> {
  const raw = await getSetting(db, KEY)
  if (!raw) return null
  try {
    const p = JSON.parse(raw) as Record<string, unknown>
    const text = (k: string) => (typeof p[k] === 'string' ? (p[k] as string) : '')
    return {
      repository: text('repository'), repositoryId: text('repositoryId'), branch: text('branch'),
      workflowFile: text('workflowFile'), events: text('events'),
      ...(text('repositoryOwnerId') ? { repositoryOwnerId: text('repositoryOwnerId') } : {}),
    }
  } catch {
    return null
  }
}

/** Policy for the runner API. Throws when nothing is configured: callers fail closed. */
export async function loadRunnerPolicy(db: Db, e: VaultEnv, audience: string): Promise<OidcPolicy> {
  if (typeof e.RUNNER_REPOSITORY === 'string' && e.RUNNER_REPOSITORY.trim()) return policyFromEnv(e, audience)
  const stored = await loadRunnerPolicyInput(db)
  if (stored) return buildPolicy(stored, audience)
  const ownerId = await loadOwnerId(db, e)
  if (!ownerId) throw new Error('vault owner is not configured')
  return buildBootstrapPolicy(ownerId, audience)
}

/** Looks up a public repository's numeric id so the owner does not have to. */
export async function resolveRepositoryId(repository: string, fetchFn: typeof fetch = fetch): Promise<string | null> {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)) return null
  try {
    const res = await fetchFn(`https://api.github.com/repos/${repository}`, {
      headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'runner-credential-vault', 'X-GitHub-Api-Version': '2022-11-28' },
      redirect: 'manual',
    })
    if (res.status !== 200) return null
    const body = (await res.json()) as { id?: unknown; full_name?: unknown }
    if (typeof body.id !== 'number' || !Number.isSafeInteger(body.id)) return null
    // GitHub canonicalises case and renames; refuse a mismatch rather than pin the wrong repository.
    if (typeof body.full_name !== 'string' || body.full_name.toLowerCase() !== repository.toLowerCase()) return null
    return String(body.id)
  } catch {
    return null
  }
}

