// Which GitHub Actions workflow may talk to this vault.
//
// The owner enters it once in Settings (repository, branch, workflow file). It is
// stored in D1 and turned into the same strict OidcPolicy the RUNNER_* Worker
// variables produce, so one validator covers both. Worker variables still win when
// present (older deployments). Nothing here is inferred from a token: a runner can
// never choose or widen its own policy.

import { policyFromEnv, type OidcPolicy } from './oidc.ts'
import { getSetting, putSetting, type VaultEnv } from './vault-config.ts'

type Db = ReturnType<typeof import('db').getDb>

const KEY = 'runner_policy'
export const DEFAULT_EVENTS = 'workflow_dispatch,schedule,push'

export interface RunnerPolicyInput {
  repository: string
  repositoryId: string
  branch: string
  workflowFile: string
  events: string
}

function toEnvRecord(p: RunnerPolicyInput): Record<string, string> {
  return {
    RUNNER_REPOSITORY: p.repository,
    RUNNER_REPOSITORY_ID: p.repositoryId,
    RUNNER_ALLOWED_REFS: `refs/heads/${p.branch}`,
    RUNNER_ALLOWED_EVENTS: p.events,
    RUNNER_ALLOWED_WORKFLOW_REFS: `${p.repository}/.github/workflows/${p.workflowFile}@refs/heads/${p.branch}`,
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
    return { repository: text('repository'), repositoryId: text('repositoryId'), branch: text('branch'), workflowFile: text('workflowFile'), events: text('events') }
  } catch {
    return null
  }
}

/** Policy for the runner API. Throws when nothing is configured: callers fail closed. */
export async function loadRunnerPolicy(db: Db, e: VaultEnv, audience: string): Promise<OidcPolicy> {
  if (typeof e.RUNNER_REPOSITORY === 'string' && e.RUNNER_REPOSITORY.trim()) return policyFromEnv(e, audience)
  const stored = await loadRunnerPolicyInput(db)
  if (!stored) throw new Error('runner repository is not configured')
  return buildPolicy(stored, audience)
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

