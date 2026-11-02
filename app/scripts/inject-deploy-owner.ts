import { execFileSync } from 'node:child_process'

const GITHUB_ID_PATTERN = /^[1-9][0-9]{0,15}$/

/**
 * The GitHub account a deployment is bound to. `id` is null when it could not be
 * determined safely; then the Worker stays locked and `/setup` explains why using
 * `error`. A build never fails just because GitHub was unreachable.
 */
export interface DeployOwner {
  id: string | null
  login?: string
  repo?: string
  error?: 'organization' | 'lookup_failed' | 'no_identity'
}

type Fetch = typeof fetch

function repositoryFromRemote(remote: string): { owner: string; repo: string } {
  const match = remote.trim().match(/^(?:https?:\/\/(?:[^@/]+@)?github\.com\/|ssh:\/\/git@github\.com\/|git@github\.com:)([A-Za-z0-9-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/i)
  if (!match) throw new Error('Git origin is not a supported github.com repository URL')
  return { owner: match[1], repo: match[2] }
}

function validatedId(value: string | undefined, source: string): string {
  const id = value?.trim() ?? ''
  if (!GITHUB_ID_PATTERN.test(id)) {
    throw new Error(source + ' did not provide a valid numeric GitHub account ID')
  }
  return id
}

function actionsContextMatchesOwner(env: NodeJS.ProcessEnv, expectedOwner: string): boolean {
  const contextOwner = env.GITHUB_REPOSITORY_OWNER?.trim()
  const repository = env.GITHUB_REPOSITORY?.trim()
  if (!contextOwner || !repository) return false
  const parts = repository.split('/')
  if (parts.length !== 2 || !parts[0] || !parts[1]) return false
  const expected = expectedOwner.toLowerCase()
  return contextOwner.toLowerCase() === expected && parts[0].toLowerCase() === expected
}

/**
 * Trust the immutable Actions owner ID for a checked-out origin only when both
 * repository context values identify the same owner as that origin.
 */
export function resolveGitHubActionsOwnerId(
  env: NodeJS.ProcessEnv = process.env,
  expectedOwner?: string,
): string | null {
  const value = env.GITHUB_REPOSITORY_OWNER_ID
  if (!value) return null
  const ownerId = validatedId(value, 'GITHUB_REPOSITORY_OWNER_ID')
  if (expectedOwner && !actionsContextMatchesOwner(env, expectedOwner)) {
    console.warn('[deploy-owner] ignoring GitHub Actions owner ID because its repository context does not match the checked-out origin owner')
    return null
  }
  console.log('[deploy-owner] using GitHub Actions repository owner ID ' + ownerId)
  return ownerId
}

function fromGhCli(): string | null {
  try {
    const output = execFileSync('gh', ['api', 'user', '--jq', '.id'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 5_000,
    })
    return validatedId(output, 'GitHub CLI authentication')
  } catch {
    return null
  }
}

type Lookup = { id: string; login: string; type: string } | null

/** Preferred: the JSON API (stable, typed). A token only raises the rate limit. */
async function lookupViaApi(owner: string, fetchFn: Fetch, env: NodeJS.ProcessEnv): Promise<Lookup> {
  try {
    const token = env.GITHUB_TOKEN || env.GH_TOKEN
    const response = await fetchFn('https://api.github.com/users/' + encodeURIComponent(owner), {
      headers: {
        Accept: 'application/vnd.github+json',
        'User-Agent': 'runner-vault-deploy-owner',
        ...(token ? { Authorization: 'Bearer ' + token } : {}),
      },
      signal: AbortSignal.timeout(10_000),
    })
    if (!response.ok) return null
    const body = await response.json() as { id?: unknown; login?: unknown; type?: unknown }
    if (typeof body.id !== 'number' || typeof body.login !== 'string' || typeof body.type !== 'string') return null
    return { id: validatedId(String(body.id), 'GitHub API'), login: body.login, type: body.type }
  } catch {
    return null
  }
}

/**
 * Resolve the owner before every production Vite build. Never throws for a lookup
 * problem (only for a malformed explicit ID): the Worker simply stays locked.
 *
 * Priority:
 * 1. Explicit numeric ID (RUNNER_VAULT_OWNER_GITHUB_ID).
 * 2. Checked-out GitHub origin via the typed JSON API, then a matching Actions
 *    owner ID whose repository context matches that origin.
 * 3. Without a Git origin, GitHub Actions' owner ID / authenticated GitHub CLI.
 *
 * HTML profile metadata is not trusted because it cannot prove account type.
 */
export async function injectDeployOwner(
  env: NodeJS.ProcessEnv = process.env,
  fetchFn: Fetch = fetch,
  readRemote: () => string = () => execFileSync('git', ['remote', 'get-url', 'origin'], {
    encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 5_000,
  }),
): Promise<DeployOwner> {
  const explicitId = env.RUNNER_VAULT_OWNER_GITHUB_ID
  if (explicitId) {
    const id = validatedId(explicitId, 'RUNNER_VAULT_OWNER_GITHUB_ID')
    console.log('[deploy-owner] using explicitly configured GitHub account ID ' + id)
    return { id }
  }

  let remote = ''
  try { remote = readRemote().trim() } catch { /* a source archive has no Git repository */ }

  let identity: { owner: string; repo: string } | null = null
  if (remote) {
    try { identity = repositoryFromRemote(remote) } catch { identity = null }
  }

  if (identity) {
    const repo = identity.owner + '/' + identity.repo
    const found = await lookupViaApi(identity.owner, fetchFn, env)
    if (found) {
      if (found.type !== 'User') {
        console.warn('[deploy-owner] ' + identity.owner + ' is an organization; setup stays locked until RUNNER_VAULT_OWNER_GITHUB_ID is set to a personal account ID')
        return { id: null, login: found.login, repo, error: 'organization' }
      }
      console.log('[deploy-owner] bound GitHub account ID ' + found.id + ' from ' + repo)
      return { id: found.id, login: found.login, repo }
    }
    const actionsId = resolveGitHubActionsOwnerId(env, identity.owner)
    if (actionsId) return { id: actionsId, login: identity.owner, repo }
    console.warn('[deploy-owner] could not verify ' + identity.owner + ' as a personal GitHub account; setup stays locked until RUNNER_VAULT_OWNER_GITHUB_ID is set')
    return { id: null, login: identity.owner, repo, error: 'lookup_failed' }
  }

  const actionsId = resolveGitHubActionsOwnerId(env)
  if (actionsId) return { id: actionsId }
  const cliId = fromGhCli()
  if (cliId) {
    console.log('[deploy-owner] bound authenticated GitHub CLI account ID ' + cliId)
    return { id: cliId }
  }
  console.warn('[deploy-owner] no GitHub identity available; set RUNNER_VAULT_OWNER_GITHUB_ID to your numeric GitHub user ID')
  return { id: null, error: 'no_identity' }
}
