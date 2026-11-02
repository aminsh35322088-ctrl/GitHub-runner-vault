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

function metaContent(html: string, name: string): string | null {
  const tag = html.match(new RegExp(`<meta\\b(?=[^>]*\\bname="${name}")[^>]*>`, 'i'))?.[0]
  return tag?.match(/\bcontent="([^"]+)"/i)?.[1] ?? null
}

function validatedId(value: string | undefined, source: string): string {
  const id = value?.trim() ?? ''
  if (!GITHUB_ID_PATTERN.test(id)) {
    throw new Error(source + ' did not provide a valid numeric GitHub account ID')
  }
  return id
}

export function resolveGitHubActionsOwnerId(env: NodeJS.ProcessEnv = process.env): string | null {
  const value = env.GITHUB_REPOSITORY_OWNER_ID
  if (!value) return null
  const ownerId = validatedId(value, 'GITHUB_REPOSITORY_OWNER_ID')
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

/** Last resort: the public profile page's metadata. */
async function lookupViaProfileHtml(owner: string, fetchFn: Fetch): Promise<Lookup> {
  try {
    const response = await fetchFn('https://github.com/' + encodeURIComponent(owner), {
      headers: { Accept: 'text/html', 'User-Agent': 'runner-vault-deploy-owner' },
      signal: AbortSignal.timeout(10_000),
    })
    if (!response.ok) return null
    const html = await response.text()
    const id = metaContent(html, 'octolytics-dimension-user_id')
    const login = metaContent(html, 'octolytics-dimension-user_login')
    if (!id || !login) return null
    // The profile page does not state the account type; the manifest flow rejects
    // organizations later because the App must be created by a User.
    return { id: validatedId(id, 'GitHub profile'), login, type: 'User' }
  } catch {
    return null
  }
}

/**
 * Resolve the owner before every production Vite build. Never throws for a lookup
 * problem (only for a malformed explicit ID): the Worker simply stays locked.
 *
 * Priority:
 * 1. Explicit numeric ID (`RUNNER_VAULT_OWNER_GITHUB_ID`).
 * 2. Owner of the checked-out GitHub origin: JSON API, then
 *    GitHub Actions' immutable owner id, then the profile page.
 * 3. GitHub Actions' owner id / authenticated GitHub CLI when there is no GitHub origin.
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
    const actionsId = resolveGitHubActionsOwnerId(env)
    if (actionsId) return { id: actionsId, login: identity.owner, repo }
    const scraped = await lookupViaProfileHtml(identity.owner, fetchFn)
    if (scraped && scraped.login.toLowerCase() === identity.owner.toLowerCase()) {
      console.log('[deploy-owner] bound GitHub account ID ' + scraped.id + ' from ' + repo + ' (profile page)')
      return { id: scraped.id, login: scraped.login, repo }
    }
    console.warn('[deploy-owner] could not look up ' + identity.owner + '; setup stays locked until RUNNER_VAULT_OWNER_GITHUB_ID is set')
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
