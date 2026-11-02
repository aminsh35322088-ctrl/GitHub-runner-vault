import { execFileSync } from 'node:child_process'

const GITHUB_ID_PATTERN = /^[1-9][0-9]{0,15}$/

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

const fromGitHubActions = () => resolveGitHubActionsOwnerId()

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

/**
 * Resolve the owner before every production Vite build.
 *
 * Priority:
 * 1. Explicit numeric ID for source archives/manual deployments.
 * 2. Owner of the checked-out GitHub origin (Deploy Button, dashboard Git
 *    connection, or a local Git clone).
 * 3. GitHub Actions' immutable repository-owner ID when no usable origin exists.
 * 4. Authenticated GitHub CLI account when no GitHub origin is available.
 *
 * The Worker independently verifies the GitHub App creator against this ID.
 */
export async function injectDeployOwner(): Promise<string> {
  const explicitId = process.env.RUNNER_VAULT_OWNER_GITHUB_ID
  if (explicitId) {
    const ownerId = validatedId(explicitId, 'RUNNER_VAULT_OWNER_GITHUB_ID')
    console.log('[deploy-owner] using explicitly configured GitHub account ID ' + ownerId)
    return ownerId
  }

  let remote = ''
  try {
    remote = execFileSync('git', ['remote', 'get-url', 'origin'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 5_000,
    }).trim()
  } catch {
    // A downloaded source archive may not contain a Git repository.
  }

  if (remote) {
    let identity: { owner: string; repo: string }
    try {
      identity = repositoryFromRemote(remote)
    } catch {
      const actionsId = fromGitHubActions()
      if (actionsId) return actionsId
      const cliId = fromGhCli()
      if (cliId) {
        console.log('[deploy-owner] using authenticated GitHub CLI account ID ' + cliId + ' (origin is not GitHub)')
        return cliId
      }
      throw new Error('No GitHub origin was found. Clone your personal GitHub repository or authenticate with gh, or set RUNNER_VAULT_OWNER_GITHUB_ID explicitly.')
    }

    const profileUrl = 'https://github.com/' + encodeURIComponent(identity.owner)
    const response = await fetch(profileUrl, {
      headers: {
        Accept: 'text/html',
        'User-Agent': 'runner-vault-deploy-owner',
      },
      signal: AbortSignal.timeout(10_000),
    })
    if (!response.ok) throw new Error('GitHub profile lookup failed with HTTP ' + response.status)

    const html = await response.text()
    const ownerId = validatedId(metaContent(html, 'octolytics-dimension-user_id') ?? undefined, 'GitHub profile')
    const ownerLogin = metaContent(html, 'octolytics-dimension-user_login')
    if (ownerLogin?.toLowerCase() !== identity.owner.toLowerCase()) {
      throw new Error('GitHub profile identity does not match the checked-out origin owner')
    }

    console.log('[deploy-owner] bound GitHub account ID ' + ownerId + ' from ' + identity.owner + '/' + identity.repo)
    return ownerId
  }

  const actionsOwnerId = fromGitHubActions()
  if (actionsOwnerId) return actionsOwnerId

  const cliId = fromGhCli()
  if (cliId) {
    console.log('[deploy-owner] bound authenticated GitHub CLI account ID ' + cliId)
    return cliId
  }

  throw new Error('No GitHub identity is available. Clone your personal GitHub repository, run gh auth login, or set RUNNER_VAULT_OWNER_GITHUB_ID to your numeric GitHub user ID.')
}
