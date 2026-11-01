import { execFileSync } from 'node:child_process'

type GitHubRepository = {
  full_name?: string
  owner?: {
    id?: number | string
    type?: string
  }
}

function repositoryFromRemote(remote: string): { owner: string; repo: string } {
  const match = remote.trim().match(/^(?:https?:\/\/(?:[^@/]+@)?github\.com\/|ssh:\/\/git@github\.com\/|git@github\.com:)([A-Za-z0-9-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/i)
  if (!match) throw new Error('Workers Builds origin is not a supported github.com repository URL')
  return { owner: match[1], repo: match[2] }
}

/**
 * Workers Builds exposes WORKERS_CI=1. The Git origin belongs to the
 * repository that Cloudflare actually checked out (the deployer's copy or
 * an explicitly imported fork), so its GitHub owner is the deployment owner.
 */
export async function injectDeployOwner(): Promise<string | null> {
  if (process.env.WORKERS_CI !== '1') return null

  const remote = execFileSync('git', ['remote', 'get-url', 'origin'], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  const { owner, repo } = repositoryFromRemote(remote)
  const apiUrl = 'https://api.github.com/repos/' + encodeURIComponent(owner) + '/' + encodeURIComponent(repo)
  const response = await fetch(apiUrl, {
    headers: {
      Accept: 'application/vnd.github+json',
      'User-Agent': 'runner-vault-deploy-owner',
      'X-GitHub-Api-Version': '2022-11-28',
    },
    signal: AbortSignal.timeout(10_000),
  })
  if (!response.ok) throw new Error('GitHub repository lookup failed with HTTP ' + response.status)

  const repository = await response.json() as GitHubRepository
  if (repository.full_name?.toLowerCase() !== (owner + '/' + repo).toLowerCase()) {
    throw new Error('GitHub repository metadata does not match the checked-out origin')
  }
  if (repository.owner?.type !== 'User') {
    throw new Error('Runner Vault ownership requires a personal GitHub account, not an organization')
  }
  const ownerId = String(repository.owner.id ?? '')
  if (!/^[1-9][0-9]{0,15}$/.test(ownerId)) {
    throw new Error('GitHub returned an invalid numeric repository owner ID')
  }

  console.log('[deploy-owner] bound GitHub user ID ' + ownerId + ' from ' + owner + '/' + repo)
  return ownerId
}
