import { execFileSync } from 'node:child_process'

function repositoryFromRemote(remote: string): { owner: string; repo: string } {
  const match = remote.trim().match(/^(?:https?:\/\/(?:[^@/]+@)?github\.com\/|ssh:\/\/git@github\.com\/|git@github\.com:)([A-Za-z0-9-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/i)
  if (!match) throw new Error('Workers Builds origin is not a supported github.com repository URL')
  return { owner: match[1], repo: match[2] }
}

function metaContent(html: string, name: string): string | null {
  const escaped = name.replace(/[.*+?^\x24{}()|[\]\\]/g, '\\$&')
  const tag = html.match(new RegExp('<meta\\b(?=[^>]*\\bname=["\\']' + escaped + '["\\'])[^>]*>', 'i'))?.[0]
  return tag?.match(/\\bcontent=["']([^"']+)["']/i)?.[1] ?? null
}

/**
 * Workers Builds exposes WORKERS_CI=1. The Git origin belongs to the
 * repository that Cloudflare actually checked out (the deployer's copy or
 * an explicitly imported fork). GitHub's public repository HTML includes
 * its numeric owner ID in metadata; use that instead of the unauthenticated
 * REST API, whose shared 60-request/hour IP limit can break parallel deploys.
 */
export async function injectDeployOwner(): Promise<string | null> {
  if (process.env.WORKERS_CI !== '1') return null

  const remote = execFileSync('git', ['remote', 'get-url', 'origin'], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  const { owner, repo } = repositoryFromRemote(remote)
  const repositoryUrl = 'https://github.com/' + encodeURIComponent(owner) + '/' + encodeURIComponent(repo)
  const response = await fetch(repositoryUrl, {
    headers: {
      Accept: 'text/html',
      'User-Agent': 'runner-vault-deploy-owner',
    },
    signal: AbortSignal.timeout(10_000),
  })
  if (!response.ok) throw new Error('GitHub repository page lookup failed with HTTP ' + response.status)

  const html = await response.text()
  const ownerId = metaContent(html, 'octolytics-dimension-user_id')
  const ownerLogin = metaContent(html, 'octolytics-dimension-user_login')
  const repositoryNwo = metaContent(html, 'octolytics-dimension-repository_nwo')
  const isPublic = metaContent(html, 'octolytics-dimension-repository_public')
  if (!ownerId || !/^[1-9][0-9]{0,15}$/.test(ownerId)) {
    throw new Error('GitHub repository page did not expose a valid numeric owner ID')
  }
  if (ownerLogin?.toLowerCase() !== owner.toLowerCase()) {
    throw new Error('GitHub repository owner metadata does not match the checked-out origin')
  }
  if (repositoryNwo?.toLowerCase() !== (owner + '/' + repo).toLowerCase()) {
    throw new Error('GitHub repository metadata does not match the checked-out origin')
  }
  if (isPublic !== 'true') {
    throw new Error('The deployed GitHub repository must be publicly readable for owner verification')
  }

  console.log('[deploy-owner] bound GitHub account ID ' + ownerId + ' from ' + owner + '/' + repo)
  return ownerId
}
