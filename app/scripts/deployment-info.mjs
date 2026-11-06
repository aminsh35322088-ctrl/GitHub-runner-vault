import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

// Publishes deployment.json at the repository root after a successful deploy
// (see .github/workflows/deploy.yml). The Runner Lab discovers the vault from
// that file, so nobody has to copy the Worker URL or a client commit SHA into
// Lab-side configuration by hand.

const appDir = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const repoRoot = resolve(appDir, '..')

export function parseWorkerName(wranglerConfigSource, configuredName = '') {
  const override = typeof configuredName === 'string' ? configuredName.trim() : ''
  const name = override || /"name"\s*:\s*"([^"]+)"/.exec(wranglerConfigSource)?.[1]
  if (!name || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(name)) {
    throw new Error('Worker name is missing or is not workers.dev-compatible')
  }
  return name
}

export function parseRepository(value) {
  if (typeof value !== 'string') throw new Error('RUNNER_VAULT_REPOSITORY must be owner/name')
  const repository = value.trim()
  if (!/^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/.test(repository)) {
    throw new Error('RUNNER_VAULT_REPOSITORY must be a valid GitHub owner/name')
  }
  return repository
}

export function repositoryFromRemote(remote) {
  if (typeof remote !== 'string') throw new Error('Git origin is not configured')
  const value = remote.trim()
  const match = /^(?:https?:\/\/(?:[^@/]+@)?github\.com\/|ssh:\/\/git@github\.com\/|git@github\.com:)([A-Za-z0-9-]{1,39})\/([A-Za-z0-9_.-]{1,100}?)(?:\.git)?\/?$/i.exec(value)
  if (!match) throw new Error('Git origin is not a supported GitHub repository URL')
  return parseRepository(match[1] + '/' + match[2])
}

export function resolveRepositoryIdentity(actionsRepository, configuredRepository, gitRemote) {
  const actionRepo = typeof actionsRepository === 'string' ? actionsRepository.trim() : ''
  const configured = typeof configuredRepository === 'string' ? configuredRepository.trim() : ''
  if (actionRepo) {
    const actual = parseRepository(actionRepo)
    if (configured && parseRepository(configured).toLowerCase() !== actual.toLowerCase()) {
      throw new Error('RUNNER_VAULT_REPOSITORY must match GITHUB_REPOSITORY')
    }
    return actual
  }
  return configured ? parseRepository(configured) : repositoryFromRemote(gitRemote)
}

function resolveRepository(configuredRepository) {
  let remote = ''
  if (!process.env.GITHUB_REPOSITORY && !configuredRepository) {
    try { remote = execFileSync('git', ['remote', 'get-url', 'origin'], { cwd: repoRoot, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 5_000 }) }
    catch {}
  }
  try {
    return resolveRepositoryIdentity(process.env.GITHUB_REPOSITORY, configuredRepository, remote)
  } catch (error) {
    if (error instanceof Error && error.message === 'Git origin is not configured') {
      throw new Error('Could not identify the Vault repository; set RUNNER_VAULT_REPOSITORY to owner/name')
    }
    throw error
  }
}

export function parsePublicVaultUrl(value) {
  if (typeof value !== 'string' || !value.trim() || value !== value.trim()) {
    throw new Error('RUNNER_VAULT_PUBLIC_URL must be an HTTPS origin')
  }
  let url
  try { url = new URL(value) } catch { throw new Error('RUNNER_VAULT_PUBLIC_URL is invalid') }
  if (url.protocol !== 'https:' || !url.hostname || url.username || url.password
    || (url.port && url.port !== '443') || (url.pathname !== '/' && url.pathname !== '')
    || url.search || url.hash) {
    throw new Error('RUNNER_VAULT_PUBLIC_URL must be an HTTPS origin without credentials, port, path, query or fragment')
  }
  return url.origin
}

export function parseWorkersSubdomain(payload) {
  if (payload && payload.success === false) {
    const message = payload.errors?.find((item) => typeof item?.message === 'string')?.message
    throw new Error('Cloudflare did not return the workers.dev subdomain' + (message ? ': ' + message : ''))
  }
  const subdomain = payload?.result?.subdomain
  if (typeof subdomain !== 'string' || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(subdomain.trim())) {
    throw new Error('Cloudflare did not return a valid workers.dev subdomain')
  }
  return subdomain.trim()
}

export async function resolveWorkersSubdomain({ configuredSubdomain, token, accountId, fetchImpl = fetch }) {
  const override = typeof configuredSubdomain === 'string' ? configuredSubdomain.trim() : ''
  if (override) return parseWorkersSubdomain({ success: true, result: { subdomain: override } })
  if (!token) throw new Error('CLOUDFLARE_API_TOKEN is not set; set CLOUDFLARE_WORKERS_SUBDOMAIN to use an authenticated Wrangler deployment')
  if (!accountId) throw new Error('CLOUDFLARE_ACCOUNT_ID is not set')

  const response = await fetchImpl(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/subdomain`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  const body = await response.json().catch(() => null)
  if (!response.ok) {
    const detail = body?.errors?.find((item) => typeof item?.message === 'string')?.message
    throw new Error('Cloudflare workers.dev lookup failed' + (detail ? ': ' + detail : ''))
  }
  return parseWorkersSubdomain(body)
}

export function buildVaultUrl(worker, subdomain) {
  return `https://${worker}.${subdomain}.workers.dev`
}

export function buildDeploymentInfo({ worker, subdomain, publicUrl, repository, clientRef, now = new Date() }) {
  if (typeof clientRef !== 'string' || !/^[0-9a-f]{40}$/.test(clientRef)) {
    throw new Error('GITHUB_SHA must be an immutable 40-character commit SHA')
  }
  return {
    url: publicUrl ? parsePublicVaultUrl(publicUrl) : buildVaultUrl(worker, subdomain),
    clientRef,
    worker,
    repository: parseRepository(repository),
    updatedAt: now.toISOString(),
  }
}

async function main() {
  const publicUrl = process.env.RUNNER_VAULT_PUBLIC_URL?.trim() || process.env.PUBLIC_ORIGIN?.trim() || ''
  const generatedConfig = resolve(appDir, 'dist/rsc/wrangler.json')
  const sourceConfig = resolve(appDir, 'wrangler.jsonc')
  const workerConfig = readFileSync(existsSync(generatedConfig) ? generatedConfig : sourceConfig, 'utf8')
  const worker = parseWorkerName(workerConfig, process.env.RUNNER_VAULT_WORKER_NAME)
  const repository = resolveRepository(process.env.RUNNER_VAULT_REPOSITORY?.trim())
  const subdomain = publicUrl ? '' : await resolveWorkersSubdomain({
    configuredSubdomain: process.env.CLOUDFLARE_WORKERS_SUBDOMAIN,
    token: process.env.CLOUDFLARE_API_TOKEN?.trim(),
    accountId: process.env.CLOUDFLARE_ACCOUNT_ID?.trim(),
  })
  const info = buildDeploymentInfo({ worker, subdomain, publicUrl, repository, clientRef: process.env.GITHUB_SHA })
  writeFileSync(resolve(repoRoot, 'deployment.json'), JSON.stringify(info, null, 2) + '\n')
  console.log('[deployment-info] wrote deployment.json for ' + info.url)
}

if (process.argv[1] && import.meta.url === new URL('file://' + resolve(process.argv[1])).href) {
  try {
    await main()
  } catch (error) {
    console.error('[deployment-info] ' + (error instanceof Error ? error.message : String(error)))
    process.exitCode = 1
  }
}
