import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

// Publishes deployment.json at the repository root after a successful deploy
// (see .github/workflows/deploy.yml). The Runner Lab discovers the vault from
// that file, so nobody has to copy the Worker URL or a client commit SHA into
// Lab-side configuration by hand.

const appDir = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const repoRoot = resolve(appDir, '..')

export function parseWorkerName(wranglerConfigSource) {
  const name = /"name"\s*:\s*"([^"]+)"/.exec(wranglerConfigSource)?.[1]
  if (!name) throw new Error('wrangler.jsonc is missing the Worker "name"')
  return name
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

export function buildDeploymentInfo({ worker, subdomain, clientRef, now = new Date() }) {
  if (typeof clientRef !== 'string' || !/^[0-9a-f]{40}$/.test(clientRef)) {
    throw new Error('GITHUB_SHA must be an immutable 40-character commit SHA')
  }
  return {
    url: buildVaultUrl(worker, subdomain),
    clientRef,
    worker,
    updatedAt: now.toISOString(),
  }
}

async function main() {
  const subdomain = await resolveWorkersSubdomain({
    configuredSubdomain: process.env.CLOUDFLARE_WORKERS_SUBDOMAIN,
    token: process.env.CLOUDFLARE_API_TOKEN?.trim(),
    accountId: process.env.CLOUDFLARE_ACCOUNT_ID?.trim(),
  })
  const worker = parseWorkerName(readFileSync(resolve(appDir, 'wrangler.jsonc'), 'utf8'))
  const info = buildDeploymentInfo({ worker, subdomain, clientRef: process.env.GITHUB_SHA })
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
