// Resolve the owner of the repository cloned by Deploy to Cloudflare.
// Workers Builds checks out the user's newly-created GitHub repository. Its
// origin remote is therefore the authoritative source for the fork owner.
import { execFileSync } from 'node:child_process'
import { readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'

if (process.env.WORKERS_CI !== '1') {
  console.log('[deploy-owner] skipped outside Cloudflare Workers Builds')
  process.exit(0)
}

function repositoryFromRemote(remote) {
  const value = remote.trim()
  const match = value.match(/^(?:https?:\/\/(?:[^@/]+@)?github\.com\/|ssh:\/\/git@github\.com\/|git@github\.com:)([A-Za-z0-9-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/i)
  if (!match) throw new Error('Workers Builds origin is not a supported github.com repository URL')
  return { owner: match[1], repo: match[2] }
}

function writeOwnerVar(config, ownerId) {
  const vars = config.match(/("vars"\s*:\s*)\{([\s\S]*?)\}/m)
  if (!vars) throw new Error('wrangler.jsonc must contain a top-level vars object')

  const ownerEntry = /("OWNER_GITHUB_ID"\s*:\s*)"[^"]*"/
  let body
  if (ownerEntry.test(vars[2])) {
    body = vars[2].replace(ownerEntry, \`$1"\${ownerId}"\`)
  } else {
    const existing = vars[2].trim().replace(/,\s*$/, '')
    body = existing
      ? \`\\n\${existing},\\n    "OWNER_GITHUB_ID": "\${ownerId}"\\n  \`
      : \`\\n    "OWNER_GITHUB_ID": "\${ownerId}"\\n  \`
  }
  return config.replace(vars[0], \`\${vars[1]}{\${body}}\`)
}

const remote = execFileSync('git', ['remote', 'get-url', 'origin'], {
  encoding: 'utf8',
  stdio: ['ignore', 'pipe', 'pipe'],
})
const { owner, repo } = repositoryFromRemote(remote)
const response = await fetch(\`https://api.github.com/repos/\${encodeURIComponent(owner)}/\${encodeURIComponent(repo)}\`, {
  headers: {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'runner-vault-deploy-owner',
    'X-GitHub-Api-Version': '2022-11-28',
  },
})
if (!response.ok) throw new Error(\`GitHub repository lookup failed with HTTP \${response.status}\`)

const repository = await response.json()
if (repository.full_name?.toLowerCase() !== \`\${owner}/\${repo}\`.toLowerCase()) {
  throw new Error('GitHub repository metadata does not match the checked-out origin')
}
if (repository.owner?.type !== 'User') {
  throw new Error('Runner Vault ownership requires a personal GitHub account, not an organization')
}
const ownerId = String(repository.owner.id ?? '')
if (!/^[1-9][0-9]{0,15}$/.test(ownerId)) {
  throw new Error('GitHub returned an invalid numeric repository owner ID')
}

const configPath = resolve(process.cwd(), 'wrangler.jsonc')
const before = readFileSync(configPath, 'utf8')
const after = writeOwnerVar(before, ownerId)
if (after !== before) writeFileSync(configPath, after)
console.log(\`[deploy-owner] bound GitHub user ID \${ownerId} from \${owner}/\${repo}\`)
