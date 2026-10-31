#!/usr/bin/env node
import fs from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { createInterface } from 'node:readline/promises'
import { stdin, stdout } from 'node:process'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const appDir = path.join(root, 'app')
const baseConfigPath = path.join(appDir, 'wrangler.jsonc')
const localConfigPath = path.join(appDir, 'wrangler.local.jsonc')
const secretsPath = path.join(root, '.vault.secrets.json')
const forceConfigure = process.argv.includes('--configure')

function execute(command, args, options = {}) {
  const executable = process.platform === 'win32' && command === 'pnpm' ? 'pnpm.cmd' : command
  const result = spawnSync(executable, args, {
    shell: process.platform === 'win32' && command === 'pnpm',
    cwd: options.cwd ?? root,
    env: options.env ?? process.env,
    stdio: options.capture ? ['ignore', 'pipe', 'inherit'] : 'inherit',
    encoding: options.capture ? 'utf8' : undefined,
  })
  if (result.error) throw result.error
  if (result.status !== 0) throw new Error(command + ' ' + args.join(' ') + ' failed (exit ' + result.status + ')')
  return options.capture ? result.stdout.trim() : ''
}

async function ask(rl, label, fallback = '') {
  const suffix = fallback ? ' [' + fallback + ']' : ''
  const answer = (await rl.question(label + suffix + ': ')).trim()
  return answer || fallback
}

function writePrivate(file, content) {
  fs.writeFileSync(file, content, { mode: 0o600 })
  try { fs.chmodSync(file, 0o600) } catch {}
}

async function githubJson(url) {
  const headers = { Accept: 'application/vnd.github+json', 'User-Agent': 'runner-vault-deploy' }
  const token = process.env.GH_TOKEN || process.env.GITHUB_TOKEN
  if (token) headers.Authorization = 'Bearer ' + token
  const response = await fetch(url, { headers })
  if (!response.ok) throw new Error('GitHub API returned HTTP ' + response.status)
  return response.json()
}

function readConfig() {
  if (fs.existsSync(localConfigPath)) return JSON.parse(fs.readFileSync(localConfigPath, 'utf8'))
  return JSON.parse(fs.readFileSync(baseConfigPath, 'utf8'))
}

function validName(value, label) {
  if (!/^[a-z0-9][a-z0-9-]{0,57}$/.test(value)) throw new Error(label + ' must use lowercase letters, digits and hyphens')
  return value
}

async function collectInstallConfig(rl) {
  const workerName = validName(await ask(rl, 'Cloudflare Worker name', 'runner-vault'), 'Worker name')
  const ownerLogin = await ask(rl, 'Owner GitHub username')
  if (!/^[A-Za-z0-9-]{1,39}$/.test(ownerLogin)) throw new Error('Invalid GitHub username')
  let ownerId
  try {
    const owner = await githubJson('https://api.github.com/users/' + encodeURIComponent(ownerLogin))
    ownerId = String(owner.id)
  } catch {
    ownerId = await ask(rl, 'Numeric GitHub user ID (needed when the GitHub API is unavailable)')
  }
  if (!/^\d{1,20}$/.test(ownerId)) throw new Error('Owner GitHub ID must be numeric')

  const repository = await ask(rl, 'Runner repository (owner/name)')
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)) throw new Error('Runner repository must be owner/name')
  let repositoryId
  try {
    const encodedRepo = repository.split('/').map(encodeURIComponent).join('/')
    const metadata = await githubJson('https://api.github.com/repos/' + encodedRepo)
    repositoryId = String(metadata.id)
  } catch {
    repositoryId = await ask(rl, 'Numeric repository ID (needed for private repositories when GH_TOKEN is unavailable)')
  }
  if (!/^\d{1,20}$/.test(repositoryId)) throw new Error('Repository ID must be numeric')

  const branch = await ask(rl, 'Allowed Git ref branch', 'main')
  if (!/^[A-Za-z0-9._/-]{1,200}$/.test(branch) || branch.startsWith('/') || branch.includes('..')) throw new Error('Invalid branch name')
  const workflowFile = await ask(rl, 'Workflow path', '.github/workflows/runner.yml')
  if (!workflowFile.startsWith('.github/workflows/') || workflowFile.includes('..') || workflowFile.includes('@')) {
    throw new Error('Workflow path must be inside .github/workflows/')
  }
  const events = await ask(rl, 'Allowed GitHub Actions events (comma-separated)', 'workflow_dispatch,schedule,push')
  const allowedEvents = events.split(',').map((v) => v.trim()).filter(Boolean)
  if (!allowedEvents.length || allowedEvents.some((v) => v === 'pull_request' || v === 'pull_request_target')) {
    throw new Error('Configure at least one event; pull-request events are not supported')
  }
  const publicOrigin = await ask(rl, 'Optional canonical PUBLIC_ORIGIN (leave empty to use the actual request URL)')
  if (publicOrigin) {
    const url = new URL(publicOrigin)
    if (url.protocol !== 'https:' || url.origin !== publicOrigin.replace(/\/$/, '')) {
      throw new Error('PUBLIC_ORIGIN must be an HTTPS origin without a path or trailing slash')
    }
  }

  return {
    workerName,
    vars: {
      OWNER_GITHUB_ID: ownerId,
      RUNNER_REPOSITORY: repository,
      RUNNER_REPOSITORY_ID: repositoryId,
      RUNNER_ALLOWED_REFS: 'refs/heads/' + branch,
      RUNNER_ALLOWED_EVENTS: allowedEvents.join(','),
      RUNNER_ALLOWED_WORKFLOW_REFS: repository + '/' + workflowFile + '@refs/heads/' + branch,
      ...(publicOrigin ? { PUBLIC_ORIGIN: publicOrigin } : {}),
    },
  }
}

function ensureSecrets() {
  if (!fs.existsSync(secretsPath)) {
    writePrivate(secretsPath, JSON.stringify({
      BETTER_AUTH_SECRET: randomBytes(32).toString('base64'),
      ENCRYPTION_KEY: randomBytes(32).toString('base64'),
    }, null, 2) + '\n')
    console.log('Created local auth/encryption keys in ' + path.relative(root, secretsPath) + ' (mode 0600). Back up securely; never commit this file.')
  }
  const secretStat = fs.lstatSync(secretsPath)
  if (!secretStat.isFile() || secretStat.isSymbolicLink()) throw new Error('.vault.secrets.json must be a regular file, not a symlink')
  fs.chmodSync(secretsPath, 0o600)
  const secrets = JSON.parse(fs.readFileSync(secretsPath, 'utf8'))
  if (typeof secrets.BETTER_AUTH_SECRET !== 'string' || secrets.BETTER_AUTH_SECRET.length < 32) {
    throw new Error('BETTER_AUTH_SECRET is missing or too short in .vault.secrets.json')
  }
  if (Buffer.from(secrets.ENCRYPTION_KEY ?? '', 'base64').length !== 32) {
    throw new Error('ENCRYPTION_KEY in .vault.secrets.json must decode to exactly 32 bytes')
  }
}

async function main() {
  const rl = createInterface({ input: stdin, output: stdout })
  try {
    execute('pnpm', ['exec', 'wrangler', 'whoami'], { cwd: appDir })
    let config = readConfig()
    if (forceConfigure || !fs.existsSync(localConfigPath) || !config.vars?.OWNER_GITHUB_ID) {
      const installation = await collectInstallConfig(rl)
      config.name = installation.workerName
      config.vars = installation.vars
      config.d1_databases = config.d1_databases ?? []
      writePrivate(localConfigPath, JSON.stringify(config, null, 2) + '\n')
    }

    const d1 = (config.d1_databases ?? []).find((entry) => entry.binding === 'DB')
    if (!d1?.database_id) {
      const databaseName = config.name + '-db'
      execute('pnpm', ['exec', 'wrangler', 'd1', 'create', databaseName,
        '--config', path.basename(localConfigPath),
        '--update-config', '--use-remote', '--binding', 'DB'], { cwd: appDir })
      config = readConfig()
    }

    const binding = (config.d1_databases ?? []).find((entry) => entry.binding === 'DB')
    if (!binding?.database_id) throw new Error('Wrangler did not persist the D1 database ID into app/wrangler.local.jsonc')
    binding.migrations_dir = '../db/drizzle-app'
    config.vars = config.vars ?? {}
    writePrivate(localConfigPath, JSON.stringify(config, null, 2) + '\n')

    ensureSecrets()
    console.log('\nApplying D1 migrations…')
    execute('pnpm', ['exec', 'wrangler', 'd1', 'migrations', 'apply', 'DB', '--remote',
      '--config', path.basename(localConfigPath)], { cwd: appDir })

    console.log('\nBuilding with this installation’s local Wrangler config…')
    execute('pnpm', ['--filter', 'runner-vault-app', 'build'], {
      cwd: root,
      env: { ...process.env, CLOUDFLARE_VITE_WRANGLER_CONFIG_PATH: './wrangler.local.jsonc' },
    })
    const builtConfig = path.join(appDir, 'dist/rsc/wrangler.json')
    if (!fs.existsSync(builtConfig)) throw new Error('Vite did not produce app/dist/rsc/wrangler.json')

    console.log('\nDeploying the Worker…')
    execute('pnpm', ['exec', 'wrangler', 'deploy', '--config', 'dist/rsc/wrangler.json'], { cwd: appDir })

    console.log('\nUploading generated auth/encryption secrets…')
    execute('pnpm', ['exec', 'wrangler', 'secret', 'bulk', '../.vault.secrets.json',
      '--config', path.basename(localConfigPath)], { cwd: appDir })

    console.log('\nDeployment completed.')
    console.log('Create a GitHub OAuth App using the Worker URL printed by Wrangler:')
    console.log('  Homepage URL: https://<your-worker-domain>')
    console.log('  Callback URL: https://<your-worker-domain>/api/auth/callback/github')
    console.log('\nThen add the OAuth credentials (never commit them):')
    console.log('  cd app')
    console.log('  pnpm exec wrangler secret put GITHUB_CLIENT_ID --config wrangler.local.jsonc')
    console.log('  pnpm exec wrangler secret put GITHUB_CLIENT_SECRET --config wrangler.local.jsonc')
    console.log('  cd ..')
    console.log('\nFinally, set VAULT_URL in the trusted Runner repository to the deployed Worker origin.')
    console.log('Use --configure on this command to change the installation-specific trust settings.')
  } finally {
    rl.close()
  }
}

main().catch((error) => {
  console.error('\nDeployment failed: ' + (error instanceof Error ? error.message : String(error)))
  process.exitCode = 1
})
