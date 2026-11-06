import { spawnSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { prepareWorkerEntrypoint } from './prepare-worker-entry.mjs'

const isWindows = process.platform === 'win32'
const binPath = (name) => resolve('node_modules', '.bin', name + (isWindows ? '.cmd' : ''))
const ownerIdPattern = /^[1-9][0-9]{0,15}$/

function runLocal(name, args, { capture = false, input } = {}) {
  const executable = binPath(name)
  if (!existsSync(executable)) {
    throw new Error(`Local ${name} executable is missing. Run pnpm install first.`)
  }

  const result = spawnSync(executable, args, {
    cwd: process.cwd(),
    env: process.env,
    encoding: 'utf8',
    shell: isWindows,
    input,
    stdio: input !== undefined ? ['pipe', capture ? 'pipe' : 'inherit', 'inherit'] : capture ? ['ignore', 'pipe', 'pipe'] : 'inherit',
  })

  if (result.error) throw result.error
  if (result.status !== 0) {
    const details = [result.stdout, result.stderr].filter(Boolean).join('\n').trim()
    throw new Error(`${name} ${args.join(' ')} failed with exit code ${result.status ?? 'unknown'}${details ? ':\n' + details : ''}`)
  }
  return capture ? (result.stdout ?? '') : ''
}

function stripAnsi(value) {
  return value.replace(/\u001b\[[0-9;]*m/g, '').trim()
}

export function parseD1DatabaseList(output) {
  const parsed = JSON.parse(stripAnsi(output))
  const rows = Array.isArray(parsed)
    ? parsed
    : Array.isArray(parsed?.result)
      ? parsed.result
      : Array.isArray(parsed?.databases)
        ? parsed.databases
        : null
  if (!rows) throw new Error('Wrangler D1 list did not return a JSON database array')

  return rows.map((row) => ({
    name: row.name ?? row.database_name,
    id: row.uuid ?? row.database_id ?? row.id,
  })).filter((row) => typeof row.name === 'string' && typeof row.id === 'string')
}

export function setD1DatabaseId(config, binding, databaseName, databaseId) {
  if (!ownerIdPattern.test(databaseId) && !/^[a-f0-9-]{16,64}$/i.test(databaseId)) {
    throw new Error('Cloudflare returned an invalid D1 database ID')
  }
  const databases = config.d1_databases
  if (!Array.isArray(databases)) throw new Error('Worker config has no d1_databases array')
  const entry = databases.find((item) => item.binding === binding)
  if (!entry) throw new Error(`Worker config is missing the ${binding} D1 binding`)
  if (entry.database_name !== databaseName) {
    throw new Error(`D1 name mismatch for ${binding}: expected ${databaseName}, found ${entry.database_name}`)
  }
  return {
    ...config,
    d1_databases: databases.map((item) => item.binding === binding
      ? { ...item, database_id: databaseId }
      : item),
  }
}


export function applyDeploymentOverrides(config, env = process.env) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    throw new Error('Generated Worker config is invalid')
  }

  const workerName = typeof env.RUNNER_VAULT_WORKER_NAME === 'string'
    ? env.RUNNER_VAULT_WORKER_NAME.trim() : ''
  if (workerName) {
    if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(workerName)) {
      throw new Error('RUNNER_VAULT_WORKER_NAME must be a valid workers.dev-compatible Worker name')
    }
    config = { ...config, name: workerName }
  }

  const databaseName = typeof env.RUNNER_VAULT_D1_DATABASE_NAME === 'string'
    ? env.RUNNER_VAULT_D1_DATABASE_NAME.trim() : ''
  if (databaseName) {
    if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$/.test(databaseName)) {
      throw new Error('RUNNER_VAULT_D1_DATABASE_NAME must contain 1-63 letters, numbers, underscores or hyphens')
    }
    if (!Array.isArray(config.d1_databases) || !config.d1_databases.some((item) => item.binding === 'DB')) {
      throw new Error('Worker config is missing the DB D1 binding')
    }
    config = {
      ...config,
      d1_databases: config.d1_databases.map((item) => item.binding === 'DB'
        ? { ...item, database_name: databaseName, database_id: undefined }
        : item),
    }
  }

  return config
}

function loadGeneratedConfig(path) {
  if (!existsSync(path)) return null
  return JSON.parse(readFileSync(path, 'utf8'))
}

function ensureOwner(config) {
  const ownerId = config?.vars?.OWNER_GITHUB_ID
  if (typeof ownerId !== 'string' || !ownerIdPattern.test(ownerId)) {
    throw new Error('Generated Worker config is missing a valid vars.OWNER_GITHUB_ID. Build from your GitHub repository or set RUNNER_VAULT_OWNER_GITHUB_ID.')
  }
}


function ensureD1(generatedConfigPath) {
  const generated = loadGeneratedConfig(generatedConfigPath)
  if (!generated) throw new Error('Vite build did not create dist/rsc/wrangler.json')

  const generatedEntry = generated.d1_databases?.find((item) => item.binding === 'DB')
  const databaseName = generatedEntry?.database_name
  if (!databaseName || !generatedEntry) {
    throw new Error('Worker config is missing the DB D1 binding or database_name')
  }

  // Resolve this installation's database without writing its UUID into the
  // tracked Wrangler template. Only the generated deployment config is mutated.
  const configuredDatabaseId = process.env.RUNNER_VAULT_D1_DATABASE_ID?.trim()
  let databaseId = configuredDatabaseId || generatedEntry.database_id
  if (!databaseId) {
    let databases
    try {
      databases = parseD1DatabaseList(runLocal('wrangler', ['d1', 'list', '--json'], { capture: true }))
    } catch (error) {
      throw new Error('Cannot resolve the DB binding. Authenticate Wrangler and grant D1 Read/Edit, or pre-create the database and set RUNNER_VAULT_D1_DATABASE_ID. ' + error.message)
    }

    let match = databases.find((item) => item.name === databaseName)
    if (!match) {
      console.log('[deploy] D1 database ' + databaseName + ' does not exist; creating it')
      try {
        runLocal('wrangler', ['d1', 'create', databaseName])
      } catch (error) {
        // A concurrent first deploy may have created the database after the list.
        databases = parseD1DatabaseList(runLocal('wrangler', ['d1', 'list', '--json'], { capture: true }))
        match = databases.find((item) => item.name === databaseName)
        if (!match) throw error
      }
      if (!match) {
        databases = parseD1DatabaseList(runLocal('wrangler', ['d1', 'list', '--json'], { capture: true }))
        match = databases.find((item) => item.name === databaseName)
      }
    }
    if (!match) throw new Error('Cloudflare did not return the D1 database ' + databaseName)
    databaseId = match.id
  }

  const nextGenerated = setD1DatabaseId(generated, 'DB', databaseName, databaseId)
  writeFileSync(generatedConfigPath, JSON.stringify(nextGenerated, null, 2) + '\n')

  console.log('[deploy] DB binding is ready: ' + databaseName)
  return databaseName
}

// ── master key provisioning ─────────────────────────────────────
//
// The vault's master key must live in the VAULT_MASTER_KEY Worker secret,
// never in D1 next to the ciphertext it decrypts. Provisioning it is part of
// deployment, not a user task: this helper runs with the same Wrangler
// credentials that just deployed the Worker, so every route (Deploy Button,
// Dashboard Git connection, Wrangler CLI) gets the secret with zero input.
// The key value is only ever passed to Wrangler on stdin — never in argv,
// files, config or logs. Provisioning never fails the deploy: if it cannot
// complete, the vault stays fail-closed (or in flagged legacy mode) and a
// later redeploy retries.

export const MASTER_KEY_SECRET = 'VAULT_MASTER_KEY'

export function parseSecretList(output) {
  const text = stripAnsi(output)
  try {
    const parsed = JSON.parse(text)
    const rows = Array.isArray(parsed) ? parsed : Array.isArray(parsed?.result) ? parsed.result : null
    if (rows) return rows.map((row) => row?.name).filter((name) => typeof name === 'string')
  } catch { /* fall through to the text shape */ }
  const names = new Set()
  for (const match of text.matchAll(/"name"\s*:\s*"([^"]+)"/g)) names.add(match[1])
  for (const line of text.split('\n')) {
    const name = line.trim()
    if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) names.add(name)
  }
  return [...names]
}

export function parseStoredMasterKey(output) {
  let parsed
  try {
    parsed = JSON.parse(stripAnsi(output))
  } catch {
    return null
  }
  const statements = Array.isArray(parsed) ? parsed : Array.isArray(parsed?.result) ? parsed.result : [parsed]
  for (const statement of statements) {
    const rows = statement?.results ?? statement?.result?.results
    if (!Array.isArray(rows)) continue
    for (const row of rows) {
      if (typeof row?.value === 'string' && row.value.trim()) return row.value.trim()
    }
  }
  return null
}

export function isValidMasterKey(value) {
  if (typeof value !== 'string') return false
  const encoded = value.trim()
  // A 32-byte key has one canonical 44-character base64 representation.
  // Buffer.from(base64) alone is permissive and silently ignores invalid data.
  if (!/^[A-Za-z0-9+/]{43}=$/.test(encoded)) return false
  try {
    const decoded = Buffer.from(encoded, 'base64')
    return decoded.length === 32 && decoded.toString('base64') === encoded
  } catch {
    return false
  }
}

/** Decide what provisioning should do. Pure: the caller performs the I/O. */
export function masterKeyAction(secretNames, storedKey) {
  if (secretNames.includes(MASTER_KEY_SECRET)) return { action: 'skip' }
  if (storedKey !== null && storedKey !== undefined) {
    return isValidMasterKey(storedKey) ? { action: 'migrate', value: storedKey } : { action: 'blocked' }
  }
  return { action: 'generate' }
}

function ensureMasterKey(databaseName, configPath) {
  let secretNames
  try {
    secretNames = parseSecretList(runLocal('wrangler', ['secret', 'list', '--config', configPath], { capture: true }))
  } catch (error) {
    console.warn('[deploy] Could not list Worker secrets; skipping master key provisioning (' + error.message + '). The vault stays fail-closed until a redeploy provisions VAULT_MASTER_KEY.')
    return
  }
  if (secretNames.includes(MASTER_KEY_SECRET)) {
    console.log('[deploy] VAULT_MASTER_KEY secret is already set')
    return
  }

  let storedKey = null
  try {
    storedKey = parseStoredMasterKey(runLocal('wrangler', ['d1', 'execute', databaseName, '--remote', '--json', '--command', "SELECT value FROM vault_setting WHERE key = 'master_key'", '--config', configPath], { capture: true }))
  } catch (error) {
    if (!/no such table/i.test(error.message)) {
      console.warn('[deploy] Could not read the stored master key from D1; skipping provisioning so an existing key is never replaced blindly (' + error.message + ').')
      return
    }
    // Fresh database: vault_setting does not exist yet, so there is no
    // legacy key to migrate.
  }

  const plan = masterKeyAction(secretNames, storedKey)
  if (plan.action === 'blocked') {
    console.warn('[deploy] A master_key row exists in D1 but is not a valid 32-byte key; leaving it untouched. Set the VAULT_MASTER_KEY Worker secret manually to the correct value, then redeploy.')
    return
  }

  const value = plan.action === 'migrate' ? plan.value : randomBytes(32).toString('base64')
  try {
    runLocal('wrangler', ['secret', 'put', MASTER_KEY_SECRET, '--config', configPath], { input: value })
  } catch (error) {
    console.warn('[deploy] Could not set the VAULT_MASTER_KEY secret (' + error.message + '). The deployment build token needs Workers Scripts edit permission; until the secret is set the vault stays fail-closed (fresh) or in legacy database mode (upgrade).')
    return
  }
  console.log(plan.action === 'migrate'
    ? '[deploy] Migrated the existing master key from D1 into the VAULT_MASTER_KEY Worker secret; the database copy is removed on the next request'
    : '[deploy] Generated a new master key and stored it as the VAULT_MASTER_KEY Worker secret')
}

export function deploy() {
  const generatedConfigPath = resolve(process.cwd(), 'dist/rsc/wrangler.json')

  // Workers Builds runs the configured build command before the deploy command.
  // Local CLI deployments must build first so Vite injects the GitHub owner ID.
  if (process.env.WORKERS_CI !== '1' || !existsSync(generatedConfigPath)) {
    runLocal('vite', ['build'])
  }

  prepareWorkerEntrypoint(resolve(process.cwd(), 'dist/rsc'))
  const generated = applyDeploymentOverrides(loadGeneratedConfig(generatedConfigPath))
  writeFileSync(generatedConfigPath, JSON.stringify(generated, null, 2) + '\n')
  ensureOwner(generated)
  const databaseName = ensureD1(generatedConfigPath)
  runLocal('wrangler', ['deploy', '--config', generatedConfigPath])
  ensureMasterKey(databaseName, generatedConfigPath)
}

if (process.argv[1] && import.meta.url === new URL('file://' + resolve(process.argv[1])).href) {
  try {
    deploy()
  } catch (error) {
    console.error('[deploy] ' + (error instanceof Error ? error.message : String(error)))
    process.exitCode = 1
  }
}
