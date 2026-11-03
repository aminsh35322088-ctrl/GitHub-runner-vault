import { spawnSync } from 'node:child_process'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { prepareWorkerEntrypoint } from './prepare-worker-entry.mjs'

const isWindows = process.platform === 'win32'
const binPath = (name) => resolve('node_modules', '.bin', name + (isWindows ? '.cmd' : ''))
const ownerIdPattern = /^[1-9][0-9]{0,15}$/

function runLocal(name, args, { capture = false } = {}) {
  const executable = binPath(name)
  if (!existsSync(executable)) {
    throw new Error(`Local ${name} executable is missing. Run pnpm install first.`)
  }

  const result = spawnSync(executable, args, {
    cwd: process.cwd(),
    env: process.env,
    encoding: 'utf8',
    shell: isWindows,
    stdio: capture ? ['ignore', 'pipe', 'pipe'] : 'inherit',
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

export function setD1DatabaseIdInJsonc(source, binding, databaseName, databaseId) {
  const array = source.match(/("d1_databases"\s*:\s*\[)([\s\S]*?)(\])/m)
  if (!array) throw new Error('wrangler.jsonc is missing the d1_databases array')

  const blocks = [...array[2].matchAll(/\{[^{}]*\}/g)]
  const target = blocks.find((match) => {
    return /"binding"\s*:\s*"([^"]+)"/.exec(match[0])?.[1] === binding
  })
  if (!target) throw new Error(`wrangler.jsonc is missing the ${binding} D1 binding`)

  const currentName = /"database_name"\s*:\s*"([^"]+)"/.exec(target[0])?.[1]
  if (currentName !== databaseName) {
    throw new Error(`wrangler.jsonc D1 name mismatch for ${binding}: expected ${databaseName}, found ${currentName ?? 'missing'}`)
  }

  let updatedBlock
  if (/"database_id"\s*:/.test(target[0])) {
    updatedBlock = target[0].replace(/("database_id"\s*:\s*)"[^"]*"/, `$1"${databaseId}"`)
  } else {
    updatedBlock = target[0].replace(
      /(\"database_name\"\s*:\s*\"[^\"]+\")\s*,?/,
      `$1,\n      "database_id": "${databaseId}"`,
    )
  }
  const absoluteStart = array.index + array[1].length + target.index
  return source.slice(0, absoluteStart) + updatedBlock + source.slice(absoluteStart + target[0].length)
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

function ensureD1(sourceConfigPath, generatedConfigPath) {
  const source = readFileSync(sourceConfigPath, 'utf8')
  const generated = loadGeneratedConfig(generatedConfigPath)
  if (!generated) throw new Error('Vite build did not create dist/rsc/wrangler.json')

  const sourceD1 = [...source.matchAll(/\{[^{}]*\}/g)].map((match) => match[0])
    .find((block) => /"binding"\s*:\s*"DB"/.test(block))
  const sourceName = sourceD1 && /"database_name"\s*:\s*"([^"]+)"/.exec(sourceD1)?.[1]
  const generatedEntry = generated.d1_databases?.find((item) => item.binding === 'DB')
  const databaseName = generatedEntry?.database_name ?? sourceName
  if (!databaseName || !generatedEntry) {
    throw new Error('Worker config is missing the DB D1 binding or database_name')
  }

  // A deployment-specific ID may be supplied as a Workers Builds / CLI variable.
  // Never commit one installation's D1 UUID into the reusable source template.
  const configuredDatabaseId = process.env.RUNNER_VAULT_D1_DATABASE_ID?.trim()
  let databaseId = generatedEntry.database_id ?? configuredDatabaseId ?? (sourceD1 && /"database_id"\s*:\s*"([^"]+)"/.exec(sourceD1)?.[1])
  if (!databaseId) {
    let databases
    try {
      databases = parseD1DatabaseList(runLocal('wrangler', ['d1', 'list', '--json'], { capture: true }))
    } catch (error) {
      throw new Error('Cannot resolve the DB binding. Authenticate Wrangler and grant D1 Read/Edit, or pre-create the database and set RUNNER_VAULT_D1_DATABASE_ID. ' + error.message)
    }

    let match = databases.find((item) => item.name === databaseName)
    if (!match) {
      console.log(`[deploy] D1 database ${databaseName} does not exist; creating it`)
      try {
        runLocal('wrangler', ['d1', 'create', databaseName, '--binding', 'DB', '--update-config'])
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
    if (!match) throw new Error(`Cloudflare did not return the newly created D1 database ${databaseName}`)
    databaseId = match.id
  }

  const nextGenerated = setD1DatabaseId(generated, 'DB', databaseName, databaseId)
  writeFileSync(generatedConfigPath, JSON.stringify(nextGenerated, null, 2) + '\n')

  const nextSource = setD1DatabaseIdInJsonc(source, 'DB', databaseName, databaseId)
  if (nextSource !== source) writeFileSync(sourceConfigPath, nextSource)

  console.log(`[deploy] DB binding is ready: ${databaseName}`)
}

export function deploy() {
  const generatedConfigPath = resolve(process.cwd(), 'dist/rsc/wrangler.json')
  const sourceConfigPath = resolve(process.cwd(), 'wrangler.jsonc')

  // Workers Builds runs the configured build command before the deploy command.
  // Local CLI deployments must build first so Vite injects the GitHub owner ID.
  if (process.env.WORKERS_CI !== '1' || !existsSync(generatedConfigPath)) {
    runLocal('vite', ['build'])
  }

  prepareWorkerEntrypoint(resolve(process.cwd(), 'dist/rsc'))
  const generated = loadGeneratedConfig(generatedConfigPath)
  ensureOwner(generated)
  ensureD1(sourceConfigPath, generatedConfigPath)
  runLocal('wrangler', ['deploy'])
}

if (process.argv[1] && import.meta.url === new URL('file://' + resolve(process.argv[1])).href) {
  try {
    deploy()
  } catch (error) {
    console.error('[deploy] ' + (error instanceof Error ? error.message : String(error)))
    process.exitCode = 1
  }
}
