import assert from 'node:assert/strict'
import test from 'node:test'
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import {
  applyDeploymentOverrides,
  isValidMasterKey,
  masterKeyAction,
  parseD1DatabaseList,
  parseSecretList,
  parseStoredMasterKey,
  setD1DatabaseId,
} from './deploy.mjs'

const DATABASE_ID = '8bd6ccde-01d7-47e4-8fd5-92bf99736b81'
const OWNER_ID = '318252513'
const deployScript = new URL('./deploy.mjs', import.meta.url)

test('parses Wrangler D1 list JSON and Cloudflare UUIDs', () => {
  const rows = parseD1DatabaseList(JSON.stringify([
    { uuid: DATABASE_ID, name: 'runner-vault-db' },
    { uuid: 'ignored-without-name' },
  ]))
  assert.deepEqual(rows, [{ name: 'runner-vault-db', id: DATABASE_ID }])
})

test('accepts a wrapped result shape returned by API-style Wrangler output', () => {
  const rows = parseD1DatabaseList(JSON.stringify({
    success: true,
    result: [{ database_name: 'runner-vault-db', database_id: DATABASE_ID }],
  }))
  assert.deepEqual(rows, [{ name: 'runner-vault-db', id: DATABASE_ID }])
})

// Bytes 0..31, the same fixed test-only key the app tests pin.
const TEST_MASTER_KEY = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8='
const EXECUTE_MASTER_KEY_CALL = "d1 execute runner-vault-db --remote --json --command SELECT value FROM vault_setting WHERE key = 'master_key'"

test('parses the Wrangler secret list JSON shape', () => {
  const names = parseSecretList(JSON.stringify([
    { name: 'VAULT_MASTER_KEY', type: 'secret_text' },
    { name: 'OTHER', type: 'secret_text' },
  ]))
  assert.deepEqual(names, ['VAULT_MASTER_KEY', 'OTHER'])
})

test('parses secret names from text output and tolerates noise', () => {
  assert.deepEqual(parseSecretList('VAULT_MASTER_KEY\n'), ['VAULT_MASTER_KEY'])
  assert.deepEqual(parseSecretList(''), [])
})

test('extracts the stored master key from D1 execute JSON', () => {
  const output = JSON.stringify([{ results: [{ value: TEST_MASTER_KEY }], success: true }])
  assert.equal(parseStoredMasterKey(output), TEST_MASTER_KEY)
  assert.equal(parseStoredMasterKey(JSON.stringify([{ results: [], success: true }])), null)
  assert.equal(parseStoredMasterKey(JSON.stringify({ result: [{ results: [{ value: TEST_MASTER_KEY }] }] })), TEST_MASTER_KEY)
  assert.equal(parseStoredMasterKey('not json'), null)
})

test('validates master keys as base64-encoded 32 bytes', () => {
  assert.equal(isValidMasterKey(TEST_MASTER_KEY), true)
  assert.equal(isValidMasterKey('AAAA'), false)
  assert.equal(isValidMasterKey(TEST_MASTER_KEY + 'garbage'), false)
  assert.equal(isValidMasterKey(TEST_MASTER_KEY.slice(0, -1) + '/'), false)
  assert.equal(isValidMasterKey(''), false)
  assert.equal(isValidMasterKey(null), false)
})

test('master key provisioning skips when the secret already exists', () => {
  assert.deepEqual(masterKeyAction(['VAULT_MASTER_KEY'], TEST_MASTER_KEY), { action: 'skip' })
  assert.deepEqual(masterKeyAction(['VAULT_MASTER_KEY'], null), { action: 'skip' })
})

test('master key provisioning migrates a valid stored key verbatim', () => {
  assert.deepEqual(masterKeyAction([], TEST_MASTER_KEY), { action: 'migrate', value: TEST_MASTER_KEY })
})

test('master key provisioning generates only when no stored key exists', () => {
  assert.deepEqual(masterKeyAction([], null), { action: 'generate' })
  assert.deepEqual(masterKeyAction(['OTHER_SECRET'], null), { action: 'generate' })
})

test('master key provisioning never replaces an unreadable stored key', () => {
  assert.deepEqual(masterKeyAction([], 'not-a-key'), { action: 'blocked' })
})

test('injects the exact D1 ID into the generated Worker config', () => {
  const config = {
    name: 'runner-vault',
    vars: { OWNER_GITHUB_ID: OWNER_ID },
    d1_databases: [{ binding: 'DB', database_name: 'runner-vault-db' }],
  }
  const updated = setD1DatabaseId(config, 'DB', 'runner-vault-db', DATABASE_ID)
  assert.equal(updated.d1_databases[0].database_id, DATABASE_ID)
  assert.equal(updated.vars.OWNER_GITHUB_ID, OWNER_ID)
  assert.equal(config.d1_databases[0].database_id, undefined)
})

test('the committed Wrangler template does not pin a deployment-specific D1 UUID', () => {
  const source = readFileSync(new URL('../wrangler.jsonc', import.meta.url), 'utf8')
  const binding = [...source.matchAll(/\{[^{}]*\}/g)].map((match) => match[0])
    .find((block) => /"binding"\s*:\s*"DB"/.test(block))
  assert.ok(binding, 'DB binding must exist')
  assert.doesNotMatch(binding, /"database_id"\s*:/)
})

test('rejects binding/name mismatches instead of reusing another database', () => {
  const config = { d1_databases: [{ binding: 'DB', database_name: 'other-db' }] }
  assert.throws(
    () => setD1DatabaseId(config, 'DB', 'runner-vault-db', DATABASE_ID),
    /D1 name mismatch/,
  )
})

test('deployment overrides are isolated to generated config and validated', () => {
  const config = {
    name: 'runner-vault',
    d1_databases: [{ binding: 'DB', database_name: 'runner-vault-db' }],
  }
  const overridden = applyDeploymentOverrides(config, {
    RUNNER_VAULT_WORKER_NAME: 'vault-instance-2',
    RUNNER_VAULT_D1_DATABASE_NAME: 'vault-instance-2-db',
  })
  assert.equal(overridden.name, 'vault-instance-2')
  assert.equal(overridden.d1_databases[0].database_name, 'vault-instance-2-db')
  assert.equal(config.name, 'runner-vault')
  assert.equal(config.d1_databases[0].database_name, 'runner-vault-db')
  assert.throws(() => applyDeploymentOverrides(config, { RUNNER_VAULT_WORKER_NAME: 'Not Valid' }), /WORKER_NAME/)
  assert.throws(() => applyDeploymentOverrides(config, { RUNNER_VAULT_D1_DATABASE_NAME: '../other' }), /D1_DATABASE_NAME/)
})


function makeDeployFixture({ withBuild = false, databases = [{ name: 'runner-vault-db', uuid: DATABASE_ID }] } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'runner-vault-deploy-'))
  const app = join(root, 'app')
  const scripts = join(app, 'scripts')
  const bin = join(app, 'node_modules', '.bin')
  const generated = join(app, 'dist', 'rsc')
  mkdirSync(scripts, { recursive: true })
  mkdirSync(bin, { recursive: true })
  mkdirSync(generated, { recursive: true })
  copyFileSync(deployScript, join(scripts, 'deploy.mjs'))
  copyFileSync(new URL('./prepare-worker-entry.mjs', import.meta.url), join(scripts, 'prepare-worker-entry.mjs'))

  writeFileSync(join(app, 'wrangler.jsonc'), `{
  "name": "runner-vault",
  "d1_databases": [
    { "binding": "DB", "database_name": "runner-vault-db" }
  ],
  "vars": { "OWNER_GITHUB_ID": "${OWNER_ID}" }
}
`)
  if (!withBuild) {
    writeFileSync(join(generated, 'index.js'), "export const helper = 'internal'; export default { fetch: () => new Response('ok') }")
    writeFileSync(join(generated, 'wrangler.json'), JSON.stringify({
      name: 'runner-vault',
      main: 'index.js',
      no_bundle: true,
      vars: { OWNER_GITHUB_ID: OWNER_ID },
      d1_databases: [{ binding: 'DB', database_name: 'runner-vault-db' }],
    }))
  }

  const stateFile = join(root, 'd1-state.json')
  const callsFile = join(root, 'calls.log')
  writeFileSync(stateFile, JSON.stringify(databases))

  const wrangler = `#!/usr/bin/env node
const fs = require('node:fs')
const args = process.argv.slice(2)
fs.appendFileSync(process.env.TEST_CALL_LOG, args.join(' ') + '\\n')
const state = JSON.parse(fs.readFileSync(process.env.TEST_DB_STATE, 'utf8'))
if (args[0] === 'd1' && args[1] === 'list') {
  process.stdout.write(JSON.stringify(state))
} else if (args[0] === 'd1' && args[1] === 'create') {
  state.push({ name: args[2], uuid: process.env.TEST_CREATED_DB_ID })
  fs.writeFileSync(process.env.TEST_DB_STATE, JSON.stringify(state))
  process.stdout.write('created')
} else if (args[0] === 'd1' && args[1] === 'execute') {
  const stored = process.env.TEST_STORED_KEY
  process.stdout.write(JSON.stringify([{ results: stored ? [{ value: stored }] : [], success: true }]))
} else if (args[0] === 'secret' && args[1] === 'list') {
  process.stdout.write(process.env.TEST_SECRETS || '[]')
} else if (args[0] === 'secret' && args[1] === 'put') {
  fs.writeFileSync(process.env.TEST_SECRET_VALUE_FILE, fs.readFileSync(0, 'utf8'))
  process.stdout.write('secret uploaded\\n')
} else if (args[0] === 'deploy') {
  process.stdout.write('mock deploy complete\\n')
} else {
  process.stderr.write('unexpected wrangler invocation: ' + args.join(' '))
  process.exit(2)
}
`
  const wranglerPath = join(bin, 'wrangler')
  writeFileSync(wranglerPath, wrangler)
  chmodSync(wranglerPath, 0o755)

  if (withBuild) {
    const vite = `#!/usr/bin/env node
const fs = require('node:fs')
const path = require('node:path')
fs.appendFileSync(process.env.TEST_CALL_LOG, 'vite ' + process.argv.slice(2).join(' ') + '\\n')
fs.mkdirSync('dist/rsc', { recursive: true })
fs.writeFileSync(path.join('dist/rsc', 'index.js'), "export const helper = 'internal'; export default { fetch: () => new Response('ok') }")
fs.writeFileSync(path.join('dist/rsc', 'wrangler.json'), JSON.stringify({
  name: 'runner-vault',
  main: 'index.js',
  no_bundle: true,
  vars: { OWNER_GITHUB_ID: process.env.TEST_OWNER_ID },
  d1_databases: [{ binding: 'DB', database_name: 'runner-vault-db' }]
}))
`
    const vitePath = join(bin, 'vite')
    writeFileSync(vitePath, vite)
    chmodSync(vitePath, 0o755)
  }

  return {
    root,
    app,
    generatedConfig: join(generated, 'wrangler.json'),
    sourceConfig: join(app, 'wrangler.jsonc'),
    stateFile,
    callsFile,
    secretValueFile: join(root, 'secret-value.txt'),
    env: {
      ...process.env,
      PATH: process.env.PATH,
      TEST_CALL_LOG: callsFile,
      TEST_DB_STATE: stateFile,
      TEST_CREATED_DB_ID: DATABASE_ID,
      TEST_OWNER_ID: OWNER_ID,
      TEST_SECRET_VALUE_FILE: join(root, 'secret-value.txt'),
    },
    cleanup() { rmSync(root, { recursive: true, force: true }) },
  }
}

function invokeDeploy(fixture, extraEnv = {}) {
  return spawnSync(process.execPath, [join(fixture.app, 'scripts', 'deploy.mjs')], {
    cwd: fixture.app,
    env: { ...fixture.env, ...extraEnv },
    encoding: 'utf8',
    timeout: 20_000,
  })
}

test('uses the deployment-provided D1 UUID without D1 API calls', () => {
  const f = makeDeployFixture()
  try {
    const result = invokeDeploy(f, {
      WORKERS_CI: '1',
      RUNNER_VAULT_D1_DATABASE_ID: DATABASE_ID,
    })
    assert.equal(result.status, 0, result.stderr)
    assert.deepEqual(readFileSync(f.callsFile, 'utf8').trim().split('\n'), ['deploy --config ' + f.generatedConfig, 'secret list --config ' + f.generatedConfig, EXECUTE_MASTER_KEY_CALL + ' --config ' + f.generatedConfig, 'secret put VAULT_MASTER_KEY --config ' + f.generatedConfig])
    assert.equal(JSON.parse(readFileSync(f.generatedConfig, 'utf8')).d1_databases[0].database_id, DATABASE_ID)
    // A fresh deploy generates a valid 32-byte key, delivered on stdin only:
    // it reaches the secret-value file but never appears in the call log.
    const generated = readFileSync(f.secretValueFile, 'utf8')
    assert.equal(isValidMasterKey(generated), true)
    assert.equal(readFileSync(f.callsFile, 'utf8').includes(generated), false)
  } finally {
    f.cleanup()
  }
})

test('Workers Builds reuses its prebuilt owner binding, resolves D1, then deploys', () => {
  const f = makeDeployFixture()
  try {
    const result = invokeDeploy(f, { WORKERS_CI: '1' })
    assert.equal(result.status, 0, result.stderr)
    const calls = readFileSync(f.callsFile, 'utf8').trim().split('\n')
    assert.deepEqual(calls, ['d1 list --json', 'deploy --config ' + f.generatedConfig, 'secret list --config ' + f.generatedConfig, EXECUTE_MASTER_KEY_CALL + ' --config ' + f.generatedConfig, 'secret put VAULT_MASTER_KEY --config ' + f.generatedConfig])
    const generated = JSON.parse(readFileSync(f.generatedConfig, 'utf8'))
    assert.equal(generated.vars.OWNER_GITHUB_ID, OWNER_ID)
    assert.equal(generated.d1_databases[0].database_id, DATABASE_ID)
    assert.equal(generated.main, 'worker.js')
    assert.equal('no_bundle' in generated, false)
    assert.equal(readFileSync(join(f.app, 'dist', 'rsc', 'worker.js'), 'utf8'), "import worker from './index.js'\nexport default worker\n")
    assert.doesNotMatch(readFileSync(f.sourceConfig, 'utf8'), /database_id/)
  } finally {
    f.cleanup()
  }
})

test('Wrangler CLI path builds first, then resolves D1 and deploys', () => {
  const f = makeDeployFixture({ withBuild: true })
  try {
    const result = invokeDeploy(f, { RUNNER_VAULT_OWNER_GITHUB_ID: OWNER_ID })
    assert.equal(result.status, 0, result.stderr)
    const calls = readFileSync(f.callsFile, 'utf8').trim().split('\n')
    assert.deepEqual(calls, ['vite build', 'd1 list --json', 'deploy --config ' + f.generatedConfig, 'secret list --config ' + f.generatedConfig, EXECUTE_MASTER_KEY_CALL + ' --config ' + f.generatedConfig, 'secret put VAULT_MASTER_KEY --config ' + f.generatedConfig])
    const generated = JSON.parse(readFileSync(f.generatedConfig, 'utf8'))
    assert.equal(generated.vars.OWNER_GITHUB_ID, OWNER_ID)
    assert.equal(generated.d1_databases[0].database_id, DATABASE_ID)
    assert.equal(generated.main, 'worker.js')
    assert.equal('no_bundle' in generated, false)
    assert.ok(existsSync(join(f.app, 'dist', 'rsc', 'worker.js')))
  } finally {
    f.cleanup()
  }
})

test('supports installation-specific Worker and D1 names without editing the source template', () => {
  const f = makeDeployFixture()
  try {
    const result = invokeDeploy(f, {
      WORKERS_CI: '1',
      RUNNER_VAULT_WORKER_NAME: 'vault-copy-1',
      RUNNER_VAULT_D1_DATABASE_NAME: 'vault-copy-1-db',
    })
    assert.equal(result.status, 0, result.stderr)
    const generated = JSON.parse(readFileSync(f.generatedConfig, 'utf8'))
    assert.equal(generated.name, 'vault-copy-1')
    assert.equal(generated.d1_databases[0].database_name, 'vault-copy-1-db')
    const calls = readFileSync(f.callsFile, 'utf8')
    assert.match(calls, /d1 list --json/)
    assert.match(calls, /deploy --config/)
    assert.match(calls, /secret list --config/)
    assert.match(calls, /d1 execute vault-copy-1-db .*--config/)
    assert.match(calls, /secret put VAULT_MASTER_KEY --config/)
    assert.doesNotMatch(readFileSync(f.sourceConfig, 'utf8'), /vault-copy-1|database_id/)
  } finally {
    f.cleanup()
  }
})

test('creates a missing D1 database before deploying', () => {
  const f = makeDeployFixture({ databases: [] })
  try {
    const result = invokeDeploy(f, { WORKERS_CI: '1' })
    assert.equal(result.status, 0, result.stderr)
    const calls = readFileSync(f.callsFile, 'utf8').trim().split('\n')
    assert.deepEqual(calls, ['d1 list --json', 'd1 create runner-vault-db', 'd1 list --json', 'deploy --config ' + f.generatedConfig, 'secret list --config ' + f.generatedConfig, EXECUTE_MASTER_KEY_CALL + ' --config ' + f.generatedConfig, 'secret put VAULT_MASTER_KEY --config ' + f.generatedConfig])
    assert.equal(JSON.parse(readFileSync(f.generatedConfig, 'utf8')).d1_databases[0].database_id, DATABASE_ID)
  } finally {
    f.cleanup()
  }
})

test('skips master key provisioning when the secret already exists', () => {
  const f = makeDeployFixture()
  try {
    const result = invokeDeploy(f, {
      WORKERS_CI: '1',
      TEST_SECRETS: JSON.stringify([{ name: 'VAULT_MASTER_KEY', type: 'secret_text' }]),
    })
    assert.equal(result.status, 0, result.stderr)
    const calls = readFileSync(f.callsFile, 'utf8').trim().split('\n')
    assert.deepEqual(calls, ['d1 list --json', 'deploy --config ' + f.generatedConfig, 'secret list --config ' + f.generatedConfig])
    assert.equal(existsSync(f.secretValueFile), false)
  } finally {
    f.cleanup()
  }
})

test('migrates a stored legacy master key into the secret verbatim', () => {
  const f = makeDeployFixture()
  try {
    const result = invokeDeploy(f, {
      WORKERS_CI: '1',
      TEST_STORED_KEY: TEST_MASTER_KEY,
    })
    assert.equal(result.status, 0, result.stderr)
    const calls = readFileSync(f.callsFile, 'utf8').trim().split('\n')
    assert.deepEqual(calls, ['d1 list --json', 'deploy --config ' + f.generatedConfig, 'secret list --config ' + f.generatedConfig, EXECUTE_MASTER_KEY_CALL + ' --config ' + f.generatedConfig, 'secret put VAULT_MASTER_KEY --config ' + f.generatedConfig])
    assert.equal(readFileSync(f.secretValueFile, 'utf8'), TEST_MASTER_KEY)
    assert.equal(readFileSync(f.callsFile, 'utf8').includes(TEST_MASTER_KEY), false)
  } finally {
    f.cleanup()
  }
})

test('refuses to deploy if the generated Worker has no owner identity', () => {
  const f = makeDeployFixture()
  try {
    const generated = JSON.parse(readFileSync(f.generatedConfig, 'utf8'))
    delete generated.vars.OWNER_GITHUB_ID
    writeFileSync(f.generatedConfig, JSON.stringify(generated))
    const result = invokeDeploy(f, { WORKERS_CI: '1' })
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /missing a valid vars.OWNER_GITHUB_ID/)
    assert.equal(existsSync(f.callsFile), false)
  } finally {
    f.cleanup()
  }
})
