import assert from 'node:assert/strict'
import test from 'node:test'
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import {
  parseD1DatabaseList,
  setD1DatabaseId,
  setD1DatabaseIdInJsonc,
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

test('rejects binding/name mismatches instead of reusing another database', () => {
  const config = { d1_databases: [{ binding: 'DB', database_name: 'other-db' }] }
  assert.throws(
    () => setD1DatabaseId(config, 'DB', 'runner-vault-db', DATABASE_ID),
    /D1 name mismatch/,
  )
})

test('adds database_id to wrangler.jsonc without dropping comments or other settings', () => {
  const source = `{
  // Keep the DB binding name stable in Worker code.
  "d1_databases": [
    { "binding": "DB", "database_name": "runner-vault-db" }
  ],
  "vars": {
    // This is public identity metadata.
    "OWNER_GITHUB_ID": "318252513"
  }
}
`
  const updated = setD1DatabaseIdInJsonc(source, 'DB', 'runner-vault-db', DATABASE_ID)
  assert.match(updated, /"database_id": "8bd6ccde-01d7-47e4-8fd5-92bf99736b81"/)
  assert.match(updated, /Keep the DB binding name stable/)
  assert.match(updated, /OWNER_GITHUB_ID/)
})

test('updates an existing database_id in wrangler.jsonc instead of duplicating it', () => {
  const source = `{
  "d1_databases": [
    {
      "binding": "DB",
      "database_name": "runner-vault-db",
      "database_id": "old-id"
    }
  ]
}
`
  const updated = setD1DatabaseIdInJsonc(source, 'DB', 'runner-vault-db', DATABASE_ID)
  assert.equal((updated.match(/"database_id"/g) ?? []).length, 1)
  assert.match(updated, new RegExp(DATABASE_ID))
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
    env: {
      ...process.env,
      PATH: process.env.PATH,
      TEST_CALL_LOG: callsFile,
      TEST_DB_STATE: stateFile,
      TEST_CREATED_DB_ID: DATABASE_ID,
      TEST_OWNER_ID: OWNER_ID,
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

test('Workers Builds reuses its prebuilt owner binding, resolves D1, then deploys', () => {
  const f = makeDeployFixture()
  try {
    const result = invokeDeploy(f, { WORKERS_CI: '1' })
    assert.equal(result.status, 0, result.stderr)
    const calls = readFileSync(f.callsFile, 'utf8').trim().split('\n')
    assert.deepEqual(calls, ['d1 list --json', 'deploy'])
    const generated = JSON.parse(readFileSync(f.generatedConfig, 'utf8'))
    assert.equal(generated.vars.OWNER_GITHUB_ID, OWNER_ID)
    assert.equal(generated.d1_databases[0].database_id, DATABASE_ID)
    assert.equal(generated.main, 'worker.js')
    assert.equal('no_bundle' in generated, false)
    assert.equal(readFileSync(join(f.app, 'dist', 'rsc', 'worker.js'), 'utf8'), "import worker from './index.js'\nexport default worker\n")
    assert.match(readFileSync(f.sourceConfig, 'utf8'), new RegExp(DATABASE_ID))
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
    assert.deepEqual(calls, ['vite build', 'd1 list --json', 'deploy'])
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

test('creates a missing D1 database before deploying', () => {
  const f = makeDeployFixture({ databases: [] })
  try {
    const result = invokeDeploy(f, { WORKERS_CI: '1' })
    assert.equal(result.status, 0, result.stderr)
    const calls = readFileSync(f.callsFile, 'utf8').trim().split('\n')
    assert.deepEqual(calls, ['d1 list --json', 'd1 create runner-vault-db --binding DB --update-config', 'd1 list --json', 'deploy'])
    assert.equal(JSON.parse(readFileSync(f.generatedConfig, 'utf8')).d1_databases[0].database_id, DATABASE_ID)
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
