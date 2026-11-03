import assert from 'node:assert/strict'
import test from 'node:test'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { prepareWorkerEntrypoint } from './prepare-worker-entry.mjs'

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), 'runner-vault-worker-entry-'))
  writeFileSync(join(directory, 'index.js'), [
    "export const A = 'workflow_dispatch,push'",
    "export const serverAction = () => 'internal RSC helper'",
    "export default { fetch: () => new Response('ok') }",
    '',
  ].join('\n'))
  writeFileSync(join(directory, 'wrangler.json'), JSON.stringify({
    name: 'runner-vault',
    main: 'index.js',
    no_bundle: true,
    compatibility_date: '2026-10-31',
    d1_databases: [{ binding: 'DB', database_name: 'runner-vault-db', database_id: 'local-only-id' }],
    vars: { OWNER_GITHUB_ID: '318252513' },
  }, null, 2))
  return directory
}

test('wraps the RSC export graph in a default-only bundled Worker entry', () => {
  const directory = fixture()
  try {
    const original = readFileSync(join(directory, 'index.js'), 'utf8')
    const config = prepareWorkerEntrypoint(directory)
    const wrapper = readFileSync(join(directory, 'worker.js'), 'utf8')
    const nextConfig = JSON.parse(readFileSync(join(directory, 'wrangler.json'), 'utf8'))

    assert.equal(original, readFileSync(join(directory, 'index.js'), 'utf8'))
    assert.match(original, /export const A/)
    assert.match(original, /serverAction/)
    assert.equal(wrapper, "import worker from './index.js'\nexport default worker\n")
    assert.equal(config.main, 'worker.js')
    assert.equal(nextConfig.main, 'worker.js')
    assert.equal('no_bundle' in nextConfig, false)
    assert.equal(nextConfig.compatibility_date, '2026-10-31')
    assert.deepEqual(nextConfig.d1_databases, [{
      binding: 'DB', database_name: 'runner-vault-db', database_id: 'local-only-id',
    }])
    assert.equal(nextConfig.vars.OWNER_GITHUB_ID, '318252513')
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
})

test('is idempotent after the worker wrapper has been generated', () => {
  const directory = fixture()
  try {
    const first = prepareWorkerEntrypoint(directory)
    const wrapperBefore = readFileSync(join(directory, 'worker.js'), 'utf8')
    const second = prepareWorkerEntrypoint(directory)
    assert.deepEqual(second, first)
    assert.equal(readFileSync(join(directory, 'worker.js'), 'utf8'), wrapperBefore)
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
})

test('fails closed if the Vite RSC entry is missing or not the expected entrypoint', () => {
  const directory = fixture()
  try {
    rmSync(join(directory, 'index.js'))
    assert.throws(() => prepareWorkerEntrypoint(directory), /index\.js/)
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
})

test('fails if Wrangler config does not identify the Vite RSC entry', () => {
  const directory = fixture()
  try {
    const configPath = join(directory, 'wrangler.json')
    const config = JSON.parse(readFileSync(configPath, 'utf8'))
    config.main = '../worker.js'
    writeFileSync(configPath, JSON.stringify(config))
    assert.throws(() => prepareWorkerEntrypoint(directory), /Expected the Vite RSC bundle/)
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
})
