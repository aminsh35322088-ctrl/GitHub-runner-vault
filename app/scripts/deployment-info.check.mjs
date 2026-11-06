import assert from 'node:assert/strict'
import test from 'node:test'
import {
  buildDeploymentInfo,
  buildVaultUrl,
  parseWorkerName,
  parseWorkersSubdomain,
  resolveWorkersSubdomain,
} from './deployment-info.mjs'

test('reads the Worker name from a commented wrangler.jsonc', () => {
  const source = `{
  // a comment before the name
  "name": "runner-vault",
  "main": "src/app.tsx"
}
`
  assert.equal(parseWorkerName(source), 'runner-vault')
  assert.throws(() => parseWorkerName('{ "main": "src/app.tsx" }'), /missing the Worker "name"/)
})

test('builds the workers.dev URL from worker and subdomain', () => {
  assert.equal(buildVaultUrl('runner-vault', 'octocat'), 'https://runner-vault.octocat.workers.dev')
})

test('parses the workers subdomain success shape', () => {
  assert.equal(parseWorkersSubdomain({ success: true, errors: [], result: { subdomain: 'octocat' } }), 'octocat')
  assert.equal(parseWorkersSubdomain({ success: true, errors: [], result: { subdomain: 'octocat-123' } }), 'octocat-123')
})

test('rejects malformed workers.dev subdomains', () => {
  for (const subdomain of ['octocat.example.com', '-octocat', 'octocat-', 'octocat/path', '']) {
    assert.throws(
      () => parseWorkersSubdomain({ success: true, result: { subdomain } }),
      /valid workers.dev subdomain/,
    )
  }
})

test('uses the configured workers.dev subdomain without an API token or network request', async () => {
  let called = false
  const subdomain = await resolveWorkersSubdomain({
    configuredSubdomain: 'amin3532',
    token: undefined,
    accountId: undefined,
    fetchImpl: async () => { called = true; throw new Error('network should not be used') },
  })
  assert.equal(subdomain, 'amin3532')
  assert.equal(called, false)
})

test('requires API credentials when no workers.dev subdomain override is configured', async () => {
  await assert.rejects(
    resolveWorkersSubdomain({ configuredSubdomain: '', token: '', accountId: '', fetchImpl: async () => { throw new Error('network should not be used') } }),
    /CLOUDFLARE_API_TOKEN is not set/,
  )
})

test('rejects Cloudflare error shapes and missing subdomains', () => {
  assert.throws(
    () => parseWorkersSubdomain({ success: false, errors: [{ code: 10000, message: 'Authentication error' }], result: null }),
    /Authentication error/,
  )
  assert.throws(() => parseWorkersSubdomain({ success: true, result: {} }), /did not return/)
  assert.throws(() => parseWorkersSubdomain(null), /did not return/)
})

test('builds the deployment.json document shape', () => {
  const info = buildDeploymentInfo({
    worker: 'runner-vault',
    subdomain: 'octocat',
    clientRef: 'a'.repeat(40),
    now: new Date('2026-11-04T00:00:00.000Z'),
  })
  assert.deepEqual(info, {
    url: 'https://runner-vault.octocat.workers.dev',
    clientRef: 'a'.repeat(40),
    worker: 'runner-vault',
    updatedAt: '2026-11-04T00:00:00.000Z',
  })
  assert.throws(() => buildDeploymentInfo({ worker: 'runner-vault', subdomain: 'octocat', clientRef: '' }), /40-character commit SHA/)
  assert.throws(() => buildDeploymentInfo({ worker: 'runner-vault', subdomain: 'octocat', clientRef: 'not-a-sha' }), /40-character commit SHA/)
})
