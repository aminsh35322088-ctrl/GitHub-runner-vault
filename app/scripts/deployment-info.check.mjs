import assert from 'node:assert/strict'
import test from 'node:test'
import {
  buildDeploymentInfo,
  buildVaultUrl,
  parsePublicVaultUrl,
  parseRepository,
  parseWorkerName,
  repositoryFromRemote,
  resolveRepositoryIdentity,
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
  assert.equal(parseWorkerName(source, 'vault-copy-1'), 'vault-copy-1')
  assert.throws(() => parseWorkerName(source, 'Bad Worker'), /workers.dev-compatible/)
  assert.throws(() => parseWorkerName('{ "main": "src/app.tsx" }'), /Worker name is missing/)
})

test('validates an explicit custom Vault origin', () => {
  assert.equal(parsePublicVaultUrl('https://vault.example.net'), 'https://vault.example.net')
  assert.equal(parsePublicVaultUrl('https://vault.example.net/'), 'https://vault.example.net')
  for (const value of [
    'http://vault.example.net', 'https://user:pw@vault.example.net',
    'https://vault.example.net/path', 'https://vault.example.net:8443',
    'https://vault.example.net/?x=1', 'https://vault.example.net/#frag',
  ]) assert.throws(() => parsePublicVaultUrl(value))
})

test('GitHub Actions repository identity is authoritative', () => {
  assert.equal(resolveRepositoryIdentity('octocat/actual', 'octocat/actual', ''), 'octocat/actual')
  assert.equal(resolveRepositoryIdentity('octocat/actual', '', ''), 'octocat/actual')
  assert.throws(() => resolveRepositoryIdentity('octocat/actual', 'octocat/other', ''), /must match GITHUB_REPOSITORY/)
  assert.equal(resolveRepositoryIdentity('', 'octocat/manual', ''), 'octocat/manual')
  assert.equal(resolveRepositoryIdentity('', '', 'git@github.com:octocat/remote.git'), 'octocat/remote')
})
test('resolves and validates a repository identity from supported GitHub remotes', () => {
  assert.equal(parseRepository('octocat/runner-vault'), 'octocat/runner-vault')
  assert.equal(repositoryFromRemote('https://github.com/octocat/runner-vault.git'), 'octocat/runner-vault')
  assert.equal(repositoryFromRemote('git@github.com:octocat/runner-vault.git'), 'octocat/runner-vault')
  assert.equal(repositoryFromRemote('ssh://git@github.com/octocat/runner-vault.git'), 'octocat/runner-vault')
  for (const value of ['octocat', 'octocat/../bad', 'https://evil.example/octocat/repo', '']) {
    assert.throws(() => parseRepository(value))
  }
  assert.throws(() => repositoryFromRemote('https://github.com.evil.example/octocat/repo.git'))
})

test('builds the workers.dev URL from worker and subdomain', () => {
  assert.equal(buildVaultUrl('runner-vault', 'octocat'), 'https://runner-vault.octocat.workers.dev')
})

test('parses the workers subdomain success shape', () => {
  assert.equal(parseWorkersSubdomain({ success: true, errors: [], result: { subdomain: 'octocat' } }), 'octocat')
  assert.equal(parseWorkersSubdomain({ success: true, errors: [], result: { subdomain: 'octocat-123' } }), 'octocat-123')
})

test('deployment metadata can publish a custom domain without Cloudflare API credentials', () => {
  const info = buildDeploymentInfo({
    worker: 'vault-copy-1',
    publicUrl: 'https://vault.example.net',
    repository: 'octocat/vault-copy',
    clientRef: 'b'.repeat(40),
    now: new Date('2026-11-04T00:00:00.000Z'),
  })
  assert.equal(info.url, 'https://vault.example.net')
  assert.equal(info.worker, 'vault-copy-1')
  assert.equal(info.repository, 'octocat/vault-copy')
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
    configuredSubdomain: 'example-account',
    token: undefined,
    accountId: undefined,
    fetchImpl: async () => { called = true; throw new Error('network should not be used') },
  })
  assert.equal(subdomain, 'example-account')
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
    repository: 'octocat/GitHub-runner-vault',
    clientRef: 'a'.repeat(40),
    now: new Date('2026-11-04T00:00:00.000Z'),
  })
  assert.deepEqual(info, {
    url: 'https://runner-vault.octocat.workers.dev',
    clientRef: 'a'.repeat(40),
    worker: 'runner-vault',
    repository: 'octocat/GitHub-runner-vault',
    updatedAt: '2026-11-04T00:00:00.000Z',
  })
  assert.throws(() => buildDeploymentInfo({ worker: 'runner-vault', subdomain: 'octocat', repository: 'octocat/repo', clientRef: '' }), /40-character commit SHA/)
  assert.throws(() => buildDeploymentInfo({ worker: 'runner-vault', subdomain: 'octocat', repository: 'octocat/repo', clientRef: 'not-a-sha' }), /40-character commit SHA/)
})
