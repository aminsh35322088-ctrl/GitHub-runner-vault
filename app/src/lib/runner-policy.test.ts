import { beforeEach, describe, expect, test } from 'vitest'
import { getDb, schema } from 'db'
import { buildPolicy, DEFAULT_EVENTS, loadRunnerPolicy, pinRunnerPolicy, resolveRepositoryId, saveRunnerPolicy } from './runner-policy.ts'

const db = getDb()
const input = { repository: 'o/r', repositoryId: '123', branch: 'main', workflowFile: 'rdc-lab.yml', events: DEFAULT_EVENTS }
const AUD = 'https://vault.test'

beforeEach(async () => { await db.delete(schema.vaultSetting) })

describe('runner policy', () => {
  test('is exact: one repository id, one branch ref, one workflow ref, no pull requests', () => {
    expect(buildPolicy(input, AUD)).toEqual({
      audience: AUD, repository: 'o/r', repositoryId: '123',
      allowedRefs: ['refs/heads/main'], allowedEvents: ['workflow_dispatch', 'schedule', 'push'],
      allowedWorkflowRefs: ['o/r/.github/workflows/rdc-lab.yml@refs/heads/main'],
    })
  })

  test.each([
    ['pull requests', { ...input, events: 'pull_request' }],
    ['a folder in the workflow file', { ...input, workflowFile: '../x.yml' }],
    ['a bad repository', { ...input, repository: 'not a repo' }],
    ['a non-numeric id', { ...input, repositoryId: 'abc' }],
    ['a wildcard branch', { ...input, branch: '../main' }],
    ['a workflow that is not yaml', { ...input, workflowFile: 'rdc-lab.sh' }],
  ])('rejects %s', (_n, bad) => {
    expect(() => buildPolicy(bad, AUD)).toThrow()
  })

  test('fails closed until the owner saves one, then uses it; Worker variables win', async () => {
    await expect(loadRunnerPolicy(db, {}, AUD)).rejects.toThrow()
    await saveRunnerPolicy(db, input, AUD)
    expect((await loadRunnerPolicy(db, {}, AUD)).repositoryId).toBe('123')
    const env = { RUNNER_REPOSITORY: 'a/b', RUNNER_REPOSITORY_ID: '9', RUNNER_ALLOWED_REFS: 'refs/heads/x', RUNNER_ALLOWED_EVENTS: 'push', RUNNER_ALLOWED_WORKFLOW_REFS: 'a/b/.github/workflows/w.yml@refs/heads/x' }
    expect((await loadRunnerPolicy(db, env, AUD)).repository).toBe('a/b')
  })

  test('builds a safe bootstrap policy from the pinned owner without manual repository settings', async () => {
    const policy = await loadRunnerPolicy(db, { OWNER_GITHUB_ID: '65' }, AUD)
    expect(policy.bootstrap).toEqual({
      ownerId: '65', branch: 'main', workflowFile: 'rdc-lab.yml',
      allowedEvents: ['workflow_dispatch', 'schedule', 'push'],
    })
    await db.delete(schema.vaultSetting)
    await expect(loadRunnerPolicy(db, {}, AUD)).rejects.toThrow()
  })

  test('atomically pins the first OIDC repository and refuses to replace it', async () => {
    const ownerBound = { ...input, repositoryOwnerId: '65' }
    const pinned = await pinRunnerPolicy(db, ownerBound, AUD)
    expect(pinned).toMatchObject(ownerBound)
    expect(await loadRunnerPolicy(db, {}, AUD)).toMatchObject({
      repository: 'o/r', repositoryId: '123', repositoryOwnerId: '65',
    })
    await expect(pinRunnerPolicy(db, { ...input, repository: 'other/repo', repositoryId: '456', repositoryOwnerId: '65' }, AUD))
      .rejects.toThrow(/already pinned/)
    expect((await loadRunnerPolicy(db, {}, AUD)).repository).toBe('o/r')
  })

  test('an invalid policy is never stored', async () => {
    await expect(saveRunnerPolicy(db, { ...input, events: 'pull_request_target' }, AUD)).rejects.toThrow()
    await expect(loadRunnerPolicy(db, {}, AUD)).rejects.toThrow()
  })

  test('repository id lookup trusts only an exact, successful, non-redirected answer', async () => {
    const ok = (async () => Response.json({ id: 1374269690, full_name: 'Aminsh/Lab' })) as unknown as typeof fetch
    expect(await resolveRepositoryId('aminsh/lab', ok)).toBe('1374269690')
    expect(await resolveRepositoryId('aminsh/other', ok)).toBeNull()
    expect(await resolveRepositoryId('x/y', (async () => new Response('', { status: 404 })) as unknown as typeof fetch)).toBeNull()
    expect(await resolveRepositoryId('x/y', (async () => new Response('', { status: 302 })) as unknown as typeof fetch)).toBeNull()
    expect(await resolveRepositoryId('x/y', (async () => { throw new Error('net') }) as unknown as typeof fetch)).toBeNull()
    expect(await resolveRepositoryId('bad name', ok)).toBeNull()
  })
})
