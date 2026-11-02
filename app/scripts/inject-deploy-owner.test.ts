import { describe, expect, it } from 'vitest'
import { injectDeployOwner, resolveGitHubActionsOwnerId } from './inject-deploy-owner'

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status })
const remote = (url: string) => () => url
const noRemote = () => { throw new Error('no git') }
const never = (async () => { throw new Error('network must not be used') }) as unknown as typeof fetch
const user = { id: 318252513, login: 'octocat', type: 'User' }

describe('deploy owner identity', () => {
  it('uses an explicit numeric ID without touching Git or the network', async () => {
    await expect(injectDeployOwner({ RUNNER_VAULT_OWNER_GITHUB_ID: '318252513', GITHUB_REPOSITORY_OWNER_ID: '999' } as NodeJS.ProcessEnv, never, noRemote))
      .resolves.toEqual({ id: '318252513' })
  })

  it('rejects malformed explicit and Actions IDs instead of weakening the check', async () => {
    await expect(injectDeployOwner({ RUNNER_VAULT_OWNER_GITHUB_ID: 'owner-name' } as NodeJS.ProcessEnv, never, noRemote)).rejects.toThrow(/valid numeric/)
    expect(() => resolveGitHubActionsOwnerId({ GITHUB_REPOSITORY_OWNER_ID: 'x' } as NodeJS.ProcessEnv)).toThrow(/valid numeric/)
  })

  it('resolves the origin owner through the JSON API and sends a token when present', async () => {
    let auth: string | null = null
    const f = (async (_u: string, init?: RequestInit) => { auth = new Headers(init?.headers).get('authorization'); return json(user) }) as unknown as typeof fetch
    const owner = await injectDeployOwner({ GITHUB_TOKEN: 't' } as NodeJS.ProcessEnv, f, remote('https://github.com/octocat/vault.git'))
    expect(owner).toEqual({ id: '318252513', login: 'octocat', repo: 'octocat/vault' })
    expect(auth).toBe('Bearer t')
  })

  it('refuses an organization owner with a clear reason instead of binding it', async () => {
    const f = (async () => json({ id: 7, login: 'acme', type: 'Organization' })) as unknown as typeof fetch
    const actionsContext = {
      GITHUB_REPOSITORY_OWNER_ID: '7',
      GITHUB_REPOSITORY_OWNER: 'acme',
      GITHUB_REPOSITORY: 'acme/vault',
    } as NodeJS.ProcessEnv
    expect(await injectDeployOwner(actionsContext, f, remote('git@github.com:acme/vault.git')))
      .toEqual({ id: null, login: 'acme', repo: 'acme/vault', error: 'organization' })
  })

  it('uses a matching Actions owner context and otherwise stays locked when the API is unavailable', async () => {
    const down = (async () => new Response('x', { status: 403 })) as unknown as typeof fetch
    const matchingActionsContext = {
      GITHUB_REPOSITORY_OWNER_ID: '42',
      GITHUB_REPOSITORY_OWNER: 'octocat',
      GITHUB_REPOSITORY: 'octocat/vault',
    } as NodeJS.ProcessEnv
    expect(await injectDeployOwner(matchingActionsContext, down, remote('https://github.com/octocat/vault')))
      .toMatchObject({ id: '42', login: 'octocat', repo: 'octocat/vault' })
    expect(await injectDeployOwner({
      ...matchingActionsContext,
      GITHUB_REPOSITORY_OWNER: 'someone-else',
      GITHUB_REPOSITORY: 'someone-else/other',
    } as NodeJS.ProcessEnv, down, remote('https://github.com/octocat/vault')))
      .toEqual({ id: null, login: 'octocat', repo: 'octocat/vault', error: 'lookup_failed' })
    expect(await injectDeployOwner({
      ...matchingActionsContext,
      GITHUB_REPOSITORY: 'octocat/another-repo',
    } as NodeJS.ProcessEnv, down, remote('https://github.com/octocat/vault')))
      .toMatchObject({ id: '42' })
    let requests = 0
    const htmlResponse = (async () => {
      requests += 1
      return new Response('<meta name="octolytics-dimension-user_id" content="318252513"><meta name="octolytics-dimension-user_login" content="octocat">')
    }) as unknown as typeof fetch
    expect(await injectDeployOwner({} as NodeJS.ProcessEnv, htmlResponse, remote('https://github.com/octocat/vault')))
      .toEqual({ id: null, login: 'octocat', repo: 'octocat/vault', error: 'lookup_failed' })
    expect(requests).toBe(1)
    expect(await injectDeployOwner({} as NodeJS.ProcessEnv, down, remote('https://github.com/octocat/vault')))
      .toEqual({ id: null, login: 'octocat', repo: 'octocat/vault', error: 'lookup_failed' })
  })

  it('rejects an Actions ID when the repository owner context alone mismatches the origin', async () => {
    const f = (async () => new Response('x', { status: 500 })) as unknown as typeof fetch
    const env = {
      GITHUB_REPOSITORY_OWNER_ID: '42',
      GITHUB_REPOSITORY_OWNER: 'octocat',
      GITHUB_REPOSITORY: 'another-owner/vault',
    } as NodeJS.ProcessEnv
    expect(await injectDeployOwner(env, f, remote('https://github.com/octocat/vault')))
      .toEqual({ id: null, login: 'octocat', repo: 'octocat/vault', error: 'lookup_failed' })
  })
})
