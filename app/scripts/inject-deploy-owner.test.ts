import { afterEach, describe, expect, it } from 'vitest'
import {
  injectDeployOwner,
  resolveGitHubActionsOwnerId,
} from './inject-deploy-owner'

const originalExplicitId = process.env.RUNNER_VAULT_OWNER_GITHUB_ID
const originalActionsId = process.env.GITHUB_REPOSITORY_OWNER_ID

afterEach(() => {
  if (originalExplicitId === undefined) delete process.env.RUNNER_VAULT_OWNER_GITHUB_ID
  else process.env.RUNNER_VAULT_OWNER_GITHUB_ID = originalExplicitId
  if (originalActionsId === undefined) delete process.env.GITHUB_REPOSITORY_OWNER_ID
  else process.env.GITHUB_REPOSITORY_OWNER_ID = originalActionsId
})

describe('deploy owner identity fallbacks', () => {
  it('uses an explicitly configured numeric owner ID before inspecting Git remotes', async () => {
    process.env.RUNNER_VAULT_OWNER_GITHUB_ID = '318252513'
    process.env.GITHUB_REPOSITORY_OWNER_ID = '999'
    await expect(injectDeployOwner()).resolves.toBe('318252513')
  })

  it('uses the immutable GitHub Actions repository owner ID for source archives', () => {
    expect(resolveGitHubActionsOwnerId({
      GITHUB_REPOSITORY_OWNER_ID: '318252513',
    } as NodeJS.ProcessEnv)).toBe('318252513')
  })

  it('rejects malformed explicit owner IDs instead of weakening the owner check', async () => {
    process.env.RUNNER_VAULT_OWNER_GITHUB_ID = 'owner-name'
    await expect(injectDeployOwner()).rejects.toThrow(/valid numeric GitHub account ID/)
  })

  it('rejects malformed GitHub Actions owner metadata', () => {
    expect(() => resolveGitHubActionsOwnerId({
      GITHUB_REPOSITORY_OWNER_ID: 'not-a-number',
    } as NodeJS.ProcessEnv)).toThrow(/valid numeric GitHub account ID/)
  })
})
