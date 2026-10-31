import { describe, expect, test } from 'vitest'
import { hasGithubOAuthConfig } from './auth-config.ts'

describe('hasGithubOAuthConfig', () => {
  test('requires both GitHub OAuth credentials', () => {
    expect(hasGithubOAuthConfig({})).toBe(false)
    expect(hasGithubOAuthConfig({ GITHUB_CLIENT_ID: 'client-id' })).toBe(false)
    expect(hasGithubOAuthConfig({ GITHUB_CLIENT_SECRET: 'client-secret' })).toBe(false)
  })

  test('rejects empty and whitespace-only credentials', () => {
    expect(hasGithubOAuthConfig({ GITHUB_CLIENT_ID: ' ', GITHUB_CLIENT_SECRET: 'secret' })).toBe(false)
    expect(hasGithubOAuthConfig({ GITHUB_CLIENT_ID: 'id', GITHUB_CLIENT_SECRET: '   ' })).toBe(false)
  })

  test('accepts both configured credentials', () => {
    expect(hasGithubOAuthConfig({ GITHUB_CLIENT_ID: 'id', GITHUB_CLIENT_SECRET: 'secret' })).toBe(true)
  })
})
