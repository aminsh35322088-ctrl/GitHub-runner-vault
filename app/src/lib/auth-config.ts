export interface GithubOAuthConfig {
  GITHUB_CLIENT_ID?: string
  GITHUB_CLIENT_SECRET?: string
}

export function hasGithubOAuthConfig(config: GithubOAuthConfig): boolean {
  return Boolean(config.GITHUB_CLIENT_ID?.trim() && config.GITHUB_CLIENT_SECRET?.trim())
}
