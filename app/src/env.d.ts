// Optional settings read by the Worker. The generated worker-configuration.d.ts
// declares the bindings; everything below is optional because the vault creates
// or derives it itself when it is absent (see lib/vault-config.ts).

declare namespace Cloudflare {
  interface Env {
    BETTER_AUTH_SECRET?: string
    VAULT_MASTER_KEY?: string
    ENCRYPTION_KEY?: string
    OWNER_GITHUB_ID?: string
    GITHUB_CLIENT_ID?: string
    GITHUB_CLIENT_SECRET?: string
    PUBLIC_ORIGIN?: string
  }
}

// nodejs_compat exposes process.env at runtime in Cloudflare Workers.
// Only the subset we actually use is declared to avoid pulling in @types/node.
declare var process: { env: Record<string, string | undefined> }
