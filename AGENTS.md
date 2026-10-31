Runner Credential Vault: single-owner credential vault (Cloudflare Worker + D1). Keep it small.

- `app/src/lib/` holds pure logic with tests; `runner-core.ts` is the runner operations, `runner-api.ts` only maps them to HTTP.
- The only place a stored value is decrypted is `readCredentialValue` in `lib/credential-service.ts`. Never return its value in `proxy` mode and never log it.
- Owner actions live in `app/src/vault-actions.ts` (`'use server'` on line 1) and must call `requireOwner()`.
- Never add an endpoint that returns a secret value to a runner without an explicit `inject` credential.
- Tests: `pnpm test` (workerd via vitest-pool-workers) and `node --test client/vault.test.mjs`.
