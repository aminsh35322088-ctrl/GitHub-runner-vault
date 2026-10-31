# Runner Credential Vault

A single-owner credential vault on Cloudflare Workers + D1 for a GitHub Actions
runner lab. A model on the runner can **use** a credential without ever seeing it,
and can **ask the owner** to register a new one through a one-time link.

Seeded from [remorses/sigillo](https://github.com/remorses/sigillo) (see `NOTICE.md`);
the multi-tenant secrets manager parts were removed.

## How it works

- **Owner** signs in with GitHub (only the account in `OWNER_GITHUB_ID` is accepted) and
  manages credentials at `/vault`: values are write-only, encrypted with AES-256-GCM
  bound to the row, with lifetime (permanent/temporary), visibility, enable/disable,
  expiry, and an append-only audit log.
- **Runner** proves its identity with the job's GitHub OIDC token, gets a 30-minute
  session, and calls `POST /api/runner/use`. The Worker adds the token, calls only the
  hosts the owner approved, follows no redirects, redacts echoed secrets, and returns
  the response. The token never reaches the runner (`delivery: proxy`, the default).
- **New credential:** the model sends metadata and setup notes to
  `POST /api/runner/registrations` and receives a one-time owner link. The owner sees the
  notes above the secret field, confirms hosts / auth header / lifetime, and pastes the token.
- `GITHUB_TOKEN` and similar can be listed as metadata-only entries (managed elsewhere).

See `docs/runner-usage.md` for the runner side and `SECURITY.md` for the trust model.

## Layout

| Path | What |
| --- | --- |
| `app/` | Worker (Spiceflow RSC UI + runner API) |
| `db/` | Drizzle schema and D1 migrations |
| `client/vault.mjs` | zero-dependency runner client (`list`, `request`, `use`) |

## Deploy (owner)

1. `wrangler d1 create runner-vault-db`, put the id in `app/wrangler.jsonc`.
2. Create a GitHub OAuth App; callback `https://<your-origin>/api/auth/callback/github`.
3. Set vars in `app/wrangler.jsonc`: `PUBLIC_ORIGIN`, `OWNER_GITHUB_ID`, `RUNNER_REPOSITORY`, `RUNNER_REPOSITORY_ID`.
4. `wrangler secret put` for `BETTER_AUTH_SECRET`, `ENCRYPTION_KEY` (`openssl rand -base64 32`), `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`.
5. `pnpm deploy`.

## Development

```
pnpm install
pnpm typecheck
pnpm test
```
