# Using the vault from a runner

## Automatic setup in GitHub Runner Lab

No Runner repository form, repository ID, shared token or manual Vault policy is required.

The existing Lab workflow needs `permissions: id-token: write`. Before RDC starts, it
downloads the reviewed Vault client, exchanges the GitHub OIDC identity for a 30-minute
Vault session and reads the metadata-only registry. The first valid run is accepted only
when all of these claims match:

- `repository_owner_id` equals the immutable owner ID pinned by the Vault deployment.
- `ref` is exactly `refs/heads/main`.
- `workflow_ref` is exactly `<repository>/.github/workflows/rdc-lab.yml@refs/heads/main`.
- `event_name` is `workflow_dispatch`, `schedule` or `push`.

The Worker atomically pins the first valid `repository`, `repository_id` and owner ID in D1.
Subsequent runs must match that immutable repository identity. Concurrent first requests
from another repository cannot replace the winner. Pull-request and fork runs are refused.

Set these Lab Actions variables once when enabling the integration:

| Variable | Value |
| --- | --- |
| `RUNNER_VAULT_URL` | HTTPS origin of the deployed Worker |
| `RUNNER_VAULT_REPOSITORY` | Repository containing the reviewed `client/vault.mjs` |
| `RUNNER_VAULT_CLIENT_REF` | Reviewed immutable 40-character Git commit SHA |

The existing **Vault smoke test** dispatch option checks OIDC, session issuance, registry
access, and the configured GitHub and Cloudflare API credentials through read-only proxy
calls. Response bodies remain in runner temporary files; logs show only pass/fail markers.

## Commands (`client/vault.mjs`)

```bash
export VAULT_URL=https://<vault-origin>

node vault.mjs list
node vault.mjs use CF_API_TOKEN GET https://api.cloudflare.com/client/v4/user/tokens/verify --purpose "verify token"
node vault.mjs request --name RAILWAY_TOKEN --service Railway --doc doc.json
```

`request` prints a one-time link for the owner and nothing secret. The model never
receives a token. `use` prints the upstream response body; the exit code is 3 for an
upstream HTTP error and 2 if the vault refused the call.

## `doc.json`

Strict schema; unknown keys are rejected and everything is shown to the owner as plain text.

```json
{
  "overview": "Needed to deploy a Worker with wrangler.",
  "task": "Deploy a Cloudflare Worker",
  "token_type": "API token",
  "creation_link": { "title": "Cloudflare API tokens", "url": "https://dash.cloudflare.com/profile/api-tokens" },
  "creation_steps": ["Create Token", "Use the Edit Cloudflare Workers template"],
  "required_permissions": [{ "name": "Workers Scripts", "level": "Edit", "why": "upload the script" }],
  "unnecessary_permissions": ["DNS", "Account Settings"],
  "security_notes": ["Restrict to one account"],
  "expiration_guidance": ["7 days is enough for a deploy"],
  "official_documentation_links": [{ "title": "Wrangler", "url": "https://developers.cloudflare.com/workers/wrangler/" }],
  "verification": "verified"
}
```

If the model did not check official documentation it must say `"verification": "unverified"`
and give an `unverified_note`.

## What a model should expect

- A credential that is missing, hidden, disabled or expired all answer `unavailable`.
- Calls to a host the owner did not approve are refused (`host_not_allowed`).
- Limits: 30 calls/min per credential, 256 KiB request, 1 MiB response, 20 s timeout.
