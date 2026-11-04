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

# Run the reviewed local CLI adapter (Northflank example)
# Run the reviewed Cloudflare Wrangler adapter:
node vault.mjs serve CLOUDFLARE_API_TOKEN --tool wrangler
# Export the exact loopback URL and non-secret placeholder printed by serve:
# CLOUDFLARE_API_BASE_URL=http://127.0.0.1:<ephemeral-port>/client/v4
# CLOUDFLARE_API_TOKEN=vault-local-placeholder
# wrangler whoami

node vault.mjs serve NORTHFLANK_API_TOKEN
# In another terminal, export the exact loopback URL and placeholder printed by serve:
# NF_API_BASE_URL=http://127.0.0.1:<ephemeral-port>/v1
# NF_API_TOKEN=vault-local-placeholder
# nf list projects --quiet --output json --noDefaults
```

`request` prints a one-time link for the owner and nothing secret. The model never
receives a token. `use` prints the upstream response body; the exit code is 3 for an
upstream HTTP error and 2 if the vault refused the call. `serve` supports only reviewed
CLI adapters, binds to loopback and does not expose or execute a command.

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

For a custom service with a documented API origin, the model must attach a strict
`service_adapter` object. For example, the Northflank adapter includes the official
API host, its read-only token check and the supported headless CLI integration:

```json
{
  "api_base_url": "https://api.northflank.com/v1",
  "auth_header": "Authorization",
  "auth_scheme": "Bearer",
  "validation": { "method": "GET", "path": "/projects" },
  "cli_tools": [{
    "id": "northflank",
    "label": "Northflank CLI",
    "binary": "nf",
    "integration": "base-url-env",
    "variable": "NF_API_BASE_URL",
    "setup_hint": "Use the Vault local bridge with NF_API_TOKEN set to its non-secret placeholder."
  }]
}
```

Place that object under `service_adapter` in the registration document. The official
documentation links must identify the same provider domain that owns the API host.
The Vault rejects custom hosts and unsafe schemes, ports, paths or CLI variable names.
Do not attach an adapter unless the official provider documentation has been checked.
The actual token must never appear in the document, model output, shell arguments or CLI environment.

## What a model should expect

- A credential that is missing, hidden, disabled or expired all answer `unavailable`.
- Calls to a host the owner did not approve are refused (`host_not_allowed`).
- Limits: 30 calls/min per credential, 256 KiB request, 1 MiB response and a configurable 5–30 s upstream timeout (20 s default).

## Telegram Bot API

Add **Telegram Bot API** from the provider catalog and paste the BotFather token. The optional **Test access & inspect permissions** action calls Telegram's official `getMe` method. It verifies the returned bot ID against the numeric prefix in the token and records the public numeric ID and username as connection metadata. A network error or rate limit is reported as unavailable, not as an invalid token.

The proxy uses Telegram's documented path authentication (`/bot<TOKEN>/METHOD_NAME`). For Telegram requests, give the Vault the method path only, for example `https://api.telegram.org/getMe`; the Vault inserts the Bot Token into the upstream path, never into a caller-controlled header. The token is not returned in runner metadata, audit details, or the response body.

This catalog entry covers the Bot API token. The `tgcloud` CLI's separate Serverless deployment login is a distinct flow documented by Telegram and is not represented as a Bot API credential here.
