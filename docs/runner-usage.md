# Using the vault from a runner

## One-time setup in the Lab workflow

The job needs permission to request an OIDC token (this is the only change to the Lab repo):

```yaml
permissions:
  id-token: write
  contents: read
```

The vault only accepts tokens from the configured repository, from `refs/heads/main`
(by default) and from `workflow_dispatch` / `schedule` events. Pull-request and fork
runs cannot get a session.

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
