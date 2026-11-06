# Runner Credential Vault

A **single-owner credential vault** on Cloudflare Workers + D1 for GitHub Actions runners.
Each deployment is isolated to one GitHub owner. The first valid OIDC run from that owner's exact
`main/.github/workflows/rdc-lab.yml` workflow automatically pins the runner repository's immutable ID in D1;
no repository name, repository ID, shared token or manual policy entry is required.

It solves one problem: *an agent on the runner needs a token for some service (Cloudflare, Railway, ...) but must never
be able to read it.*

- The agent can **use** a stored credential: it asks the vault "call this URL with credential `X`". The Worker adds the
  token, makes the call, and returns the response. **The token never reaches the runner.**
- The agent can **ask the owner** to register a missing credential: it gets a **one-time link** to give to the owner, who
  opens a web page, reads the agent's setup notes, chooses the rules and pastes the token.
- The **owner** can create credentials directly from a searchable, categorized provider catalog in the dashboard (or choose a custom service), as well as see, hide, disable, expire, replace and delete credentials and read an audit log.

> Seeded from [remorses/sigillo](https://github.com/remorses/sigillo) (see `NOTICE.md`). The multi-tenant secrets-manager
> parts were removed; what remains is a single-owner registry with a proxy and a runner API.

---

## Contents

1. [Threat model](#threat-model)
2. [How it works](#how-it-works)
3. [Credential model](#credential-model)
4. [Runner API reference](#runner-api-reference)
5. [Runner client](#runner-client)
6. [Owner UI](#owner-ui)
7. [Deployment](#deployment) (step by step)
8. [Configuration reference](#configuration-reference)
9. [Operations](#operations)
10. [Development and tests](#development-and-tests)
11. [Known limits and roadmap](#known-limits-and-roadmap)
12. [Repository layout](#repository-layout)

---

## Threat model

**Goal:** a compromised or prompt-injected model on the runner cannot read a stored secret.

The Runner host and trusted workflow are part of the trusted computing base, but the model/Agent is not. The trusted bootstrap passes the OIDC requester to a separate Broker over an anonymous pipe, then removes it before Agent startup. The Agent runs under an unprivileged Unix UID and receives neither OIDC requester nor Vault Session. The vault therefore:

| Risk | Mitigation |
| --- | --- |
| Agent reads the token | Token is stored only in the Worker (AES-256-GCM, bound to the row) and is never returned in `proxy` mode. |
| Agent sends the token to an attacker's host | The Worker calls **only hosts the owner approved** per credential; HTTPS only, default port, no redirects followed. |
| Agent smuggles auth / routing headers | Request header **allowlist**; the auth header is set by the Worker after everything else. |
| Upstream echoes the token back | Response body and headers are scanned and the token is **redacted** (raw, URL-encoded, JSON-escaped, base64). |
| Agent tricks the owner into a bad setup | Models only *propose* a name and setup notes. The **owner** chooses hosts, auth header, lifetime and visibility. Notes are shown as plain text with the real hostname next to each link. |
| Someone else gets a runner session | Bootstrap requires the deployment-pinned `repository_owner_id`, exact `main` ref, `rdc-lab.yml` `workflow_ref`, and an allowed event. The first repository ID is atomically pinned in D1; later runs must match it. Pull-request events are refused. |
| Stolen session | 30-minute sessions, atomic D1 sliding-window limits, append-only audit log, and an owner-side **revoke all sessions** button. |
| Someone else logs in to the owner UI | Sign-in uses a **private GitHub App created by you** and is restricted to **one numeric account id** (the app's creator); cookie sessions only. |
| Agent edits the vault code | The vault runs as a separate Cloudflare Worker. |

What the vault does **not** protect against: an agent that is allowed to call an approved host can do anything that token
permits on that host. Keep tokens least-privilege and short-lived (temporary credentials max 24 hours).
OIDC authenticates the *workflow run*, not an individual process. The Runner host and trusted bootstrap remain trusted; the Agent receives only the Broker operations allowed to its Unix UID and never receives the OIDC requester or the Vault Session.

See `SECURITY.md` for the short version.

## How it works


```
    Trusted GitHub Actions job (trusted bootstrap only)
                  |
                  | OIDC requester passed over anonymous stdin pipe
                  v
    Broker process (runner-vault-broker Unix UID; memory only)
       | obtains OIDC token and short-lived Vault Session
       | keeps Session only in process memory
       | HTTPS + Session
       v
    Cloudflare Vault Worker --------------------> approved upstream
       | decrypts stored credential in memory

    Agent / RDC process (rdc-agent Unix UID)
       |
       | client/vault.mjs: fixed JSON protocol v1
       | AF_UNIX socket; peer UID checked with SO_PEERCRED
       +----------------------------------------> Broker

    Owner browser -- GitHub OAuth --> /vault
                                     requests / register / audit / settings
```

The trusted bootstrap passes the GitHub OIDC requester capability to the Broker through an anonymous pipe and then scrubs it.
The Broker runs under its own unprivileged Unix identity and is the only long-lived service process that retains the Vault Session. The Agent uses a fixed, versioned Unix-socket protocol; the
Broker verifies the peer UID, accepts only reviewed operations, and never exports its Session or OIDC token. If the optional
Broker is unavailable, Vault CLI operations fail closed; RDC, Tailscale and non-Vault Agent work continue independently.

Registering a new credential:

1. The agent finds the name missing in `list` and runs `request` with a setup document.
2. The vault creates a **pending, hidden** entry and returns a **one-time link** (about 15 minutes, works once).
3. The owner signs in with GitHub. A Vault notification and the Runner requests inbox show the pending request, runner identity, setup notes and read-only API destination. The owner reviews the request, then supplies only the secret token, lifetime/expiry and runner visibility. Hosts, auth header/scheme and validation behavior come from the verified provider adapter; no manual network or scope settings are exposed.
4. If the original 15-minute link expires or is superseded, the owner can create a fresh one-time owner form from the request inbox. Reissuing invalidates every earlier unused link; the link hash remains the only value stored in the database.
5. The owner can dismiss an unwanted pending request. Dismissal atomically removes only an unfilled pending credential, invalidates its links through the foreign-key cascade and records an append-only audit event; active credentials cannot be dismissed through this action.
6. Known providers can also be added directly from **Add credential**. Unknown providers are requested by the runner so the model can attach official documentation and a reviewed Service Adapter.
7. The credential becomes **Active**; the agent sees minimal metadata in `list` and can call it through `use`. CLI integration metadata is returned separately and only when requested.

## Credential model

One flat registry; a credential has these properties:

| Property | Values | Meaning |
| --- | --- | --- |
| `name` | `^[A-Z][A-Z0-9_]*$` | Stable identifier. Some names (`PATH`, `LD_*`, proxy variables, ...) are reserved. |
| `status` | `pending` / `active` / `disabled` | `pending` = model asked, owner has not stored a value yet. |
| `visible` | true / false | Hidden credentials cannot be listed or used. |
| `lifetime` | `permanent` / `temporary` | Temporary credentials **must** expire within 24 hours. |
| `expiresAt` | time or none | Permanent ones may optionally expire (max about 3 years). |
| `delivery` | `proxy` only | The Worker makes the API call; the raw token is never returned to the runner. |
| `allowedHosts` | exact hostnames | Required for `proxy`. No wildcards, no IPs, no ports, no internal suffixes. |
| `authHeader` / `authScheme` | header name; `Bearer` / `Token` / `Raw` | How the token is attached upstream (default `Authorization: Bearer <token>`). |
| `externallyManaged` | true / false | Metadata-only entry such as `GITHUB_TOKEN`: listed for discovery, holds no value, can never be proxied. |

**Availability rule.** A runner can list or use a credential only if it is `active`, `visible`, not expired and has a value
(or is an externally managed entry for listing). It is re-checked against the stored row on **every** call, so disabling,
hiding, deleting or expiry takes effect on the very next request. A missing, hidden, disabled or expired credential all
answer the same `unavailable` (no probing for hidden names).

**Supported credential formats.** The current registry stores opaque single-line text values and presents them through
owner-approved HTTPS API requests. The upstream auth formatter supports Authorization: Bearer, Authorization: Token,
and raw/custom API-key headers. This works for personal access tokens, OAuth access tokens, GitHub App installation
tokens and ordinary provider API keys when the provider accepts a compatible HTTP header. Validation is provider-adapter
based and does not itself refresh or renew credentials.

**Explicit limits.** Browser GitHub OAuth is only the Vault owner's dashboard sign-in. Provider Device Authorization,
automatic OAuth refresh-token rotation, browser-cookie/session capture, multi-line SSH private-key or certificate storage,
SSH-agent signing, TLS client-certificate delivery, and environment/file injection are not implemented. The database
and runner contract are proxy-only; legacy inject rows are not usable. Do not register these unsupported values under
a token label or assume that a successful save makes their lifecycle operational. They require distinct, reviewed delivery
and key-handling designs rather than relaxing the single-line/header validation.

**Encryption.** Values are AES-256-GCM encrypted with a 32-byte key derived (HKDF) from a random master key supplied
as the `VAULT_MASTER_KEY` Worker secret. The authenticated data binds each ciphertext to `credential:{id}:v{keyVersion}`, so a ciphertext
copied to another row will not decrypt. See [Where the key lives](#where-the-key-lives) for the trade-off.

**Setup documentation** attached by a model is validated against a strict schema (unknown keys rejected, size limits,
https-only links with public hostnames, control and bidi characters stripped) and rendered as plain text. It must state
honestly whether the model verified it against official documentation (`verified`/`unverified`).

## Runner API reference

All endpoints are JSON, return `Cache-Control: no-store`, and answer **503 `vault_not_configured`** if the Worker is
missing required configuration (it fails closed). Authenticated endpoints take `Authorization: Bearer <session>`.

### `POST /api/runner/session`

Header: `Authorization: Bearer <GitHub OIDC JWT>` (audience = the vault origin).
`200 { token, expiresAt }`. `401 unauthorized` for any rejection (the reason is only written to the audit log).
`429 rate_limited` after 20 sessions per hour.

### `GET /api/runner/registry`

`200 { credentials: [{ name, service, purpose, lifetime, delivery, validation, expiresAt, externallyManaged }] }`.
Only Active + Visible entries. This intentionally stable, minimal contract never exposes API hosts, Adapter configuration, IDs or values.

### `GET /api/runner/integrations`

A separate authenticated capability endpoint for CLI consumers. It returns only Active + Visible, unexpired, value-backed credentials that have a reviewed CLI Adapter:
`200 { integrations: [{ name, service, adapter: { apiBaseUrl, cliTools } }] }`.
It never returns the token, encrypted value, credential ID or arbitrary documentation. Do not use this endpoint for general model registry discovery.

### `POST /api/runner/registrations`

Body `{ name, service, doc }`, where `doc` follows the schema in `docs/runner-usage.md`. The vault generates purpose automatically from the service catalog.
`200 { link, expiresAt }`: give the link to the owner. `400 invalid_name | reserved_name | invalid_doc` (with `detail`),
`409 exists`, `429 rate_limited` (10 per hour).

### `POST /api/runner/use`

JSON requests use body `{ name, method, url, headers?, body?, purpose?, consumer? }`. Their complete JSON envelope is capped at 512 KiB and the proxy still enforces its 10 MiB body limit after parsing.

For large or binary uploads, use the raw transport instead of embedding the payload in JSON:

- `Content-Type: application/octet-stream`
- `X-Vault-Proxy-Metadata: <unpadded base64url of UTF-8 JSON metadata>`
- The request body contains the original bytes, unchanged. The metadata object contains `name`, `method`, `url`, and optional `headers`, `purpose`, and `consumer`.
- The raw body is limited to 10 MiB. A declared `Content-Length` is checked before reading; the streamed byte count is also enforced when the header is absent or inaccurate.

The optional low-cardinality `consumer` field is used only to group aggregate usage (for example `cli:northflank`); it is not trusted as an identity.

- Methods: `GET HEAD POST PUT PATCH DELETE`. URL: `https`, default port, no user info, host in the owner's list.
- Request headers allowed: `accept`, `accept-language`, `content-type`, `if-match`, `if-none-match`,
  `x-github-api-version`, `x-api-version`. Anything else (including `Authorization`, `Host`, `Cookie`) is refused.
- Limits: raw request body 10 MiB, JSON envelope 512 KiB, at most 3 active raw uploads per Worker isolate (`503 proxy_busy` when full), response 1 MiB (then `truncated: true`), configurable 5–30 s upstream timeout (default 20 s), 30 calls per minute per credential. Redirects are **not** followed (a `3xx` is returned as is).

`200 { status, headers, body, truncated, redacted }`: `status` is the **upstream** status; an upstream error is still a
`200` from the vault. Vault-side errors:

| HTTP | `error` | Meaning |
| --- | --- | --- |
| 400 | `invalid_request`, `invalid_body`, `bad_method`, `bad_url`, `bad_header`, `body_not_allowed`, `not_a_proxy_credential` | Malformed or not allowed. |
| 401 | `missing_token`, `unauthorized` | No or invalid session (expired, revoked, tampered). |
| 403 | `host_not_allowed` | Host not approved by the owner for this credential. |
| 404 | `unavailable` | Missing, hidden, disabled or expired (indistinguishable on purpose). |
| 413 | `body_too_large` | Raw request body over 10 MiB or JSON envelope over 512 KiB. |
| 429 | `rate_limited` | Too many calls. |
| 503 | `proxy_busy` | Three raw uploads are already active in this Worker isolate; retry later. |
| 502 / 504 | `upstream_error`, `upstream_timeout` | Upstream failed (no detail is returned, so nothing can leak). |

Every call is audited with the worker-observed result, the purpose the agent gave, and `METHOD host/path -> status`
(never the query string, headers, body or token).

## Runner client

`client/vault.mjs` is one zero-dependency file (Node 18+). It talks only to the local version-1 AF_UNIX Broker protocol
(default socket `/run/runner-vault/broker.sock`, override with `VAULT_BROKER_SOCKET`). It never reads
`ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN`, never performs direct OIDC or Runner API requests, and has no Session cache or
fallback. The trusted workflow bootstraps a separate `runner-vault-broker` Unix account; that process obtains OIDC and
keeps the short-lived Vault Session in memory. The CLI sends only fixed operations and request payloads over the socket.
The Broker checks the connecting process UID with `SO_PEERCRED` and does not expose Session material. Run the CLI as
`rdc-agent`; if the Broker is absent or denied, the CLI fails closed while non-Vault Runner work remains available.

```bash
export VAULT_URL=https://<your-vault-origin>

node client/vault.mjs list
node client/vault.mjs use CF_API_TOKEN GET https://api.cloudflare.com/client/v4/user/tokens/verify --purpose "verify token"
node client/vault.mjs request --name RAILWAY_TOKEN --service Railway --doc doc.json

# Supported CLI bridge (Northflank example): run in one terminal
# Supported Cloudflare Wrangler bridge:
node client/vault.mjs serve CLOUDFLARE_API_TOKEN --tool wrangler
# Export the loopback URL and placeholder printed by serve:
# CLOUDFLARE_API_BASE_URL=http://127.0.0.1:<ephemeral-port>/client/v4
# CLOUDFLARE_API_TOKEN=vault-local-placeholder
# wrangler whoami

node client/vault.mjs serve NORTHFLANK_API_TOKEN

# In a second terminal, use the displayed loopback-only env values:
# NF_API_BASE_URL=http://127.0.0.1:<ephemeral-port>/v1
# NF_API_TOKEN=vault-local-placeholder
# nf list projects --quiet --output json --noDefaults
```

The bridge binds only to `127.0.0.1`, maps paths to the Adapter's fixed HTTPS API origin, filters request headers and never forwards the CLI's placeholder token. The Vault Worker injects the actual credential directly upstream. Stop the bridge with Ctrl+C; it is not a general-purpose reverse proxy.

Wrangler's API base URL and token overrides are documented in the [Cloudflare system environment variables reference](https://developers.cloudflare.com/workers/wrangler/system-environment-variables/). Northflank's `NF_API_BASE_URL` and `NF_API_TOKEN` behavior is documented in the [Northflank CLI package reference](https://www.npmjs.com/package/@northflank/cli).

Exit codes: `0` ok, `2` vault refused, `3` upstream HTTP error. See `docs/runner-usage.md` for `doc.json` and what a model
should expect. The trusted runner workflow must request `permissions: id-token: write` and set `VAULT_URL` to the deployed Worker origin.

## Owner UI

The dashboard has a searchable provider catalog and a guided three-step credential form (Service/Request → Secret → Access). Runner-created credentials appear in a dedicated request inbox with automatic in-panel notifications, runner identity, requested task, setup documentation, API destination and explicit link state (active, expired, used/replaced or not issued). The inbox uses a bounded metadata-only query rather than fetching each request separately. The owner can reissue an expired one-time form without creating a duplicate credential, or dismiss an unwanted pending request with explicit confirmation and an audit record. When a request is approved or dismissed, its request notifications are marked read. The owner supplies only the secret, lifetime/expiry and visibility. The UI displays the verified API destination as read-only; hosts, auth header/scheme and validation behavior are derived from reviewed provider adapters and cannot be manually broadened from the form. For model-requested credentials, the read-only API origin and supported CLI consumer are shown in the setup notes. On supported providers, the UI can test a token and inspect identity/permissions where the provider exposes them. A timeout, rate limit or missing permission is never silently labelled an invalid token.

Sign in at `https://<origin>/login` with the owner GitHub account.

| Page | What it does |
| --- | --- |
| `/vault` | Dashboard overview, credential registry, validation summary, pending Runner request shortcut and integration shortcuts. |
| `/vault/requests` | Owner inbox for pending Runner requests, runner identity metadata, model-authored setup notes, API destination, explicit link state, single-use link renewal and safe dismissal. |
| `/vault/register/<link>` | One-time registration page with model-authored setup notes, read-only API destination and write-only secret field. |
| `/vault/credentials/<id>` | Credential details, token validation report, enable/disable, show/hide, delete, replace value and recent activity. |
| `/vault/validation` | Validation state and history, first-failure time, next check, exponential retry backoff and manual recheck. |
| `/vault/analytics` | 30-day aggregate request counts, success/error rate, latency and usage by CLI/Runner consumer; no request bodies, headers or token values. |
| `/vault/integrations` | Owner view of provider destinations and supported CLI adapters. |
| Global header bell | Unread count, recent Vault events including new Runner credential requests, mark-read and mark-all-read actions on every panel page. No separate notification page or Telegram delivery. |
| `/vault/audit` | Append-only audit log (database triggers block updates and deletes). |
| `/vault/settings` | Validation interval, default lifetime/visibility, proxy timeout, per-credential proxy/session/registration throughput limits, analytics/notification retention, runner session revocation and metadata-only external entries. |

Runner traffic limits are owner-configurable in **Settings → Runner traffic limits**. Defaults are 30 proxy calls per credential per minute, 20 OIDC sessions per hour and 10 credential-registration requests per hour; each has a bounded adjustable range. D1 reserves quota slots atomically before a proxy request or registration is accepted, so concurrent bursts cannot all pass a stale count. Proxy quotas use the credential's immutable database ID rather than its display name; deleting a credential cascades its old reservations. Audit, usage and last-used metadata are persisted through the Worker's background lifecycle hook after the response, while the atomic D1 reservation remains the source of truth for rate limiting.

## Deployment

There is exactly one way to deploy: a setup wizard drives a GitHub Actions workflow. No local CLI, nothing to configure by hand — the wizard connects to Cloudflare, walks you through creating the single deploy token from a prefilled template, and links you to saving it and running the deploy. The owner identity comes from the repository owner, so there is no first-visitor owner claim.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://aminsh35322088-ctrl.github.io/GitHub-runner-vault/)

*The button opens the setup wizard, hosted from this repository's `docs/` folder via GitHub Pages.*

### Steps

1. Fork this repository under the personal GitHub account that will own the vault (or use your existing copy of it). On a fork, GitHub leaves Actions off by default: open the **Actions** tab once and enable workflows, or the deploy in step 7 cannot run.
2. Enable GitHub Pages once: **Settings → Pages → Deploy from a branch → main → /docs → Save**. The wizard then lives at `https://<you>.github.io/GitHub-runner-vault/`.
3. Open the wizard (button above). It works out your GitHub username and repository name from its own address — there is nothing to type in.
4. **Connect Cloudflare.** If login is enabled for your copy (see the next subsection), the wizard signs you in with Cloudflare, finds your account and checks that Workers and D1 are reachable. Otherwise it offers to continue with a token only.
5. Create the deploy token with the wizard's button — the permissions (Workers Scripts: Edit, D1: Edit, Account Settings: Read) and the token name are pre-selected; press **Create Token** and paste the value back into the wizard. (A Cloudflare login only lasts an hour, so the long-lived token still does the actual deploying.) The wizard verifies the token in your browser; the token is never stored and is only ever sent to Cloudflare's API.
6. Save the token as the CLOUDFLARE_API_TOKEN repository secret — the wizard links straight to the prefilled form. If token verification lists multiple Cloudflare accounts and step 4 did not pin one, the wizard also offers the optional CLOUDFLARE_ACCOUNT_ID secret for the account you pick.
7. Run the **Deploy to Cloudflare** workflow from the Actions tab (the wizard links there too), then use the wizard's **Check deployment** button — it shows your vault URL as soon as the run publishes it.
8. Open the vault URL and finish setup below.

### Optional: enable Cloudflare login (once per copy)

The wizard's first step can sign the owner in with Cloudflare (read-only: account, Workers and D1 checks) instead of starting cold. This repository's own copy is already registered (client ID in `docs/wizard-config.json`); for a fork, register your own once:

1. In Cloudflare open **Manage account → OAuth clients → Create client**, name it **Runner Vault Setup Wizard**, and create a **public** client with token authentication **None** (PKCE) and the grants **Authorization Code** and **Refresh Token**.
2. Set its redirect URL to your wizard address (`https://<you>.github.io/<repo>/`) and allow the scopes **Account Settings: Read**, **D1: Read** and **Workers: Content Read-Only** (the picker has no scope literally named "Workers Scripts" — that is the Workers read scope; `offline_access` is added automatically with the Refresh Token grant).
3. Put your client ID in `docs/wizard-config.json` in your repository (`cloudflareOAuthClientId`), replacing the inherited one, and commit. A fork inherits the upstream owner's client ID in that file, and only that owner's Cloudflare account can approve it — until you replace it (or empty the value to skip login entirely), the wizard's login cannot complete for you. The token path works fully regardless.
4. Deploy the OAuth relay once. Cloudflare's token endpoint sends no CORS headers, so a browser page can authorize but can never read the exchange response — a tiny stateless Worker relays it. In your Cloudflare account open **Workers & Pages → Create → Worker**, name it `vault-wizard-relay`, replace its code with [`docs/oauth-relay-worker.js`](docs/oauth-relay-worker.js) and deploy. It stores nothing, has no secrets (the client is public/PKCE) and only forwards the single-use authorization code. Put its URL in `docs/wizard-config.json` as `cloudflareOAuthRelayUrl` (this repository's own relay is already configured). If you run the wizard from a different origin, set the Worker's `ALLOWED_ORIGINS` variable to your wizard origin — the default covers this repository's Pages origin.

### Updating

Every merge to `main` that changes `app/**`, `client/**`, or the root pnpm manifests redeploys automatically; documentation-only changes do not. Re-running the workflow by hand is always safe: the build, D1 provisioning and master-key provisioning are idempotent, and an upgrade keeps the existing D1 data, owner pin and credentials.

### How it works

- The workflow runs `pnpm deploy` (the root script). The build takes the owner ID from the repository owner, and `app/scripts/deploy.mjs` resolves or creates the D1 database, deploys the Worker with Wrangler using your token, and provisions the `VAULT_MASTER_KEY` Worker secret (see *Where the key lives*). The Worker creates its tables on first request.
- After deploying, the workflow publishes `deployment.json` at the repository root with the vault URL and the exact commit that was deployed. The Runner Lab reads that file to discover the vault, so there are no Lab-side variables to set.

### Finish setup

1. Open the Worker URL (`https://<name>.<you>.workers.dev`) and choose *Create the GitHub App* using the personal GitHub account that owns the deployed repository (or matches the explicitly configured owner ID). The app is always named `Runner Vault <your numeric GitHub ID>` — the name is fixed per account, so setup never creates a differently-named app on a later run. If GitHub reports that the name is taken, the app already exists under your account: delete it under **GitHub Settings → Developer settings → GitHub Apps** and run setup again, and it is recreated under the same name.
2. Sign in to the owner dashboard. No Runner repository form is required: the first valid OIDC run from the owner's `main/.github/workflows/rdc-lab.yml` workflow proves the owner identity and atomically pins the repository ID. Later runs must match the pinned repository, owner, branch, event and workflow. Pull-request events are refused.
3. Nothing to configure in the Runner Lab: its workflow reads `deployment.json` from this repository and connects automatically — see the [Runner Lab README](https://github.com/aminsh35322088-ctrl/GitHub-Runner-Lab). The trusted workflow provisions separate `rdc-agent` and `runner-vault-broker` Unix identities, passes the OIDC requester to the Broker over an anonymous pipe, and starts the Broker before exposing its socket to the Agent. The Broker keeps the Vault Session in memory; the Agent uses only the fixed Unix-socket CLI protocol. If Vault is not configured or the Broker cannot start, Vault operations remain unavailable without blocking RDC or Tailscale. No runner PAT or manual policy value is needed.

### Where the key lives

The master key is a Worker secret: `VAULT_MASTER_KEY` (32 random bytes, base64). **Nobody has to create or paste it.**
The deploy helper provisions it automatically after every successful deploy (the GitHub Actions workflow above is
the only supported route): it generates a new key for a fresh deployment or copies a legacy D1 key
verbatim into the secret during an upgrade. The value is sent to Wrangler through stdin only, never argv, files or logs.
If provisioning cannot complete, a fresh deployment fails closed and a legacy deployment stays in the warned read-only
mode until a later redeploy retries.

Deployments created before this was required may still hold a master key in D1 (`vault_setting.master_key`). They
keep working in a flagged legacy mode — existing credentials stay readable and Settings shows a warning — but
storing new credentials is paused until the owner sets the secret. Migration is automatic on the first request
after the secret is set: if the secret equals the stored key, the database copy is simply deleted; if it differs,
every stored value and the sealed GitHub client secret are preflighted, then all ciphertext rewrites, the GitHub
secret reseal and deletion of the database copy commit in one atomic D1 batch. If any value cannot be decrypted,
the migration stops without rewriting any row and retains the old database key. In that case, the deploy helper will copy the existing D1 key into `VAULT_MASTER_KEY` on a later redeploy;
if provisioning is blocked by deployment permissions, set the secret manually as a fallback or repair the affected data before retrying.

Existing deployments that already have `BETTER_AUTH_SECRET` and `ENCRYPTION_KEY` secrets keep using them unchanged.

### Starting over

Existing D1 owner pins are preserved during upgrades. To rebind a legacy vault that was claimed by the wrong first visitor, delete only the owner/sign-in settings below; the next request pins the current repository owner. Service credentials are not touched.

If sign-in is misconfigured, delete the sign-in settings and open `/setup` again (D1 console):
`DELETE FROM vault_setting WHERE key IN ('github_client_id','github_client_secret','owner_github_id','owner_github_login');`
Stored credentials are not touched.

## Configuration reference

A deployment needs exactly one GitHub repository secret (`CLOUDFLARE_API_TOKEN`); everything else below is automatic, an optional override, or configured in the UI.

| Name | Kind | Notes |
| --- | --- | --- |
| `CLOUDFLARE_API_TOKEN` | Actions secret | **The one required input.** Created with the wizard's prefilled template (Workers Scripts: Edit, D1: Edit, Account Settings: Read); used only by the deploy workflow. |
| `CLOUDFLARE_ACCOUNT_ID` | Actions secret | Optional. Only needed when the token can see more than one account; otherwise the workflow resolves the single account automatically. |
| `VAULT_MASTER_KEY` | Worker secret | Provisioned automatically by the deploy helper (see above); keeps the master key out of D1. Set manually only as a fallback. |
| `PUBLIC_ORIGIN` | var | Canonical HTTPS origin for a custom domain. By default the actual request origin is used. |
| `OWNER_GITHUB_ID` | var | Set by the deploy workflow from the repository owner; pinned in D1 on first use. Never set by hand. |
| `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` | vars / secrets | Optional override for the private GitHub sign-in App created through `/setup`. |
| `RUNNER_REPOSITORY`, `RUNNER_REPOSITORY_ID`, `RUNNER_ALLOWED_REFS`, `RUNNER_ALLOWED_EVENTS`, `RUNNER_ALLOWED_WORKFLOW_REFS` | vars | Optional explicit static policy override. When absent, owner-verified OIDC bootstrap pins the first repository automatically. |
| `BETTER_AUTH_SECRET`, `ENCRYPTION_KEY` | secrets | Legacy explicit keys; both must be set to be used. |
| `RUNNER_VAULT_D1_DATABASE_ID` | deploy env | Optional internal override: UUID of a pre-created D1 database; skips D1 list/create calls. Never commit this deployment-specific value. |
| `DB` | D1 binding | Provisioned automatically by the deploy helper during the Actions deploy. |

## Operations

- **Disable all Runner access:** `/vault/settings` → *Vault Access* → *Disable Vault Access*. This blocks Runner API requests and atomically advances the global access epoch plus the Session revocation cutoff. Re-enabling does not restore old Sessions; each Runner must authenticate again and obtain a Session for the current epoch.
- **Revoke runner sessions only:** `/vault/settings` → *Runner sessions* → *Revoke all runner sessions*. Use this when you need to invalidate Sessions without disabling the Vault.
- **Rotate a credential:** open it → *Replace value*. The old value is overwritten.
- **Disable one credential:** open it → *Disable* or *Hide*. The change takes effect on the next request.
- **Delete:** destroys the stored ciphertext; the audit trail stays.
- **Audit log:** `/vault/audit`. Rows contain runner identity, credential, result and sanitized request metadata. Caller-controlled purpose, body, headers, names that fail validation and secret values are not persisted.
- **Rotating the key:** set a new `VAULT_MASTER_KEY` secret and redeploy; on the first request the vault re-encrypts every stored value under the new key automatically.
- **Backups:** D1 holds ciphertext and metadata only (legacy deployments may still hold the master key until migrated — see above). Treat exports like secrets.

## Development and tests

```bash
pnpm install
pnpm typecheck                       # tsc
pnpm test                            # workerd tests + client tests
cd app && pnpm dev   # then open /setup
```

`app/.dev.vars` is git-ignored. Local dev uses a local D1; the schema is created on first request like in production.
The table SQL lives in `app/db/drizzle-app/*.sql`; after editing it run `pnpm --filter runner-vault-app embed-schema` (tests fail if the generated
`app/src/lib/schema-sql.generated.ts` is stale).

Run `pnpm validate` for typecheck, tests and production build. Tests cover: encryption and AAD binding, availability rules, one-time links (including concurrent use and concurrent creation), documentation
validation, OIDC verification (bad algorithm, issuer, audience, expiry, repository, ref, event, tampering, JWKS refresh and
outage), session signing and revocation, the proxy (host allowlist, header override attempts, redirects, size caps,
redaction in every encoding, timeouts) and the runner API end to end (including rate limits and fail-closed behaviour).

## Known limits and roadmap

- Runner delivery is proxy-only. Legacy `inject` rows are disabled and hidden.
- OIDC proves the workflow run, not a single process; any process able to read the job's OIDC request variables can request a run-bound token. Keep the workflow job trusted and minimize untrusted code in it.
- No automatic key rotation tooling.
- Provider validation depends on the documented read-only API. Unsupported services remain explicitly `unsupported`; unavailable endpoints remain inconclusive.
- Suggested hardening after first deploy: a branch ruleset on `main` of this repository and Cloudflare Access in front of `/vault/*` as a second owner gate.
- Runner integration is deployment-specific: the trusted repository's workflow reads `deployment.json` (vault URL + pinned client revision) from this repository; review vault upgrades before merging them, because the Lab follows the deployed revision.

## Repository layout

| Path | What |
| --- | --- |
| `app/` | The Worker: Spiceflow (React Server Components) owner UI, runner API, BetterAuth GitHub login, first-time `/setup` |
| `app/src/lib/` | Crypto, provider adapters, lifecycle validation, notifications, analytics, enrollment links, OIDC, sessions, proxy, runner core |
| `app/src/runner-api.ts` | HTTP routes for runners; logic is in `lib/runner-core.ts` |
| `db/` | Drizzle schema (types) and the baseline SQL (`db/drizzle-app/`), embedded into the Worker |
| `client/vault.mjs` | Zero-dependency runner client |
| `docs/runner-usage.md` | Runner-side usage and `doc.json` schema |
| `docs/index.html` | The GitHub Pages setup wizard (the Deploy button at the top of [Deployment](#deployment)) |
| `SECURITY.md`, `NOTICE.md` | Trust model, upstream credit |
