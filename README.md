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

The runner is **not** a trust boundary. An agent may have elevated permissions and share its runner account with workflow processes, so runner-side secrets cannot be protected from that agent. The vault therefore:

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
OIDC authenticates the *workflow run*, not one process, so any process on the runner can use that run's session.

See `SECURITY.md` for the short version.

## How it works

```
 Runner (GitHub Actions job)                 Cloudflare Worker (this repo)               Upstream
 ┌──────────────────────────┐   OIDC token   ┌───────────────────────────────┐
 │ agent → client/vault.mjs │ ─────────────▶ │ POST /api/runner/session      │  verify RS256 JWT vs GitHub JWKS,
 │                          │ ◀───────────── │   → 30-min signed session     │  repo id / ref / event pinned
 │                          │                │                               │
 │   use NAME GET <url>     │ ─────────────▶ │ POST /api/runner/use          │
 │                          │                │   decrypt token (in memory)   │ ──── HTTPS + token ───▶ api.example.com
 │   ◀ response (redacted)  │ ◀───────────── │   redact echoed token         │ ◀──────────────────────
 │                          │                │                               │
 │   request --doc doc.json │ ─────────────▶ │ POST /api/runner/registrations│
 │   ◀ one-time owner link  │ ◀───────────── │   creates pending entry + link│
 └──────────────────────────┘                └───────────────▲───────────────┘
                                                             │ GitHub OAuth (owner only)
                                              Owner browser ─┘  /vault  requests · register · detail · audit · settings
```

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

`client/vault.mjs` is one zero-dependency file (Node 18+). It reads `VAULT_URL` and, inside a GitHub Actions job with
`permissions: id-token: write`, uses `ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN` to get an OIDC token and caches the 30-minute
session in a `0600` file.

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

Choose the deployment path that matches how you work. Every supported build path resolves the intended personal GitHub account before the Worker is deployed; there is no first-visitor owner claim.

### 1. Deploy to Cloudflare button

The Deploy Button is the quickest route. Authorize GitHub and Cloudflare; Cloudflare creates a new repository under the GitHub account authorizing deployment, provisions D1, and deploys through Workers Builds. During the Vite build, the checked-out GitHub origin is used to resolve the numeric account ID through GitHub's typed JSON user API. If that API is unavailable, the immutable Actions owner ID is accepted only when both `GITHUB_REPOSITORY_OWNER` and the owner in `GITHUB_REPOSITORY` match the checked-out origin. HTML profile metadata is never treated as proof of a personal account; if identity cannot be verified, `/setup` stays locked until `RUNNER_VAULT_OWNER_GITHUB_ID` is configured. That ID becomes the Worker runtime variable `OWNER_GITHUB_ID` and is pinned in D1 on first request.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/aminsh35322088-ctrl/GitHub-runner-vault/tree/main/app)

The button's source is the upstream repository and it creates an independent copy; it does not deploy an existing fork's commits. To deploy your exact fork, use the Dashboard GitHub connection below. The source repository for a Deploy Button must be public, but the destination repository can be private.

### 2. Connect your GitHub account from the Cloudflare Dashboard

To import your own fork:

1. Open **Workers & Pages → Create application → GitHub** and authorize the Cloudflare GitHub App.
2. Select your personal fork/repository.
3. Set **Root directory** to `app`.
4. Set **Build command** to `pnpm build`.
5. Set **Deploy command** to `pnpm deploy`.
6. Save and deploy.

For an existing Worker, use **Settings → Builds → Connect** and select the same repository. The Worker name must match `name` in `app/wrangler.jsonc` (default: `runner-vault`); change the config name too if you intentionally use a different Worker name. The GitHub repository should be your personal fork. If you intentionally connect a repository owned by someone else, add the build variable `RUNNER_VAULT_OWNER_GITHUB_ID` with your own numeric GitHub user ID under **Settings → Builds → Build variables**; that explicit value overrides the repository owner.

Workers Builds runs the same build-time owner resolver. The deploy command reuses that build, then resolves the `DB` D1 binding and deploys through Wrangler. If D1 does not exist, the deploy helper creates it. For owner lookup reliability, provide `GH_TOKEN` or `GITHUB_TOKEN` as an encrypted Workers Builds build variable; the deploy helper sends it only to GitHub's user API.

**Important — D1 permissions:** Cloudflare's automatically generated Workers Builds API token does not include D1 permissions by default. To let the helper discover/create D1 automatically, open **My Profile → API Tokens**, find the token selected in this Worker under **Settings → Builds → API token**, and add **Account → D1 Read** and **Account → D1 Edit**. Keep the user-scoped token selected for Workers Builds.

Alternatively, create the D1 database in **Storage & databases → D1**, then set its UUID as the `RUNNER_VAULT_D1_DATABASE_ID` Workers Builds build variable (or CLI environment variable). The deploy helper uses that deployment-specific value and skips D1 list/create operations, so the default Build token does not need D1 permissions. Keep the UUID out of the reusable repository config; without this variable, the helper discovers the named database or creates it when missing.

### 3. Wrangler CLI from a Git checkout

Clone your own GitHub repository, then deploy from `app`:

```bash
git clone https://github.com/YOUR_ACCOUNT/GitHub-runner-vault.git
cd GitHub-runner-vault/app
pnpm install --frozen-lockfile
pnpm exec wrangler login
pnpm deploy
```

`pnpm deploy` runs the Vite production build, derives the owner from GitHub `origin`, resolves or creates the configured D1 database, updates the generated Wrangler config with its ID, and finally runs `wrangler deploy`. Use this project command rather than invoking `wrangler deploy` directly, because the wrapper performs the owner and D1 bootstrap first.

The Vite RSC bundle is kept at `dist/rsc/index.js` for its internal server-action and module graph imports. The build then generates a small `dist/rsc/worker.js` entry that exports only the default Worker handler and removes Wrangler's `no_bundle` setting. This is intentional: Workerd service entrypoints accept handlers, not arbitrary named RSC exports. Both Workers Builds (which reuses the prepared build) and the Wrangler CLI path run the same idempotent preparation step before deployment.

The repository contains two pnpm workspaces: the root workspace used by CI and the `app` workspace used by Cloudflare Workers Builds. Both lockfiles are committed and must be kept in sync. The root workspace explicitly includes `app` and `app/db`; build output under `app/dist` is not a workspace package.

When there is no GitHub origin (for example, a source archive), the build falls back to the authenticated GitHub CLI account:

```bash
gh auth login
pnpm deploy
```

Alternatively, set `RUNNER_VAULT_OWNER_GITHUB_ID` to the numeric ID of the intended personal GitHub account for that build; this explicit value takes priority. When a Git origin exists but GitHub's JSON API is unavailable, the Actions owner-ID fallback is accepted only if both `GITHUB_REPOSITORY_OWNER` and the owner portion of `GITHUB_REPOSITORY` match the checked-out origin. A mismatch or missing context leaves the Worker locked. GitHub Actions builds without a Git checkout can use their trusted `GITHUB_REPOSITORY_OWNER_ID` context. The Worker still checks the GitHub App creator against the resolved ID during `/setup`.

### 4. Manual upload / dashboard editor without Git

A direct upload or quick edit has no Git checkout or Vite build from which to derive identity. Before opening `/setup`, add `OWNER_GITHUB_ID` as a **Worker runtime variable** under **Settings → Variables & Secrets**. Set the numeric ID of the intended personal GitHub account. It is public identity metadata, not a secret. Also create/bind the D1 database as `DB` (the binding name must match `app/wrangler.jsonc`) before deploying the built Worker. The GitHub App creator must match the owner ID exactly.

If no valid owner ID is present, `/setup` stays locked. The app never falls back to whichever visitor arrives first.

### Finish setup

1. Open the Worker URL (`https://<name>.<you>.workers.dev`) and choose *Create the GitHub App* using the personal GitHub account that owns the deployed repository (or matches the explicitly configured owner ID). The app is always named `Runner Vault <your numeric GitHub ID>` — the name is fixed per account, so setup never creates a differently-named app on a later run. If GitHub reports that the name is taken, the app already exists under your account: delete it under **GitHub Settings → Developer settings → GitHub Apps** and run setup again, and it is recreated under the same name.
2. Sign in to the owner dashboard. No Runner repository form is required: the first valid OIDC run from the owner's `main/.github/workflows/rdc-lab.yml` workflow proves the owner identity and atomically pins the repository ID. Later runs must match the pinned repository, owner, branch, event and workflow. Pull-request events are refused.
3. Set the Lab Actions variables `RUNNER_VAULT_URL`, `RUNNER_VAULT_REPOSITORY` (the public Vault source repository) and `RUNNER_VAULT_CLIENT_REF` (a reviewed immutable client commit). The existing Lab workflow downloads the client, obtains an OIDC token, establishes a short-lived session and reads the registry before starting RDC. No runner token or manual policy value is needed.

The Deploy Button provisions D1 automatically. Dashboard Git connection and Wrangler CLI deployments use the deploy helper to find or create the named D1 database, patch the built Worker config, and deploy. The Worker creates its tables on first request.

### Where the key lives

The master key is a Worker secret: `VAULT_MASTER_KEY` (32 random bytes, base64). **Nobody has to create or paste it.**
The deploy helper provisions it automatically after a successful Worker deploy on all supported routes (Deploy Button,
Dashboard Git connection and Wrangler CLI): it generates a new key for a fresh deployment or copies a legacy D1 key
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

A normal deployment sets exactly one secret (`VAULT_MASTER_KEY`); everything else below is optional and the rest is configured in the UI.

| Name | Kind | Notes |
| --- | --- | --- |
| `VAULT_MASTER_KEY` | secret | **Required for new deployments.** Keeps the master key out of D1 (see above). |
| `PUBLIC_ORIGIN` | var | Canonical HTTPS origin for a custom domain. By default the actual request origin is used. |
| `OWNER_GITHUB_ID` | var | Derived during production build from GitHub `origin`, authenticated `gh`, or an explicit build variable; pinned in D1 on first use. Manual uploads must set this Worker runtime variable. |
| `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` | vars / secrets | Optional override for the private GitHub sign-in App created through `/setup`. |
| `RUNNER_REPOSITORY`, `RUNNER_REPOSITORY_ID`, `RUNNER_ALLOWED_REFS`, `RUNNER_ALLOWED_EVENTS`, `RUNNER_ALLOWED_WORKFLOW_REFS` | vars | Optional explicit static policy override. When absent, owner-verified OIDC bootstrap pins the first repository automatically. |
| `BETTER_AUTH_SECRET`, `ENCRYPTION_KEY` | secrets | Legacy explicit keys; both must be set to be used. |
| `RUNNER_VAULT_D1_DATABASE_ID` | build var | Optional UUID of a pre-created D1 database; skips D1 list/create API calls. Never commit this deployment-specific value. |
| `DB` | D1 binding | Provisioned by Deploy Button or the deploy helper. Auto-discovery/creation needs D1 Read/Edit on the Workers Builds token or Wrangler login. |

## Operations

- **Revoke runner access now:** `/vault/settings` → *Revoke all runner sessions*. Do this after a runner reset or suspected leak.
- **Rotate a credential:** open it → *Replace value*. The old value is overwritten.
- **Disable quickly:** *Disable* or *Hide* takes effect on the next request.
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
- Runner integration is deployment-specific: install client/vault.mjs in the trusted repository and set its VAULT_URL Actions variable. Pin the client revision and review upgrades.

## Repository layout

| Path | What |
| --- | --- |
| `app/` | The Worker: Spiceflow (React Server Components) owner UI, runner API, BetterAuth GitHub login, first-time `/setup` |
| `app/src/lib/` | Crypto, provider adapters, lifecycle validation, notifications, analytics, enrollment links, OIDC, sessions, proxy, runner core |
| `app/src/runner-api.ts` | HTTP routes for runners; logic is in `lib/runner-core.ts` |
| `db/` | Drizzle schema (types) and the baseline SQL (`db/drizzle-app/`), embedded into the Worker |
| `client/vault.mjs` | Zero-dependency runner client |
| `docs/runner-usage.md` | Runner-side usage and `doc.json` schema |
| `SECURITY.md`, `NOTICE.md` | Trust model, upstream credit |
