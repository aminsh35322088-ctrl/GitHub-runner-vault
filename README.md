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
| Stolen session | 30-minute sessions, rate limits, append-only audit log, and an owner-side **revoke all sessions** button. |
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
                                              Owner browser ─┘  /vault  list · register · detail · audit · settings
```

Registering a new credential:

1. The agent finds the name missing in `list` and runs `request` with a setup document.
2. The vault creates a **pending, hidden** entry and returns a **one-time link** (about 15 minutes, works once).
3. The owner opens the link (must be signed in with GitHub), reads the notes, reviews **allowed hosts, auth header/scheme,
   lifetime, expiry and visibility**, pastes the token and saves. The link is consumed atomically.
4. Alternatively, the owner can create the credential directly from **Add credential** in the dashboard without a runner request.
5. The credential becomes **Active**; the agent sees it in `list` and can `use` it.

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

**Encryption.** Values are AES-256-GCM encrypted with a 32-byte key derived (HKDF) from a random master key the vault
generates on first use. The authenticated data binds each ciphertext to `credential:{id}:v{keyVersion}`, so a ciphertext
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
Only Active + Visible entries. Never values, hosts or ids.

### `POST /api/runner/registrations`

Body `{ name, service, doc }`, where `doc` follows the schema in `docs/runner-usage.md`. The vault generates purpose automatically from the service catalog.
`200 { link, expiresAt }`: give the link to the owner. `400 invalid_name | reserved_name | invalid_doc` (with `detail`),
`409 exists`, `429 rate_limited` (10 per hour).

### `POST /api/runner/use`

Body `{ name, method, url, headers?, body?, purpose? }`.

- Methods: `GET HEAD POST PUT PATCH DELETE`. URL: `https`, default port, no user info, host in the owner's list.
- Request headers allowed: `accept`, `accept-language`, `content-type`, `if-match`, `if-none-match`,
  `x-github-api-version`, `x-api-version`. Anything else (including `Authorization`, `Host`, `Cookie`) is refused.
- Limits: request body 256 KiB, response 1 MiB (then `truncated: true`), 20 s upstream timeout, 30 calls per minute per
  credential. Redirects are **not** followed (a `3xx` is returned as is).

`200 { status, headers, body, truncated, redacted }`: `status` is the **upstream** status; an upstream error is still a
`200` from the vault. Vault-side errors:

| HTTP | `error` | Meaning |
| --- | --- | --- |
| 400 | `invalid_request`, `bad_method`, `bad_url`, `bad_header`, `body_not_allowed`, `not_a_proxy_credential` | Malformed or not allowed. |
| 401 | `missing_token`, `unauthorized` | No or invalid session (expired, revoked, tampered). |
| 403 | `host_not_allowed` | Host not approved by the owner for this credential. |
| 404 | `unavailable` | Missing, hidden, disabled or expired (indistinguishable on purpose). |
| 413 | `body_too_large` | Request body over 256 KiB. |
| 429 | `rate_limited` | Too many calls. |
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
```

Exit codes: `0` ok, `2` vault refused, `3` upstream HTTP error. See `docs/runner-usage.md` for `doc.json` and what a model
should expect. The trusted runner workflow must request `permissions: id-token: write` and set `VAULT_URL` to the deployed Worker origin.

## Owner UI

From the dashboard, choose **Add credential** to browse the built-in provider catalog (Cloudflare, Railway, GitHub, Vercel, Netlify, DigitalOcean, OpenAI, Anthropic, Groq, Mistral, Hugging Face, Stripe, Sentry, Supabase, Pinecone and Slack), search by provider/category, or add a custom service. Known providers prefill their documented API host and auth header; the owner can inspect and edit these values before creating a credential. This path works independently of any runner/model registration request. Purpose is generated from the selected service; no purpose field is required. On supported providers, entering a token triggers server-side verification and saving repeats the check before encryption. GitHub classic OAuth scopes and Cloudflare User/Account Token policies are shown where the provider API exposes them. GitHub does not expose a complete Fine-grained PAT permission list through its general authentication endpoint. New Cloudflare `cfat_` Account Tokens are routed directly to the Account Token verification endpoint and show an Account ID field next to the token input. The runner registration flow uses the same provider catalog for its defaults.

Sign in at `https://<origin>/login` with the owner GitHub account.

| Page | What it does |
| --- | --- |
| `/vault` | Credential list: status, delivery, expiry, last used. |
| `/vault/register/<link>` | The one-time registration page: the agent's setup notes above a write-only secret field, automatic token verification and permission inspection, plus advanced host, auth, lifetime, expiry and visibility controls. |
| `/vault/credentials/<id>` | Details, enable/disable, show/hide, delete, replace value or rules, recent activity. Stored values are never displayed. |
| `/vault/audit` | Append-only audit log (database triggers block updates and deletes). |
| `/vault/settings` | Inspect the automatically pinned runner identity, **revoke all runner sessions**, review advanced-settings guidance and add metadata-only entries (for example `GITHUB_TOKEN`). |

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

Alternatively, create the D1 database in **Storage & databases → D1**, copy its UUID, and add `"database_id": "<UUID>"` to the `DB` entry in `app/wrangler.jsonc` in your repository. With a configured ID the deploy helper skips D1 list/create operations, so the default Build token does not need D1 permissions. The Deploy Button's resource provisioning path normally supplies the required D1 resource automatically.

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

1. Open the Worker URL (`https://<name>.<you>.workers.dev`) and choose *Create the GitHub App* using the personal GitHub account that owns the deployed repository (or matches the explicitly configured owner ID).
2. Sign in to the owner dashboard. No Runner repository form is required: the first valid OIDC run from the owner's `main/.github/workflows/rdc-lab.yml` workflow proves the owner identity and atomically pins the repository ID. Later runs must match the pinned repository, owner, branch, event and workflow. Pull-request events are refused.
3. Set the Lab Actions variables `RUNNER_VAULT_URL`, `RUNNER_VAULT_REPOSITORY` (the public Vault source repository) and `RUNNER_VAULT_CLIENT_REF` (a reviewed immutable client commit). The existing Lab workflow downloads the client, obtains an OIDC token, establishes a short-lived session and reads the registry before starting RDC. No runner token or manual policy value is needed.

The Deploy Button provisions D1 automatically. Dashboard Git connection and Wrangler CLI deployments use the deploy helper to find or create the named D1 database, patch the built Worker config, and deploy. The Worker creates its tables on first request.

### Where the key lives

By default the master key is generated by the Worker and stored in the same D1 database as the encrypted values, so
nobody has to create or paste a key. That protects against anything that sees ciphertext but not the key *in use* (for
example a copied credential row), but **not** against someone who can read the whole D1 database. If that matters to you,
add a Worker secret `VAULT_MASTER_KEY` (32 random bytes, base64: `openssl rand -base64 32`) **before storing your first
credential**; it takes precedence and the database copy is never used. Changing the master key later makes existing
values undecryptable, so re-enter them.

Existing deployments that already have `BETTER_AUTH_SECRET` and `ENCRYPTION_KEY` secrets keep using them unchanged.

### Starting over

Existing D1 owner pins are preserved during upgrades. To rebind a legacy vault that was claimed by the wrong first visitor, delete only the owner/sign-in settings below; the next request pins the current repository owner. Service credentials are not touched.

If sign-in is misconfigured, delete the sign-in settings and open `/setup` again (D1 console):
`DELETE FROM vault_setting WHERE key IN ('github_client_id','github_client_secret','owner_github_id','owner_github_login');`
Stored credentials are not touched.

## Configuration reference

Everything below is optional. A normal deployment sets nothing; everything is configured in the UI.

| Name | Kind | Notes |
| --- | --- | --- |
| `VAULT_MASTER_KEY` | secret | Keeps the key out of D1 (see above). |
| `PUBLIC_ORIGIN` | var | Canonical HTTPS origin for a custom domain. By default the actual request origin is used. |
| `OWNER_GITHUB_ID` | var | Derived during production build from GitHub `origin`, authenticated `gh`, or an explicit build variable; pinned in D1 on first use. Manual uploads must set this Worker runtime variable. |
| `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` | vars / secrets | Optional override for the private GitHub sign-in App created through `/setup`. |
| `RUNNER_REPOSITORY`, `RUNNER_REPOSITORY_ID`, `RUNNER_ALLOWED_REFS`, `RUNNER_ALLOWED_EVENTS`, `RUNNER_ALLOWED_WORKFLOW_REFS` | vars | Optional explicit static policy override. When absent, owner-verified OIDC bootstrap pins the first repository automatically. |
| `BETTER_AUTH_SECRET`, `ENCRYPTION_KEY` | secrets | Legacy explicit keys; both must be set to be used. |
| `DB` | D1 binding | Provisioned by Deploy Button or the deploy helper. Auto-discovery/creation needs D1 Read/Edit on the Workers Builds token or Wrangler login; a configured `database_id` skips those API calls. |

## Operations

- **Revoke runner access now:** `/vault/settings` → *Revoke all runner sessions*. Do this after a runner reset or suspected leak.
- **Rotate a credential:** open it → *Replace value*. The old value is overwritten.
- **Disable quickly:** *Disable* or *Hide* takes effect on the next request.
- **Delete:** destroys the stored ciphertext; the audit trail stays.
- **Audit log:** `/vault/audit`. Rows contain runner identity, credential, result and sanitized request metadata. Caller-controlled purpose, body, headers, names that fail validation and secret values are not persisted.
- **Rotating the key:** not automated. Re-enter the credentials after changing `VAULT_MASTER_KEY` (old ciphertexts will not decrypt).
- **Backups:** D1 holds ciphertext and metadata (and, unless you set `VAULT_MASTER_KEY`, the master key). Treat exports like secrets.

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
- No GitHub-side validation test for stored tokens (`validation` stays `not_tested`).
- Suggested hardening after first deploy: a branch ruleset on `main` of this repository and Cloudflare Access in front of `/vault/*` as a second owner gate.
- Runner integration is deployment-specific: install client/vault.mjs in the trusted repository and set its VAULT_URL Actions variable. Pin the client revision and review upgrades.

## Repository layout

| Path | What |
| --- | --- |
| `app/` | The Worker: Spiceflow (React Server Components) owner UI, runner API, BetterAuth GitHub login, first-time `/setup` |
| `app/src/lib/` | Crypto, policy, docs schema, enrollment links, credential service, OIDC, sessions, proxy, runner core |
| `app/src/runner-api.ts` | HTTP routes for runners; logic is in `lib/runner-core.ts` |
| `db/` | Drizzle schema (types) and the baseline SQL (`db/drizzle-app/`), embedded into the Worker |
| `client/vault.mjs` | Zero-dependency runner client |
| `docs/runner-usage.md` | Runner-side usage and `doc.json` schema |
| `SECURITY.md`, `NOTICE.md` | Trust model, upstream credit |
