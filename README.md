# Runner Credential Vault

A **single-owner credential vault** on Cloudflare Workers + D1 for GitHub Actions runners.
Each deployment is isolated and configured for one GitHub owner and one trusted runner repository; no account,
repository, Worker URL or database ID is baked into the source.

It solves one problem: *an agent on the runner needs a token for some service (Cloudflare, Railway, ...) but must never
be able to read it.*

- The agent can **use** a stored credential: it asks the vault "call this URL with credential `X`". The Worker adds the
  token, makes the call, and returns the response. **The token never reaches the runner.**
- The agent can **ask the owner** to register a missing credential: it gets a **one-time link** to give to the owner, who
  opens a web page, reads the agent's setup notes, chooses the rules and pastes the token.
- The **owner** has a small web UI to see, hide, disable, expire, replace and delete credentials, and to read an audit log.

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
| Someone else gets a runner session | Runner identity is a **GitHub OIDC token** pinned to each deployment's repository name and numeric id, exact ref, event and workflow. Pull-request events are refused. |
| Stolen session | 30-minute sessions, rate limits, append-only audit log, and an owner-side **revoke all sessions** button. |
| Someone else logs in to the owner UI | GitHub OAuth restricted to **one numeric account id**; cookie sessions only. |
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
3. The owner opens the link (must be signed in with GitHub), reads the notes, sets **allowed hosts, auth header/scheme,
   lifetime, expiry and visibility**, pastes the token and saves. The link is consumed atomically.
4. The credential becomes **Active**; the agent sees it in `list` and can `use` it.

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

**Encryption.** Values are AES-256-GCM encrypted with `ENCRYPTION_KEY` (mandatory, exactly 32 random bytes, base64). The
authenticated data binds each ciphertext to `credential:{id}:v{keyVersion}`, so a ciphertext copied to another row will
not decrypt. There is no derived or fallback key.

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

Body `{ name, service, purpose, doc }`, where `doc` follows the schema in `docs/runner-usage.md`.
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
node client/vault.mjs request --name RAILWAY_TOKEN --service Railway --purpose "deploy" --doc doc.json
```

Exit codes: `0` ok, `2` vault refused, `3` upstream HTTP error. See `docs/runner-usage.md` for `doc.json` and what a model
should expect. The trusted runner workflow must request `permissions: id-token: write` and set `VAULT_URL` to the deployed Worker origin.

## Owner UI

Sign in at `https://<origin>/login` with the owner GitHub account.

| Page | What it does |
| --- | --- |
| `/vault` | Credential list: status, delivery, expiry, last used. |
| `/vault/register/<link>` | The one-time registration page: the agent's setup notes above a write-only secret field, plus hosts, auth header/scheme, lifetime, expiry and visibility. |
| `/vault/credentials/<id>` | Details, enable/disable, show/hide, delete, replace value or rules, recent activity. Stored values are never displayed. |
| `/vault/audit` | Append-only audit log (database triggers block updates and deletes). |
| `/vault/settings` | **Revoke all runner sessions**; add a metadata-only entry (for example `GITHUB_TOKEN`). |

## Deployment

Prerequisites: Node.js 24+, pnpm 12+, a Cloudflare account, and a GitHub account.
The deployment helper uses Wrangler for Cloudflare authentication. Set `GH_TOKEN` (or `GITHUB_TOKEN`) only when
the runner repository is private and GitHub's unauthenticated API cannot read its metadata.

**1. Install and authenticate**

```bash
pnpm install --frozen-lockfile
cd app
pnpm exec wrangler login
cd ..
```

**2. Deploy interactively**

```bash
pnpm vault:deploy
```

The first run asks for the Worker name, owner GitHub username, trusted runner repository, workflow file, branch and
allowed events. It resolves the GitHub owner/repository numeric IDs through the GitHub API (for a private repository,
provide a GitHub token through `GH_TOKEN` or enter the repository ID when prompted).

The helper creates an ignored local Wrangler config and a new D1 database for this installation, applies migrations,
builds with that config, deploys the Worker and generates two cryptographic secrets. It never writes installation
values into tracked source files. Re-run with `pnpm vault:deploy -- --configure` to change the trust configuration.

The local files `app/wrangler.local.jsonc` and `.vault.secrets.json` are private installation state and are ignored by
Git. Back up `.vault.secrets.json` securely: losing `ENCRYPTION_KEY` makes stored credentials unrecoverable. Never
commit either file.

**3. Configure GitHub owner login**

After deployment, Wrangler prints the Worker URL. Create a GitHub OAuth App (GitHub → Settings → Developer settings
→ OAuth Apps → New) with:

- Homepage URL: the deployed Worker origin
- Authorization callback URL: `<WORKER_ORIGIN>/api/auth/callback/github`

Then set the OAuth credentials as Worker secrets:

```bash
cd app
pnpm exec wrangler secret put GITHUB_CLIENT_ID --config wrangler.local.jsonc
pnpm exec wrangler secret put GITHUB_CLIENT_SECRET --config wrangler.local.jsonc
cd ..
```

The owner GitHub account entered during deployment is the only account allowed to sign in.

**4. Connect the runner repository**

Set the repository Actions variable `VAULT_URL` to the deployed Worker origin. The trusted workflow must request an
OIDC token with `permissions: id-token: write`; only the repository, numeric repository ID, ref, event and exact
workflow reference configured during deployment are accepted. Pull-request events are rejected.

**5. Verify**

```bash
curl -i -X POST "$VAULT_URL/api/runner/session"
```

Without an OIDC bearer token, the expected response is `401`. A `503 vault_not_configured` indicates a missing
installation setting or secret. Sign in at `<WORKER_ORIGIN>/login` after configuring the GitHub OAuth App.

## Configuration reference

All installation-specific values are supplied by the interactive deploy command and kept in the ignored local
`app/wrangler.local.jsonc` file. No per-account values belong in the tracked Wrangler config.

| Name | Kind | Required | Notes |
| --- | --- | --- | --- |
| `PUBLIC_ORIGIN` | var | no | Optional canonical HTTPS origin for a custom domain. By default, the Worker uses the actual request origin. |
| `OWNER_GITHUB_ID` | var | yes | Numeric GitHub user ID resolved from the username entered during setup. |
| `RUNNER_REPOSITORY` | var | yes | Exact `owner/name` of the trusted Actions repository. |
| `RUNNER_REPOSITORY_ID` | var | yes | Numeric GitHub repository ID; prevents name-reuse impersonation. |
| `RUNNER_ALLOWED_REFS` | var | yes | Comma-separated exact refs accepted for OIDC. |
| `RUNNER_ALLOWED_EVENTS` | var | yes | Comma-separated allowed event names; pull-request events are rejected. |
| `RUNNER_ALLOWED_WORKFLOW_REFS` | var | yes | Exact GitHub `job_workflow_ref` allowlist. |
| `BETTER_AUTH_SECRET` | secret | yes | Generated automatically and uploaded by the deploy helper. |
| `ENCRYPTION_KEY` | secret | yes | Generated automatically; 32 random bytes, base64. Back it up securely. |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | secret | yes for owner login | Created after deployment in a GitHub OAuth App and uploaded manually. |
| `DB` | D1 binding | yes | Created and bound automatically by the deploy helper for each installation. |

## Operations

- **Revoke runner access now:** `/vault/settings` → *Revoke all runner sessions*. Do this after a runner reset or suspected leak.
- **Rotate a credential:** open it → *Replace value*. The old value is overwritten.
- **Disable quickly:** *Disable* or *Hide* takes effect on the next request.
- **Delete:** destroys the stored ciphertext; the audit trail stays.
- **Audit log:** `/vault/audit`. Rows contain runner identity, credential, result and sanitized request metadata. Caller-controlled purpose, body, headers, names that fail validation and secret values are not persisted.
- **Rotating `ENCRYPTION_KEY`:** not automated. Re-enter the credentials after changing the key (old ciphertexts will not decrypt).
- **Backups:** D1 holds only ciphertext and metadata. Back up `ENCRYPTION_KEY` separately.

## Development and tests

```bash
pnpm install
pnpm typecheck                       # tsc
pnpm test                            # 208 workerd tests + client tests
cd app && CLOUDFLARE_VITE_WRANGLER_CONFIG_PATH=./wrangler.local.jsonc npx vite dev  # after first-time setup
```

`app/.dev.vars` (git-ignored) supplies local `BETTER_AUTH_SECRET`, `ENCRYPTION_KEY`, and GitHub OAuth values.
The local Wrangler config is generated by the first-time deployment setup and contains that installation's D1 binding
and trusted GitHub settings; do not copy it into source control.

Run `pnpm validate` for typecheck, tests and production build. Tests cover: encryption and AAD binding, availability rules, one-time links (including concurrent use and concurrent creation), documentation
validation, OIDC verification (bad algorithm, issuer, audience, expiry, repository, ref, event, tampering, JWKS refresh and
outage), session signing and revocation, the proxy (host allowlist, header override attempts, redirects, size caps,
redaction in every encoding, timeouts) and the runner API end to end (including rate limits and fail-closed behaviour).

## Known limits and roadmap

- Runner delivery is proxy-only. Legacy `inject` rows are disabled and hidden by migration 0013.
- OIDC proves the workflow run, not a single process; any process able to read the job's OIDC request variables can request a run-bound token. Keep the workflow job trusted and minimize untrusted code in it.
- No automatic `ENCRYPTION_KEY` rotation tooling.
- No GitHub-side validation test for stored tokens (`validation` stays `not_tested`).
- Suggested hardening after first deploy: a branch ruleset on `main` of this repository and Cloudflare Access in front of `/vault/*` as a second owner gate.
- Runner integration is deployment-specific: install client/vault.mjs in the trusted repository and set its VAULT_URL Actions variable. Pin the client revision and review upgrades.

## Repository layout

| Path | What |
| --- | --- |
| `app/` | The Worker: Spiceflow (React Server Components) owner UI, runner API, BetterAuth GitHub login |
| `app/src/lib/` | Crypto, policy, docs schema, enrollment links, credential service, OIDC, sessions, proxy, runner core |
| `app/src/runner-api.ts` | HTTP routes for runners; logic is in `lib/runner-core.ts` |
| `db/` | Drizzle schema and D1 migrations (`db/drizzle-app/`) |
| `client/vault.mjs` | Zero-dependency runner client |
| `docs/runner-usage.md` | Runner-side usage and `doc.json` schema |
| `SECURITY.md`, `NOTICE.md` | Trust model, upstream credit |
