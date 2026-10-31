# Runner Credential Vault

A **single-owner credential vault** on Cloudflare Workers + D1, built for the
[GitHub Runner Lab](https://github.com/aminsh35322088-ctrl/GitHub-Runner-Lab) (a disposable GitHub Actions runner that AI
agents work on).

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

The runner is **not** a trust boundary. The Lab's agent user has passwordless `sudo` and Docker access, and the Actions
runner processes share its account, so nothing stored on the runner can be protected from the agent. The vault therefore:

| Risk | Mitigation |
| --- | --- |
| Agent reads the token | Token is stored only in the Worker (AES-256-GCM, bound to the row) and is never returned in `proxy` mode. |
| Agent sends the token to an attacker's host | The Worker calls **only hosts the owner approved** per credential; HTTPS only, default port, no redirects followed. |
| Agent smuggles auth / routing headers | Request header **allowlist**; the auth header is set by the Worker after everything else. |
| Upstream echoes the token back | Response body and headers are scanned and the token is **redacted** (raw, URL-encoded, JSON-escaped, base64). |
| Agent tricks the owner into a bad setup | Models only *propose* a name and setup notes. The **owner** chooses hosts, auth header, lifetime and visibility. Notes are shown as plain text with the real hostname next to each link. |
| Someone else gets a runner session | Runner identity is a **GitHub OIDC token** pinned to the Lab repository (name and numeric id), `refs/heads/main` and `workflow_dispatch`/`schedule` by default. Pull-request and fork runs are refused. |
| Stolen session | 30-minute sessions, rate limits, append-only audit log, and an owner-side **revoke all sessions** button. |
| Someone else logs in to the owner UI | GitHub OAuth restricted to **one numeric account id**; cookie sessions only. |
| Agent edits the vault code | The vault is a **separate private repository**. |

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
should expect. The matching Lab-side change (the `id-token: write` permission) is documented in the Lab repository at
`docs/credential-vault.md`.

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

Prerequisites: a Cloudflare account, Node 20+, `pnpm`, and `wrangler` (installed by `pnpm install`).

**1. Clone and install**

```bash
git clone https://github.com/aminsh35322088-ctrl/GitHub-runner-vault.git
cd GitHub-runner-vault && pnpm install
npx wrangler login
```

**2. Create the D1 database** and put its id in `app/wrangler.jsonc` (`d1_databases[0].database_id`):

```bash
npx wrangler d1 create runner-vault-db
```

> A database with this name and id may already exist in the owner's Cloudflare account (the id committed in
> `app/wrangler.jsonc`). If so, skip this step. If you are using a different account, replace the id.

**3. Pick the Worker URL** (for example `https://runner-vault.<your-subdomain>.workers.dev`) and set `PUBLIC_ORIGIN` in
`app/wrangler.jsonc` to exactly that origin (scheme + host, no trailing slash). The first deploy tells you the URL; you may
deploy once, then set it and deploy again.

**4. Create a GitHub OAuth App** (GitHub → Settings → Developer settings → OAuth Apps → New):

- Homepage URL: your `PUBLIC_ORIGIN`
- Authorization callback URL: `<PUBLIC_ORIGIN>/api/auth/callback/github`

Note the **Client ID** and generate a **Client secret**.

**5. Set the non-secret variables** in `app/wrangler.jsonc` `vars`:

| Var | Value |
| --- | --- |
| `PUBLIC_ORIGIN` | the exact Worker origin |
| `OWNER_GITHUB_ID` | the **numeric** id of the owner's GitHub account: `curl https://api.github.com/users/<login>` → `id` |
| `RUNNER_REPOSITORY` | `aminsh35322088-ctrl/GitHub-Runner-Lab` |
| `RUNNER_REPOSITORY_ID` | `1374269690`; numeric id of the Lab repo |

**6. Set the secrets** (never commit these; each command prompts for the value):

```bash
cd app
openssl rand -base64 32 | npx wrangler secret put BETTER_AUTH_SECRET
openssl rand -base64 32 | npx wrangler secret put ENCRYPTION_KEY     # exactly 32 bytes, base64
npx wrangler secret put GITHUB_CLIENT_ID
npx wrangler secret put GITHUB_CLIENT_SECRET
```

Keep an offline backup of `ENCRYPTION_KEY`. Without it every stored credential is unrecoverable.
(If the Worker does not exist yet, `wrangler secret put` offers to create it, or run step 7 first and add secrets after.)

**7. Migrate and deploy**

```bash
cd ..                      # repository root
pnpm run deploy            # applies D1 migrations, builds, deploys  (use "run": plain `pnpm deploy` is a pnpm built-in)
```

Alternative: connect the repository to the Worker in the Cloudflare dashboard (Workers → your Worker → Settings → Builds)
so every push to `main` builds and deploys; run `npx wrangler d1 migrations apply DB --remote --config app/wrangler.jsonc`
for migrations.

**8. Verify**

1. Open `<PUBLIC_ORIGIN>/login` and sign in with the owner GitHub account. A different GitHub account is refused.
2. `curl -s -X POST <PUBLIC_ORIGIN>/api/runner/registry -i` returns `401` (or `405` for the wrong method), not `503`. A `503 vault_not_configured` means a variable or secret above is missing.
3. In the Lab, apply the workflow permission change and run the checklist in the Lab's `docs/credential-vault.md`.

## Configuration reference

| Name | Kind | Required | Notes |
| --- | --- | --- | --- |
| `PUBLIC_ORIGIN` | var | yes | Pins the origin used for OAuth callbacks, trusted origins and owner links. |
| `OWNER_GITHUB_ID` | var | yes | Numeric GitHub account id. Empty = nobody can sign in (fails closed). |
| `RUNNER_REPOSITORY` | var | yes | `owner/name`. Empty = runner API answers 503. |
| `RUNNER_REPOSITORY_ID` | var | yes | Numeric repository id; a mismatch or missing value rejects runner authentication. |
| `RUNNER_ALLOWED_REFS` | var | no | Comma list, default `refs/heads/main`. |
| `RUNNER_ALLOWED_EVENTS` | var | no | Default `workflow_dispatch,schedule,push`; PR events stay excluded. |
| `RUNNER_ALLOWED_WORKFLOW_REFS` | var | yes/defaulted | Exact `job_workflow_ref` allowlist; the default is only Lab's `rdc-lab.yml@refs/heads/main`. |
| `BETTER_AUTH_SECRET` | secret | yes | Signs owner sessions; also (via HKDF, separate label) runner sessions. At least 32 characters. |
| `ENCRYPTION_KEY` | secret | yes | 32 random bytes, base64. |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | secret | yes | GitHub OAuth App for the owner login. |
| `DB` | D1 binding | yes | `runner-vault-db`. |

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
cd app && npx vite dev               # local dev (needs app/.dev.vars, see below)
```

`app/.dev.vars` (git-ignored) for local runs: `BETTER_AUTH_SECRET`, `ENCRYPTION_KEY`, `OWNER_GITHUB_ID`,
`PUBLIC_ORIGIN` (use a `*.localhost` host so `crypto.randomUUID` has a secure context). Apply migrations locally with
`npx wrangler d1 migrations apply DB --local`.

Run `pnpm validate` for typecheck, tests and production build. Tests cover: encryption and AAD binding, availability rules, one-time links (including concurrent use and concurrent creation), documentation
validation, OIDC verification (bad algorithm, issuer, audience, expiry, repository, ref, event, tampering, JWKS refresh and
outage), session signing and revocation, the proxy (host allowlist, header override attempts, redirects, size caps,
redaction in every encoding, timeouts) and the runner API end to end (including rate limits and fail-closed behaviour).

## Known limits and roadmap

- Runner delivery is proxy-only. Legacy `inject` rows are disabled and hidden by migration 0013.
- OIDC proves the workflow run, not a single process; any process able to read the job's OIDC request variables can request a run-bound token. Keep the workflow job trusted and minimize untrusted code in it.
- No automatic `ENCRYPTION_KEY` rotation tooling.
- No GitHub-side validation test for stored tokens (`validation` stays `not_tested`).
- The Lab installs the zero-dependency client from the pinned Vault commit when `VAULT_URL` is configured; see the Lab's `docs/credential-vault.md`.
- Suggested hardening after first deploy: a branch ruleset on `main` of this repository and Cloudflare Access in front of `/vault/*` as a second owner gate.

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
