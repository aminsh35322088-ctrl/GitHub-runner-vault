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
| Someone else gets a runner session | Runner identity is a **GitHub OIDC token** pinned to each deployment's repository name and numeric id, exact ref, event and workflow. Pull-request events are refused. |
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

From the dashboard, choose **Add credential** to browse the built-in provider catalog (Cloudflare, Railway, GitHub, Vercel, Netlify, DigitalOcean, OpenAI, Anthropic, Groq, Mistral, Hugging Face, Stripe, Sentry, Supabase, Pinecone and Slack), search by provider/category, or add a custom service. Known providers prefill their documented API host and auth header; the owner can inspect and edit these values before creating a credential. This path works independently of any runner/model registration request. The runner registration flow uses the same provider catalog for its defaults.

Sign in at `https://<origin>/login` with the owner GitHub account.

| Page | What it does |
| --- | --- |
| `/vault` | Credential list: status, delivery, expiry, last used. |
| `/vault/register/<link>` | The one-time registration page: the agent's setup notes above a write-only secret field, plus hosts, auth header/scheme, lifetime, expiry and visibility. |
| `/vault/credentials/<id>` | Details, enable/disable, show/hide, delete, replace value or rules, recent activity. Stored values are never displayed. |
| `/vault/audit` | Append-only audit log (database triggers block updates and deletes). |
| `/vault/settings` | **Revoke all runner sessions**; add a metadata-only entry (for example `GITHUB_TOKEN`). |

## Deployment

You need a Cloudflare account and a GitHub account. No command line, no API token and no hand-made secrets.

**1. Deploy** — press the button and authorize GitHub and Cloudflare. Cloudflare clones the project into your
GitHub account and deploys it through Workers Builds. During the build, the project reads the actual Git origin,
resolves the repository owner's numeric GitHub ID through GitHub's API, and injects it as the Worker's
`OWNER_GITHUB_ID` runtime variable. The first Worker request pins that ID in D1. No GitHub Actions setup, manual
owner ID, setup code, or extra Cloudflare token is required.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/aminsh35322088-ctrl/GitHub-runner-vault/tree/main/app)

The Worker and its D1 database are provisioned in your Cloudflare account. The schema is created on first request.

**2. Confirm the owner** — open your Worker's URL (`https://<name>.<you>.workers.dev`) and press
*Create the GitHub App*. Use the same GitHub account that owns the repository created by Deploy to Cloudflare.
GitHub returns the App creator's numeric account ID; the Worker compares it with the pinned deployment owner ID.
A different account is rejected, and opening the Worker first cannot claim ownership. Once matched, the sign-in
credentials are stored encrypted and `/setup` closes permanently.

**3. Choose your runner repository** — sign in, open *Settings → Runner repository* and enter the repository, branch and
workflow file that may use the vault (for example `you/your-runner-repo`, `main`, `rdc-lab.yml`). Public repositories are
looked up for you; for a private one, also enter its numeric repository id. Pull-request runs are never accepted.

**4. Point the runner at it** — set the Actions variable `VAULT_URL` (or `RUNNER_VAULT_URL`, depending on your workflow)
to the Worker URL and install `client/vault.mjs` (see [Runner client](#runner-client)).

Deploying from a terminal instead: `cd app && pnpm install && pnpm deploy` (needs `wrangler login`).

### Where the key lives

By default the master key is generated by the Worker and stored in the same D1 database as the encrypted values, so
nobody has to create or paste a key. That protects against anything that sees ciphertext but not the key *in use* (for
example a copied credential row), but **not** against someone who can read the whole D1 database. If that matters to you,
add a Worker secret `VAULT_MASTER_KEY` (32 random bytes, base64: `openssl rand -base64 32`) **before storing your first
credential**; it takes precedence and the database copy is never used. Changing the master key later makes existing
values undecryptable, so re-enter them.

Existing deployments that already have `BETTER_AUTH_SECRET` and `ENCRYPTION_KEY` secrets keep using them unchanged.

### Starting over

If sign-in is misconfigured, delete the sign-in settings and open `/setup` again (D1 console):
`DELETE FROM vault_setting WHERE key IN ('github_client_id','github_client_secret','owner_github_id');`
Stored credentials are not touched.

## Configuration reference

Everything below is optional. A normal deployment sets nothing; everything is configured in the UI.

| Name | Kind | Notes |
| --- | --- | --- |
| `VAULT_MASTER_KEY` | secret | Keeps the key out of D1 (see above). |
| `PUBLIC_ORIGIN` | var | Canonical HTTPS origin for a custom domain. By default the actual request origin is used. |
| `OWNER_GITHUB_ID` | secret | Provisioned automatically by the Deploy workflow from the GitHub repository owner's numeric ID. Do not set it from user input. |
| `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` | vars / secrets | Optional override for the private GitHub sign-in App created through `/setup`. |
| `RUNNER_REPOSITORY`, `RUNNER_REPOSITORY_ID`, `RUNNER_ALLOWED_REFS`, `RUNNER_ALLOWED_EVENTS`, `RUNNER_ALLOWED_WORKFLOW_REFS` | vars | Fix the runner policy in configuration; then the Settings form is read-only. |
| `BETTER_AUTH_SECRET`, `ENCRYPTION_KEY` | secrets | Legacy explicit keys; both must be set to be used. |
| `DB` | D1 binding | Created automatically on deploy. |

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
