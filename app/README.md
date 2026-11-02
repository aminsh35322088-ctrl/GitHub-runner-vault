# Runner Credential Vault

This directory is the self-contained Cloudflare Worker project. It includes the pnpm workspace, database package, Wrangler config, schema bootstrap and deploy helpers.

## Supported deployment paths

### 1. Deploy to Cloudflare button

Use the button in the repository's root README. Cloudflare creates a new repository under the GitHub account authorizing the deployment, provisions the D1 resource, and configures Workers Builds.

During the production Vite build, the project reads the checked-out GitHub `origin`, resolves the owner's numeric ID from the public GitHub profile metadata, and injects it as the Worker's `OWNER_GITHUB_ID` runtime variable. The first Worker request pins that ID in D1. The GitHub App created during `/setup` must belong to that exact personal GitHub account.

The button's source URL is fixed to the upstream repository; it does not deploy a pre-existing fork's commits. To deploy your existing fork instead, use the Dashboard GitHub connection below.

### 2. Connect your GitHub account from the Cloudflare Dashboard

For a new Worker:

1. Open **Workers & Pages → Create application → GitHub**.
2. Authorize the Cloudflare GitHub App and select your personal fork/repository.
3. Set **Root directory** to `app`.
4. Set **Build command** to `pnpm build`.
5. Set **Deploy command** to `pnpm deploy`.
6. Save and deploy.

For an existing Worker, open **Settings → Builds → Connect** and choose the same repository. Its Worker name must match the `name` field in `wrangler.jsonc` (default: `runner-vault`), or update that field before connecting. The GitHub repository should be your personal fork. If you intentionally connect a repository owned by someone else, set `RUNNER_VAULT_OWNER_GITHUB_ID` to your numeric ID in **Settings → Builds → Build variables**; it overrides the Git origin owner.

Workers Builds runs the same owner-resolution code as the Deploy Button. The deploy command reuses the completed build, resolves or creates the `DB` D1 database, patches the generated Wrangler config with its ID, then deploys.

**Important — D1 permissions:** Cloudflare's automatically generated Workers Builds API token does not include D1 permissions by default. To let the helper discover/create D1 automatically, open **My Profile → API Tokens**, find the token selected in this Worker under **Settings → Builds → API token**, and add **Account → D1 Read** and **Account → D1 Edit**. (The account-generated token must stay user-scoped for Workers Builds.)

Alternatively, create the D1 database in **Storage & databases → D1**, copy its UUID, and add `"database_id": "<UUID>"` to the `DB` entry in `app/wrangler.jsonc` in your repository. With a configured ID the deploy helper skips D1 list/create operations, so the default Build token does not need D1 permissions. The Deploy Button's resource provisioning path normally supplies the required D1 resource automatically.

### 3. Wrangler CLI from a Git checkout

Clone your own GitHub repository (not the upstream repository), log in to Cloudflare, then run:

```bash
cd app
pnpm install --frozen-lockfile
pnpm exec wrangler login
pnpm deploy
```

`pnpm deploy` runs the Vite production build, derives the owner from the GitHub `origin`, checks for the configured D1 database (creating it if missing), patches the final Worker config, and finally runs `wrangler deploy`. The Wrangler login must have D1 Read/Edit permissions when the database needs to be created.

If you are deploying from a source archive without a Git remote, authenticate GitHub CLI first:

```bash
gh auth login
pnpm deploy
```

The build uses `gh api user --jq .id` as the owner identity when no GitHub origin exists. You can also set the numeric ID explicitly with `RUNNER_VAULT_OWNER_GITHUB_ID`. In Cloudflare Workers Builds, add it under **Settings → Builds → Build variables**; for local CLI use it as an environment variable. Do not set this to an organization ID; the sign-in App must be owned by a personal GitHub account.

Use the project command `pnpm deploy` rather than running `wrangler deploy` directly: the wrapper ensures that owner metadata and the D1 binding are present before invoking Wrangler.

### 4. Manual upload or a dashboard editor without Git

A manual upload has no Git origin and no build step from which to derive the owner. Before opening `/setup`, add `OWNER_GITHUB_ID` as a **Worker runtime variable** under **Settings → Variables & Secrets**. Use the numeric ID of the intended personal GitHub owner. It is public identity metadata, not a secret. GitHub's manifest-conversion callback still verifies the App creator's ID against this value, so a different account cannot claim the vault.

If no valid owner ID is available, `/setup` stays locked. The application never falls back to first-visitor ownership.

## After deployment

1. Open the Worker URL and choose **Create the GitHub App** using the same personal GitHub account that owns the deployed repository (or matches the manually configured owner ID).
2. Sign in and configure the trusted runner repository, branch and workflow in Settings.
3. Set the Worker URL as the `VAULT_URL` Actions variable in the trusted runner repository and grant the workflow `id-token: write`.

The Worker creates its tables on first request. The Deploy Button provisions D1 automatically; the Wrangler deploy helper also resolves and binds the configured D1 database for CLI and Git-connected deployments.

For the threat model and runner integration guide, see the [upstream README](https://github.com/aminsh35322088-ctrl/GitHub-runner-vault/blob/main/README.md), [security notes](https://github.com/aminsh35322088-ctrl/GitHub-runner-vault/blob/main/SECURITY.md) and [runner usage guide](https://github.com/aminsh35322088-ctrl/GitHub-runner-vault/blob/main/docs/runner-usage.md).

## Local development

```bash
pnpm install
cp .dev.vars.example .dev.vars
pnpm dev
```

Run `pnpm validate` for typecheck, Node deploy-helper tests, Worker tests, client-contract tests and production build.
