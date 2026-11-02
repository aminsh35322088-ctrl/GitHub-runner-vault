# Runner Credential Vault

This directory is the self-contained Cloudflare Worker project used by the Deploy to Cloudflare button. It includes its own pnpm workspace, lockfile, database package, Wrangler configuration and schema bootstrap.

## First deployment

1. Deploy this project using the Deploy to Cloudflare button and authorize GitHub and Cloudflare. Cloudflare clones the project into your GitHub account and deploys it with Workers Builds.
   The button creates a fresh copy from the upstream source; a manual fork beforehand is not required. To deploy an already-customized fork, import that repository from **Workers & Pages → Create application → GitHub** instead.
2. The build reads the checked-out repository's Git origin, extracts the numeric owner ID from GitHub's public repository-page metadata, and injects it as the Worker `OWNER_GITHUB_ID` variable. The first request pins it in D1. During setup, GitHub's manifest-conversion response must identify a personal GitHub App owner with that same ID; organization-owned apps are rejected. No owner ID or setup code is entered manually.
3. Open the Worker URL and create the private GitHub App using the same GitHub account that owns the repository created by Deploy to Cloudflare. The Worker verifies the App creator's numeric ID against the pinned deployment owner; a different account cannot claim ownership.
4. Sign in, open **Add credential** to create credentials directly from the provider catalog, and configure the trusted runner repository, branch and workflow in Settings.
5. Add the Worker URL as the `VAULT_URL` Actions variable in the trusted runner repository and grant the workflow `id-token: write`.

For the complete threat model and runner integration guide, see the [upstream README](https://github.com/aminsh35322088-ctrl/GitHub-runner-vault/blob/main/README.md), [security notes](https://github.com/aminsh35322088-ctrl/GitHub-runner-vault/blob/main/SECURITY.md) and [runner usage guide](https://github.com/aminsh35322088-ctrl/GitHub-runner-vault/blob/main/docs/runner-usage.md). The zero-dependency runner client remains maintained in the upstream repository at [client/vault.mjs](https://github.com/aminsh35322088-ctrl/GitHub-runner-vault/blob/main/client/vault.mjs).

## Local development

```bash
pnpm install
cp .dev.vars.example .dev.vars
pnpm dev
```

Run `pnpm validate` for typecheck, Worker tests, client-contract tests and production build.
