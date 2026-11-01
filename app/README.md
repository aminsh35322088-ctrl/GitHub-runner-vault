# Runner Credential Vault

This directory is the self-contained Cloudflare Worker project used by the Deploy to Cloudflare button. It includes its own pnpm workspace, lockfile, database package, Wrangler configuration and schema bootstrap.

## First deployment

1. Deploy this project to your Cloudflare account using the Deploy to Cloudflare button in the upstream repository.
2. Set the required `SETUP_CODE` secret to a private phrase of at least 12 characters.
3. Open the Worker URL, enter the setup code, and create the private GitHub App. The GitHub account that creates the app becomes the sole vault owner.
4. Sign in and configure the trusted runner repository, branch and workflow in Settings.
5. Add the Worker URL as the `VAULT_URL` Actions variable in the trusted runner repository and grant the workflow `id-token: write`.

For the complete threat model and runner integration guide, see the [upstream README](https://github.com/aminsh35322088-ctrl/GitHub-runner-vault/blob/main/README.md), [security notes](https://github.com/aminsh35322088-ctrl/GitHub-runner-vault/blob/main/SECURITY.md) and [runner usage guide](https://github.com/aminsh35322088-ctrl/GitHub-runner-vault/blob/main/docs/runner-usage.md). The zero-dependency runner client remains maintained in the upstream repository at [client/vault.mjs](https://github.com/aminsh35322088-ctrl/GitHub-runner-vault/blob/main/client/vault.mjs).

## Local development

```bash
pnpm install
cp .dev.vars.example .dev.vars
# Set SETUP_CODE in .dev.vars, then:
pnpm dev
```

Run `pnpm validate` for typecheck, Worker tests, client-contract tests and production build.
