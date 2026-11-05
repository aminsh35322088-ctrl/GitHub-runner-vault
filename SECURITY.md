# Security model

**Goal:** a compromised or prompt-injected model on the runner cannot read a stored secret.

- Secrets never leave the Worker in `proxy` mode; the Worker makes the call. Values are
  AES-256-GCM encrypted with the row id and key version as AAD; the 32-byte key is derived from a random master key
  supplied as the `VAULT_MASTER_KEY` Worker secret. The deploy helper provisions that secret on all supported deploy
  routes, generating it for fresh deployments and copying the old D1 value verbatim on upgrades. If provisioning
  cannot complete, a fresh deployment fails closed. Older deployments remain in flagged legacy mode (new credential
  storage paused) until a redeploy provisions the secret. If the key differs, every credential and the GitHub App
  secret is preflighted, then all ciphertext rewrites and key removal commit atomically; any unreadable value blocks
  migration and preserves the old D1 key.
- The runner is **not** a trust boundary: anything on it can use its own session. So the
  vault limits what a session can do: owner-approved hosts only, header allowlist, no redirects,
  response redaction, rate limits, 30-minute sessions, owner-side revoke, append-only audit.
- The owner can disable all Runner API access with the global Vault Access setting. The Worker checks this flag directly from D1 on every Runner request (not through the preferences cache); a failed setting read denies access. Disabling atomically advances the existing Session revocation cutoff, so re-enabling never revives previously issued Sessions. Owner dashboard access remains available while Runner access is disabled.
- Runner identity is GitHub OIDC (RS256 only) restricted by repository id, ref and event.
  It authenticates the workflow run, not an individual process.
- The only supported deployment route is the repository's **Deploy to Cloudflare** GitHub Actions workflow,
  which supplies the repository owner's numeric GitHub ID as `RUNNER_VAULT_OWNER_GITHUB_ID` from the trusted
  Actions context. (The build still honours the general resolution order — explicit ID, then the checked-out
  GitHub origin via GitHub's typed JSON user API, then the Actions owner ID when its repository context matches
  that origin — but no other route is documented or supported.) HTML profile metadata is never trusted because
  it cannot distinguish Users from Organizations. If the identity cannot be verified, the Worker remains
  locked. The ID is injected as Worker runtime `OWNER_GITHUB_ID`, which is public identity metadata, not a
  credential.
- On first use, the Worker atomically pins the expected ID in D1, so later repository transfers or build metadata
  changes cannot silently transfer ownership. `/setup` remains locked without a valid deployment owner. The private
  GitHub App created through `/setup` must have the exact same numeric creator ID; the callback rejects mismatches
  and organization-owned Apps before storing credentials. A one-time state cookie binds the callback to the
  initiating browser. There is no first-visitor/first-finisher ownership path.
- Models propose names and setup notes; the **owner** decides hosts, auth header, lifetime
  and visibility. Notes are treated as hostile text (strict schema, no HTML, visible link hosts).
- `inject` delivery is stored as a setting but **not implemented yet**: the runner API refuses to
  proxy such credentials and has no endpoint that returns a value. If added, it must be limited to
  low-privilege or short-lived tokens.

Report vulnerabilities privately to the repository owner, not in a public issue.
