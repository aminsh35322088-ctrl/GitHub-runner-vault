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
- The Runner host and authorized GitHub Actions workflow are the trust boundary. The CLI obtains a single-use GitHub OIDC token from the Actions requester endpoint and exchanges it directly with the Worker over HTTPS. OIDC authenticates the workflow run, not an individual process: any process in that authorized job that can read the OIDC requester environment can request a short-lived Runner Session. The Session is held only in CLI process memory and is never written to disk. The Worker still enforces immutable repository/owner identity, the pinned workflow/ref/event policy, one-time OIDC token IDs, rate limits, operation checks, owner-side revocation, access epochs and append-only audit records. Provider tokens and the Vault encryption key remain inside the Worker and are never returned to the Runner.
- The owner can disable all Runner API access with the global Vault Access setting. The Worker reads the enabled flag and monotonic access epoch together from D1 on every Runner request (not through the preferences cache); a failed or malformed read denies access. Disabling atomically advances the access epoch and the existing Session revocation cutoff. Every issued Session is signed with its epoch, so sessions from before a disable remain invalid after re-enable, including when different Worker isolates have skewed clocks. Owner dashboard access remains available while Runner access is disabled.
- Runner identity is GitHub OIDC (RS256 only) restricted by repository id, ref and event.
  It authenticates the workflow run, not an individual process.
- Production deployment can use Wrangler OAuth from a trusted owner-controlled environment or the optional
  **Deploy to Cloudflare** GitHub Actions workflow. The Actions path supplies the repository owner's numeric
  GitHub ID as `RUNNER_VAULT_OWNER_GITHUB_ID`; the OAuth path resolves the owner from the checked-out GitHub
  origin through GitHub's typed JSON user API. Both paths use the same build helper and Worker configuration.
  The GitHub Actions workflow is manual-only and requires `CLOUDFLARE_API_TOKEN`; the Wrangler OAuth path does
  not require a Cloudflare token in GitHub Secrets. HTML profile metadata is never trusted because
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
