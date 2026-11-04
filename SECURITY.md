# Security model

**Goal:** a compromised or prompt-injected model on the runner cannot read a stored secret.

- Secrets never leave the Worker in `proxy` mode; the Worker makes the call. Values are
  AES-256-GCM encrypted with the row id and key version as AAD; the 32-byte key is derived from a random master key
  supplied as the `VAULT_MASTER_KEY` Worker secret. Fresh deployments without the secret fail closed. Deployments
  created before the secret was required may still hold the key in D1 next to the ciphertext; they run in a flagged
  legacy mode (new credential storage paused) until the owner sets the secret, which migrates all ciphertexts atomically and deletes the
  database copy only after every credential and the GitHub App secret can be resealed.
- The runner is **not** a trust boundary: anything on it can use its own session. So the
  vault limits what a session can do: owner-approved hosts only, header allowlist, no redirects,
  response redaction, rate limits, 30-minute sessions, owner-side revoke, append-only audit.
- Runner identity is GitHub OIDC (RS256 only) restricted by repository id, ref and event.
  It authenticates the workflow run, not an individual process.
- Production Vite builds resolve a numeric personal GitHub owner ID in this order: explicit
  `RUNNER_VAULT_OWNER_GITHUB_ID`; the checked-out GitHub origin via GitHub's typed JSON user API; then
  GitHub Actions' immutable owner ID only when both `GITHUB_REPOSITORY_OWNER` and the owner in
  `GITHUB_REPOSITORY` match that origin. With no Git origin, the Actions repository-owner ID or authenticated
  GitHub CLI account may be used. HTML profile metadata is never trusted because it cannot distinguish Users
  from Organizations. If the identity cannot be verified, the Worker remains locked. The ID is injected as
  Worker runtime `OWNER_GITHUB_ID`, which is public identity metadata, not a credential. A manual Dashboard
  upload must set the same runtime variable and bind its D1 database as `DB`. A dashboard Git connection must
  point at the intended personal fork; connecting the upstream project binds the upstream repository owner
  unless an explicit build owner ID is configured.
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
