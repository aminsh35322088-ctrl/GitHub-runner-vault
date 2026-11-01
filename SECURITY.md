# Security model

**Goal:** a compromised or prompt-injected model on the runner cannot read a stored secret.

- Secrets never leave the Worker in `proxy` mode; the Worker makes the call. Values are
  AES-256-GCM encrypted with the row id and key version as AAD; the 32-byte key is derived from a random master key (generated on first use, or
  supplied as `VAULT_MASTER_KEY`). Without `VAULT_MASTER_KEY` the master key sits in D1 next to the ciphertext.
- The runner is **not** a trust boundary: anything on it can use its own session. So the
  vault limits what a session can do: owner-approved hosts only, header allowlist, no redirects,
  response redaction, rate limits, 30-minute sessions, owner-side revoke, append-only audit.
- Runner identity is GitHub OIDC (RS256 only) restricted by repository id, ref and event.
  It authenticates the workflow run, not an individual process.
- Owner login is a private GitHub App created through `/setup`; it is restricted to one numeric account id (the
  app's creator) and sessions are cookie-only. `/setup` needs the deployer's `SETUP_CODE`, locks after 10 wrong
  tries per hour, and closes permanently once an owner exists.
- Models propose names and setup notes; the **owner** decides hosts, auth header, lifetime
  and visibility. Notes are treated as hostile text (strict schema, no HTML, visible link hosts).
- `inject` delivery is stored as a setting but **not implemented yet**: the runner API refuses to
  proxy such credentials and has no endpoint that returns a value. If added, it must be limited to
  low-privilege or short-lived tokens.

Report vulnerabilities privately to the repository owner, not in a public issue.
