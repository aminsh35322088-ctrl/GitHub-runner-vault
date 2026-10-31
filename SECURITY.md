# Security model

**Goal:** a compromised or prompt-injected model on the runner cannot read a stored secret.

- Secrets never leave the Worker in `proxy` mode; the Worker makes the call. Values are
  AES-256-GCM encrypted with the row id and key version as AAD; `ENCRYPTION_KEY` is mandatory (32 bytes).
- The runner is **not** a trust boundary: anything on it can use its own session. So the
  vault limits what a session can do: owner-approved hosts only, header allowlist, no redirects,
  response redaction, rate limits, 30-minute sessions, owner-side revoke, append-only audit.
- Runner identity is GitHub OIDC (RS256 only) restricted by repository id, ref and event.
  It authenticates the workflow run, not an individual process.
- Owner login is GitHub OAuth restricted to one numeric account id; sessions are cookie-only.
- Models propose names and setup notes; the **owner** decides hosts, auth header, lifetime
  and visibility. Notes are treated as hostile text (strict schema, no HTML, visible link hosts).
- `inject` delivery returns a value to the runner and should only be used for low-privilege or
  short-lived tokens.

Report vulnerabilities privately to the repository owner, not in a public issue.
