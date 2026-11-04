-- Consumed GitHub OIDC token ids. Verification alone leaves a captured token
-- replayable until it expires (~10 minutes); the session path records the
-- token's jti here after successful verification, and the primary key makes
-- consuming the same token twice fail atomically. Rows are useless once the
-- token has expired and are deleted opportunistically by the session path.
CREATE TABLE oidc_token_use (
  jti text PRIMARY KEY NOT NULL,
  subject text NOT NULL DEFAULT '',
  expires_at integer NOT NULL,
  created_at integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX oidc_token_use_expires_at_idx ON oidc_token_use (expires_at);
