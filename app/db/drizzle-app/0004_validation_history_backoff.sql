-- Validation history and retry state for credential lifecycle monitoring.
ALTER TABLE credential ADD COLUMN validation_failure_count integer NOT NULL DEFAULT 0 CHECK (validation_failure_count BETWEEN 0 AND 1000);
--> statement-breakpoint
ALTER TABLE credential ADD COLUMN first_validation_failure_at integer;
--> statement-breakpoint
CREATE TABLE credential_validation_history (
  id text PRIMARY KEY,
  credential_id text NOT NULL,
  credential_name text NOT NULL DEFAULT '',
  provider text NOT NULL CHECK (length(provider) BETWEEN 1 AND 80),
  source text NOT NULL CHECK (source IN ('scheduled', 'manual')),
  status text NOT NULL CHECK (length(status) BETWEEN 1 AND 40),
  message text NOT NULL DEFAULT '' CHECK (length(message) <= 600),
  identity text,
  token_type text,
  permission_source text NOT NULL CHECK (length(permission_source) <= 40),
  permissions_json text NOT NULL DEFAULT '[]',
  permissions_complete integer NOT NULL DEFAULT 0 CHECK (permissions_complete IN (0, 1)),
  duration_ms integer NOT NULL DEFAULT 0 CHECK (duration_ms >= 0),
  checked_at integer NOT NULL,
  CONSTRAINT fk_credential_validation_history_credential
    FOREIGN KEY (credential_id) REFERENCES credential(id) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE INDEX credential_validation_history_credential_idx ON credential_validation_history (credential_id, checked_at);
--> statement-breakpoint
CREATE INDEX credential_validation_history_checked_idx ON credential_validation_history (checked_at);
