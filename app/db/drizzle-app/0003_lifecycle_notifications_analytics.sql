-- Credential lifecycle, in-panel notifications and low-cardinality usage analytics.
ALTER TABLE credential ADD COLUMN validation_status text NOT NULL DEFAULT 'not_tested';
--> statement-breakpoint
ALTER TABLE credential ADD COLUMN last_validated_at integer;
--> statement-breakpoint
ALTER TABLE credential ADD COLUMN next_validation_at integer;
--> statement-breakpoint
CREATE INDEX credential_validation_due_idx ON credential (status, next_validation_at);
--> statement-breakpoint
CREATE TABLE vault_notification (
  id text PRIMARY KEY,
  dedupe_key text NOT NULL UNIQUE,
  kind text NOT NULL,
  severity text NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
  title text NOT NULL CHECK (length(title) <= 160),
  message text NOT NULL CHECK (length(message) <= 600),
  credential_id text,
  credential_name text NOT NULL DEFAULT '',
  created_at integer NOT NULL,
  read_at integer,
  CONSTRAINT fk_vault_notification_credential_id_credential_id_fk
    FOREIGN KEY (credential_id) REFERENCES credential(id) ON DELETE SET NULL
);
--> statement-breakpoint
CREATE INDEX vault_notification_created_idx ON vault_notification (created_at);
--> statement-breakpoint
CREATE INDEX vault_notification_unread_idx ON vault_notification (read_at, created_at);
--> statement-breakpoint
CREATE TABLE credential_usage_hourly (
  id text PRIMARY KEY,
  credential_id text NOT NULL,
  window_start integer NOT NULL,
  consumer text NOT NULL DEFAULT 'runner',
  request_count integer NOT NULL DEFAULT 0,
  success_count integer NOT NULL DEFAULT 0,
  error_count integer NOT NULL DEFAULT 0,
  latency_total_ms integer NOT NULL DEFAULT 0,
  latency_max_ms integer NOT NULL DEFAULT 0,
  UNIQUE (credential_id, window_start, consumer),
  CONSTRAINT fk_usage_credential FOREIGN KEY (credential_id) REFERENCES credential(id) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE INDEX credential_usage_window_idx ON credential_usage_hourly (window_start);
--> statement-breakpoint
CREATE INDEX credential_usage_credential_idx ON credential_usage_hourly (credential_id, window_start);
