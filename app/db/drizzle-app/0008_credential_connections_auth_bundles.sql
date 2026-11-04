ALTER TABLE credential ADD COLUMN connection_label text NOT NULL DEFAULT '' CHECK (length(connection_label) <= 120);
--> statement-breakpoint
ALTER TABLE credential ADD COLUMN provider_account_id text NOT NULL DEFAULT '' CHECK (length(provider_account_id) <= 160);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS credential_provider_connection_idx ON credential (service, provider_account_id, connection_label);
