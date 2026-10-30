-- Small key/value settings owned by the vault itself (e.g. runner_revoked_before).
CREATE TABLE `vault_setting` (
	`key` text PRIMARY KEY CHECK (length(`key`) BETWEEN 1 AND 64),
	`value` text NOT NULL CHECK (length(`value`) <= 500),
	`updated_at` integer NOT NULL
);
