-- Runner Credential Vault schema (single baseline).
-- Auth tables follow BetterAuth; credential tables hold the encrypted registry.

CREATE TABLE `account` (
	`id` text PRIMARY KEY,
	`user_id` text NOT NULL,
	`account_id` text NOT NULL,
	`provider_id` text NOT NULL,
	`access_token` text,
	`refresh_token` text,
	`access_token_expires_at` integer,
	`refresh_token_expires_at` integer,
	`scope` text,
	`id_token` text,
	`password` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	CONSTRAINT `fk_account_user_id_user_id_fk` FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON DELETE CASCADE
);--> statement-breakpoint
CREATE TABLE `session` (
	`id` text PRIMARY KEY,
	`user_id` text NOT NULL,
	`token` text NOT NULL UNIQUE,
	`expires_at` integer NOT NULL,
	`ip_address` text,
	`user_agent` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	CONSTRAINT `fk_session_user_id_user_id_fk` FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON DELETE CASCADE
);--> statement-breakpoint
CREATE TABLE `user` (
	`id` text PRIMARY KEY,
	`name` text NOT NULL,
	`email` text NOT NULL UNIQUE,
	`email_verified` integer DEFAULT false NOT NULL,
	`image` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL
);--> statement-breakpoint
CREATE TABLE `verification` (
	`id` text PRIMARY KEY,
	`identifier` text NOT NULL,
	`value` text NOT NULL,
	`expires_at` integer NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL
);--> statement-breakpoint
CREATE INDEX `account_user_id_idx` ON `account` (`user_id`);--> statement-breakpoint
CREATE INDEX `session_user_id_idx` ON `session` (`user_id`);--> statement-breakpoint

-- Flat credential registry for the runner vault.
--
-- Metadata and the encrypted value live in the same row but are separate
-- columns: no query that lists credentials ever selects value_encrypted / value_iv.
-- A credential is usable by a runner only when status = 'active' AND visible = 1
-- AND (expires_at IS NULL OR expires_at > now); that rule is enforced in code
-- (lib/credential-policy.ts) and mirrored by the registry listing query.

CREATE TABLE `credential` (
	`id` text PRIMARY KEY,
	`name` text NOT NULL UNIQUE CHECK (`name` GLOB '[A-Z][A-Z0-9_]*' AND length(`name`) BETWEEN 2 AND 64),
	`service` text NOT NULL CHECK (length(`service`) BETWEEN 1 AND 80),
	`purpose` text NOT NULL CHECK (length(`purpose`) <= 500),
	`token_type` text NOT NULL DEFAULT '' CHECK (length(`token_type`) <= 120),
	`status` text NOT NULL DEFAULT 'pending' CHECK (`status` IN ('pending', 'active', 'disabled')),
	`visible` integer NOT NULL DEFAULT 0 CHECK (`visible` IN (0, 1)),
	`lifetime` text NOT NULL DEFAULT 'temporary' CHECK (`lifetime` IN ('permanent', 'temporary')),
	`delivery` text NOT NULL DEFAULT 'proxy' CHECK (`delivery` IN ('proxy', 'inject')),
	-- JSON array of exact hostnames the proxy may call. Set or confirmed by the owner only.
	`allowed_hosts` text NOT NULL DEFAULT '[]',
	-- 1 = metadata-only entry (e.g. GITHUB_TOKEN already managed elsewhere); never holds a value.
	`externally_managed` integer NOT NULL DEFAULT 0 CHECK (`externally_managed` IN (0, 1)),
	`validation` text NOT NULL DEFAULT 'not_tested' CHECK (`validation` IN ('not_tested', 'valid', 'invalid', 'insufficient_permissions')),
	-- Model-prepared setup documentation (sanitized JSON, see lib/credential-docs.ts).
	`doc_json` text NOT NULL DEFAULT '{}',
	`value_encrypted` text,
	`value_iv` text,
	`key_version` integer NOT NULL DEFAULT 1,
	`auth_header` text NOT NULL DEFAULT 'Authorization' CHECK (length(`auth_header`) BETWEEN 1 AND 64),
	`auth_scheme` text NOT NULL DEFAULT 'Bearer' CHECK (`auth_scheme` IN ('Bearer', 'Token', 'Raw')),
	`expires_at` integer,
	`last_used_at` integer,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	CHECK (`externally_managed` = 0 OR (`value_encrypted` IS NULL AND `value_iv` IS NULL)),
	CHECK ((`value_encrypted` IS NULL) = (`value_iv` IS NULL)),
	CHECK (`status` <> 'active' OR `externally_managed` = 1 OR `value_encrypted` IS NOT NULL)
);--> statement-breakpoint
CREATE INDEX `credential_status_idx` ON `credential` (`status`);--> statement-breakpoint

-- One-time, short-lived links the owner opens in a browser to register or edit a
-- credential. Only the SHA-256 of the token is stored; the link itself is shown once.
CREATE TABLE `enrollment_link` (
	`id` text PRIMARY KEY,
	`credential_id` text NOT NULL,
	`kind` text NOT NULL CHECK (`kind` IN ('register', 'edit')),
	`token_hash` text NOT NULL UNIQUE,
	`expires_at` integer NOT NULL,
	`used_at` integer,
	`requested_by` text NOT NULL DEFAULT '' CHECK (length(`requested_by`) <= 200),
	`created_at` integer NOT NULL,
	CONSTRAINT `fk_enrollment_link_credential_id_credential_id_fk` FOREIGN KEY (`credential_id`) REFERENCES `credential`(`id`) ON DELETE CASCADE
);--> statement-breakpoint
CREATE INDEX `enrollment_link_credential_id_idx` ON `enrollment_link` (`credential_id`);--> statement-breakpoint

-- Append-only audit trail written by the Worker itself. Rows never contain secret
-- values, authorization headers or request bodies. `actor` is who the Worker saw
-- (owner session or authenticated runner); anything a runner merely *reports* is
-- stored in `reported_result` and is never treated as fact.
CREATE TABLE `credential_audit` (
	`id` text PRIMARY KEY,
	`at` integer NOT NULL,
	`credential_id` text,
	`credential_name` text NOT NULL DEFAULT '',
	`action` text NOT NULL CHECK (length(`action`) <= 60),
	`actor` text NOT NULL CHECK (length(`actor`) <= 200),
	`request_id` text NOT NULL DEFAULT '',
	`purpose` text NOT NULL DEFAULT '' CHECK (length(`purpose`) <= 500),
	`result` text NOT NULL DEFAULT '' CHECK (length(`result`) <= 60),
	`reported_result` text NOT NULL DEFAULT '' CHECK (length(`reported_result`) <= 500),
	`detail` text NOT NULL DEFAULT '' CHECK (length(`detail`) <= 500)
);--> statement-breakpoint
CREATE INDEX `credential_audit_at_idx` ON `credential_audit` (`at`);--> statement-breakpoint
CREATE INDEX `credential_audit_credential_idx` ON `credential_audit` (`credential_id`);--> statement-breakpoint
CREATE TRIGGER `credential_audit_no_update` BEFORE UPDATE ON `credential_audit`
BEGIN SELECT RAISE(ABORT, 'credential_audit is append-only'); END;--> statement-breakpoint
CREATE TRIGGER `credential_audit_no_delete` BEFORE DELETE ON `credential_audit`
BEGIN SELECT RAISE(ABORT, 'credential_audit is append-only'); END;;--> statement-breakpoint

-- Small key/value settings owned by the vault itself (e.g. runner_revoked_before).
CREATE TABLE `vault_setting` (
	`key` text PRIMARY KEY CHECK (length(`key`) BETWEEN 1 AND 64),
	`value` text NOT NULL CHECK (length(`value`) <= 500),
	`updated_at` integer NOT NULL
);;--> statement-breakpoint

CREATE UNIQUE INDEX `enrollment_link_one_unused_per_credential_kind_idx`
ON `enrollment_link` (`credential_id`, `kind`)
WHERE `used_at` IS NULL;
