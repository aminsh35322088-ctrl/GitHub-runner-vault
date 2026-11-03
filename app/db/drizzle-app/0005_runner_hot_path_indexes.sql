-- Cover the runner's credential registry and rate-limit lookup paths.
CREATE INDEX credential_runner_registry_idx ON credential (status, visible, name);
--> statement-breakpoint
CREATE INDEX credential_audit_credential_at_idx ON credential_audit (credential_id, at);
--> statement-breakpoint
CREATE INDEX credential_audit_name_at_idx ON credential_audit (credential_name, at);
--> statement-breakpoint
CREATE INDEX credential_audit_action_at_idx ON credential_audit (action, at);
--> statement-breakpoint
CREATE INDEX credential_audit_action_name_at_idx ON credential_audit (action, credential_name, at);
