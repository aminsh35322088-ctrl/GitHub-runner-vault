ALTER TABLE `jwks` ADD `expires_at` integer;--> statement-breakpoint
ALTER TABLE `oauth_access_token` ADD `resources` text;--> statement-breakpoint
ALTER TABLE `oauth_client` ADD `jwks` text;--> statement-breakpoint
ALTER TABLE `oauth_client` ADD `jwks_uri` text;--> statement-breakpoint
ALTER TABLE `oauth_consent` ADD `resources` text;--> statement-breakpoint
ALTER TABLE `oauth_refresh_token` ADD `resources` text;