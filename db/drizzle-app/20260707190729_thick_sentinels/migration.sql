ALTER TABLE `org` ADD `auto_join_domain` text;--> statement-breakpoint
CREATE INDEX `org_auto_join_domain_idx` ON `org` (`auto_join_domain`);