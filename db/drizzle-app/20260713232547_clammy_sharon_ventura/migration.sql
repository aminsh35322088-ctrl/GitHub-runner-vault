CREATE TABLE `member_access` (
	`id` text PRIMARY KEY,
	`org_member_id` text NOT NULL,
	`project_id` text NOT NULL,
	`restricted_secrets` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	CONSTRAINT `fk_member_access_org_member_id_org_member_id_fk` FOREIGN KEY (`org_member_id`) REFERENCES `org_member`(`id`) ON DELETE CASCADE,
	CONSTRAINT `fk_member_access_project_id_project_id_fk` FOREIGN KEY (`project_id`) REFERENCES `project`(`id`) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE UNIQUE INDEX `member_access_member_project_unique` ON `member_access` (`org_member_id`,`project_id`);--> statement-breakpoint
CREATE INDEX `member_access_org_member_id_idx` ON `member_access` (`org_member_id`);--> statement-breakpoint
CREATE INDEX `member_access_project_id_idx` ON `member_access` (`project_id`);