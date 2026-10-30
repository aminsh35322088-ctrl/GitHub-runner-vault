CREATE TABLE `member_access` (
  `id` text PRIMARY KEY NOT NULL,
  `org_member_id` text NOT NULL REFERENCES `org_member`(`id`) ON DELETE CASCADE,
  `project_id` text NOT NULL REFERENCES `project`(`id`) ON DELETE CASCADE,
  `restricted_secrets` text,
  `created_at` integer NOT NULL,
  `updated_at` integer NOT NULL
);
CREATE UNIQUE INDEX `member_access_member_project_unique` ON `member_access` (`org_member_id`, `project_id`);
CREATE INDEX `member_access_org_member_id_idx` ON `member_access` (`org_member_id`);
CREATE INDEX `member_access_project_id_idx` ON `member_access` (`project_id`);
