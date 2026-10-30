-- Drop restrictedSecrets from member_access (SQLite doesn't support DROP COLUMN
-- before 3.35.0, but D1 uses a recent SQLite version that supports it)
ALTER TABLE `member_access` DROP COLUMN `restricted_secrets`;

-- Add accessRole to secret_event: minimum role needed to read this secret's value
ALTER TABLE `secret_event` ADD COLUMN `access_role` text NOT NULL DEFAULT 'member';

-- Add projectIds to org_invitation: JSON array of project IDs for scoped invites
ALTER TABLE `org_invitation` ADD COLUMN `project_ids` text;
