-- Move access role from secret_event to environment.
-- Environments (like production) can be restricted to admins only.

-- Add accessRole to environment
ALTER TABLE `environment` ADD COLUMN `access_role` text NOT NULL DEFAULT 'member';

-- Drop accessRole from secret_event (no longer needed, secrets inherit from env)
ALTER TABLE `secret_event` DROP COLUMN `access_role`;
