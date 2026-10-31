-- How the proxy presents the stored value to the upstream API. Owner-controlled.
-- Default matches the common `Authorization: Bearer <token>` convention.
ALTER TABLE `credential` ADD `auth_header` text NOT NULL DEFAULT 'Authorization' CHECK (length(`auth_header`) BETWEEN 1 AND 64);--> statement-breakpoint
ALTER TABLE `credential` ADD `auth_scheme` text NOT NULL DEFAULT 'Bearer' CHECK (`auth_scheme` IN ('Bearer', 'Token', 'Raw'));
