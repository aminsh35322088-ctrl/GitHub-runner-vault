ALTER TABLE `org` ADD COLUMN `auto_join_domain` text;
CREATE INDEX `org_auto_join_domain_idx` ON `org` (`auto_join_domain`);
