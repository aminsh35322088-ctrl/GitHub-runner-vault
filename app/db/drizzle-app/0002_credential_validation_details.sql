-- Store only the sanitized token inspection result; token values remain write-only.
ALTER TABLE credential ADD COLUMN validation_details text;
