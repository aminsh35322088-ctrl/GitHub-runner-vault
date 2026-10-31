-- Proxy-only delivery: legacy inject entries cannot be used by the runner.
-- Preserve encrypted bytes for owner-managed review, but disable and hide them.
UPDATE "credential"
SET "status" = 'disabled', "visible" = 0, "delivery" = 'proxy'
WHERE "delivery" = 'inject' AND "externally_managed" = 0;--> statement-breakpoint

-- Metadata-only external records do not need a separate delivery mode either.
UPDATE "credential"
SET "delivery" = 'proxy'
WHERE "delivery" = 'inject' AND "externally_managed" = 1;--> statement-breakpoint

-- Retain only the newest unused link for each credential/kind pair before
-- enforcing the invariant at the database layer.
UPDATE "enrollment_link" AS old
SET "used_at" = "created_at"
WHERE "used_at" IS NULL
  AND EXISTS (
    SELECT 1 FROM "enrollment_link" AS newer
    WHERE newer."credential_id" = old."credential_id"
      AND newer."kind" = old."kind"
      AND newer."used_at" IS NULL
      AND (newer."created_at" > old."created_at"
        OR (newer."created_at" = old."created_at" AND newer."id" > old."id"))
  );--> statement-breakpoint

CREATE UNIQUE INDEX "enrollment_link_one_unused_per_credential_kind_idx"
ON "enrollment_link" ("credential_id", "kind")
WHERE "used_at" IS NULL;
