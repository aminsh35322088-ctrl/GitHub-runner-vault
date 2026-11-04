-- Pre-verification session attempts get their own rate-limit scope, so a flood
-- of invalid OIDC tokens can be bounded per client IP before any audit row is
-- written. SQLite cannot alter a CHECK constraint, so the table is rebuilt with
-- the extended scope list; rows and indexes are carried over.
CREATE TABLE runner_rate_limit_event_new (
  id text PRIMARY KEY NOT NULL,
  scope text NOT NULL CHECK (scope IN ('session', 'session_attempt', 'registration', 'proxy')),
  subject text NOT NULL CHECK (length(subject) BETWEEN 1 AND 160),
  credential_id text,
  created_at integer NOT NULL,
  CONSTRAINT fk_runner_rate_limit_event_credential
    FOREIGN KEY (credential_id) REFERENCES credential(id) ON DELETE CASCADE
);
--> statement-breakpoint
INSERT INTO runner_rate_limit_event_new (id, scope, subject, credential_id, created_at)
  SELECT id, scope, subject, credential_id, created_at FROM runner_rate_limit_event;
--> statement-breakpoint
DROP TABLE runner_rate_limit_event;
--> statement-breakpoint
ALTER TABLE runner_rate_limit_event_new RENAME TO runner_rate_limit_event;
--> statement-breakpoint
CREATE INDEX runner_rate_limit_event_scope_subject_at_idx
  ON runner_rate_limit_event (scope, subject, created_at);
--> statement-breakpoint
CREATE INDEX runner_rate_limit_event_created_at_idx
  ON runner_rate_limit_event (created_at);
