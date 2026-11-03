-- Atomic sliding-window quota reservations for OIDC sessions, registrations and proxy calls.
-- The credential foreign key scopes proxy quota to an immutable credential ID and
-- cascades reservations when that credential is deleted.
CREATE TABLE runner_rate_limit_event (
  id text PRIMARY KEY NOT NULL,
  scope text NOT NULL CHECK (scope IN ('session', 'registration', 'proxy')),
  subject text NOT NULL CHECK (length(subject) BETWEEN 1 AND 160),
  credential_id text,
  created_at integer NOT NULL,
  CONSTRAINT fk_runner_rate_limit_event_credential
    FOREIGN KEY (credential_id) REFERENCES credential(id) ON DELETE CASCADE
);
--> statement-breakpoint
CREATE INDEX runner_rate_limit_event_scope_subject_at_idx
  ON runner_rate_limit_event (scope, subject, created_at);
--> statement-breakpoint
CREATE INDEX runner_rate_limit_event_created_at_idx
  ON runner_rate_limit_event (created_at);
