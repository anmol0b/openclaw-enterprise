-- Private precursor: the integration owner applies this through the canonical
-- migration journal. This fragment creates no alternate migration path.
CREATE TABLE occ.egress_send_receipts (
  sender_id text NOT NULL CHECK (length(sender_id) > 0),
  sender_generation bigint NOT NULL CHECK (sender_generation > 0),
  use_id text NOT NULL CHECK (length(use_id) > 0),
  attempt_id text NOT NULL CHECK (length(attempt_id) > 0),
  binding jsonb NOT NULL CHECK (jsonb_typeof(binding) = 'object'),
  outcome jsonb NOT NULL CHECK (jsonb_typeof(outcome) = 'object'),
  settled boolean NOT NULL DEFAULT false,
  feedback text CHECK (feedback = 'fenced'),
  PRIMARY KEY (sender_id, sender_generation, use_id, attempt_id),
  CHECK ((binding->'sender'->>'id' = sender_id
      AND (binding->'sender'->>'generation')::bigint = sender_generation
      AND binding->>'useId' = use_id AND binding->>'attemptId' = attempt_id
      AND length(binding->>'deadlineAt') > 0
      AND jsonb_typeof(binding->'material') IN ('object', 'null')) IS TRUE),
  CHECK ((
    (outcome->>'kind' = 'refused' AND outcome->'dispatched' = 'false'::jsonb AND settled)
    OR (outcome->>'kind' IN ('response', 'provider_rejected', 'response_blocked')
        AND outcome->>'dispatch' = 'confirmed' AND settled)
    OR (outcome->>'kind' = 'uncertain' AND outcome->>'dispatch' = 'possible')
  ) IS TRUE),
  CHECK (outcome->>'kind' <> 'provider_rejected' OR feedback IS NOT DISTINCT FROM 'fenced'),
  CHECK (outcome->>'kind' <> 'response_blocked' OR (outcome->>'code' = 'response_policy') IS TRUE),
  CHECK (outcome->>'kind' NOT IN ('response', 'provider_rejected')
    OR ((outcome->>'status')::integer BETWEEN 100 AND 599) IS TRUE),
  CHECK (feedback IS NULL OR (settled AND outcome->>'dispatch' = 'confirmed'
    AND binding->'material'->>'kind' = 'static') IS TRUE)
);

GRANT SELECT, INSERT, UPDATE (outcome, settled, feedback) ON occ.egress_send_receipts TO occ_app;
