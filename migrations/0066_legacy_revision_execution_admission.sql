-- Revisions admitted before 0058 carry no execution admission. That release neither
-- authenticated nor governed their direct requests, which is exactly the unprotected
-- mode. 0058 left them without a decision, so after an upgrade the application reader
-- refused every pre-existing Agent: createRevision decodes the earlier revisions, and
-- the worker's reconcile, stop, retire and delete paths all read them, so no new
-- revision could even replace them. Record the decision they were admitted under.
-- It grants nothing: unprotected refuses managed routes, bindings and preparation.
-- A snapshot that already carries a decision, an egress plan or the protected reader
-- marker is never relabeled; validation then proves every stored row carries one
-- consistent decision, or the whole upgrade fails and the ledger stays unchanged.
DROP TRIGGER agent_revisions_are_immutable ON occ.agent_revisions;
--> statement-breakpoint
UPDATE occ.agent_revisions
SET admitted_spec = admitted_spec || '{"execution_admission":{"version":2,"mode":"unprotected"}}'::jsonb
WHERE NOT (admitted_spec ? 'execution_admission')
  AND NOT (admitted_spec ? 'egress_plan')
  AND NOT ((admitted_spec->'harness_auth') ? 'protectedExecutionVersion');
--> statement-breakpoint
CREATE TRIGGER agent_revisions_are_immutable
BEFORE UPDATE ON occ.agent_revisions
FOR EACH ROW EXECUTE FUNCTION occ.reject_row_mutation();
--> statement-breakpoint
ALTER TABLE occ.agent_revisions VALIDATE CONSTRAINT agent_revisions_execution_admission;
