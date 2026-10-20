ALTER TABLE occ.agents ADD COLUMN gateway_managed_mode boolean NOT NULL DEFAULT true;
--> statement-breakpoint
GRANT UPDATE (gateway_managed_mode) ON occ.agents TO occ_app;
--> statement-breakpoint
-- Previously deployed Gateways did not receive the managed-mode bundle.
ALTER TABLE occ.agent_revisions ADD COLUMN gateway_managed_mode boolean NOT NULL DEFAULT false;
--> statement-breakpoint
ALTER TABLE occ.agent_revisions ALTER COLUMN gateway_managed_mode DROP DEFAULT;
