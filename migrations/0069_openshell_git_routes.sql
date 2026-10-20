-- A revision's OpenShell Git route as the worker that prepared it last verified it: the
-- identity and custody facts a restarted or replacement worker needs to re-observe the
-- installation and re-adopt the route instead of requiring a new revision (finding 2128).
-- Never token material: the material is read again from prepared custody through the
-- normal preparation path. `fence` names the adoption; every write by the worker that
-- holds a route carries its fence, so a worker whose fence is stale writes nothing and
-- stops using the route. `write_pending` outlives a worker that stopped mid-write: the
-- outcome of that provider write is unknown, and the next worker tombstones the route.
-- `blocked` is the tombstone; a blocked route is never adopted again.
CREATE TABLE occ.openshell_git_routes (
  revision_id text PRIMARY KEY REFERENCES occ.agent_revisions(id) ON DELETE CASCADE,
  namespace_id text NOT NULL,
  agent_id text NOT NULL,
  workspace text NOT NULL,
  sandbox text NOT NULL,
  binding_id text NOT NULL CHECK (binding_id ~ '^[A-Za-z0-9_-]{32}$'),
  fence bigint NOT NULL DEFAULT 1 CHECK (fence >= 1),
  worker_instance uuid NOT NULL,
  adopted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  provider_id text,
  profile_version text CHECK (profile_version ~ '^[1-9][0-9]*$'),
  provider_resource_version text CHECK (provider_resource_version ~ '^[1-9][0-9]*$'),
  credential_state text CHECK (credential_state IN ('bootstrap', 'active')),
  material_expires_at timestamptz,
  material_version uuid,
  preparation_attempt_id uuid,
  observed jsonb,
  write_pending text CHECK (write_pending IN ('bootstrap', 'rotate')),
  blocked text,
  CHECK ((provider_id IS NULL) = (profile_version IS NULL)
    AND (provider_id IS NULL) = (provider_resource_version IS NULL)
    AND (provider_id IS NULL) = (credential_state IS NULL)),
  CHECK ((credential_state = 'active') = (material_expires_at IS NOT NULL)),
  CHECK ((material_version IS NULL) = (preparation_attempt_id IS NULL)),
  CHECK (observed IS NULL OR (jsonb_typeof(observed) = 'object'
    AND observed ?& ARRAY['workspace', 'sandbox', 'sandboxId', 'executionId', 'provider',
      'providerId', 'providerResourceVersion', 'profileVersion', 'credentialState',
      'attachmentEpoch', 'providerEnvRevision', 'configRevision', 'policyHash',
      'supervisorSessionId', 'processInstanceId', 'networkInstanceId']
    AND (observed - ARRAY['workspace', 'sandbox', 'sandboxId', 'executionId', 'provider',
      'providerId', 'providerResourceVersion', 'profileVersion', 'credentialState',
      'attachmentEpoch', 'providerEnvRevision', 'configRevision', 'policyHash',
      'supervisorSessionId', 'processInstanceId', 'networkInstanceId']) = '{}'::jsonb))
);
--> statement-breakpoint
CREATE INDEX openshell_git_routes_namespace ON occ.openshell_git_routes (namespace_id);
--> statement-breakpoint
GRANT SELECT, INSERT, UPDATE(fence, worker_instance, adopted_at, updated_at, provider_id,
  profile_version, provider_resource_version, credential_state, material_expires_at,
  material_version, preparation_attempt_id, observed, write_pending, blocked)
ON occ.openshell_git_routes TO occ_app;
