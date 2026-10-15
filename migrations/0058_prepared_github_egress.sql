-- Recognize a freshly consented, Agent-isolated repository metadata grant. No rows or grants are rewritten.
CREATE FUNCTION occ.egress_source_is_valid(value jsonb, owner_namespace text, owner_source text)
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT occ.static_egress_source_is_valid(value, owner_namespace, owner_source) OR COALESCE(
    jsonb_typeof(value) = 'object'
    AND value ?& fields AND value - fields = '{}'::jsonb
    AND value->'schemaVersion' = '2'::jsonb AND value->>'adoption' = 'prepared' AND value->>'retention' = 'none'
    AND value->>'origin' ~ '^https://[a-z0-9.-]+(:[0-9]+)?$'
    AND jsonb_typeof(key) = 'object' AND key ?& keys AND key - keys = '{}'::jsonb
    AND key->>'installationId' ~ '^ins_[0-9a-f-]{36}$'
    AND key->>'namespaceId' = owner_namespace AND key->'source'->>'id' = owner_source
    AND occ.egress_ref_is_valid(key->'source') AND occ.egress_ref_is_valid(key->'backend')
    AND key->'provider' = '{"id":"github-app-metadata","generation":1}'::jsonb
    AND occ.egress_ref_is_valid(value->'sender') AND occ.egress_ref_is_valid(value->'resolver')
    AND jsonb_typeof(grant_value) = 'object' AND grant_value ?& grants AND grant_value - grants = '{}'::jsonb
    AND grant_value->>'kind' = 'github_repository_metadata' AND grant_value->>'profile' = 'metadata-read'
    AND grant_value->>'appId' ~ '^[1-9][0-9]*$' AND grant_value->>'installationId' ~ '^[1-9][0-9]*$'
    AND grant_value->>'repositoryId' ~ '^[1-9][0-9]*$'
    AND grant_value->>'repository' ~ '^[a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+$'
    AND grant_value->>'repository' !~ '/[.]{1,2}$'
    AND grant_value->>'isolationId' ~ '^agt_[0-9a-f-]{36}$',
    false)
  FROM (SELECT value->'key' AS key, value->'grant' AS grant_value,
    ARRAY['key','schemaVersion','adoption','retention','sender','resolver','origin','grant'] AS fields,
    ARRAY['installationId','namespaceId','source','backend','provider'] AS keys,
    ARRAY['kind','appId','installationId','repositoryId','repository','isolationId','profile'] AS grants) source
$$;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION occ.egress_source_is_valid(jsonb, text, text) TO occ_app;
--> statement-breakpoint
ALTER TABLE occ.credential_sources DROP CONSTRAINT credential_sources_egress_valid,
  ADD CONSTRAINT credential_sources_egress_valid CHECK (egress IS NULL OR occ.egress_source_is_valid(egress, namespace_id, id));
