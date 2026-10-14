---
rfc: index.md
---

# Proposed source migration and legacy disposition

[RFC-0020](index.md) changes the default for *new* static sources. It must not silently give an
existing source’s Secret writer authority to replace the credential an Agent uses. This is the
required cutover and retirement contract, not a migration that has already run.

## Preserve approved static material

Suppose an operator approved `v1` and a Secret writer later stored `v2`. Migrate that source in
`explicit_update` mode, pinned to approved `v1` or an owned immutable snapshot of it. Reading the
latest Secret would select the wrong credential. If the approved material cannot be recovered or its
ownership verified, fail closed and require an authorized source update. Keep running attachments on
their approved material until replacement installation is verified.

To opt an existing source into live adoption:

1. Require `credential_source:update` on the exact source and `secret:operate` on the selected live
   Secret. Consumer permission cannot approve replacement.
2. Stage a separate candidate; validate material access and replacement attachments. Do not
   overwrite the approved snapshot or stop a working Agent to test the candidate.
3. Activate mode, material reference and source generation together. Carry all three through
   projections, attachments, Resolver evidence and cache keys. Refusal or failure before cutover
   leaves the prior approved admission active.
4. If activation is uncertain, inspect the durable cutover record and reconcile partial effects
   under that attempt. Do not assume rollback or let a late completion activate a superseded
   candidate.

“Keep the prior admission” does not override an operation denial or known revocation. Every use
still needs both current checks. New sources default to live adoption; a mutable reference with a
longer TTL cannot implement explicit update. A general promotion framework is unnecessary for this
cutover. Optional explicit promotion remains
[#1965](https://github.com/openclaw/openclaw-enterprise/issues/1965).

For a *version* target, the matching Secret Driver serves that exact approved version. For a
*snapshot*, its admitted owner serves the immutable value and version; the SecretRef records origin
and need not still exist or be readable. Keep references within the source’s Installation and
Namespace. Preserve the origin/version revocation association across eviction and reread. If the
selected store is unavailable, fail or use only eligible retained material; never substitute the
provenance store or its latest value.

[Read bounds](lifecycle.md#live-secret-cutover) begin at an authoritative read, not snapshot
approval. Set `authoritativeObservedAt` on success; retained results keep that timestamp. Zero
retention means read the approved snapshot again, not delete it.

Before retiring an old provider key, verify adoption where requests are served and account
separately for outstanding use. A storage write proves neither. Accepted cleanup survives loss of
source-use rights.

## Legacy methods and consumers

Retire the legacy capability after the migration and parity work below. Preserve
these original eight methods' responsibilities from the
[pinned legacy contract](https://github.com/openclaw/openclaw-enterprise/blob/4c3952b15caad45a43b0144e185d54be0e040f1f/packages/contracts/src/index.ts#L1325-L1355):

| Legacy method       | Successor                                                                                                                       |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `listSourceTypes`   | `CredentialSourceControl.describeTypes`                                                                                         |
| `registerSource`    | `applySource`, then separately `configureRefresh` for dynamic inputs                                                            |
| `updateSource`      | `applySource` for admitted configuration and approved static replacement/opt-in; Secret reads follow the admitted adoption mode |
| `sourceStatus`      | `sourceStatus`; separate per-grant `refreshStatus`                                                                              |
| `removeSource`      | `removeSource` plus `removeRefresh`, retaining provider/profile cleanup                                                         |
| `attachForRevision` | `EgressProxyDriver.configureRevision` → Sandbox `installEgress`                                                                 |
| `attachmentStatus`  | Egress `attachmentStatus` joined to Sandbox `egressStatus`                                                                      |
| `withdraw`          | OCC durable withdrawal → `withdrawBinding`, including late-create rechecks                                                      |

The [current interface](../../../packages/contracts/src/index.ts) also requires
`validateSourceConfig`. Preserve its pre-Secret-read, no-I/O validation through
OCC schema validation and the provider's `normalizeInput` before admission/effects;
do not remove it when retiring the original eight methods.

| Existing consumer or record                                                                               | Required destination/parity                                                                                                                                                                                                                                               |
| --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Source `driverId` / persisted `driver_id`; revision `credentialGatewayId` in source and Harness snapshots | SourceKey, Binding and Route generations; preserve immutable revision admission and re-resolve current authority at dispatch.                                                                                                                                             |
| Source reference, metadata, states, field/type catalog                                                    | Retain Namespace identity, safe metadata and registration/deletion uncertainty; describe schema/version, rotation and Harness compatibility. Preserve `openai`, `bearer-token`, `oauth2-client-credentials`, `oauth2-refresh-token` semantics through admitted providers. |
| `{sourceId}` Agent binding; Harness authentication selection                                              | Extend to exact binding/grant/route snapshot. Preserve source selection, model compatibility and placeholder clients; no fallback to projected model Secrets.                                                                                                             |
| `CredentialSourceInput`, Gateway contexts and attachments                                                 | Replace resolved-string bags with Source/Command and lifecycle-only roots; replace `{sourceId, ref}` and Sandbox `credentialAttachments` with authenticated Attachment/receipt.                                                                                           |
| Configuration capability, Backend pairing, registration, exports and package validation                   | Compose source facet, `egress_proxy`, retained Sandbox/Secret/refresh, provider registry, Resolver and Authorizer. Remove `credential_gateway` selection and old imports after parity. No alias retaining the old interface.                                              |
| OCC source HTTP APIs, audit/IAM, console/setup tools, generated schemas                                   | Preserve create/list/get/update/rotate/delete/withdraw/status and denial-before-existence behavior; update safe status composition and generation admission. No material export.                                                                                          |
| Worker, Compute, maintenance, withdrawals and companion revisions                                         | Retain durable requester attribution, suppression/rechecks after late create, pending cleanup and exact receipts. Withdrawn required model binding blocks startup; optional tool binding may be omitted.                                                                  |
| Persistence repositories/adapters/constraints, source-copy utilities                                      | Migrate records and outstanding attempts together; preserve historical migrations. Source recreation remains distinct from authority-free deep forks.                                                                                                                     |
| Refresh and native OAuth seed delivery                                                                    | Remove all Gateway type coupling; transfer family custody explicitly from old seed/Harness state before starting the one owner.                                                                                                                                           |
| Repo discovery/profiles/grants/sessions and bootstrap                                                     | Retain Repo ownership; Compute/bootstrap own optional clone gate, deadlines and partial-workspace cleanup.                                                                                                                                                                |
| Proposed #1785 `withSourceToken` (may prepare)                                                            | Trusted Forwarder library inside OCC owns the business send; management authorizes preparation; use lifecycle `prepare`, then Resolver/Forwarder with post-preparation check. Not a runtime resolver method.                                                              |

### Earlier Token Service proposal

[PR #924](https://github.com/openclaw/openclaw-enterprise/pull/924) supplied issuer
metadata, normalized grants, scope/expiry validation, distinct issuer/consumer
duties, discovery, uncertainty and cleanup. Retain those requirements with
background preparation and warm-only requests, separately authorized management,
central or delegated custody and durable rotating state. Do not restore
demand-driven Agent issuance, memory-only rotating inputs or an indefinite Agent
bearer. [#1691](https://github.com/openclaw/openclaw-enterprise/pull/1691) describes
narrower refresh composition. Standalone packaging and Git-hook/`pushRefAllowlist`
removal remain historical/separate work; neither proposal is thereby accepted.
The [original design](https://github.com/openclaw/openclaw-enterprise/tree/55e261623e6ba879eab1e2d27daa309d571a994a/specs/rfcs/0056-token-service)
preserves its rationale.

### Successor caller flows

Use these paths to check that the migration preserved what each caller can do.

- **Static inference.** OCC `applySource` admits live or approved immutable material. Compute
  `configureRevision` and Sandbox `installEgress` install the binding. `capture` classifies
  inference; `forward` checks access, resolves through `readCredentialInput` or eligible retention,
  checks the selected version, sends and protects the response.
- **GitHub.** OCC admits repository IDs and permissions, then `configureRefresh`. In the background
  OpenShell calls the OCE issuer; OCE exchanges and validates the token; OpenShell commits it. On
  each operation, check access, resolve through `readWarm`, check again, send. Cold returns
  `not_ready` without preparation.
- **Optional clone.** Compute observes the exact attachment, `refreshStatus` and bounded required
  readiness, then delegates the repository and execution to bootstrap. Bootstrap uses `capture` and
  `forward` for each clone operation and returns
  [completion evidence](lifecycle.md#2-prepare-the-optional-repository). Compute owns the gate and
  cleanup.
- **Management discovery.** OCC authenticates caller and user, captures the business operation and
  obtains its preparation Permit before access. `prepare`, inspect or reconcile if necessary, then
  `forward` inside OCC. Check before the warm read and again with the selected material after
  preparation. Return sanitized metadata. The owner separately authorizes issuer calls.

Cutover must reconcile owned providers, catalog changes, running attachments and
uncertain cleanup, then disable legacy reattachment/refresh paths. Retire exports,
composition and persistence coupling only after consumer migration and adapter
parity. This permits a temporary adapter, not indefinite compatibility or a
cosmetic rename. [Lifecycle qualification](lifecycle.md#implementation-discovery-and-qualification)
owns the remaining proof.
