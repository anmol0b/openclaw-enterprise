---
rfc: index.md
---

# Proposed source migration and legacy disposition

This companion to [RFC-0020](index.md) preserves approved material and maps
`CredentialGatewayDriver` consumers to the proposed contracts. It specifies
required cutover behavior, not an implemented migration procedure.

## Preserve approved static material

Migration retains each existing source's `explicit_update` mode and approved
immutable value/version or owned snapshot. It must preserve the material actually
approved, not read the latest value from the recorded SecretRef. If that material
cannot be recovered or its ownership verified, fail closed and require an
authorized source update. Preserve running attachments' approved material until
replacement installation is verified; migration cannot silently expand a Secret
writer's authority.

An operator with exact `credential_source:update` and `secret:operate` on the
selected live Secret may explicitly opt in. Validate a separate candidate's
material access and replacement attachments before activating its mode,
reference and source generation together. Carry them through projections,
attachments, Resolver evidence and cache keys; do not overwrite the approved
snapshot or stop a working Agent before replacement validation. Keep the prior
approved admission active until durable cutover; refused or failed opt-in
preserves it. An uncertain activation requires inspection of that durable record,
not an assumption of rollback. Reconcile partial effects under the recorded
attempt; late completion cannot activate a superseded candidate.

Existing operations still need both current checks. Operation denial or known
revocation cannot fall back to old material; consumer permission never approves
replacement.

New sources default to live adoption. Existing explicit updates still select
approved immutable material; a mutable SecretRef with a longer TTL is not an
implementation. This preserves the existing source-update boundary without a
general promotion framework. Optional explicit promotion remains
[#1965](https://github.com/openclaw/openclaw-enterprise/issues/1965).

A snapshot's admitted owner stores and serves its immutable value/version. The
recorded SecretRef preserves origin; its latest value, availability or current
existence is not needed to read that snapshot. Version targets instead read the
exact approved version from their matching Secret Driver. Preserve origin/version
associations so known revocation of the approved material still denies use,
including after reread or cache eviction; a provenance-only change does not
approve replacement. All references remain in the source's Installation/Namespace.
An inaccessible selected store fails or uses only eligible retained material;
never substitute the provenance store or mutable latest value.

Snapshot creation/approval time is not serving-cache age. A successful
authoritative read of that snapshot establishes `authoritativeObservedAt`;
retained results keep it. Zero retention requires another authoritative read,
not deletion of the approved snapshot. [Read bounds](lifecycle.md#live-secret-cutover)
still constrain retained reads in either mode.

A storage update alone does not prove universal adoption or permit retirement
of an old provider key. Confirm serving adoption and outstanding use separately;
accepted cleanup survives loss of source-use rights.

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

These sequences show how migrated callers use the proposed contracts.

| Caller               | Named API sequence and observable result                                                                                                                                                                                                                                                                                                                   |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Static inference     | OCC `applySource` admits adoption mode and live or approved immutable material; Compute `configureRevision` → Sandbox `installEgress`. `capture` classifies inference; `forward` uses check 1 → `resolve` → `readCredentialInput`/eligible retention → check 2 → injection and safe response.                                                              |
| Scoped GitHub        | OCC admits repository IDs/permissions and `configureRefresh`. In the background, OpenShell calls the OCE issuer; OCE exchanges and validates the token; OpenShell commits it. Each captured operation uses fresh check 1 → `resolve`/`readWarm` → fresh check 2 → send. Cold returns `not_ready` without preparation.                                      |
| Optional clone       | Compute observes exact attachment, `refreshStatus` and bounded required readiness; issues repository/execution delegation to bootstrap. Bootstrap uses `capture`/`forward` for every clone operation and returns [completion evidence](lifecycle.md#2-prepare-the-optional-repository). Compute owns the startup gate and cleanup.                         |
| Management discovery | OCC authenticates caller/user, captures the business operation and obtains its preparation Permit before access; `prepare` → inspect/reconcile if needed → in-process `forward` → fresh check 1 → warm resolve → check 2 after preparation → business provider send. Return sanitized metadata. Issuer's provider calls have separate owner authorization. |

Cutover must reconcile owned providers, catalog changes, running attachments and
uncertain cleanup, then disable legacy reattachment/refresh paths. Retire exports,
composition and persistence coupling only after consumer migration and adapter
parity. This permits a temporary adapter, not indefinite compatibility or a
cosmetic rename. [Lifecycle qualification](lifecycle.md#implementation-discovery-and-qualification)
owns the remaining proof.
