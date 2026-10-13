---
rfc: index.md
---

# Proposed source and egress management contracts

This companion defines the replacement for `CredentialGatewayDriver`. Names and
shapes are proposed transport-neutral IDL, not implemented exports or a public
configuration format. Tables are closed records: all fields are required unless
marked optional; unknown fields are rejected. Wire encoding may change without
dropping these semantics. [Runtime contracts](runtime-contracts.md) and
[lifecycle contracts](lifecycle.md#lifecycle-interface) share these definitions.

## Identities and admission

| Shape                | Fields and meaning                                                                                                                                                                                                                                                                                                                                                 |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `Id`, `Ref`          | `Id`: immutable opaque string; deletion/recreation gets a new ID. `Ref`: `{id: Id, generation: positive integer}`. Generations increase on configuration change, never material rotation.                                                                                                                                                                          |
| `Scope`, `SourceKey` | `Scope`: `{installationId: Id, namespaceId: Id}`. `SourceKey`: `{scope: Scope, source: Ref, backend: Ref, provider: Ref}`.                                                                                                                                                                                                                                         |
| `Execution`          | `{scope: Scope, agentId: Id, servicePrincipalId: Id, revisionId: Id, executionId: Id}`. OCC assigns the execution; the stable Agent principal is separate.                                                                                                                                                                                                         |
| `Management`         | `{scope: Scope, servicePrincipalId: Id, initiatingPrincipalId: Id, purpose: configuration\|discovery, authorizationId: Id}`; OCC derives this context, not permission to skip current checks.                                                                                                                                                                      |
| `Context`            | `execution{execution: Execution}` or `management{management: Management}`. Route and Binding must carry the same variant and exact context.                                                                                                                                                                                                                        |
| `Bounds`, `Command`  | `Bounds`: `{deadlineAt: UTC timestamp, cancellation: local cancellation signal}`. Cancellation cannot prove remote cancellation. `Command`: bounds plus `requestId: UUID`, `admission: Permit`.                                                                                                                                                                    |
| `Permit`             | Runtime-verifiable OCC reference binding authenticated principal, purpose, exact target refs/generations, action, audience, input digest and expiry. Control action/purpose are constrained below; runtime purposes are defined at their methods. Issued after authorization, never caller assertions.                                                             |
| `SecretRef`          | `{scope: Scope, secretId: Id, secretDriver: Ref}`; exact live Secret identity, not a value or value version.                                                                                                                                                                                                                                                       |
| `Grant`              | Initial closed schemas: `inference` with `models: string[]`; `github` with `appId`, `installationId`, `repositoryIds: nonempty Id[]`, `permissions: {contents: read\|write, metadata: read}`; `oauth` with `audience: string, scopes: string[]`; `api` with `audience: string, operationPolicy: Ref`. Registered extensions follow the typed admission rule below. |
| `Binding`            | `{binding: Ref, context: Context, source: SourceKey, grant: Grant, grantHash: SHA-256, isolationId: Id, requiredForStartup: boolean}`. Canonical sorted/deduplicated grants have no implicit wildcard. Default isolation is per Agent; sharing requires explicit admission.                                                                                        |
| `Route`              | `{route: Ref, context: Context, origin: HTTPS origin, methods: HTTP method[], pathPrefix: string, operationPolicy: Ref, responsePolicy: Ref, use: Binding\|none, grant: Grant, deadlineMs: positive integer}`. Prefix matching is segment-aware; provider classification supplies finer constraints. Credential-free routes still have grants.                     |
| `Custody`            | `{sender: Ref, resolver: Ref, owner: Ref\|none, issuer: Ref\|none}` identifies trusted permitted consumers. Source policy must admit each material transfer.                                                                                                                                                                                                       |

OCC's existing source service owns schema validation, IAM authorization, durable
intent, generations and audit. Trusted Backend composition supplies provider
definitions; requests never choose implementations. Source configuration changes
advance its generation, including input-reference, route-policy or custody changes.
Bindings/routes get new generations when their grant or selection changes. A
live Secret value change preserves configuration generations.

OCC admits management routes and bindings from registered configuration/discovery
operations and current service and initiating-user rights. They have scoped,
versioned refs, an explicit grant and isolation, and a bounded deadline; management
bindings set `requiredForStartup: false`. They need no Agent, execution or Sandbox
attachment. `authorizationId` identifies the operation context, not a cached allow.
Agent/bootstrap cannot select this variant; management cannot borrow an Agent
binding. Shared material reuse still requires explicit isolation admission.

`Source` is `{key: SourceKey, schemaVersion: registered positive integer, custody: Custody, input: Input}`.
`Input` selects one registered closed schema; initial forms are:

| Kind             | Required fields                                                                                                                                                                                                               |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `static`         | `secret: SecretRef`, `cache: none\|bounded{freshMs, totalEligibleAgeMs}`; bounded durations are positive milliseconds, total ≥ fresh. Either public duration set to zero normalizes to `none`. Defaults: 600000 and 14400000. |
| `github-app`     | `appId: Id, installationId: Id, signingKey: SecretRef, familyId: Id`                                                                                                                                                          |
| `oauth-client`   | `tokenEndpoint: HTTPS URL, clientId: string, clientSecret: SecretRef, familyId: Id`                                                                                                                                           |
| `oauth-rotating` | `tokenEndpoint: HTTPS URL, clientId: string, refreshSeed: SecretRef, clientSecret: SecretRef\|none, familyId: Id`                                                                                                             |

Dynamic roots go only to the lifecycle owner/issuer. Generic egress provisioning
receives `SourceProjection`: key, schemaVersion, custody and input kind, with
familyId for dynamic inputs; no Secret/root references. Cross-Namespace references,
unsupported schemas and grants are refused before effects. Bindings may overlap
for explicit selection; capture must select one exact route. Admission refuses
indistinguishable routes within a binding. See [binding selection](runtime-contracts.md#binding-selection).

Provider registration supplies versioned closed Input, Grant and Classification
schemas, validators, normalizers and trusted injection definitions. An admitted
value is typed by `(provider Ref, schemaVersion, kind)`; hooks accept only that
schema's validated result. Custom providers and additional GitHub permissions
extend provider-owned schemas without core provider switches or arbitrary
context bags. SourceProjection preserves this schema identity and only admitted
nonsecret routing fields; Secret/root fields never enter it.

Trusted Backend factories publish an immutable `Composition` record keyed by
backend Ref: `sourceControl: CredentialSourceControl`, registered provider Refs
and schema versions, egress/sandbox/secret Refs, and `lifecycle:
{owner: Ref, refresh: CredentialRefreshDriver, warmReader: WarmCredentialReader,
issuer: CredentialIssuer}|none`. References resolve only to installed facets.
OCC binds SourceKey to this record at admission, checks versions/custody and uses
its facets for status and cleanup even after catalog withdrawal. Composition
changes advance backend generation; requests cannot discover/load plugins.

Illustrative **proposed admission record**, after OCC resolves user-facing names;
this is not accepted public YAML:

```yaml
key:
  scope: { installationId: inst-1, namespaceId: ns-1 }
  source: { id: source-1, generation: 2 }
  backend: { id: openshell-1, generation: 1 }
  provider: { id: github-1, generation: 1 }
schemaVersion: 1
custody:
  sender: { id: sender-1, generation: 1 }
  resolver: { id: resolver-1, generation: 1 }
  owner: { id: lifecycle-1, generation: 1 }
  issuer: { id: github-issuer-1, generation: 1 }
input:
  kind: github-app
  appId: app-1
  installationId: github-installation-1
  familyId: family-1
  signingKey:
    scope: { installationId: inst-1, namespaceId: ns-1 }
    secretId: signing-key-1
    secretDriver: { id: secrets-1, generation: 1 }
```

## Results and recovery

`Error` is `{code}` from this closed set: `unauthorized`, `invalid_input`,
`unsupported`, `stale_generation`, `request_conflict`, `ownership_conflict`,
`references_remaining`, `backend_failed`, `unavailable`, `cancelled`, `deadline_exceeded`.
No provider-controlled text is returned. `Read<T>` is `ok(value: T)` or
`refused(error: Error)`.

`Change<T>` distinguishes acceptance and effect:

| Result                                                                     | Meaning                                                                 |
| -------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| `applied(value: T, operation: Operation)`                                  | Operation applied; applied configuration is not material readiness.     |
| `pending(operation: Operation)`                                            | Accepted work is incomplete.                                            |
| `uncertain(operation: Operation)`                                          | The external outcome is unknown.                                        |
| `failed(operation: Operation, error: Error, cleanup: CleanupObligation[])` | Known failure after acceptance, possibly with partial external effects. |
| `refused(error: Error)`                                                    | No effect accepted.                                                     |

Neither rollback nor a failed result erases cleanup obligations.
`Operation` contains `id`, requestId, target refs, action, exact-input digest,
purpose, owner Ref, attemptId, original deadline, `cleanup: CleanupObligation[]`, and state
`pending|uncertain|applied|failed`, with optional safe Error and completion time.
Applied configuration is not material readiness.

`Action` is facet-qualified: CredentialSourceControl `applySource|removeSource`,
EgressProxyDriver `configureRevision|withdrawBinding|removeRevision`, SandboxDriver
`installEgress`, CredentialRefreshDriver `configureRefresh|prepare|removeRefresh`,
or CredentialIssuer `issue|retire`.
`purpose` is `configuration|discovery|lifecycle|cleanup`, restricted by that
method's caller and Permit. OCC derives both; Agent claims cannot select them.
`CleanupObligation` records resource Ref, owner Ref, attemptId, allowed cleanup
Action and `state: pending|uncertain|complete`. Removal, withdrawal and retirement
qualify, plus Sandbox `installEgress` restricted to the reducing successor of an
accepted withdrawal/removal. Cleanup can never broaden routing; obligations
persist independently of completion.

Every mutating facet below implements `inspect(operationId, bounds) → Read<Operation>`
and `reconcile(operationId, cleanupPermit, bounds) → Change<Operation>` for its
own operations. OCC's durable reconciler drives these after disconnect/restart;
it observes or completes the original intent, never blindly replays issuance.
Inspection/reconciliation retains the original action/purpose; cleanup authority
cannot start new source-use or issuance intent.
An exact requestId returns the recorded result; changed input conflicts. Stale or
superseded generations cannot apply, including late completion. Shared profiles
also require a monotonic applied policy generation.

`CleanupPermit` is a Permit limited to an already accepted operation, exact
resource/action/attempt and cleanup audience. Durable obligations survive expiry
and loss of source-use rights; OCC may issue a successor cleanup permit after
verifying that obligation. It cannot authorize use, new issuance or broader deletion.

## Source control

`CredentialSourceControl` is an internal Backend facet called by OCC, not a new
registered Driver. All methods are required.

| Method and input                                                         | Result and responsibility                                                                                                    |
| ------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------- |
| `describeTypes(backend: Ref, bounds: Bounds)`                            | `Read<Descriptor[]>`; configuration-dependent catalog.                                                                       |
| `applySource(source: Source, command: Command)`                          | `Change<SourceStatus>`; reconciles registration or admitted configuration replacement. Does not copy every root into egress. |
| `sourceStatus(key: SourceKey, bounds: Bounds)`                           | `Read<SourceStatus>`; observes exact source configuration.                                                                   |
| `removeSource(key: SourceKey, cleanup: CleanupPermit, command: Command)` | `Change<Removal>`; coordinates lifecycle retirement, provider/profile deletion and absence confirmation.                     |

`Descriptor` contains provider Ref, schemaVersion, input kind, supported Grant
kinds, config/Secret field lists (`name`, scalar type, required, purpose,
issuerRotated), `rotation: none|external|refresh`, and
`harnessAuth: none|{modelProvider: string, loginMode: api_key}`. Field lists describe
the registered closed Input schemas. Catalog removal blocks new admission, not status,
withdrawal or cleanup of existing identities.

`SourceStatus`: key, `appliedGeneration: integer|none`,
`state: pending|applied|failed|absent`, `operationId: Id|none`, `error: Error|none`.
Dynamic per-grant readiness comes from `CredentialRefreshDriver.refreshStatus`.
Static sources have no warm lifecycle; live usability is checked during resolve.
`Removal`: `state: removed|absent|cleanup_pending|references_remaining`,
`outstandingOperationIds: Id[]`, `remainingBindingRefs: Ref[]`. Pending cleanup
is not reported as removed.

## Egress and Sandbox handoff

`EgressProxyDriver` is the **one new registered capability**, `egress_proxy`.
`SandboxDriver` retains networking/enforcement and consumes its exact attachment.
One OpenShell object may implement both; two daemons are not required. Keeping
all protection management inside Sandbox was an alternative, but would obscure
replaceable egress configuration and withdrawal ownership.

| Method and input                                                                                  | Result                                                                                                                                                     |
| ------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `capabilities()`                                                                                  | `Capabilities` below; declarations require qualification of the exact composition at startup/admission.                                                    |
| `configureRevision(plan: Plan, command: Command)`                                                 | `Change<Attachment>`; Compute configures the complete binding set, all-or-refuse. Partial effects remain owned cleanup, never a partial usable attachment. |
| `attachmentStatus(attachment: Attachment, bounds: Bounds)`                                        | `Read<AttachmentStatus>`; Compute/worker reads Egress state joined with Sandbox-issued installation evidence.                                              |
| `withdrawBinding(attachment: Attachment, binding: Ref, cleanup: CleanupPermit, command: Command)` | `Change<Withdrawal>`; egress owns detachment and prevents late reattachment.                                                                               |
| `removeRevision(attachment: Attachment, cleanup: CleanupPermit, command: Command)`                | `Change<Removal>`; retires all revision bindings.                                                                                                          |

| Shape              | Required fields                                                                                                                                                                                                                                                                                                                          |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Capabilities`     | `contractVersion: 1`, `attachmentVersions: integer[]`, supported input/Grant kinds, `protocols: (https\|sse)[]`, `enforcement: enforced\|disabled`, booleans for authenticated capture, per-operation resolution, two online checks, protected responses and admitted custody. Protected admission requires every applicable capability. |
| `Plan`             | `plan: Ref, execution: Execution, sandbox: Ref, egress: Ref, attachmentVersion: 1, routes: Route[], sources: SourceProjection[]`                                                                                                                                                                                                         |
| `Attachment`       | Adapter-issued authenticated reference: `id: Id, plan: Plan, policyGeneration: positive integer, bindingRefs: Ref[], audience: Ref`. No values, root refs or permission inferred from provider names.                                                                                                                                    |
| `InstallReceipt`   | Sandbox-authenticated `id: Id, attachmentId: Id, plan: Ref, execution: Execution, sandbox: Ref, egress: Ref, attachmentVersion: 1, policyGeneration: positive integer, bindingRefs: Ref[], enforcement: applied\|refused, observedAt: UTC timestamp`.                                                                                    |
| `AttachmentStatus` | attachmentId, `effectiveAttachment: Attachment\|none`, `receipt: InstallReceipt\|none`, per-binding Ref and `state: pending\|applied\|withheld\|failed\|revoked\|absent`, `error: Error\|none`                                                                                                                                           |
| `Withdrawal`       | attachmentId, binding Ref, `state: pending\|detached\|absent`, `successor: Attachment`, `receipt: InstallReceipt\|none`, observation timestamp; detachment evidence records the remaining exact binding set.                                                                                                                             |

The proposed Sandbox networking facet adds
`installEgress(attachment, command) → Change<InstallReceipt>` and
`egressStatus(attachment, bounds) → Read<InstallReceipt|none>`, with the same
inspect/reconcile contract. Every Plan route and binding must use the execution variant matching its exact
Execution; management contexts cannot enter attachments or installation.
Compute invokes installation while provisioning;
the target Sandbox input `egressAttachment: Attachment` replaces
`credentialAttachments`. Sandbox verifies version, audience, execution and the
entire plan before reporting enforcement. Egress owns binding apply/withdraw;
Sandbox only installs/enforces the resulting configuration and reports evidence.
Withdrawal follows this handoff:

1. Egress advances policyGeneration, tombstones withdrawn binding Refs and
   records a successor attachment with the remaining bindings and effective
   routes, bounded by the original admitted plan.
2. `attachmentStatus` exposes the successor while withdrawal is pending.
   Compute/worker calls `installEgress`; Sandbox enforces its effective routes
   and refuses stale installation.
3. Egress remains pending until Sandbox evidence confirms that generation and
   binding set. Older receipts cannot settle withdrawal. Tombstones outlive any
   possible late installation.

Revision removal uses the same handoff with empty routes, or confirmed Sandbox
destruction, before reporting absence.

`configureRevision` also reconciles a newly admitted Plan for the **same running
Execution**; a grant change does not inherently require an Agent restart.
Reductions affect subsequent OCC checks immediately, subject to the accepted
check-to-send race. Expansion needs separate admission and exact-scope preparation
before new use. Existing narrower operations may continue only where their
current bindings remain authorized. Policy generations and withdrawal tombstones
prevent an older installation from restoring access.

Compute waits separately for source configuration, required dynamic grant
material, exact applied attachment and authenticated Harness `serving` status.
Static usability is checked by authorized resolution, not an invented warm-status
API. None implies another. Protected capability flags also require evidence for
the selected implementation versions, configuration, custody, enforcement and
provider/protocol slice; self-report is not installed proof. Existing same-Backend/Kubernetes pairing guards stay until
replacement adapters prove this join; they are initial implementation limits.

## Complete legacy disposition

Retire the legacy capability after the migration and parity work below. The pinned [legacy contract](https://github.com/openclaw/openclaw-enterprise/blob/4c3952b15caad45a43b0144e185d54be0e040f1f/packages/contracts/src/index.ts#L1264-L1385)
contains all eight methods:

| Legacy method       | Successor                                                                                    |
| ------------------- | -------------------------------------------------------------------------------------------- |
| `listSourceTypes`   | `CredentialSourceControl.describeTypes`                                                      |
| `registerSource`    | `applySource`, then separately `configureRefresh` for dynamic inputs                         |
| `updateSource`      | `applySource` for admitted configuration; `SecretDriver.readCredentialInput` for live values |
| `sourceStatus`      | `sourceStatus`; separate per-grant `refreshStatus`                                           |
| `removeSource`      | `removeSource` plus `removeRefresh`, retaining provider/profile cleanup                      |
| `attachForRevision` | `EgressProxyDriver.configureRevision` → Sandbox `installEgress`                              |
| `attachmentStatus`  | Egress `attachmentStatus` joined to Sandbox `egressStatus`                                   |
| `withdraw`          | OCC durable withdrawal → `withdrawBinding`, including late-create rechecks                   |

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
| Proposed #1785 `withSourceToken` (may prepare)                                                            | Trusted OCC management service owns authorization/preparation; use lifecycle `prepare`, then Resolver/Forwarder with post-preparation check. Not a runtime resolver method.                                                                                               |

Cutover must reconcile owned providers, catalog changes, running attachments and
uncertain cleanup, then disable legacy reattachment/refresh paths. Retire exports,
composition and persistence coupling only after consumer migration and adapter
parity. This permits a temporary adapter, not indefinite compatibility or a
cosmetic rename. [Lifecycle qualification](lifecycle.md#implementation-discovery-and-qualification)
owns the remaining proof.
