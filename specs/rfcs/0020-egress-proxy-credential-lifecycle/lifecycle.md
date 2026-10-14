---
rfc: index.md
---

# Proposed credential lifecycle

[RFC-0020](index.md) separates preparing a usable credential from permission to use it. OpenShell
can renew a GitHub installation token while an Agent is idle. A later Agent or bootstrap request can
use only material already prepared for its exact grant; a cold read starts no work. Here, “Token
Service” means the retained `CredentialRefreshDriver` capability, not a required separate service.

[Management contracts](control-contracts.md) govern admission and durable attempts.
[Runtime contracts](runtime-contracts.md) bind the selected version to an actual operation.

## 1. Configure and warm

![Proposed configuration and warmup](assets/configuration-warmup.svg)

_All interactions are proposed. Sequence arrows distinguish calls/returns, not
implementation status. [Editable source](assets/configuration-warmup.mmd)._

OCC admits configuration and grants. The owner prepares dynamic material
independently of requests, including while Agents are idle. Compute observes
four separate states:

| State                 | Evidence                                               |
| --------------------- | ------------------------------------------------------ |
| Configuration applied | Source configuration is accepted and applied.          |
| Material ready        | The required dynamic grant has eligible warm material. |
| Binding installed     | Sandbox confirms the exact revision attachment.        |
| Harness serving       | The Harness reports authenticated serving status.      |

Compute gates required dynamic startup on all four within a configured warm wait.
Static inputs have no warm lifecycle; authorized resolution checks usability.
Acceptance alone proves neither dynamic readiness nor static usability.

### Lifecycle interface

Evolve `CredentialRefreshDriver` (`credential_refresh`) without importing any
`CredentialGateway` context, source-input or attachment types. It uses SourceKey,
Grant, Bounds, Command, Permit, Read, Change, Operation, CleanupPermit and Removal
from [management contracts](control-contracts.md). Prepared material is separate
from the request-bound MaterialEvidence in [runtime contracts](runtime-contracts.md).

| Shape             | Required fields and semantics                                                                                                                                                                                                                                                                                                                                                                             |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `WarmKey`         | `{source: SourceKey, grant: Grant, grantHash: SHA-256, isolationId: Id}`. Exact normalized admitted scope, never source-only caching.                                                                                                                                                                                                                                                                     |
| `Family`          | `{scope: Scope, familyId: Id, generation: positive integer, owner: Ref, ownerEpoch: positive integer}`. Canonical input family shared across all grants consuming that input. OCC admits one owner; its durable store fences epochs.                                                                                                                                                                      |
| `LifecycleConfig` | `{source: Source, family: Family, warmKeys: WarmKey[], renewBeforeMs: positive integer, minValidityMs: positive integer, issuer: Ref, inputAuthority: Permit}`. Source's roots are delivered only to its admitted owner/issuer.                                                                                                                                                                           |
| `LifecycleStatus` | family, WarmKey, `configuredGeneration: integer\|none`, `committed: CommittedDynamic\|none`, `readiness: ready\|cold\|expired\|insufficient_validity\|withheld`, `activity: idle\|preparing\|refreshing\|uncertain\|reauthorization_required\|removing`, `attempt: Operation\|none`, `nextRenewalAt: timestamp\|none`, `error: Error\|none`, `recovery: none\|reconcile\|reauthorize\|fix_configuration`. |
| `Preparation`     | `{target: WarmKey, family: Family, mode: ensure_ready\|rotate, minRemainingValidityMs: nonnegative integer, authorization: Permit}`. Permit binds management caller, initiating user, captured Use, source/grant, purpose, destination and original deadline.                                                                                                                                             |

`CommittedDynamic` is `{target: WarmKey, family: Family, materialId: Id,
materialVersion: string, preparationAttemptId: Id, actualGrant: Grant,
providerExpiresAt: UTC timestamp}`. It contains no request, execution or binding
handle. The same admitted warm entry may serve distinct authorized bindings;
preparation and readiness do not establish permission to use it.

`CredentialRefreshDriver` methods are required for a dynamic source:

| Method and caller                                                                               | Result/semantics                                                                                                                                                                           |
| ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| OCC `configureRefresh(config: LifecycleConfig, command: Command)`                               | `Change<LifecycleStatus[]>`; accepts configuration and authorizes independent warming, not readiness. Reauthorization changes family generation/input authority; routine renewal does not. |
| Authorized management `prepare(request: Preparation, command: Command)`                         | `Change<LifecycleStatus>`; ensure-ready may reuse eligible committed material; rotate requests one owned refresh. Neither implies issuer revocation of the old token.                      |
| OCC/Compute `refreshStatus(target: WarmKey, bounds: Bounds)`                                    | `Read<LifecycleStatus>`; readiness evaluated for admitted minimum validity at observation time.                                                                                            |
| OCC cleanup `removeRefresh(family: Family, cleanup: CleanupPermit, command: Command)`           | `Change<Removal>`; stop new preparation, settle attempts and dispose/revoke owned artifacts as supported. Preserve uncertain cleanup.                                                      |
| OCC reconciler `inspect(operationId, bounds)` / `reconcile(operationId, cleanupPermit, bounds)` | `Read<Operation>` / `Change<Operation>` for the exact accepted attempt, as in management contracts. Family status alone cannot settle it.                                                  |

Known failures return `failed` with the exact operation, safe error and cleanup;
pending and uncertain remain distinct. Partial effects and late candidates stay
owned until settled. Failure permits neither assumed rollback nor repeated issuance.

The owner exposes the internal read-only facet
`WarmCredentialReader.readWarm({target: WarmKey, authorization: AccessPermit, minRemainingValidityMs}, bounds)`
to the Resolver. It returns `warm(candidate: trusted custody handle, evidence: CommittedDynamic)`
or [Refusal](runtime-contracts.md#forwarding-sequence-and-results). The handle
binds the operation/Resolver and expires within Bounds. Resolver verifies WarmKey
and current binding, then adds request binding and clamped usability to produce
MaterialEvidence and the sender's single-use MaterialHandle. Read performs no
issuance, signing, refresh, scheduling or refresh-capable retrieval.

### One owner and durable attempts

Two grants can consume one rotating input. Isolating their WarmKeys prevents cross-grant reuse; it
does *not* serialize consumption of the shared refresh token. Retire the input family only after all
admitted source and grant dependencies are released. Otherwise return `references_remaining` and
preserve the other consumers’ input and material.

The owner must, in order:

1. Serialize consumption across the whole family and fence this owner epoch and attempt.
2. Persist the attempt and uncertainty marker *before* calling `CredentialIssuer.issue`.
3. Validate the returned authority and expiry. Commit both replacement input and runtime candidate
   durably *before* publishing readiness.
4. Publish only under the current fence. Retain even a late candidate for owned cleanup.

If the provider rotates a refresh token and the owner crashes before saving its replacement, a lock
cannot recover that token. Inspect where the provider supports it; otherwise explicit
reauthorization may be necessary. A timeout, new process or lost lease never licenses replay. A
bootstrap Secret cannot overwrite canonical replacement input. When taking custody from a Harness,
stop its refresh consumer before starting this owner.

During ordinary renewal, continue serving eligible committed material without restarting or
periodically interrupting the proxy or Agent. Exceptional reauthorization may interrupt only the
affected credential; fail closed and expose recovery status. Hot cutover remains later work.

### Management preparation and retrieval

![Proposed authorized management preparation](assets/management-preparation.svg)

_All interactions are proposed; arrows distinguish calls/returns. Management can
prepare through the one owner, then uses the common Forwarder.
[Editable source](assets/management-preparation.mmd)._

For MVP configuration or discovery, the trusted Forwarder runs inside OCC. OpenShell stores and
refreshes the token; OCC may hold an access token briefly to inject it. Later placements must
preserve this sequence:

1. Authenticate the caller and initiating user, capture the business operation, then authorize
   preparation for its exact source, purpose, grant and destination *before* access.
2. If authorized, ask the designated owner to `prepare`. Keep any uncertain effect owned even if
   retrieval fails or is cancelled. A readiness check cannot turn refresh-capable retrieval into
   `readWarm`.
3. Call `forward`. It checks current authority before resolution, then checks the actual operation
   and selected material before each business send. Return sanitized metadata; no caller receives
   roots, tokens or a material-consuming callback.

The owner separately authorizes issuer calls. Agent and bootstrap callers have no preparation flag,
and management does not impersonate an Agent.

### Live Secret cutover

New static sources default to live adoption: a Secret writer can change the value consumed without
changing source generation. Existing sources keep their approved immutable version or snapshot in
`explicit_update` mode until an operator authorized for that exact source opts in. Admission governs
mode, policy and approved material. Neither consumer permission, a mutable reference nor a longer
TTL can approve replacement. Failed opt-in preserves approval; known revocation still denies.

Apply these bounds to reads of the *admitted target*:

- **Fresh.** Default ten minutes, configurable per source. A successful authoritative read at 09:00
  is fresh until 09:10.
- **Eligible stale.** Default four hours *total*, configurable per source. That 09:00 read is
  eligible only until 13:00, and only on positively classified transport, timeout or throttling
  errors. Failed reads and lower-cache hits never reset age.
- **Fail closed.** No fallback on cold, denied, revoked, missing, unknown error or unavailable authority.
- **Zero.** Either public cache duration of zero selects `none`; otherwise both are positive bounded
  durations. Zero retention or zero request-age limit requires an authoritative read, no retention
  or fallback anywhere. Use fresh material within the original deadline and provider or Secret
  expiry; zero does not mean immediate expiry.

Recheck usability at dispatch. Reading an approved snapshot starts read age, regardless of approval
date; no current provenance Secret is needed. Zero disables read reuse, not the snapshot.
[Secret results](runtime-contracts.md#versioned-secret-access) define age and version evidence;
[migration](migration.md#preserve-approved-static-material) carries mode and target through
admission, attachments, resolution, evidence and caches.

## 2. Prepare the optional repository

![Proposed optional clone gate](assets/clone-startup.svg)

_All edges are proposed. Bootstrap has execution/repository delegation, no
management preparation authority. [Editable source](assets/clone-startup.mmd)._

1. OCC admits repository IDs/permissions and authentic URL mapping. Repositories
   remain optional and first-class; Repo retains discovery, profiles, grants,
   sessions, deadlines and cleanup.
2. The lifecycle owner prepares the exact WarmKey in the background. Compute
   observes `refreshStatus` within the startup bound and the exact installation
   receipt; expiry requires a fresh check, not a remembered ready boolean.
3. Compute obtains an OCC Permit for executor, Execution, repositoryId, clone
   operation, source/grant, audience and original deadline. Trusted bootstrap
   `capture`/`forward` checks every Git HTTP operation; it need not use the Agent's
   own proxy. No request-time issuance or Agent-visible Git credentials.
4. Bootstrap returns authenticated completion to Compute: execution, repositoryId,
   admitted requested Git ref (or none for the repository default), observed
   commit ID (or none), attemptId, workspace Ref, deadline,
   `outcome: succeeded|failed|uncertain`, and
   `cleanup: none|required|complete`. Only observed success satisfies the default
   clone gate. Failure/uncertainty blocks startup unless explicitly configured to
   opt out of that gate; the opt-out grants no extra authority.

Compute/bootstrap owns partial-workspace cleanup and exact-attempt reconciliation;
unknown clone effects are not blindly replayed. Revision-selection UX is later
work. Repo-plus-Sandbox guards stay until integration is qualified. Owners need
provisioning/credential failure status; operators need refresh/expiry visibility.
Alert channels and thresholds remain implementation choices.

### GitHub issuer bridge

The MVP uses OpenShell's OAuth refresh mechanism to call an OCE-hosted
[GitHub issuer](runtime-contracts.md#provider-semantics-and-issuer-boundary).
OpenShell owns renewal and commits installation tokens. OCE retains the App
private key and GitHub grant validation; the issuer runs no second renewal loop.

The proposed paths are separate:

```text
Background preparation: OpenShell refresher → OCE issuer → GitHub → OpenShell warm store
Agent/bootstrap request: Capture → fresh OCC check → warm read → fresh OCC check → send
```

The bridge authenticates the owner and maps an opaque identifier to an
OCC-admitted installation, repository set and permissions; callers cannot expand
the grant. OCE signs an App JWT, exchanges it for an installation token,
validates actual authority and expiry, and returns an OAuth-compatible token
response. OCE retains the App key; OpenShell receives only its issuer-call
credential and resulting token.

The adapter must correlate grant, owner epoch, issuance attempt, material
identity/version and provider-backed expiry across the OAuth exchange and warm
read; a fallback TTL cannot establish validity. The source schema and bridge
protocol require qualification; transport and encoding remain implementation
choices. Agent/bootstrap reads never invoke the issuer or refresh-capable retrieval.
Keep refusal, temporary failure and uncertain issuance distinct; reconcile unknown
effects without blind replay.

An OCE-owned lifecycle remains a fallback under the same contracts if the bridge
cannot satisfy these requirements. It requires an explicit implementation decision
and must still deliver GitHub in MVP. Each family has one owner at a time.

## 3. Resolve and forward

![Proposed request authorization and resolution](assets/request-caching.svg)

_All interactions are proposed; arrows distinguish calls/returns.
[Editable source](assets/request-caching.mmd)._

![Proposed final authorization and dispatch](assets/request-forwarding.svg)

_Continuation of the same proposed request, including material absence.
[Editable source](assets/request-forwarding.mmd)._

![Proposed static and dynamic credential selection](assets/credential-selection.svg)

_All edges are proposed. Dynamic reuse remains behind Resolver; no proxy fallback
or stale grace. [Editable source](assets/credential-selection.mmd)._

Read the diagrams in order: check before access, check again with the actual material, then send at
most once. The [runtime contract](runtime-contracts.md#two-policy-checks-and-common-resolution)
defines the evidence and outcome. An issuer outage may leave eligible committed material usable; an
unavailable Resolver or authority refuses use. Cold lookup starts no work.

## 4. Withdraw and recover

![Proposed withdrawal and recovery](assets/revocation-recovery.svg)

_All interactions are proposed; arrows distinguish calls/returns. Owners retain
attempts after process replacement. [Editable source](assets/revocation-recovery.mmd)._

1. OCC commits logical denial and durable withdrawal intent.
2. Egress `withdrawBinding` owns detachment; Sandbox reports enforcement evidence.
3. Retain revision-specific suppression and late-create rechecks. An earlier
   absence observation cannot erase a tombstone while an attachment may arrive.

Logical denial, detached binding, removed source and issuer revocation are
distinct results. Issuer retirement requests provider revocation only when
supported. OCE denial and detach stop mediated future use; neither recalls an
exported bearer nor undoes sent effects. Report each result and outstanding cleanup.

`reportRejection` carries authenticated SendReceipt, source/grant generations
and exact material version. Resolver durably deduplicates the receipt/version
and coalesces recovery for that version; duplicates cannot trigger repeated
recovery work. Static version fences survive cache eviction and reread without
approving replacement. Dynamic recovery stays with the one owner; late N cannot
invalidate or recover N+1. The sender returns the provider failure through
SafeResponse, unchanged where policy permits or redacted/refused where required,
without retry.

Preserve the owner, deadline, attempt and cleanup for unknown send/refresh/clone
effects through restart, including late outcomes. Use inspect/reconcile or explicit
reauthorization, never blind replay. Restored configuration is not warm readiness.
Ordinary retirement waits for replacement visibility/adoption and old in-flight
use; emergency revocation may precede those observations.

## Parking and forks

[Security](security.md#withdrawal-and-owner-loss) retains confirmed last-owner
hold, asynchronous parking and data preservation; remaining team owners keep
working. Unknown directory state is not confirmed owner loss. [Authorized deep
forks](security.md#authorized-forks) receive fresh stopped identities,
independent data and no inherited credentials, grants, approvals or sessions.
External IdP synchronization, copy-on-write and stronger stream revocation remain
separate work.

## Earlier Token Service proposal

[Earlier Token Service decisions](migration.md#earlier-token-service-proposal)
retain their scope, custody and recovery requirements.

## Implementation discovery and qualification

[The migration inventory](control-contracts.md#complete-legacy-disposition) covers
legacy methods and consumers. Implement admission/attempt state, migrate source
and egress management, connect runtime checks/Resolver, qualify static inference
and GitHub, then integrate Harness/optional clone before retiring old exports,
composition and persistence coupling.

| Area               | Required evidence                                                                                                                                                                                                                                                                                                                                                       |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| OpenShell join     | Versioned Egress/Sandbox receipt, authenticated capture, final OCC check after material selection, actual warm-only read, response policy and no bypass. Current adapters do not satisfy the complete contract.                                                                                                                                                         |
| Lifecycle          | Prove family-wide fencing, durable replacement, attempt-correlated outcomes and continued old-token reads during routine renewal.                                                                                                                                                                                                                                       |
| Static and custody | Versioned reads, trustworthy cache age/errors, zero retention, new-source live defaults, preserved explicit-update snapshots, authorized opt-in and exact permitted consumers.                                                                                                                                                                                          |
| Providers          | Real scoped GitHub, safe responses, bootstrap completion/cleanup and Codex account integration; qualify the actual selected protocol.                                                                                                                                                                                                                                   |
| Composition        | Qualify each protected capability against the actual versions, configuration, provider/protocol slice and custody; self-declared flags are insufficient. Preserve initial Kubernetes/same-Backend/Repo guards until replacements work. Additional loading, independent backends, strong local development, DNS, packaging and scale/HA require follow-up qualification. |

Qualify package loading and protocols in composition. For Codex, demonstrate that a placeholder-only
client obtains required account metadata, starts, executes and handles renewal or reconnect while
provider credentials stay outside the Harness. Qualify its actual WebSocket or HTTP/SSE path;
management retrieval cannot stand in for warm resolution. Generalized bootstrap, including
cloud-init, is later work.

MVP requires static inference and GitHub, including the issuer bridge. OCE 1.0 also requires GitHub
preclone, Codex OAuth and custom dynamic paths. Any slice that rotates inputs, even in MVP, must
meet the concurrency, restart and uncertain-effect requirements. Distinguish source, fixture,
installed-runtime and live-provider evidence; no-op CI and accepted deployment prove neither
enforcement nor readiness.

Related: [security validation](security.md#required-validation),
[Credential Gateway RFC](../0016-sandbox-credential-injection/index.md) and
[Agent egress RFC](../0017-agent-egress-0x/index.md).
