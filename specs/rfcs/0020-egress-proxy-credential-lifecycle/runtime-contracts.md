---
rfc: index.md
---

# Proposed capture, resolution and forwarding contracts

These proposed internal contracts use [management identities](control-contracts.md#identities-and-admission)
and closed records. They add no registered Driver or Agent token API. Runtime
authentication must enforce handle associations; TypeScript brands are insufficient.
The MVP management Forwarder is a trusted library inside OCC. OpenShell retains
token storage and refresh; the OCC sender may hold access tokens transiently for
injection. Generic contracts allow later service/worker placements. Physical
OpenShell transport remains to be qualified.

## Capture and trusted handles

`EgressForwarder.capture(peer: Peer, exchange: Exchange, bounds: Bounds)` returns
`captured(operation: OperationHandle)` or `Refusal`. Only trusted transport can
construct Peer and Exchange. The sender authenticates credentials and derives
Caller from current OCC execution/delegation records, not workload JSON.

| Shape             | Required fields/variants                                                                                                                                                                                                                                                                                                                                                               |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Caller`          | `agent`: Execution; `bootstrap`: Execution plus executorId, delegationId, repositoryId; `management`: the admitted Management context. All identifiers are immutable Ids.                                                                                                                                                                                                              |
| `Peer`            | Authenticated channel handle, trusted sender Ref, identity evidence handle; both handles are issued by the transport verifier and bound to its audience, expiry and anti-replay state.                                                                                                                                                                                                 |
| `Exchange`        | Transport-owned immutable request plus response sink, connection evidence, absolute deadline and optional `selection: Selection` (default `automatic`). No caller-provided function may receive material.                                                                                                                                                                              |
| `Request`         | `method: HTTP method`, canonical HTTPS URL, ordered header name/value pairs, body representation below, connection `{address: IP, port: integer, tlsName: string, httpAuthority: string}`.                                                                                                                                                                                             |
| `Body`            | `bounded`: sealed bytes and size limit; `stream`: sealed reader, registered operation-policy Ref, finite byte limit and grammar state. Both expose policy-relevant fields to OCC before dispatch; digest alone is insufficient.                                                                                                                                                        |
| `Use`             | `{id: Id, caller: Caller, route: Route, request: Request, classification: Classification, selection: Selection, capturedAt: UTC timestamp, deadlineAt: UTC timestamp}`                                                                                                                                                                                                                 |
| `Classification`  | Initial closed schemas: inference `generate{model: string}` or `list_models{}`; GitHub `repository{repositoryId: Id, action: clone\|read\|write}` or `list_repositories{installationId: Id}`; OAuth/API `{operationPolicy: Ref, action: string}` validated against that versioned policy's closed action list. Extensions use the registered provider schema, never arbitrary context. |
| `OperationHandle` | Opaque runtime reference to sealed Use and response sink, bound to peer/sender and deadline; single-use dispatch.                                                                                                                                                                                                                                                                      |

Capture requires authenticated Caller/Context agreement: Agent and bootstrap use
their Execution; management uses its Management identity, purpose and source-scoped
route/binding. The management variant carries through Use, both permits and the
selected MaterialEvidence binding reference; it invents no Execution. Discovery
uses admitted management policy, not invented model/repository IDs or Agent authority.

### Binding selection

`Selection` is `automatic` or `explicit{binding: Ref}`. The trusted transport
maps a configured placeholder or integration selector to a binding Ref in the
authenticated context. Missing selection means automatic. Malformed, conflicting
or unknown explicit selectors are refused. Selection is untrusted intent, not
identity or permission; its adapter-specific encoding must be qualified.

Capture matches admitted routes using caller context, destination, method and
provider-classified operation, including repository/model and relevant body. It
uses configuration and request semantics; selection reads no credential or issues
material.

| Selection                                                                    | Result                                                                              |
| ---------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| Automatic; exactly one route matches                                         | Capture that route and its binding, or its explicit credential-free use.            |
| Automatic; zero or multiple routes match                                     | Refuse; multiple matches return `ambiguous_route`. No priority or first-match rule. |
| Explicit binding; exactly one matching route uses it                         | Capture that route; validate context, current generations and operation.            |
| Explicit binding is invalid, foreign or mismatched, or several routes remain | Refuse without trying another binding or a credential-free route.                   |

Selectors grant no authority, Driver choice or wider scope; errors disclose no
foreign bindings. Both paths share checks and forwarding. Denial, unavailable
material or cold tokens never cause identity fallback. Remove control selectors
before dispatch; conflicting authentication fields cannot smuggle them through.

Capture freezes the verified context, selection, request and operation after
permitted noncredential transformations. Streams pin policy-relevant semantics
and enforce the admitted grammar without buffering an unbounded body. A later
frame needing another decision is another operation; refuse unsupported or opaque
streams. Injection cannot change the authorized operation: changed content needs
new capture and checks. The handle binds no token or cached authorization;
rotation is resolved at use.

## Two policy checks and common resolution

| Method                               | Input                                                                                                                                                     | Result and caller                                                                                                                                                                                      |
| ------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `EgressAuthorizer.check`             | `{phase: before_access, operation: OperationHandle}` or `{phase: before_send, operation: OperationHandle, material: MaterialEvidence\|none}`, plus Bounds | Trusted Forwarder calls OCC. `allow(permit: AccessPermit\|SendPermit)` for the corresponding phase, or Refusal.                                                                                        |
| `CredentialResolver.resolve`         | `{operation: OperationHandle, access: AccessPermit, maxStaticAgeMs: nonnegative integer, minRemainingValidityMs: nonnegative integer}`, plus Bounds       | Forwarder only; `ready(material: MaterialHandle, evidence: MaterialEvidence)` or Refusal. Limits can tighten admitted policy, never widen it. No issuer/provider call, signing, refresh or scheduling. |
| `CredentialResolver.reportRejection` | `RejectionFeedback`, plus Bounds                                                                                                                          | Trusted response classifier only; `recorded`, `obsolete` or Refusal. Durably deduplicates authenticated receipt/version and fences only that version; dynamic recovery coalesces at its owner.         |
| `EgressForwarder.forward`            | OperationHandle                                                                                                                                           | `ForwardOutcome` below; owns the complete sequence, not an injection callback. Uses capture's original Bounds.                                                                                         |

OCC dereferences the runtime-verified handle to inspect the exact Use. Each check
verifies the route/binding Context against the authenticated Caller and evaluates
current IAM and applicable initiating-user rights, execution or delegation
currency, hold/withdrawal state, source/binding/backend/provider/route
generations, normalized grant and actual classified operation. Static checks bind
the adoption mode and admitted material reference; consumer authorization cannot
replace an approved version. For selected dynamic material, verify its current
family generation and owner epoch as well. This extends OCC policy evaluation;
generic IAM principal/action/resource input alone is insufficient. Checks include
credential-free operations and cache hits. No cached allow substitutes for either
fresh online evaluation.

`AccessPermit` is a Permit restricted to this Use, source and resolver, expiring
within its deadline; it authorizes one resolution, never a send. `SendPermit`
additionally binds selected material identity/version or explicit `none`, sender,
and a short finite `sendStartBy` timestamp. Neither is renewable authority.

`MaterialEvidence` contains SourceKey, binding Ref, grantHash, isolationId,
materialId, materialVersion, usableUntil, and exactly one variant:

| Kind      | Additional required evidence                                                                                                                                                                                                                                                                                                                                                                                           |
| --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `static`  | SecretRef, `adoption: live\|explicit_update`, `material: StaticMaterialRef`, authoritativeObservedAt, `retention: none\|bounded`, `freshness: fresh\|eligible_stale`; bounded usableUntil respects source total-age, positive request age limit and selected-material expiry. `none` is fresh authoritative material confined to this request's deadline, applicable positive age bounds and selected-material expiry. |
| `dynamic` | familyId, familyGeneration (positive integer), owner Ref, ownerEpoch (positive integer), preparationAttemptId, actual normalized Grant, providerExpiresAt; usableUntil never exceeds expiry.                                                                                                                                                                                                                           |

`MaterialHandle` binds evidence to this Use, AccessPermit, permitted sender and
deadline. It is single-use and consumed inside trusted injection only. Internal
or remote handles need runtime registries or authenticated audience/expiry/replay
validation. No handle or usable bytes reach an Agent, UI, arbitrary callback,
diagnostic or log. Material is not authority.

The Resolver reuses dynamic material by exact
[WarmKey](lifecycle.md#lifecycle-interface), including admitted scope. Every
credentialed operation resolves again; a narrower grant cannot borrow a broader
token. Valid committed material may survive issuer outage; Resolver failure has
no proxy fallback. Credential-free use skips resolution and passes `none` to check 2.

Static evidence's SecretRef equals Input's `secret` (snapshot provenance).
`materialId` identifies the selected Secret or snapshot; `materialVersion` equals
the returned version and, for approved targets, `valueVersion`. Both checks bind
the admitted mode, reference and selected Driver/scope; evidence cannot
substitute provenance for the target. Cache keys include SourceKey, mode,
target/store, material reference, version, grant and isolation. Known revocation
fences that material across caches.

Source cache `none` or request `maxStaticAgeMs=0` forces an authoritative read
of the admitted target without retention/fallback at any serving layer. Zero
requires a fresh read, not zero elapsed age at send. Confine material to the
request deadline, positive age bounds and selected-material expiry; discard it
after completion/cancellation. `authoritativeObservedAt` is the successful
selected-store read time, not snapshot creation/approval time; lower-cache hits
cannot renew it. An owned snapshot is authoritative storage: zero disables reuse
of read results, not the snapshot, and never selects the latest Secret.

### Forwarding sequence and results

1. Validate capture and obtain check 1.
2. Resolve material if credentialed; obtain check 2 over the unchanged Use and
   actual selected evidence.
3. Validate handle binding, material usability, send-start and original deadlines.
4. Consume handles, strip execution authentication, inject material, send once
   and protect the response.

Resolution cannot dispatch. Separate management preparation grants no lasting authority.

`Refusal` is one of these closed safe variants:

| Kind                             | Codes                                                                                                                                          |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `denied`                         | `identity`, `unauthorized`, `withdrawn`, `stale_configuration`, `scope_mismatch`, `ambiguous_route`, `invalid_handle`, `unsupported_operation` |
| `not_ready`                      | `cold`, `expired`, `insufficient_validity`, `material_missing`, `attachment_pending`, `recovery_required`                                      |
| `unavailable`                    | `authority`, `resolver`, `secret_store`, `lifecycle`                                                                                           |
| `cancelled`, `deadline_exceeded` | No additional fields; pre-dispatch only.                                                                                                       |

`SendReceipt` is authenticated evidence containing Use ID, sender Ref, selected
MaterialEvidence or none, attemptId, original deadline and
`dispatch: confirmed|possible`. It is retained by the sender's recovery owner;
classification cannot be supplied by the Agent.

| `ForwardOutcome`    | Required fields and meaning                                                                                                                                 |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `refused`           | `dispatched: false, error: Refusal`; no send possible.                                                                                                      |
| `response`          | `receipt: SendReceipt, response: SafeResponse`; confirmed dispatch.                                                                                         |
| `provider_rejected` | `receipt: SendReceipt, response: SafeResponse, feedback: RejectionFeedback`; preserves the provider failure under response policy, with no automatic retry. |
| `response_blocked`  | receipt, `code: response_policy`; provider effect may already exist.                                                                                        |
| `uncertain`         | receipt with possible dispatch; reconcile exact attempt, never infer safe retry from timeout.                                                               |

`SafeResponse` contains status, policy-processed ordered headers, bounded bytes
or a protected stream, and policy-processed trailers. Stream completion reports
`complete|blocked|interrupted`; failure after headers is not pre-send refusal.
The caller receives safe data, not internal receipts or handles.

`RejectionFeedback` is `{receipt: SendReceipt, evidence: MaterialEvidence,
classification: credential_rejected}` from the trusted classifier. It binds the
selected version. Resolver authenticates the receipt and exact evidence, then
durably deduplicates by sender, Use ID, attemptId and material identity/version.
Duplicates return the recorded outcome without new invalidation or recovery.
Recovery delivery is idempotent for that exact store-qualified version; multiple
receipts coalesce into one durable obligation. Late N cannot invalidate or
schedule recovery for N+1. A static fence survives eviction, restart and rereads
of that version; it cannot approve replacement or opt-in. Dynamic recovery belongs
to the lifecycle owner.

Return the provider failure as-is when policy permits; configured redaction
changes SafeResponse, and refusal produces `response_blocked`. Feedback may be
recorded when the response is blocked, without leaking its content. Redirects
never inherit credentials; a new admitted operation needs both checks within the
original deadline. No automatic retry follows possible dispatch. The accepted
check-to-send race remains; no atomic revocation or renewable lease is implied.

## Versioned Secret access

Evolve the retained `SecretDriver` with
`readCredentialInput({secret: SecretRef, material: StaticMaterialRef|none, authorization: Permit, retention: none|permitted}, bounds)`.
Its only callers are the Resolver for static material and the authorized
lifecycle owner/issuer for initial inputs. Existing CRUD/resolve remains; the
old value-only callback cannot supply this evidence.

| Result                                            | Required fields/meaning                                                                                                                                                                             |
| ------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `value`                                           | trusted custody handle, immutable value version, authoritativeObservedAt, `expiresAt: timestamp\|none`. Only the permitted resolver/issuer can consume the handle; it is not a workload projection. |
| `temporary`                                       | `reason: transport\|timeout\|throttled`; positively classified eligible failure.                                                                                                                    |
| `denied`, `missing`, `revoked`, `unknown_failure` | No value; never permits retained fallback.                                                                                                                                                          |
| `cancelled`, `deadline_exceeded`                  | No value or fallback.                                                                                                                                                                               |

Static reads route by [admitted target](control-contracts.md#identities-and-admission),
not provenance: `secret` preserves Input's SecretRef but never triggers a latest
read for approved targets. The Permit binds source generation, mode, provenance,
selected Driver/scope/identity, approved version (if any), consumer and
`static_read` purpose.
For issuer input only, `material: none` routes by `secret.secretDriver` with
`issuer_input` authority. Source-use rights grant no direct Secret-read permission.
Static retention initially belongs in the Resolver. The
[ten-minute/four-hour-total rules](lifecycle.md#live-secret-cutover) apply across
serving layers: lower caches preserve authoritative age, failed reads never reset
it, and zero disables retention/fallback. A Driver without trustworthy evidence
cannot advertise eligible stale support. Only admitted live sources adopt new
values on required reads; explicit-update sources require authorized replacement.
Known revocation denies either mode.

## Provider semantics and issuer boundary

Trusted Backend composition registers `CredentialProviderDefinition` by provider
Ref and schemaVersion, with closed Input/Grant/Classification schemas and their
normalizers, validators, injection definitions and hooks below. Unknown fields or
versions fail admission. Custom schemas may extend credential forms and GitHub
permissions without core switches, arbitrary context bags, request-time plugin
discovery, general middleware or per-provider services.

| Hook             | Exact input → result                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `normalizeInput` | Provider's closed Input → `Read<Input>` for that schema; canonicalize references/configuration and validate typed fields before admission.                                                                                                                                                                                                                                                                                                                               |
| `normalizeGrant` | `(SourceProjection, Grant) → Read<{grant: Grant, grantHash: SHA-256}>` for that schema; reject missing/unsupported restrictions.                                                                                                                                                                                                                                                                                                                                         |
| `classify`       | `(SourceProjection, Grant, Request) → Read<Classification>`; validate destination and policy-relevant content. Git clone uses real repository URL/ID mapping and Git HTTP semantics.                                                                                                                                                                                                                                                                                     |
| `injectionPlan`  | `(Classification) → Read<InjectionPlan>`; typed result from the registered closed injection schema. Built-ins: `authorization{header: Authorization, scheme: Bearer\|Basic, username: string\|none}` and `named_header{header: registered name}` for static credentials. Custom encodings require trusted versioned definitions, qualified custody and response policy. Admitted endpoint only; replace conflicting credentials. Basic requires qualified Git transport. |
| `responsePolicy` | `(Classification) → Read<{policy: Ref, mediaTypes: string[], encodings: string[], streaming: boolean, maxBytes: positive integer}>`; policy Ref resolves to registered sanitizer/refusal behavior for status, headers, body, trailers and frame boundaries.                                                                                                                                                                                                              |
| `validateIssued` | `(Grant, Issued) → Read<Validated>`; compare actual returned authority, provider-required baseline permissions and expiry against exact normalized grant; reject excess, missing rights or unverifiable expiry.                                                                                                                                                                                                                                                          |

`CredentialIssuer.issue(attempt: IssuerAttempt, bounds: Bounds)` returns
`issued(candidate: Issued)`, `not_dispatched(error: Error)`,
`rejected(code: unauthorized|invalid_grant|provider_refused)`, or
`uncertain(attemptId: Id)`. Rejected proves a known refusal, not a generic
transport failure. `inspect(attempt, bounds)` returns the same settled outcomes
or uncertain; it observes provider-supported evidence, never repeats the exchange.
`retire(candidate, cleanupPermit, bounds) → Change<Removal>` disposes exact
candidate custody and, when supported, revokes it; reports remaining obligations
rather than promising universal bearer recall.

`IssuerAttempt` contains SourceKey, exact Grant, WarmKey, familyId, owner Ref,
ownerEpoch, attemptId, original deadline and owner-authorized input handle.
That handle binds the canonical input version, issuer audience and purpose;
only the fenced owner/issuer may consume it. `Issued` contains runtime candidate
custody handle, actual Grant, providerExpiresAt, provider issuance ID (or none),
and replacement input `unchanged` or `rotated(custodyHandle, inputVersion)`.
`Validated` contains that candidate, normalized actual Grant and validated expiry.
These handles contain no public export method; roots and usable bytes remain in
trusted custody. The owner publishes [CommittedDynamic](lifecycle.md#lifecycle-interface)
only after durable commit. Resolver derives request-bound MaterialEvidence from
that evidence; the stored warm entry itself has no execution binding.

GitHub issuance signs an App JWT and requests an installation token for explicit
repository IDs/permissions; the key and JWT never become runtime candidates.
For MVP, OpenShell schedules renewal through an OAuth-compatible OCE issuer. The
bridge must preserve grant, owner epoch, attempt, material identity/version,
expiry and authentication evidence. Source schema, bridge protocol and transport
are not yet qualified.

## Concrete caller flows

[Successor caller flows](migration.md#successor-caller-flows) trace the concrete
API sequences through these contracts.

The proposed #1785 `withSourceToken` caller uses management discovery. Only
trusted sender/custody callbacks consume material; caller functions cannot receive
it or bypass capture, checks or response policy. Agent flags and bootstrap
delegation cannot grant preparation. See [security](security.md) for holds and forks.
