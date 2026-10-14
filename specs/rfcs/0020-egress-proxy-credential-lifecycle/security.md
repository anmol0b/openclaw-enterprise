---
rfc: index.md
---

# Egress Proxy security model

[RFC-0020](index.md) must let a potentially compromised Agent use a provider without giving it the
provider credential or a way around enforcement. A trusted sender checks authority before it obtains
material and again before it sends. Even then, withdrawal can race dispatch, and blocking a response
cannot undo the provider’s action.

Review this as a proposed security contract, not evidence of a qualified system.
[Lifecycle](lifecycle.md) covers preparation, rotation, startup and recovery.
[Management](control-contracts.md) and [runtime contracts](runtime-contracts.md) define the proposed
fields, checks and results.

## Assets and threat model

The design protects provider credentials and refresh inputs; admitted sources,
routes and grants; Agent and caller identities; provider operations and their
responses; and workspace data preserved during parking or a fork. An Agent can
be compromised, issue malicious requests, or try to obtain provider material.
A Secret writer can change live-adopted values; existing explicit-update sources
retain approved immutable material until an authorized source update. A provider,
store or network can fail, return unexpected content, or leave an effect uncertain.

The trust boundary is between Agent workloads and trusted senders, resolvers,
lifecycle owners, Secret Drivers and OCC. Trusted components and their
configuration need their own protection and isolation. A resolver handle
guards mistakes among trusted callers; it does not defend against hostile code
in the same process. A route constrains mediated use, but cannot narrow the
authority of a bearer stolen from a trusted component or provider.

| Abuse or failure                                                     | Proposed boundary                                                                                                       |
| -------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| An Agent tries to steal credentials or bypass its grant.             | Enforce egress and keep material and handles outside the workload. OCC checks each operation against current authority. |
| A caller substitutes an operation, route or material after approval. | Bind the final check to the actual immutable operation and selected material identity and version.                      |
| A shared source or warm token is used across the wrong scope.        | Authorize each Agent; partition resolver reuse by admitted source generation, normalized grant and isolation boundary.  |
| A provider returns a credential in a response.                       | Apply provider-specific response policy; redact or refuse forms that cannot be handled safely.                          |
| A refresh, send or clone has an unknown outcome.                     | Retain the attempt and reconcile the effect or reauthorize; do not blindly replay it.                                   |
| An owner loses access or a workspace is copied.                      | Hold and park on confirmed last-owner loss; a deep fork receives a fresh stopped identity and no inherited authority.   |

These boundaries depend on qualified enforcement and custody. Source inspection
or fixture behavior alone cannot prove them.

## Callers and trust boundaries

OCC admits source, binding, backend, provider, route and grant configuration.
The trusted sender derives caller context from an authenticated boundary, not
from the request's assertions. An Agent has a stable Namespace-scoped
ServicePrincipal and a separate bearer for an individual execution. Each Agent
must be authorized to use a binding, even when the source is shared.

### Agent and bootstrap

Trusted bootstrap is a separate caller with authenticated delegation limited to
the execution and configured repository. It need not traverse the Agent's proxy.
Its request-path resolution is warm-only, and its delegation does not grant
management preparation. Its clone and cleanup duties are in
[repository preparation](lifecycle.md#2-prepare-the-optional-repository).

### Management preparation

Configuration or discovery authenticates a control-plane caller separately. Authorize the exact
Installation, Namespace, source, purpose, operation, scope and destination, including applicable
initiating-user and saved-binding rights. No Agent flag or request field can confer this authority.

Management captures the business operation *before* seeking preparation authority. Only if
authorized may it ask the designated owner to prepare or refresh material. In MVP, that owner is
OpenShell; the business Forwarder is a trusted library inside OCC. OCC may hold an access token
briefly for injection. It checks authority before obtaining that material and again, after
preparation, before *each* provider send. The lifecycle owner separately authorizes issuer calls.
Later service or worker placements must preserve these boundaries.

### Retrieval and recovery

Only designated trusted sender or custody code may consume usable material. There is no arbitrary
caller callback, exported signing or refresh root, second refresher or token returned to an Agent or
UI. Provisioning roots to the lifecycle owner requires its own authorization. Return a sanitized
business response and audit caller, initiating principal, source, grant, destination, purpose and
outcome without secrets.

Deny use on withdrawal, unavailable authority, failed preparation or material still unusable by the
original deadline. Failed or cancelled retrieval may nonetheless have caused a refresh. Preserve
that attempt; never replay it blindly.
[Management retrieval](lifecycle.md#management-preparation-and-retrieval) does not weaken warm-only
Agent and bootstrap resolution.

## Authorize each operation

Consider a Git read of repository `123`. The sender needs to know who is calling, which repository
and action policy covers, and which exact material it would send. A valid token alone answers none
of those questions.

1. **Capture.** Authenticate the caller and seal the actual operation: destination, protocol
   authority and policy-relevant content. For a stream, expose those semantics to OCC and enforce a
   registered grammar and finite bounds. A digest alone is not inspectable; unbounded buffering is
   not required.
2. **Before access.** Check current authority online for this caller, versioned route, normalized
   grant and operation. Require an admitted binding for credentialed use. The provider classifies
   GitHub repository ID and action; a request cannot select another source or backend, load a driver
   or widen the grant. Refuse on unavailable authority, ambiguous route, unsupported operation or
   insufficient scope.
3. **Before send.** Check online again over the same immutable operation, caller, versioned route
   and grant, now with nonsecret identity and version of the material selected, or explicit `none`.
   For static material bind admitted mode and reference, selected store, scope and exact version. A
   snapshot does not depend on the provenance Secret’s current value. Consumer permission cannot
   approve replacement. Policy never receives credential bytes, and the sender cannot substitute
   material or operation.
4. **Dispatch.** Recheck usability and send once within the short finite send-start limit and
   original absolute deadline. A changed route or grant needs readmission and repeated checks.

Apply the sequence to credential-free operations and cache hits too. Every HTTP subrequest,
redirect, retry or new operation on a reused connection needs both fresh checks and any resolution.
No transport encoding, cached allow or retry can remove a check or extend the original deadline.
Concrete deadlines, time protocol and enforcement remain to be selected. The final-check race is
described [below](#withdrawal-and-owner-loss).

## Resolution and custody

The request-path Resolver serves static and dynamic material through one
contract. It accepts an admitted binding and operation context and returns a
use-bound, single-use handle to trusted code, or `Denied`, `NotReady` or
`Unavailable`. A handle conveys no authority to send. Material version can
change independently of configuration generation. The implementation must
provide nonsecret identity, version and expiry evidence for the final check and
dispatch. [MaterialEvidence and handle validation](runtime-contracts.md#two-policy-checks-and-common-resolution)
define required fields and associations; physical transport remains to be qualified.

### Dynamic reuse

Dynamic token reuse is confined behind the Resolver by source generation,
normalized grant and isolation boundary. A narrower grant cannot borrow a
broader token. Every credentialed Agent or bootstrap operation resolves again.
There is no dynamic token push, reusable proxy-side cache or fallback, and static
stale grace does not apply. A healthy Resolver may serve eligible unexpired
material during an issuer outage; Resolver failure refuses use. For Agent and
bootstrap requests, cold or expired dynamic material yields `NotReady` without
request-time issuance, signing, refresh or scheduling. Separately authorized
management preparation does not change that lookup contract or permit proxy
fallback. Authenticated rejection feedback can prompt background recovery through
the lifecycle owner; it does not make lookup schedule refresh or permit an
automatic sender retry. See [withdrawal and recovery](lifecycle.md#4-withdraw-and-recover).

### Custody

Source policy must permit material at the trusted sender, and its implementation
must qualify that custody. Registering a refresh source does not itself authorize
delivery of signing or refresh inputs to the Egress Proxy or other
consumers; those inputs remain confined to the roles that need them under the
admitted custody policy. Keep provider credentials and resolver handles out of
Agent workloads, files and diagnostics; strip Agent authentication before
forwarding. Static freshness and typed failures are specified in
[live Secret cutover](lifecycle.md#live-secret-cutover); rotating input custody,
fencing and durable replacement are specified in
[withdrawal and recovery](lifecycle.md#4-withdraw-and-recover).

Admitted custody policy and runtime qualification are RFC requirements, not
claims established by current adapters.

## Protect responses

A trusted provider-specific policy covers successes, errors and streams,
including headers, bodies, trailers and encodings.

| Result                       | Treatment                                                                                                                                                              |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Safe content                 | Pass the permitted response to the Agent.                                                                                                                              |
| Content requiring protection | Redact or refuse it; unsafe forms cannot pass unchecked. The Agent receives a permitted response or placeholder, not provider material.                                |
| Provider rejection           | Retain a policy-processed `SafeResponse` and typed exact-version feedback. Preserve the failure where safe; redact or refuse as configured. Never retry automatically. |

A blocked response, provider rejection or local timeout after dispatch does not
establish that the provider performed no action. Distinguish refusal before
send from a known response and a possible dispatch. Preserve uncertain attempts
for the [recovery owner](lifecycle.md#4-withdraw-and-recover).

## Protocol and bypass boundaries

Prevent unmediated Agent egress and bind the destination and protocol authority
to the authorized operation.

| Traffic or failure                     | Required boundary                                                 |
| -------------------------------------- | ----------------------------------------------------------------- |
| Opaque SSH, database and other traffic | Deny without individually authorizable operations.                |
| UDP and QUIC                           | Prevent bypass of enforcement.                                    |
| Additional protocols                   | Require explicit operation boundaries and evidence.               |
| Enforcement or dependency failure      | Hardened deployments must not silently fall back to no-op egress. |

## Withdrawal and owner loss

A check that observes a committed reduction or hold denies the removed access. But in MVP a send can
*start after withdrawal was acknowledged* if its final check raced the change. Work already in
flight may continue to its original deadline. Cancellation is best effort and timeout proves neither
remote cancellation nor absence of an effect. Ordered admission and renewable stream leases remain
follow-ups.

Report logical OCE denial, Egress detachment and provider-supported revocation separately. None can
recall an exported bearer or undo a sent operation. Expanding scope requires any newly required warm
material and a fresh check; authorized narrower access can continue.

When an OCE operator disables or removes the *last* authorized owner, install a hold and fence new
admissions, subject to the dispatch race above. A team Agent with another owner continues. Unknown
owner or directory state is not confirmed loss. Report incomplete containment and `parking` until
stop and preservation evidence justify `parked`.

Deployment, restart, repair, deletion and garbage collection cannot bypass the hold or remove
protected data. Platform cleanup of exact accepted work survives loss of requester access. Releasing
the hold needs current authority and fresh execution admission. Synchronizing external
identity-provider offboarding is later work.

## Authorized forks

An authorized reader can fork the declared readable artifact set from an
immutable captured version. Recheck source-read and destination-create
authority before visibility. The deep copy has independent application data and
mutable references, a fresh stopped identity and runtime home, and no inherited
credentials, grants, approvals or sessions. Copied schedules, hooks and pending
work remain inert until admitted. The original remains available for authorized
read-only review. Copy-on-write and deeper incident preservation require
separate designs.

## Accepted limits and open questions

The check-to-send race and best-effort cancellation are accepted limits. These
integration choices remain open:

| Choice                         | Evidence or constraint                                                                                                                                    |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| First sender/custody transport | Qualify execution bearer issuance, delivery and lifetime, bootstrap delegation and management identity. Identity fields and audiences are specified.      |
| GitHub issuer bridge           | OpenShell owns renewal; qualify source schema, issuer authentication and transport, preserving grant, owner epoch, attempt, material and expiry evidence. |
| Provider/operation support     | Qualify GitHub, static inference and DNS enforcement. Qualify Codex WebSocket boundaries or an HTTP/SSE path.                                             |

Engineering must choose concrete deadlines, clocks and alert thresholds within
these contracts. External authorization integration, identity exchange, horizontal
HA and proxy fallback need separate work. These choices do not weaken either
check, the custody boundary or fail-closed behavior.

## Required validation

A hardened Egress Proxy MVP must qualify its declared provider slice with actual
enforcement. Evidence must cover caller and tenant isolation; scope and grant
checks; withdrawal and partitions; protocol bypass; safe response handling;
cache and renewal bounds; bounded startup; and uncertain cleanup. Any slice
using rotating inputs must prove concurrency fencing, durable replacement,
restart and uncertain-effect recovery. OCE 1.0 must qualify the full static
inference, GitHub preclone, Codex OAuth and custom dynamic paths.

Migration proof must also exercise stale commands, conflicting request IDs,
forged attachments/receipts, catalog removal cleanup, late attachment after
withdrawal, family-wide rotating locks across distinct grants, and rejection of
N after N+1. Duplicate authenticated receipt/version reports must survive restart
without repeated recovery work. Exercise both static adoption modes, failed and
authorized opt-in, unchanged approved material after a Secret-only update, known
revocation, and mode/version isolation across caches. Cover mismatched version
refs, foreign snapshot owners/scopes, unavailable provenance with an accessible
approved snapshot, zero-retention snapshot reads, and rejection followed by
cache eviction/reread. Confirm every legacy consumer has moved before removing
old exports and persistence coupling.

Check profile capabilities at startup and Agent admission against qualification
evidence for the exact implementation versions, configuration, provider/protocol
slice and custody. Self-declared capabilities are insufficient. Minimal CI and
fixture/no-op adapters cannot prove enforcement or injection; deployment
acceptance alone does not prove material or Agent readiness. Keep source,
fixture, installed-runtime and live-provider evidence distinct. The
[qualification plan](lifecycle.md#implementation-discovery-and-qualification)
describes remaining integration and proof work.
