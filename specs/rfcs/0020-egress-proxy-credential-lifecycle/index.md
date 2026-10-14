---
author: freeqaz-openai
implementation_status: Not implemented
status: Proposed
---

# Egress Proxy and credential lifecycle

- **ID:** RFC-0020
- **Created:** 2026-10-06
- **Updated:** 2026-10-14
- **RFC PR:** [#1530](https://github.com/openclaw/openclaw-enterprise/pull/1530)

## Problem and proposal

An owner grants `build-agent` read access to GitHub repository `123`. The Agent should be able to fetch that repository without ever receiving a GitHub token. A trusted sender obtains the token, then checks permission again before sending. If that check sees the owner has withdrawn access, it must refuse. If withdrawal races the final check, the request can still reach GitHub; we cannot take it back.

We propose separating three jobs: prepare a credential in the background, authorize the actual operation, and send it from outside the Agent. This replaces `CredentialGatewayDriver`, which combines source management and execution attachments. It also changes the [static credential workflow](../../../docs/reference/credential-sources.md#update-a-source): new sources follow their live Secret by default; existing sources keep the exact material an operator approved. The first release must support **both GitHub and static inference**. The contracts below are proposals, not implemented APIs.

<a id="roles-and-deployment"></a>

## Architecture

The OpenClaw Control Plane (OCC) admits sources and grants. Compute uses `EgressProxyDriver` to configure an execution; `SandboxDriver` installs that exact attachment and prevents bypass. A trusted sender handles the provider request. One OpenShell installation may do several of these jobs; the boxes show [responsibilities](control-contracts.md), not required daemons.

![Proposed request path from the Agent through Sandbox enforcement to a sender that checks with OCC before and after resolving a credential](assets/overview.svg)

[Editable diagram](assets/overview.mmd) · [Runtime contracts](runtime-contracts.md) · [Lifecycle](lifecycle.md) · [Security boundaries](security.md)

<a id="examples-and-startup"></a>
<a id="github-and-inference"></a>
<a id="declare-access-then-bind-the-request"></a>
<a id="authorization-and-forwarding"></a>
<a id="one-request"></a>

## How the Agent reads repository 123

1. **Prepare.** An owner grants read access to repository `123`. In the background, OpenShell renews an installation token through an OAuth-compatible OpenClaw Enterprise (OCE) issuer. OCE keeps the GitHub App key and validates the actual grant and expiry; OpenShell commits the token.
2. **Capture and authorize.** The Agent makes an ordinary Git request. The sender authenticates its execution, captures the actual operation, and [selects the one admitted route](runtime-contracts.md#binding-selection). If several match, an explicit, validated binding must select exactly one. A placeholder identifies a binding; it grants no permission.
3. **Resolve and check again.** OCC checks current authority before the sender asks for a token prepared for this exact grant. If none is ready or it has expired, resolution returns `not_ready` without minting, refreshing or scheduling anything. With usable material, OCC checks the same operation and the selected material identity and version. Neither check may use a cached allow, even on a credential cache hit or an operation that needs no credential.
4. **Send once.** The sender rechecks usability, injects the token and returns only what response policy permits. Redirects and new operations repeat both checks. There is no fallback identity and no automatic retry after possible dispatch. Finite deadlines bound the [final-check race](security.md#authorize-each-operation).

Trusted integrations call `capture` then `forward`; a request-scoped SDK may wrap both. The Agent neither runs these checks nor receives a credential handle.

[Optional repository startup](lifecycle.md#2-prepare-the-optional-repository) uses this same path. Compute waits a bounded time for readiness; trusted bootstrap checks each clone operation. By default an unconfirmed clone blocks startup. Opting out of that gate grants no additional access; Compute and bootstrap still own partial-workspace cleanup.

<a id="credential-resolution"></a>
<a id="declarative-configuration-and-request-apis"></a>
<a id="interfaces"></a>
<a id="configuration-and-authorization"></a>
<a id="egress-proxy"></a>
<a id="credential-resolver"></a>
<a id="secret-driver-and-token-lifecycle"></a>
<a id="static-credentials"></a>
<a id="dynamic-credentials"></a>
<a id="configuration-and-lifecycle-decisions"></a>

## What changes when a credential or grant changes

**A static inference key changes from `v1` to `v2`.** A new live source adopts `v2` on its next required authoritative read, without redeployment. An [existing explicit-update source](migration.md) still reads approved `v1`, even with caching disabled. Only an authorized source update can replace it or opt into live adoption. [Read defaults](lifecycle.md#live-secret-cutover) are ten minutes fresh, four hours *total* eligible age for specified store failures, and no retention or fallback when the applicable age limit is zero.

**A dynamic credential rotates.** [One fenced owner](lifecycle.md#lifecycle-interface) manages the entire input family. It records the attempt before contacting the provider and commits replacement material before reporting readiness. [Rejection and recovery](lifecycle.md#4-withdraw-and-recover) identify the exact receipt and version; a delayed rejection of version N cannot invalidate N+1. An uncertain exchange is never blindly repeated.

**Access changes.** An [admitted grant change](control-contracts.md#identities-and-admission) can apply to the same running execution. OCC denial, confirmed detachment and provider-supported revocation are distinct. None recalls an exported bearer or undoes a provider effect.

### Authorized management preparation

For [configuration and discovery](lifecycle.md#management-preparation-and-retrieval), the MVP sender is a trusted library inside OCC. Management captures the business operation and obtains separate authority to prepare material; the sender then performs both fresh checks before each business send. OpenShell owns storage and refresh. Management callers receive neither root credentials nor a material callback.

<a id="delivery-and-verification"></a>
<a id="earlier-token-service-proposal"></a>

## Delivery scope

[Qualify the OpenShell path](lifecycle.md#implementation-discovery-and-qualification), including authenticated custody, issuer correlation, warm-only reads, response protection and optional clone. Keep existing Kubernetes, same-Backend and Repo guards until replacements qualify. Fixtures and deployment acceptance cannot prove enforcement or readiness. OCE 1.0 also requires rotating Codex OAuth and custom dynamic providers with safe recovery.

[Retire the legacy contracts](control-contracts.md#complete-legacy-disposition) only after consumer and adapter parity. Preserve the [earlier Token Service requirements](lifecycle.md#earlier-token-service-proposal); optional explicit promotion remains [#1965](https://github.com/openclaw/openclaw-enterprise/issues/1965). Independent backends, loading and packaging, strong local development, high availability and generalized bootstrap including cloud-init remain follow-ups.

<a id="appendix-failure-and-recovery"></a>
<a id="appendix-essential-guarantees"></a>

[Confirmed loss of the last owner](security.md#withdrawal-and-owner-loss) holds new admissions and parks with data retained. [Authorized deep forks](security.md#authorized-forks) start stopped, with independent data and no inherited authority. Identity-provider synchronization, copy-on-write and renewable leases remain later work; see [required validation](security.md#required-validation) for the acceptance boundary.
