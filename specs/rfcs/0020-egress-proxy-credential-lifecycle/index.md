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

Agents need provider access without receiving credentials, and OpenClaw Enterprise (OCE) needs replaceable egress. Today `CredentialGatewayDriver` combines source management with attachments. The [static credential workflow](../../../docs/reference/credential-sources.md#update-a-source) copies values into the gateway; a Secret change requires a source update and redeployment.

Retire that Driver, introduce `EgressProxyDriver`, retain `SandboxDriver` networking, and evolve `SecretDriver` and `CredentialRefreshDriver`. Internal source control, forwarding, authorization, resolution and provider contracts complete the path. GitHub and static inference are both MVP requirements. All interfaces here are proposed, not implemented exports.

<a id="roles-and-deployment"></a>

## Architecture

An owner configures a source and grants use. The OpenClaw Control Plane (OCC) admits configuration; Compute installs the attachment; a trusted sender mediates egress outside the Agent.

![Proposed Agent request path](assets/overview.svg)

_[Editable diagram](assets/overview.mmd) · [Control contracts](control-contracts.md) · [Runtime contracts](runtime-contracts.md) · [Lifecycle](lifecycle.md) · [Security](security.md)_

| Contract                                     | Responsibility                                                                       |
| -------------------------------------------- | ------------------------------------------------------------------------------------ |
| `CredentialSourceControl`                    | OCC manages admitted backend sources.                                                |
| `EgressProxyDriver`                          | Compute configures, observes and withdraws execution bindings.                       |
| `SandboxDriver` networking                   | Install the exact attachment, intercept traffic and prevent bypass.                  |
| `EgressForwarder` and `EgressAuthorizer`     | Capture, check, inject, send and protect responses; OCC evaluates current authority. |
| `CredentialResolver`                         | Resolve admitted static or warm dynamic material per operation.                      |
| `SecretDriver` and `CredentialRefreshDriver` | Read versioned inputs; manage one lifecycle owner and warm reader.                   |
| Provider definition and `CredentialIssuer`   | Define provider semantics; issue and validate scoped material.                       |

One OpenShell composition may fulfill multiple roles; separate contracts do not require separate daemons. Trusted factories bind immutable identities, versioned routes and grants. Callers cannot select code, another source or a wider scope. Existing Kubernetes, same-Backend and Repo guards stay until replacement integration is qualified.

![Proposed credential sources and background preparation](assets/credential-architecture.svg)

_The Token Service is the `CredentialRefreshDriver` responsibility. [Editable diagram](assets/credential-architecture.mmd) · [Configuration and warmup](lifecycle.md#1-configure-and-warm)_

<a id="examples-and-startup"></a>

## GitHub and inference

|           | GitHub App                                                                                                                                           | Static inference                                                                                                          |
| --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| Configure | Admit repository IDs and permissions.                                                                                                                | New sources default to live Secret adoption. Existing sources retain approved immutable material until authorized opt-in. |
| Prepare   | OpenShell renews in the background through an OAuth-compatible OCE issuer. OCE retains the App key and validates scope; OpenShell commits the token. | Resolver reads the admitted live value or approved immutable version/snapshot.                                            |
| Use       | Read the exact warm grant; cold returns `not_ready` without issuance.                                                                                | Read the admitted selection or eligible retained material.                                                                |
| Change    | Ordinary renewal keeps eligible committed material usable.                                                                                           | Live values change without redeploy; explicit-update material changes only through an authorized source update.           |

Optional repositories remain first-class. Compute waits a bounded time for required warmth; bootstrap checks each clone operation and fails closed by default. Clone-gate opt-out grants no additional authority. Compute/bootstrap owns partial-workspace cleanup. See [repository preparation](lifecycle.md#2-prepare-the-optional-repository).

## Declare access, then bind the request

Configuration maps **Agent → binding → source → backend/provider**, with an admitted grant. Capture binds the verified caller and actual request to that declaration.

| Example                                                                                        | Selection                                                                               |
| ---------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `build-agent → repo-reader → company-github → OpenShell/GitHub`; repository `123`, read access | Automatically select the unique matching admitted route.                                |
| `build-agent → inference → model-source → OpenShell/model provider`; approved model            | Use the same capture/forward path with static resolution.                               |
| Multiple routes match                                                                          | Require an explicit validated binding selector that yields one route; otherwise refuse. |

Selection is automatic when unique; an explicit selector uses the same validation and contracts. A configured placeholder or trusted integration identifies a binding; it grants no authority. An invalid selection, denied authority or unavailable credentials never triggers fallback to another identity or a credential-free route. See [selection rules](runtime-contracts.md#binding-selection).

Trusted integrations call `capture` then `forward`; a request-scoped SDK may wrap both. Agent clients never orchestrate these checks or receive material handles.

<a id="authorization-and-forwarding"></a>

## One request

1. **Capture:** Authenticate the caller, select the route and seal the operation.
2. **Check:** OCC evaluates current authority before material access.
3. **Resolve:** Select admitted static or warm dynamic material into a request-bound handle.
4. **Check again:** OCC checks the operation and selected material identity/version, or explicit absence.
5. **Send:** Recheck usability, inject, send once and apply response policy.

Both OCC checks are fresh, including cache hits and credential-free operations. A handle grants no authority. Redirects and new operations repeat the checks. Provider failures pass through only when safe; there is no automatic retry after possible dispatch. Finite deadlines bound the accepted [check-to-send race](security.md#authorize-each-operation).

### Authorized management preparation

The MVP management Forwarder is a trusted library **inside OCC**. Authenticated management captures the operation and authorizes the exact source, initiating user and preparation purpose before access. It may ask the same lifecycle owner to prepare, then forwards with both fresh checks and selected-material evidence before each business send.

OpenShell retains storage and refresh; the trusted OCC sender may hold access tokens transiently. Roots never go to management callers, and material callbacks are internal only. Generic contracts permit later service/worker placements. Agent/bootstrap resolution remains warm-only, without a refresh flag, proxy fallback or simulated Agent execution. See [management preparation](lifecycle.md#management-preparation-and-retrieval).

<a id="credential-resolution"></a>
<a id="declarative-configuration-and-request-apis"></a>
<a id="interfaces"></a>
<a id="configuration-and-authorization"></a>
<a id="egress-proxy"></a>
<a id="credential-resolver"></a>
<a id="secret-driver-and-token-lifecycle"></a>
<a id="static-credentials"></a>
<a id="dynamic-credentials"></a>

## Configuration and lifecycle decisions

| Decision                 | Contract                                                                                                                                                                                                                                                                                                                                                                                 |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Static adoption          | Existing approved immutable material survives migration. Snapshot reads use the admitted owner/version; SecretRef is provenance, never a latest-value dependency. Exact source-update authority is required for replacement or live opt-in; consumer permission is not replacement approval. Failed opt-in preserves approved state; known revocation denies. [Migration](migration.md). |
| Static retention         | Ten-minute freshness; four-hour **total** eligible age during classified store errors. Zero retention or zero request-age forces authoritative reading without retention/fallback. [Read bounds](lifecycle.md#live-secret-cutover).                                                                                                                                                      |
| Dynamic lifecycle        | One fenced owner spans the entire input family. Persist attempts and replacements before readiness; uncertain effects are never blindly replayed. [Lifecycle interface](lifecycle.md#lifecycle-interface).                                                                                                                                                                               |
| Live changes             | An admitted grant update may affect the same Execution. Material versions remain separate from configuration generations. [Admission](control-contracts.md#identities-and-admission).                                                                                                                                                                                                    |
| Rejection and withdrawal | Deduplicate authenticated receipt/version feedback; late N cannot invalidate N+1 or repeat recovery. OCE denial, detach and provider-supported revocation are distinct; none recalls exported bearers or undoes sent effects. [Recovery](lifecycle.md#4-withdraw-and-recover).                                                                                                           |

<a id="delivery-and-verification"></a>
<a id="earlier-token-service-proposal"></a>

## Delivery scope

The OpenShell-first MVP must qualify static inference and GitHub, the issuer bridge, warm-only reads, response protection and optional clone. OCE 1.0 additionally requires rotating Codex OAuth and custom dynamic paths with safe concurrency and recovery.

Authenticated transport, bridge correlation and installed provider/protocol behavior remain to be qualified. Fixtures, no-op egress and deployment acceptance do not prove enforcement or readiness. Independent backends, loading/packaging, strong local development, HA, and generalized bootstrap including cloud-init remain follow-ups. See [qualification](lifecycle.md#implementation-discovery-and-qualification).

[Migration](control-contracts.md#complete-legacy-disposition) covers the original eight methods, current validation hook and legacy consumers; retire exports and persistence coupling after parity, without an alias. [Earlier Token Service decisions](lifecycle.md#earlier-token-service-proposal) retain scope, custody and recovery requirements. Optional explicit promotion remains [#1965](https://github.com/openclaw/openclaw-enterprise/issues/1965), outside this amendment.

<a id="appendix-failure-and-recovery"></a>

## Appendix: essential guarantees

Confirmed last-owner loss holds new admissions and asynchronously parks with data retained; team Agents continue for remaining owners. Authorized deep forks start stopped with independent data and no inherited authority. External IdP synchronization, copy-on-write and renewable leases remain later work. [Owner loss](security.md#withdrawal-and-owner-loss) · [Forks](security.md#authorized-forks) · [Required validation](security.md#required-validation).
