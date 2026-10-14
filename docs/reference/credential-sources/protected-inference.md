# Protected static inference

The optional `egress_proxy` Driver adds protected static inference through
OpenShell. For each admitted request, OCC checks current authorization, reads the
current Kubernetes Secret material, and protects the response before the trusted
supervisor releases it to the Agent.

This first connected slice implements part of
[RFC 0020](../../../specs/rfcs/0020-egress-proxy-credential-lifecycle/index.md).
It requires a fresh Agent revision and matching OpenShell gateway and supervisor
candidates implementing the receipt and signed-instance contract below. The bundled
OpenShell release does not provide that counterpart. A manifest, loaded policy or
historical receipt alone does not establish protected readiness; installed runtime
qualification is separate. GitHub's dynamic credential lifecycle, retirement of
the old Driver path, additional bindings and general platform rollout remain
follow-up work.

## Supported boundary

The first provider admits one static `openai` source for one dedicated Codex
Agent execution and its explicitly configured primary model.

| Request                     | Supported form                                                                                                                                                                                                 |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /v1/responses`        | HTTPS, explicit `store: false`, text input, bounded reasoning state and local function/custom tools, including namespaces. The closed schema covers the selected Codex 0.163.0-alpha.2 Responses HTTP profile. |
| `POST /v1/chat/completions` | HTTPS and text only, without streaming or tools.                                                                                                                                                               |

Unknown fields, remote provider tools, image/audio/file input, prior-response
lookup, arbitrary model selection and discovery are refused before credential
access. Custom endpoints must implement the same closed protocol and response
policy; configuring one does not establish arbitrary provider compatibility.

The provider normalizes an inference-only grant with `providerTools: none`.
Normal protected Codex configuration derives `web_search="disabled"`,
`supports_websockets=false`, `request_max_retries=0` and `stream_max_retries=0`
from that grant. The startup authentication probe also passes both zero-retry
settings explicitly because it runs with `--ignore-user-config`. A protected
probe timeout fails startup without a second model request. Local tools and ordinary
Harness components remain enabled; unprotected Agents keep their existing
configuration.

Requests are limited to 1 MiB and an absolute 30-second operation horizon.
Finite Responses SSE is buffered completely before delivery, subject to the same
30 seconds and 4 MiB response limit. This increases time to the first visible
output; it is not indefinite streaming. Redirects, upgrades, compressed or opaque
responses, dynamic credential issuance and multiple source bindings are unsupported.

### Choose a source

New sources created while `egress_proxy` is selected use `adoption: live` and
`retention: none`. Each operation reads its exact Namespace Secret through the
selected versioned Secret Driver. Kubernetes supplies the owned object UID and
resourceVersion. An update applies to the next operation without changing the
source's configuration generation. The Agent receives a nonsecret client marker,
not the provider key.

An existing source keeps its gateway copy until an authorized caller opts it in:
`PATCH /namespaces/:namespaceId/credential-sources/:credentialSourceId` with
`{"adoption":"live"}`. The caller needs exact `credential_source:update` and
`secret:operate` permissions. The source must be unbound, the counterpart supported,
and the candidate material valid. A failed admission leaves the previous
configuration intact. Source GET/list expose adoption and retention;
`status.state: ready` means source admission, not installed runtime protection.

## Authority and response handling

The supervisor calls `HttpCredentialAccess.Resolve` over verified TLS with its
gateway-issued extension JWT. OCC verifies the issuer, audience, key ID,
Ed25519 signature, expiry, supervisor subject, immutable Sandbox ID and signed
`instance_id`. The supervisor, outside the Agent, registers its startup instance
before requesting an extension token. The gateway validates that supplied instance
against the authenticated Sandbox registration before signing it. Missing or stale
instances refuse. This is gateway-validated registration: it trusts the supervisor
and gateway and does not attest the supervisor binary. OCC maps the identity to a
persisted installation and exact admitted revision route. Workload headers cannot
supply execution identity, Namespace, source, or provider.

OCC checks the Agent's current exact source `operate` permission before reading
material. `AuthorizeSend` opens a separate policy transaction and checks that
permission again, together with the selected material, source generation,
binding, installation, withdrawal state and rejection fence. Both checks query
current loaded-enforcement evidence and require its instance/configuration to
match the admitted installation and signed caller. Replacement cannot inherit a
previous installation record. The opaque handle
and ordered injection digest are single-use. The supervisor must begin its sole
send before the returned bound, at most one second after the final check. The
accepted check-to-send race remains; no automatic retry is authorized.

The response policy requires a complete JSON object or a finite Responses SSE
sequence of at most 4 MiB. SSE events use a closed JSON schema, consistent response
identity, ordered sequence numbers when present and a terminal response event.
Output items have bounded, unique identities and must finish before release;
indexed events must belong to their open item. Duplicate JSON keys,
incomplete/unknown events and unsupported framing refuse. Credential protection
scans decoded strings and the text-delta concatenation exposed by Codex, even
across distinct item IDs, including URL encoding and base64 forms. Supported
function-call arguments are decoded through their protocol-defined JSON layer,
including completed accumulated deltas, with a 1 MiB argument bound and bounded
object depth and size. Strings inside that object are not decoded recursively.
This supported-format policy does not prove protection against arbitrary provider
transformations. The counterpart must
withhold incomplete responses and strip protected headers and trailers. A 401
fences that store-qualified material version in PostgreSQL; a new version can
be selected. Provider effects may already exist when delivery is blocked. There
is no durable send receipt or inferred outcome recovery in this slice.

## Installation configuration

Keep the existing [OpenShell Backend and Sandbox configuration](../drivers/openshell-credential-gateway.md).
Add the same egress Driver ID to `backend[].drivers.egress_proxy` and select:

```yaml
drivers:
  egress_proxy:
    id: openshell-egress
    configuration:
      middlewareName: oce-authority
      binaries: [/usr/bin/model-client]
      authority:
        host: 127.0.0.1
        port: 9444
        certificatePath: /etc/openclaw/egress/tls.crt
        privateKeyPath: /etc/openclaw/egress/tls.key
        issuerPublicKeyPath: /etc/openclaw/egress/issuer.pub
        issuer: https://openshell-gateway.example.com
        audience: oce-egress
        keyId: current
```

The API owns this TLS listener; the worker does not open another listener.
Development requires loopback. Production requires an explicitly configured
reachable host and operator-provided TLS and issuer trust. The existing Backend
must use explicit HTTPS and bearer-file authentication. No new chart exposure or
publication is provided by this change. All phases of an operation must reach
the same authority process; outstanding handles are local and restart fails
closed. It allows at most 1,024 pending or outstanding operations, reserving
capacity before authentication or storage awaits, and 4,096 replay reservations.
Excess traffic refuses. Protected request IDs are canonical UUIDv7 values whose
embedded creation time fixes the replay horizon at creation plus 30 seconds,
independent of JWT expiry or a shorter submitted deadline. Creation may be at most
one second ahead of the authority clock; the deadline must be future and within
that fixed horizon. Reusing an ID cannot extend it. A new ID does not authorize
automatic retry after possible effects. Shared state for replicated authority
processes is not implemented.

The operator registers the authority as `[[openshell.supervisor.middleware]]`
with `grpc_endpoint`, `audience`, `tls_ca_cert_path`, and a 4 MiB payload
bound. Gateway signing uses `[openshell.gateway.gateway_jwt]`. Insecure transport
is unsupported. Both peers must negotiate
`openshell.supervisor-middleware.http-credential-access.v1`.

Compute gives the paired Sandbox the admitted plan. The adapter requires exact
loaded network policy and middleware configuration, including every auxiliary
rule produced by the paired Sandbox,
`credential_authority: true` and `fail_closed`. The authenticated policy-status
response must include `LoadedEnforcementEvidence` for the exact Sandbox, current
registered instance, policy version/hash, configuration/environment revisions and
`openshell.supervisor-middleware.http-credential-access.v1`. Configuration revisions
include the installed middleware registry. The adapter stores an immutable fingerprint
and requeries the gateway during access and send authorization. Missing, failed,
rejected, replaced or stale evidence refuses; a cached manifest cannot substitute.
The gateway must validate current registration and effective configuration when
reporting and querying this evidence. A global policy override that does not match
the admitted Sandbox revision cannot qualify.

Before the first model probe, the generated Harness waits up to 180 seconds for
authenticated enrollment through its existing bearer-passthrough service.
Compute observes enforcement, commits the installation and verifies it is still
current before the selected Sandbox Driver releases startup. The challenge binds
the admitted execution and plan to a fresh nonce for each Harness process.
Wrong-instance, stale and replayed releases refuse. Enrollment carries no provider
material or send permission; both request authority checks still run. An expired
wait holds an `egress-enrollment` startup failure with code `UNAVAILABLE`. A
protected manifest without enrollment input refuses before starting a native
process. Inspect installation evidence and Harness service reachability before
deploying again.

A Harness-only process restart also waits on a fresh challenge. The default
Kubernetes Compute selection does not schedule periodic active-revision
maintenance, so automatic release after that restart is not supported by this
slice. A new deployment is the supported recovery procedure; an old release is
never reused.

The adapter receives the runtime Namespace selected by Compute. IAM decisions,
persisted execution identity and audit evidence retain the logical Namespace ID.

A first-slice withdrawal destroys only that owned single-binding Sandbox and
confirms absence. A policy-only reduction for multiple bindings is not implemented.
Deployment qualification must additionally prove supervisor enforcement and
workload no-bypass networking. Use fresh revisions with matching gateway and
supervisor candidates. Mixed-version hot upgrades are not supported in this slice.

### Refusals and recovery

| Condition                                                                        | Result                                                                                                                               |
| -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| Installation missing or no longer current                                        | Access is refused. Check the current loaded-enforcement evidence and exact Sandbox instance.                                         |
| Startup enrollment expires                                                       | The Harness holds `egress-enrollment` / `UNAVAILABLE`; check the installation and authenticated service, then deploy a new revision. |
| Unsupported operation, stale authorization, invalid handle or exhausted capacity | The attempt is refused before its business send. A new request ID does not authorize retry after possible effects.                   |
| Response is incomplete, unsupported or reflects protected material               | Delivery is blocked with `egress_response_policy`; the provider may already have acted.                                              |
| Provider returns 401                                                             | The material version is fenced; a new Secret version can be selected for a later operation.                                          |

## Extension ownership

| RFC responsibility                  | Implemented owner and limit                                                                                                                                                                                                              |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Credential Provider                 | Registered `CredentialProviderDefinition` normalizes source configuration and grants, declares routes, classifies operations, injects static material and protects responses. The current operation/grant types describe inference only. |
| Credential binding                  | `EgressPlan` freezes source generation, grant, route, execution and binding identities during ordinary Agent admission. Workload headers cannot select them.                                                                             |
| Credential access                   | `EgressForwarder` and controller policy units enforce authenticated identity, current permission, receipt and material evidence around the selected versioned Secret Driver. No request-time mint or refresh scheduler exists.           |
| Enforcement adapter                 | `EgressProxyDriver` prepares, verifies and withdraws the paired Sandbox attachment. The OpenShell adapter owns receipt interpretation and current-state queries.                                                                         |
| Trusted sender and response custody | The supervisor performs the sole business send and withholds the complete response until provider-owned policy approves delivery. This requires the matching runtime counterpart.                                                        |

Another provider requires a registered definition and a supported declarative
binding. New operation families need deliberate contract extensions; the current
inference fields are not a universal custom-provider API. Dynamic issuance,
provider revocation and distributed authority state remain outside this slice.

See the [request flow](../../flows/credential-source-egress.md) for source ownership
and the [verification boundaries](../../testing/static-egress.md) for available proof.
