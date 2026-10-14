# Protected static inference

The optional `egress_proxy` Driver adds request-bound static credential access to
credential sources. This is an implementation slice of
[RFC 0020](../../../specs/rfcs/0020-egress-proxy-credential-lifecycle/index.md),
not qualification of an OpenShell deployment or completion of that proposal.
The bundled OpenShell release does not provide the required credential-access
counterpart. A fresh Agent revision requires a matching gateway and supervisor
that implement the loaded-enforcement receipt and signed instance contract below.
A gateway manifest, loaded policy or historical receipt alone does not establish
protected readiness. Installed runtime qualification remains separate.

## Supported boundary

The first provider admits one static `openai` source, one dedicated Agent
execution, and its explicitly configured primary model. It accepts HTTPS POST
requests to `/v1/responses` with explicit `store: false`, text input, bounded
reasoning state and local function/custom tools, including namespaces. The closed
schema covers the selected Codex 0.163.0-alpha.2 Responses HTTP profile. Text-only
`/v1/chat/completions` remains available without streaming or tools. Unknown fields,
remote provider tools, image/audio/file input, prior-response lookup, arbitrary
model selection and discovery refuse before credential access.

The provider normalizes an inference-only grant with `providerTools: none`.
Normal protected Codex configuration derives `web_search="disabled"`,
`supports_websockets=false`, `request_max_retries=0` and `stream_max_retries=0`
from that grant. Local tools and ordinary Harness components remain enabled;
unprotected Agents keep their existing configuration. Custom endpoints do not
imply arbitrary provider compatibility: they must implement this same closed
protocol and response policy.

Requests are limited to 1 MiB and an absolute 30-second operation horizon.
Finite Responses SSE is buffered completely before delivery, subject to the same
30 seconds and 4 MiB response limit. This increases time to the first visible
output; it is not indefinite streaming. Redirects, upgrades, compressed or opaque
responses, dynamic credential issuance and multiple source bindings are unsupported.

New sources created while `egress_proxy` is selected use `adoption: live` and
`retention: none`. Each operation reads its exact Namespace Secret through the
selected versioned Secret Driver. Kubernetes supplies the owned object UID and
resourceVersion. Secret updates apply to the next operation without changing the
source's configuration generation. The Agent receives a nonsecret client marker,
not the provider key.

Existing sources retain their gateway copy until an authorized caller sends
`PATCH /namespaces/:namespaceId/credential-sources/:credentialSourceId` with
`{"adoption":"live"}`. Admission requires exact `credential_source:update`,
`secret:operate`, a supported counterpart, and valid candidate material. This
first implementation requires the source to be unbound. Failed admission leaves
its previous configuration intact. Source GET/list expose adoption and retention;
`status.state: ready` means source admission, not installed runtime protection.

## Authority and response handling

The supervisor calls `HttpCredentialAccess.Resolve` over verified TLS with its
gateway-issued extension JWT. OCC verifies the issuer, audience, key ID,
Ed25519 signature, expiry, supervisor subject, immutable Sandbox ID and signed
`instance_id`. The supervisor registers its own startup instance before requesting
an extension token; the gateway validates that supplied instance against the
authenticated Sandbox registration before signing it. Missing or stale instances
refuse. This trusts the supervisor and gateway; it is not remote binary attestation.
OCC maps that identity to a persisted installation and an exact admitted revision route.
Workload headers cannot supply execution identity, Namespace, source, or provider.

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
Duplicate JSON keys, incomplete/unknown events and unsupported framing refuse.
Credential protection scans decoded strings and joined text deltas, including
URL encoding and base64 forms. This is a conservative supported-format policy,
not a proof against arbitrary provider transformations. The counterpart must
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
bound. Gateway signing uses `[openshell.gateway.gateway_jwt]`. Insecure transport is unsupported. Both peers must negotiate
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

A first-slice withdrawal destroys only that owned single-binding Sandbox and
confirms absence. A policy-only reduction for multiple bindings is not implemented.
Deployment qualification must additionally prove supervisor enforcement and
workload no-bypass networking. Mixed-version hot activation is not established by
these consumer checks.

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
