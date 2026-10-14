# Protected static inference

The optional `egress_proxy` Driver adds request-bound static credential access to
credential sources. This is an implementation slice of
[RFC 0020](../../../specs/rfcs/0020-egress-proxy-credential-lifecycle/index.md),
not qualification of an OpenShell deployment or completion of that proposal.
The bundled OpenShell release does not provide the required credential-access
counterpart. Missing negotiation or loaded policy evidence refuses admission or
provisioning; legacy credential substitution is not protected readiness.

## Supported boundary

The first provider admits one static `openai` source, one dedicated Agent
execution, and its explicitly configured primary model. It accepts HTTPS POST
requests to `/v1/responses` with string input and explicit `store: false` or `/v1/chat/completions` with text
messages. Request bodies are limited to 1 MiB and an absolute 30-second deadline.
Streaming, tools, arbitrary model selection, discovery, redirects, upgrades,
compressed responses, dynamic credential issuance, and multiple source bindings
are unsupported. Native Harness clients that require these operations fail;
this path does not establish a successful native model turn.

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
Ed25519 signature, expiry, supervisor subject and immutable Sandbox ID. It maps
that identity to a persisted installation and an exact admitted revision route.
Workload headers cannot supply execution identity, Namespace, source, or provider.

OCC checks the Agent's current exact source `operate` permission before reading
material. `AuthorizeSend` opens a separate policy transaction and checks that
permission again, together with the selected material, source generation,
binding, installation, withdrawal state and rejection fence. The opaque handle
and ordered injection digest are single-use. The supervisor must begin its sole
send before the returned bound, at most one second after the final check. The
accepted check-to-send race remains; no automatic retry is authorized.

The response policy requires a complete JSON object of at most 4 MiB. It rejects
unsupported framing and credential reflection, including decoded JSON strings,
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
closed. It allows at most 1,024 outstanding operations and 4,096 request replay
reservations, retained until the authenticating JWT expires. Shared state for
replicated authority processes is not implemented.

The operator registers the authority as `[[openshell.supervisor.middleware]]`
with `grpc_endpoint`, `audience`, `tls_ca_cert_path`, and a 4 MiB payload
bound. Gateway signing uses `[openshell.gateway.gateway_jwt]`. Insecure transport is unsupported. Both peers must negotiate
`openshell.supervisor-middleware.http-credential-access.v1`.

Compute gives the paired Sandbox the admitted plan. The adapter requires exact
loaded network policy and middleware configuration, including every auxiliary
rule produced by the paired Sandbox,
`credential_authority: true` and `fail_closed`, before recording the immutable
Sandbox ID. A first-slice withdrawal destroys only that owned single-binding
Sandbox and confirms absence. A policy-only reduction for multiple bindings is
not implemented. Deployment qualification must additionally prove the actual
supervisor enforces the hook and the workload cannot bypass it.

See the [request flow](../../flows/credential-source-egress.md) for source ownership
and the [verification boundaries](../../testing/static-egress.md) for available proof.
