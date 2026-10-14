# Verify protected static inference

Use these checks to distinguish the OCE source and fixture paths from an installed
OpenShell deployment and a real provider. Run them with the installed workspace
dependencies; an individual suite's coverage does not establish a deployment result.

## Authority and provider fixtures

Run the bounded authority integration:

```sh
node --test tests/integration/static-egress.test.mjs
```

It exercises real Fastify authentication, source and Agent admission, native IAM,
controller transactions, OpenShell adapters, Ed25519 extension identity, TLS gRPC
and HTTPS provider request/response bytes. The Kubernetes Secret Driver uses its
actual SDK against a TLS storage fixture that supplies UID/resourceVersion.
Gateway policy and loaded-enforcement observations are passive fixtures matching
the supplier protobuf contract. The suite checks missing receipts refuse, then
records only the installation returned by the actual Driver consumer. It tests
current evidence again at access and send, including replacement and stale records.
These fixtures do not establish that a supervisor produced or enforced a receipt.
The physical-placement case uses the selected Kubernetes Compute resolver against
the TLS fixture, with logical and runtime Namespace names deliberately different.
No real Sandbox, model service or cluster is launched by this suite.

The cases protect separate failures: current permission revoked between the two
checks; authoritative material rotation; forged identity and unsupported operation
refused before access; replay and selected-material mismatch; credential reflection;
provider rejection fencing; missing counterpart, altered installed policy and
owned withdrawal. Sustained sequential requests cross the 4,096 reservation count
using the supported clock port, without waiting for JWT expiry. Concurrent blocked
Secret reads exhaust the 1,024 active budget before completion and release capacity
on delivery. The provider is a genuine HTTPS wire fixture, not a model turn.

`tests/fixtures/static-egress/codex-responses.json` preserves a selected Codex
0.163.0-alpha.2 packaged CLI request and finite synthetic SSE response consumed by
that CLI. Prompt, model, identity, local tool names and descriptive values are sanitized;
field and local-tool schema shapes are retained. The protected profile disables
provider web search while keeping local functions and namespaces. The default remote web-search
tool is a refusal vector. The application test sends these bytes through actual
classification, credential access, send authorization and whole-response protection.
It also rejects unknown fields/events, remote tools, duplicate JSON keys, incomplete
SSE, credential reflection split across distinct output-item IDs, and credentials
escaped inside function-argument JSON or its accumulated streaming deltas.

This capture proves the selected direct CLI wire shape against a synthetic provider.
It does not establish byte identity with a runtime image, generated Harness execution,
a real model response or installed OpenShell enforcement. A separate interrupted
response probe with request/stream retry counts set to zero observed one request
and a failed CLI turn; it is not a provider-effect recovery test.

## Startup enrollment

Run the startup coordination integration separately:

```sh
node --test tests/integration/egress-enrollment.test.mjs
```

It launches the actual generated entrypoint and uses the selected Sandbox Driver's
real service client against local HTTP fixtures. A substituted CLI process makes
one local request through the real authority path after enrollment. The test proves
that an absent receipt blocks the first request, a committed receipt alone does not
release startup, and stale, wrong-instance or wrong-execution releases refuse. A
restart gets a fresh challenge. It does not execute packaged Codex or a supervisor.
The Compute conformance case `provider Harness endpoint owns Gateway transport
through preparation and activation` separately checks commit ordering and changed
evidence using Driver dependencies. Generated-wrapper conformance covers explicit
zero retry arguments, protected timeout failure and unchanged legacy retry behavior.

## Captured supplier wires

The companion `openshell-receipt.json` contains actual protobuf bytes from the
supplier's connected gateway token, TLS registry, OPA installation and receipt-query
fixture. The consumer decodes those bytes, preserving uint64 values, and verifies
the captured claim shape with a local fixture signing key and renewed timestamps;
it does not reuse or establish custody of the producer's token. The separate
`openshell-operation.json` captures the sender's TLS/gRPC request after a 100 ms
delay. Its deadline remains creation plus 30 seconds. The consumer checks that
historical operation refuses before material access. These two captures come from
different synthetic component fixtures, not one installed Sandbox.

## PostgreSQL state

With a migrated disposable database selected through `OCC_TEST_DATABASE_URL`, run:

```sh
node --test tests/integration/postgres-static-egress.test.mjs
```

Follow the [database setup](postgresql.md): migrate with `occ_migrator` and run
with `occ_app`. This test uses persisted authentication and native IAM, source and
revision state, exact installation identity, rejection fences and database
constraints. A separate state reader verifies persisted observations. It does not
claim an application-process restart or provider outcome recovery.

## Installed runtime and provider qualification

End-to-end qualification needs a fresh protected revision rendered by the updated
controller, matching gateway/supervisor candidates, persisted installation evidence,
and a reachable authenticated bearer-passthrough Harness service. Observe no model
request before commit/enrollment, one initial probe afterward, and a fresh challenge
after process restart. This nonce check does not establish automatic recovery:
the default Kubernetes selection queues no periodic active-revision maintenance.
Also verify timeout holds startup without a business retry.

Before qualifying a deployment, additionally prove the actual supervisor requires
the credential-access capability, binds the exact loaded policy, refuses missing
counterparts, withholds response bytes until protection completes, and prevents
workload bypass. Use the [OpenShell qualification contract](../reference/drivers/openshell-sandbox.md#qualification-contract)
and [real runtime procedures](kubernetes.md). The bundled legacy release is not
qualified by these tests. Indefinite streaming, WebSockets and dynamic credentials
remain unsupported.
Finite SSE must finish within the original 30 seconds and 4 MiB before any bytes
are released. Fresh revisions with matching gateway/supervisor candidates are the
intended installed scope; mixed-version hot upgrades are unsupported and
no-bypass networking requires separate runtime proof. There is no successful installed native model-turn
evidence in this consumer suite.

## Protected launch packaging

The [explicit local profile](../guides/deploy/local-openshell-images.md#select-the-protected-profile)
generates normal Installation and Helm inputs. For a local packaging check,
select the matching supplier chart through the test-only
`OCC_TEST_OPENSHELL_CHART` and an installed Helm executable through `OCC_HELM_BIN`:

```sh
OCC_TEST_OPENSHELL_CHART=/absolute/supplier/deploy/helm/openshell \
OCC_HELM_BIN=/absolute/bin/helm \
GOEXPERIMENT=jsonv2 go test ./internal/occdev
node --test --test-name-pattern='OpenShell mTLS|OpenShell service transport never' \
  tests/conformance/openshell-gateway-wire.test.mjs
OCC_HELM_BIN=/absolute/bin/helm node --test --test-name-pattern='protected authority' \
  tests/integration/production-kubernetes-packaging.test.mjs
```

The Go case runs the release coordinator with command-boundary fixtures, loads
its output through real controller composition, checks the generated server
certificate, and renders both charts with real Helm. It proves configuration,
credential projection, database selection and startup ordering, not a cluster,
PostgreSQL execution or installed middleware negotiation. The wire cases use
generated CA/client certificates and actual loopback gRPC TLS, including DNS and
IP server identity, foreign-client refusal and absence of client credentials on
the separate service transport. They do not prove OpenShell's role mapping.

Connected qualification additionally requires reviewed, revision-matched images,
normal Agent admission, a disposable `openclaw_k8s_` database, and verified public
Gateway server trust for the Agent's WSS client. The Backend's API/worker trust
mount alone does not configure that client. Never project the administrator
client Secret into an Agent to solve server trust.

For a synthetic HTTPS provider, the supervisor reads its normal system CA bundle;
`SSL_CERT_FILE` does not configure upstream TLS re-encryption. A fixture image may
preserve the original bundle at `/etc/ssl/certs/ca-certificates.crt` and append the
fixture's public CA. Preserve all normal binaries/components, record the base and
derived image digests and CA fingerprint, and identify results as fixture-image
proof. Keep the CA private key outside images and Pods. Do not change host trust
or disable hostname checking.

The existing `server.hostGatewayIP` supplier value maps `host.openshell.internal`.
The protected launcher passes the optional canonical private IPv4 selected by
`OCC_DEVELOPMENT_OPENSHELL_HOST_GATEWAY_IP` to that value.
Use it only after verifying the owned host address is reachable from the selected
runtime and the fixture server certificate covers that exact hostname. A connected
test must explicitly admit that owned origin; it must not accept arbitrary
external hosts. Initial enrollment does not establish automatic recovery after
a Harness process restart; qualify any required reconciliation/redeployment
separately. Packaging and loopback tests do not establish a connected model turn,
supervisor enforcement or no-bypass networking.
