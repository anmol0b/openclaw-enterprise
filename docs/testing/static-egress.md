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

## Check connected request admission without a runtime

```sh
node --test tests/integration/egress-connected-preflight.test.mjs
```

The `checks-baseline-2` lane runs this file. It checks serialized request bytes
through Fastify's real content parser, authentication and native IAM with
in-memory storage and fixture Compute. Valid protected requests must reach the
missing-counterpart refusal; an unrelated `400` cannot qualify them. It also
checks the connected observer's database guards, proto3 uint64 handling and
rejection of partial assistant output, exact bearer/mTLS input shapes, fixture
hostname restrictions and obfuscated provider vectors. It starts no provider,
cluster or model runtime and supplies no installation receipt.

## Select the prepared connected lane

The `egress-connected` CLI lane owns
[agent-openshell-static-egress-k3d-real.test.mjs](../../tests/integration/agent-openshell-static-egress-k3d-real.test.mjs).
It is excluded from `ci`, `full` and GitHub workflow dispatch. It does not prepare
infrastructure. The generic `openshell` lane's HTTP fixture is insufficient:
this test requires an installed protected controller, worker and authenticated
OpenShell counterpart. Missing selected inputs fail; an unselected discovery
skip is not proof.

Prepare an owned, ready Namespace with one physical placement in a disposable
loopback k3d cluster with enforcing NetworkPolicies. Use the normal Launcher,
workspace mounts, workload identity and RuntimeClass prerequisites from
[OpenShell testing](openshell.md). Migrate a dedicated `openclaw_k8s_*` database
with the migrator and run the controller and observer as `occ_app`; see
[PostgreSQL setup](postgresql.md). The test verifies that its database contains
the same Installation returned by the controller.

The protected product and supplier source must agree on physical namespace
mapping, loaded-enforcement receipt readiness, finite Responses protection and
zero automatic retries, including the startup authentication probe. Build and
select the corresponding immutable images before running. This test cannot
qualify a checkout that lacks those contracts or a legacy gateway-copy setup.

Set `OCC_TEST_EGRESS_CONNECTED_INPUTS` to an absolute path to a private JSON file.
The [input validator](../../tests/helpers/egress-connected-inputs.mjs) defines its
exact contract:

| Input                                                                                                | Required preparation                                                                                                                                                                                                                         |
| ---------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `version`, `namespaceId`, `model`                                                                    | Version `1`, the existing `ns_*` tenant ID and explicit Codex model name.                                                                                                                                                                    |
| `apiOrigin`, `serviceKeyPath`                                                                        | Loopback controller origin and absolute path to its provisioned non-Agent service key.                                                                                                                                                       |
| `kubeconfigPath`, `kubernetesContext`, `runtimeClass`                                                | Explicit kubeconfig, disposable `k3d-*` context and approved OpenShell RuntimeClass.                                                                                                                                                         |
| `controllerNamespace`, `controllerSelector`, `openShellGatewayNamespace`, `openShellGatewaySelector` | Exact namespaces and selectors for the prepared controller (both API and worker) and supplier gateway Pods.                                                                                                                                  |
| `oceCommit`, `supplierCommit`                                                                        | Accepted 40-character source commits. These are recorded provenance; Pod image references do not establish build-source equivalence.                                                                                                         |
| `images`                                                                                             | Digest-pinned references under `agent`, `controller`, `gateway`, `openShellGateway`, `sandbox`, and `supervisor`, imported and registered in k3s. Use the exact references rendered in Pod specs.                                            |
| `openShellBackend`                                                                                   | HTTPS `endpoint`, absolute `rootCertificatePath`, and exactly `auth: { mode: "bearerTokenFile", path: "…" }` or `auth: { mode: "mtls", certificatePath: "…", privateKeyPath: "…" }`. All auth paths must be absolute; no insecure transport. |
| `provider`                                                                                           | Fixture-only HTTPS `.test` or exact `host.openshell.internal` `origin` ending `/v1`, explicit reachable IP `bindHost`, matching high `bindPort`, and absolute `certificatePath`/`privateKeyPath`.                                            |

The parent operator prepares the provider certificate/SAN, supervisor DNS and
routing, trusted CA store and scoped egress. The test binds that listener but
changes none of those settings. The native `host.openshell.internal` alias must
resolve to the prepared listener address and appear in its certificate SAN;
it permits no other provider hostname. mTLS requires a controller build with
Backend mTLS support; input validation alone does not establish that support.
Use synthetic material only; no real provider
credential is required. Supply the controller's loopback PostgreSQL URL through
`OCC_TEST_DATABASE_URL` in an existing private environment file. URL query
parameters are rejected because they can override the selected host or database.
Keep both input files and credential contents out of logs and Git.

With those prerequisites ready, select a fresh result directory:

```sh
run_dir="$PWD/.build/egress-connected/run-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$run_dir"
node --env-file=/absolute/path/to/private/connected.env \
  scripts/ci/run-tests.mjs run egress-connected \
  --state "$run_dir/state.json" --results "$run_dir/results.json"
```

The environment file supplies `OCC_TEST_EGRESS_CONNECTED_INPUTS` and
`OCC_TEST_DATABASE_URL`; lane selection supplies `OCC_TEST_EGRESS_CONNECTED=1`.
The test has a 30-minute deadline, a 12-minute activation wait, 90-second Codex
turns and 20-second API requests. Connected cluster commands have a 120-second
local deadline. The overall deadline takes precedence over the individual
step limits. Allow at least 40 minutes for the file and cleanup, plus the
parent's separate stack teardown budget. A killed kubectl client does not prove
that its remote process stopped. Do not replay an uncertain operation.

### Read evidence and retain cleanup custody

The test creates resources through public APIs, deploys through the real worker,
reads its persisted installation, and checks the authenticated supplier receipt.
It uses the packaged Codex app-server caller from the Agent Gateway Pod. It
requires one normal startup probe, then counts fifteen measured provider sends:
permitted access, regrant, rotation, and six hostile responses with recovery, including split-ID text deltas and
JSON-escaped function arguments.
IAM revocation and the ordinary-binary bypass probe must send nothing upstream.
Hostile responses must fail with the supplier's explicit pre-return refusal and
no partial assistant output. Synthetic material must be absent from observed
responses, bounded logs, diagnostics, audit, Pod specs and ConfigMaps.

The per-run `.build/egress-connected/runtime-<uuid>/` directory retains atomic
phase checkpoints, resource IDs and bounded provider observations without raw
requests or credentials. Failure diagnostics retain the phase and source
location. Cleanup deletes the owned Agent, waits for API absence and disappearance of
the observed Sandbox and owned workload Pods, removes recorded supporting
resources and closes the provider. An unobserved Sandbox identity requires
parent reconciliation. The test never owns the
prepared Namespace, database, cluster, controller or gateway installation.
A failed or unconfirmed create remains in the ledger for reconciliation; a
cleanup error or outer termination requires the parent's owned-resource recovery.

A passing selected run establishes only this static-inference slice at its
recorded inputs. Source checks are not runtime proof. The scenario does not
prove real-provider usefulness, all workload credential/control-API containment,
revocation between Resolve and AuthorizeSend, mixed-version activation, HA,
dynamic credentials, long-lived streaming or complete Egress MVP delivery.
