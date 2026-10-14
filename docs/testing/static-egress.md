# Verify protected static inference

Run the bounded authority integration with the installed workspace dependencies:

```sh
node --test tests/integration/static-egress.test.mjs
```

It exercises real Fastify authentication, source and Agent admission, native IAM,
controller transactions, OpenShell adapters, Ed25519 extension identity, TLS gRPC
and HTTPS provider request/response bytes. The Kubernetes Secret Driver uses its
actual SDK against a TLS storage fixture that supplies UID/resourceVersion.
Gateway loaded-policy observations are fixtures. The suite explicitly checks
that these observations without an applied-capability receipt refuse installation;
it inserts a synthetic installation only to exercise the authority separately.
Compute placement is passive;
no real Sandbox, model service or cluster is launched by this suite.

The cases protect separate failures: current permission revoked between the two
checks; authoritative material rotation; forged identity and unsupported operation
refused before access; replay and selected-material mismatch; credential reflection;
provider rejection fencing; missing counterpart, altered installed policy and
owned withdrawal. The provider is a genuine HTTPS wire fixture, not a model turn.

With a migrated disposable database selected through `OCC_TEST_DATABASE_URL`, run:

```sh
node --test tests/integration/postgres-static-egress.test.mjs
```

Follow the [database setup](postgresql.md): migrate with `occ_migrator` and run
with `occ_app`. This test uses persisted authentication and native IAM, source and
revision state, exact installation identity, rejection fences and database
constraints. A separate state reader verifies persisted observations. It does not
claim an application-process restart or provider outcome recovery.

Before qualifying a deployment, additionally prove the actual supervisor requires
the credential-access capability, binds the exact loaded policy, refuses missing
counterparts, withholds response bytes until protection completes, and prevents
workload bypass. Use the [OpenShell qualification contract](../reference/drivers/openshell-sandbox.md#qualification-contract)
and [real runtime procedures](kubernetes.md). The bundled legacy release is not
qualified by these tests. Long-lived streaming and dynamic credentials are outside
this verification; source checks establish no successful native model-turn evidence.

## Check connected request admission without a runtime

```sh
node --test tests/integration/egress-connected-preflight.test.mjs
```

The `checks-baseline-2` lane runs this file. It checks serialized request bytes
through Fastify's real content parser, authentication and native IAM with
in-memory storage and fixture Compute. Valid protected requests must reach the
missing-counterpart refusal; an unrelated `400` cannot qualify them. It also
checks the connected observer's database guards, proto3 uint64 handling and
rejection of partial assistant output, and the obfuscated provider vectors. It starts no provider, cluster or model
runtime and supplies no installation receipt.

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

| Input                                                                                                | Required preparation                                                                                                                                                                              |
| ---------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `version`, `namespaceId`, `model`                                                                    | Version `1`, the existing `ns_*` tenant ID and explicit Codex model name.                                                                                                                         |
| `apiOrigin`, `serviceKeyPath`                                                                        | Loopback controller origin and absolute path to its provisioned non-Agent service key.                                                                                                            |
| `kubeconfigPath`, `kubernetesContext`, `runtimeClass`                                                | Explicit kubeconfig, disposable `k3d-*` context and approved OpenShell RuntimeClass.                                                                                                              |
| `controllerNamespace`, `controllerSelector`, `openShellGatewayNamespace`, `openShellGatewaySelector` | Exact namespaces and selectors for the prepared controller (both API and worker) and supplier gateway Pods.                                                                                       |
| `oceCommit`, `supplierCommit`                                                                        | Accepted 40-character source commits. These are recorded provenance; Pod image references do not establish build-source equivalence.                                                              |
| `images`                                                                                             | Digest-pinned references under `agent`, `controller`, `gateway`, `openShellGateway`, `sandbox`, and `supervisor`, imported and registered in k3s. Use the exact references rendered in Pod specs. |
| `openShellBackend`                                                                                   | HTTPS `endpoint`, absolute `rootCertificatePath`, and `auth: { mode: "bearerTokenFile", path: "…" }`. No insecure transport.                                                                      |
| `provider`                                                                                           | Fixture-only HTTPS `.test` `origin` ending `/v1`, explicit reachable `bindHost`, matching high `bindPort`, and absolute `certificatePath`/`privateKeyPath`.                                       |

The parent operator prepares the provider certificate/SAN, supervisor DNS and
routing, trusted CA store and scoped egress. The test binds that listener but
changes none of those settings. Use synthetic material only; no real provider
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
