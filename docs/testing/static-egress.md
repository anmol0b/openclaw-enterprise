# Verify protected static inference

Run the bounded authority integration with the installed workspace dependencies:

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
Compute placement is passive;
no real Sandbox, model service or cluster is launched by this suite.

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
that CLI. Prompt, model, identity, local tool names and descriptive values are sanitized; field and
local-tool schema shapes are retained. The protected profile disables provider web
search while keeping local functions and namespaces. The default remote web-search
tool is a refusal vector. The application test sends these bytes through actual
classification, credential access, send authorization and whole-response protection.
It also rejects unknown fields/events, remote tools, duplicate JSON keys, incomplete
SSE and credential reflection split across deltas.

This capture proves the selected direct CLI wire shape against a synthetic provider.
It does not establish byte identity with a runtime image, generated Harness execution,
a real model response or installed OpenShell enforcement. A separate interrupted
response probe with request/stream retry counts set to zero observed one request
and a failed CLI turn; it is not a provider-effect recovery test.

The companion `openshell-receipt.json` contains actual protobuf bytes from the
supplier's connected gateway token, TLS registry, OPA installation and receipt-query
fixture. The consumer decodes those bytes, preserving uint64 values, and verifies
the captured claim shape with a local fixture signing key and renewed timestamps;
it does not reuse or establish custody of the producer's token. The separate
`openshell-operation.json` captures the sender's TLS/gRPC request after a 100 ms
delay. Its deadline remains creation plus 30 seconds. The consumer checks that
historical operation refuses before material access. These two captures come from
different synthetic component fixtures, not one installed Sandbox.

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
qualified by these tests. Indefinite streaming, WebSockets and dynamic credentials remain unsupported.
Finite SSE must finish within the original 30 seconds and 4 MiB before any bytes
are released. Fresh revisions with matching gateway/supervisor candidates are the
intended installed scope; mixed-version hot activation and no-bypass networking
require separate runtime proof. There is no successful installed native model-turn
evidence in this consumer suite.
