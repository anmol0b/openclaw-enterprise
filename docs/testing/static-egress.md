# Verify protected static inference

Run the bounded authority integration with the installed workspace dependencies:

```sh
node --test tests/integration/static-egress.test.mjs
```

It exercises real Fastify authentication, source and Agent admission, native IAM,
controller transactions, OpenShell adapters, Ed25519 extension identity, TLS gRPC
and HTTPS provider request/response bytes. The Kubernetes Secret Driver uses its
actual SDK against a TLS storage fixture that supplies UID/resourceVersion.
Gateway loaded-policy observations are fixtures. Compute placement is passive;
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
qualified by these tests. Streaming and dynamic credentials remain unsupported;
there is no successful native model-turn evidence in this implementation slice.
