# Develop and withdraw the protected egress schema

The schema can be exercised with ordinary unprotected development revisions. The
[protected execution cutoff](../../reference/credential-sources/protected-inference.md#execution-admission-cutoff)
remains closed until the installed pair and its release authority are qualified.

## Upgrade or withdraw a development installation

Use a disposable database for the first upgrade. The supported starting schema
includes `0054_credential_source_pat` and `0055_compute_revision_admission`.
Migrations 0056 through 0061 add the egress schema and check the revision's
Harness authentication shape. Migration checks compare the receipt ledger,
catalog and effective grants.

A private development database whose 0055 was `static_egress` has a different history.
Stop its writers and withdraw it using its own matching release and quiesced backup, or
retire it and create a fresh disposable installation. Never renumber applied receipts.

Before upgrading from 0055, pause new admissions. Use the release that owns each
execution, including any anonymous reader, to stop it, retire predecessors and
reconcile outstanding work. Confirm the stop completed, no revision is active and
no cleanup remains. Stay on that release if you cannot finish or need to deploy
the same Agent again.

Stop workers and maintenance writers, then take and verify a physical database
snapshot. Confirm the previous migration command accepts the restored catalog. On PostgreSQL
18.6, a quiesced database copy (`CREATE DATABASE ... TEMPLATE ... STRATEGY FILE_COPY`
with the same database-level access) preserved the catalog and receipt history.
A logical dump and restore can reparse CHECK expressions and fail that exact
catalog check even when the restore command succeeds. Retain the matching
controller, runtime, supplier and configuration revisions with the snapshot.

Apply the normal migration once. Keep the stopped Agent and its revision for
read-only inspection and audit. The revision list preserves its identity. Revision detail
reports `SAVED_CONFIGURATION_UNREADABLE` because 0055 recorded no execution
admission. Deploying that Agent returns 503 without creating a revision or
queuing work. The controller must be able to read every revision to stop or retire it.
Leave the saved Compute admission, credential-source reference and history intact.

To resume development, start the matching API and workers with `conduit`
unselected. Create a **new Agent** in the same Namespace, with its own Configuration
and service principal. Deploy revision 1 and confirm its execution admission is
`unprotected`. Start without the old credential, grants, mounts, helpers or sessions.
Do not arrange to reattach them later. Withhold any new binding unless durable evidence
shows equivalent authority or an authorized binder explicitly admits the broader access.
Permission to update a source is not that consent.

If the migration transaction fails, verify the previous history before resuming
the old installation. After a successful migration, switching binaries alone
does not restore the old writer contract. Before admitting any work, withdrawal
can restore the quiesced snapshot and its matching binaries as a unit. After
new admissions or a possible provider send, stop writers and reconcile those
effects first. Never delete a dispatch receipt or replay an uncertain operation to
make a rollback appear clean.

## Select fresh whole-execution protection

This selection requires explicit whole-execution authority and the current paired
Compute release and OpenShell custody profiles. An earlier executable-scoped
selection cannot authorize this principal. Keep its existing restrictions until
an authorized binder admits the broader access.

Keep the existing [OpenShell Backend and Sandbox configuration](../../reference/drivers/openshell-credential-gateway.md).
Add the same egress Driver ID to `backend[].drivers.conduit` and select:

```yaml
drivers:
  conduit:
    id: openshell-egress
    configuration:
      middlewareName: oce-authority
      authorityScope: execution
      authority:
        host: 127.0.0.1
        port: 9444
        certificatePath: /etc/openclaw/egress/tls/tls.crt
        privateKeyPath: /etc/openclaw/egress/tls/tls.key
        issuerPublicKeyPath: /etc/openclaw/egress/issuer/issuer.pub
        issuer: openshell-gateway:openshell-gateway
        audience: oce-egress
        keyId: current
```

The API owns this TLS listener; the worker does not open another listener.
Development requires loopback. Production requires an explicitly configured
reachable host and operator-provided TLS and issuer trust. The existing Backend
must use explicit HTTPS and [bearer-file or mTLS authentication](../../reference/backends.md#openshell-gateway).
All phases of an operation must reach
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

### Helm packaging

The OCE chart's `egressAuthority.enabled` defaults to `false`. When enabled, set
`port` to the authority listener port, `tlsSecretName` to a Secret with `tls.crt`
and `tls.key`, and `issuerSecretName` to a Secret with `public.pem`. The chart
mounts these at the example paths above on the API only. It exposes a ClusterIP
Service named `openclaw-enterprise-egress-authority`, with a NetworkPolicy limited
to `clients`: each entry must contain an explicit `namespaceSelector` and
`podSelector.matchLabels`. Select only the Gateway and trusted supervisors.
The Installation's production listener host must accept that Service traffic;
use its exact DNS name in the server certificate and middleware endpoint.

For native mTLS, `backend.openshell.clientSecretName` projects `ca.crt`, `tls.crt`
and `tls.key` under `/etc/openclaw/openshell` into the API and worker. It does not
project those credentials to Agents or bootstrap/migration Jobs. The issuer's
private signing key is never selected by the authority volume. The supervisor
receives public authority trust through the supplier's middleware registration.

The [protected local launch profile](../../guides/deploy/local-openshell-images.md#select-the-protected-profile)
creates these bindings and TLS inputs, uses native OpenShell PKI, and installs
the authority before waiting for Gateway readiness. Neither chart configuration
nor successful startup qualifies connected enforcement; follow the
[verification boundary](../../testing/static-egress.md#protected-launch-packaging).
