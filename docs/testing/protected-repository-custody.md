# Qualify the installed repository response and dispatch custody

Run the dedicated `egress-custody-installed` lane on a newly prepared, disposable
controller and OpenShell pair before landing whole-execution repository authority.
The [lane manifest](../../scripts/ci/test-suites/egress-custody-installed.json)
requires every named observation. An ordinary CI pass or the inference lane above
does not run this qualification. Preserve exact build, image selection, installed
configuration and independent network-enforcement evidence with the result.

Use the version 2 connected inputs above, with `authorityProfile` set to
`fresh-whole-execution` and no `credentialConnector`. The supplier must actually
report, in order, credential access, installation exchange, response custody and
execution authority. Configure its fixture bridge and valid TLS trust for both
ordinary workload clients. Select the fixture HTTPS origin (without `/v1`) in
`drivers.conduit.configuration.preparedGitHub.apiOrigin` in the Installation.
Supply `issuerCaPath: /etc/openclaw/prepared-github-issuer/ca.crt` and
`custodyKeyPath: /etc/openclaw/prepared-github/custody.key`. In the chart select
`preparedGitHub.custodySecretName`, `issuerCaConfigMapName`, exact `issuerCidrs`
IPv4 /32 and `issuerPort`. The API and worker need working DNS and verified
TLS to that origin. The test checks the selected private origin in both Pods
before enrollment; a credential source cannot redirect it. The test also checks
the workload's effective authorization cannot retrieve or project the Compute signer.

The test generates an App key, an explicitly consented Agent source and metadata-only
installation token. It contacts neither GitHub nor a model provider.

Before installing the disposable API controller, start the following observer on
its owner host. Use the same limited disposable database selected for the test.
The directory must not already exist. Keep the Unix socket on this host. Route
only that API controller's database connection through the observer's loopback
data port using the disposable network's supported forwarding. This observer
needs an explicitly non-TLS local PostgreSQL wire; never turn off an existing
transport security requirement to run it. Permit the deliberate restart only
on this API Pod template with the annotation
`openclaw.dev/egress-custody-qualification-restart: permitted`. Keep the owner
forward to the API service alive across Pod replacement. Include setup, test,
fresh API readiness, evidence and cleanup in the actual slot and outer deadline.

```sh
node tests/fixtures/egress-custody-postgres-observer.mjs "$new_observer_dir" "$data_port"
```

In the qualification shell, set the four connected inputs from the lane manifest,
then select the actual lane. The state and results paths must belong to this attempt.

```sh
export OCC_TEST_EGRESS_DISPATCH_OBSERVER_SOCKET="$new_observer_dir/control.sock"
node scripts/ci/run-tests.mjs run egress-custody-installed \
  --state "$attempt/state.json" --results "$attempt/results.json"
```

Require passed results for the two different workload clients, independently
observed direct TCP bypass attempt, actual forbidden final trailer, specific
authorization update and lost commit acknowledgment across API restart, and
the replaced execution with no inherited request or response. The diagnostic
names the private `.build/egress-connected/runtime-<uuid>/` directory. Retain its
`observations.json` through cleanup and `upstream.json` with the result. The
post-restart read is a new positive control, never a replay of the uncertain
dispatch. Stop the owned observer and forwarding, then remove the disposable
installation. Reconcile any unknown resource from its ledger without replay.
