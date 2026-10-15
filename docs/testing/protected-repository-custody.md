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

The test generates an App key, separately consented dedicated Agents and metadata-only
installation credentials. It contacts neither GitHub nor a model provider.

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
CI_RUNNER_TEST_TIMEOUT_MS=5100000 node scripts/ci/run-tests.mjs run egress-custody-installed \
  --state "$attempt/state.json" --results "$attempt/results.json"
```

Reserve 90 minutes for the lane after setup, plus time for collection and disposal.
The installed test has a 67-minute execution budget. The 85-minute file timeout above
also covers owned-resource cleanup. If set, the runner's absolute `CI_RUNNER_DEADLINE_MS`
must allow that full window.

Require both files in the manifest to pass. At the real TLS gRPC authority, a synthetic
enrolled peer presents the copied opening first on the wrong sink, crosses two signed
openings and two live dispatch handles, and attempts to splice an actual pending reply.
The installed test cannot extract a supervisor's possession key to repeat that injection.
Instead it holds two separately authorized executions' actual replies, makes B finish
first with only the final forbidden trailer, checks B's exact refusal and A's exact approved
identity through TLS FIN, then checks B's own fresh authorized read. The separate trailer
control has identical chunk framing and no trailers. For replacement, B remains authorized
with its own accepted read pending while A's late valid response is released. It must receive
only its expected refusal through FIN, then its own fresh successful read. The subsequent IAM denial is a withdrawal control.

Require the ordinary curl and Node workload reads, observed direct TCP attempt, and
specific dispatch acknowledgment loss and API restart as well. The diagnostic
names the private `.build/egress-connected/runtime-<uuid>/` directory. Retain its
`observations.json` through cleanup and `upstream.json` with the result. The
post-restart read is a new positive control, never a replay of the uncertain
dispatch. Stop the owned observer and forwarding, then remove the disposable
installation. Reconcile any unknown resource from its ledger without replay.
