# Git and draft pull requests through OpenShell

This opt-in, pre-release integration lets a dedicated Codex Agent use native Git
and create a draft pull request through stock OpenShell 0.1.4. The OCE worker
holds the GitHub App signing key and prepared credential custody key. OpenShell
calls the worker's authenticated request-phase middleware for the admitted
repository binding before forwarding a GitHub request.

**Use this only for an explicitly accepted pre-release trial.** Stock OpenShell
cannot require this middleware on every sandbox, and its middleware request does
not independently prove TLS to the GitHub origin. Registering the service does
not close either gap. This is not a general hardened credential-isolation claim.
Qualify your actual deployment before admitting a real repository credential;
chart renders and source tests do not establish an AWS deployment result.

## Prerequisites

Check these before the trial; each one stops Git or the Agent:

- **Kernel.** The Driver requires Landlock (`hard_requirement`), and Sandboxes need
  Landlock ABI v3 or later, Linux 6.2 or newer. A node on an older kernel, such as
  the 5.15 kernel of Ubuntu 22.04, fails Sandbox startup.
- **Supervisor trust.** The OpenShell supervisor makes its own TLS connections to
  GitHub and the model endpoint, using its image's CA bundle. If a private CA or a
  TLS-inspecting proxy sits on either path, use a supervisor image that trusts that
  CA; otherwise the model probe times out and Git requests fail.
- **Unattended commands.** With
  `plugins.entries.codex.config.appServer.approvalPolicy: on-request` and no
  approver, Codex declines the shell commands it asks about, so Git never runs. For
  an unattended trial, set it to `never`, which removes the approval step.
- **PATH.** Draft creation needs the helper on PATH; see the login-shell note below.

## Prepare the installation

Start with the [repository installation inputs](../../guides/repository-credentials/installation.md)
and [prepared Git policy](prepared-native-git.md). Select Kubernetes Compute,
the OpenShell Sandbox Driver and dedicated Codex. Keep the ordinary OpenShell
inference configuration for Codex; this integration adds repository access.
Select `repositoryCredentials.authority: prepared-git` in Helm and merge
[`openshell.fragment.yaml`](../../../deploy/examples/repository-credentials/openshell.fragment.yaml)
into the Installation. Do not select `credential_proxy`, `egressAuthority`, or
the separate metadata-read `preparedGitHub` Helm settings for this route.

The existing repository inputs still supply the registry, broker image and
configuration, public CA, GitHub App key and dedicated 32-byte custody key.
`repositoryCredentials.preparedCustodySecretName` supplies `custody.key`, and
`repositoryCredentials.appKeySecretName` supplies `private-key.pem`; only the worker
mounts these under `/etc/openclaw/prepared-repository`. Preserve the custody key
across restarts. Never put these keys in Agent configuration or Helm values.

Prepare a separate serving certificate whose DNS SAN covers
`openclaw-enterprise-openshell-git.openclaw-system.svc`, its private key, and the
**public** PEM key from the selected OpenShell Gateway JWT signing bundle.
Create these resources in the OCE namespace with your approved Kubernetes context:

```bash
kubectl --context "$CONTEXT" -n openclaw-system create secret tls openshell-git-tls \
  --cert=/secure/occ/openshell-git/tls.crt \
  --key=/secure/occ/openshell-git/tls.key
kubectl --context "$CONTEXT" -n openclaw-system create configmap openshell-gateway-public \
  --from-file=gateway-public.pem=/secure/occ/openshell-git/gateway-public.pem
```

Add this to the existing production values. Replace the example namespace and Pod
labels with observed labels for your Gateway and trusted supervisors; both call
the middleware. Do not select Agent workload Pods as trusted callers.

```yaml
openshellGit:
  enabled: true
  port: 8445
  tlsSecretName: openshell-git-tls
  issuerPublicKeyConfigMapName: openshell-gateway-public
  clients:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: openshell-system
      podSelector:
        matchLabels:
          app: openshell-gateway
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: openshell-system
      podSelector:
        matchLabels:
          app: openshell-supervisor
```

The chart exposes a ClusterIP Service on port 8445 and allows that port only from
these peers under the chart's default-deny policy. It mounts the serving key,
certificate and public issuer key at the fragment's `/etc/openclaw/openshell-git`
paths in the worker. The API, initialization Job and repository sidecar do not
receive this projection. Keep the worker port equal in Helm and the Installation.
If the OpenShell namespace enforces egress, also permit its Gateway and supervisors
to reach this Service's selected worker Pods on TCP 8445 and resolve cluster DNS.

Set `authority.issuer` to `openshell-gateway:<gateway_id>` from the actual Gateway
JWT configuration, `keyId` to the contents of its `kid_path`, and `audience` to the
registration audience below. The fragment's values are examples, not discovery.
The Gateway's signing private key stays with the Gateway. Render and inspect the
combined production values, then use your normal Helm upgrade procedure.

## Register the request-phase service

Stock OpenShell 0.1.4 uses static operator configuration. Add the following entry
to the Gateway configuration, using the certificate's exact Service DNS name.
Mount the serving CA's public certificate at `tls_ca_cert_path` on the Gateway.
Its existing `[openshell.gateway.gateway_jwt]` must be configured with signing key,
public key, key ID and gateway ID matching the OCE verifier settings.

```toml
[[openshell.supervisor.middleware]]
name = "oce-prepared-git"
grpc_endpoint = "https://openclaw-enterprise-openshell-git.openclaw-system.svc:8445"
tls_ca_cert_path = "/etc/openshell/certs/oce-git-ca.pem"
audience = "oce-prepared-git"
max_payload_bytes = 4194304
timeout = "3s"
```

Start the configured OCE worker before restarting the Gateway: Gateway startup
calls authenticated `Describe` and refuses an unavailable or incompatible service.
OCE advertises the request-phase binding; policy admission calls `ValidateConfig`.
The registration name must match `drivers.repo.openShell.registrationName`.
OCE attaches the selected binding to the sandbox policy with `on_error: fail_closed`
for `github.com` and `api.github.com`. Do not hand-author its binding identifier.
Those hosts come only from this route: if another Sandbox Driver network policy
(`policy.networkPolicies`, such as a `source-control` policy) also allows them, the
Installation refuses to start and names that policy. The Driver still needs at
least one policy, such as the model endpoint's.
Retain HTTPS, hostname verification and authenticated Gateway JWTs; do not enable
`allow_insecure_transport`. This policy attachment still has the stock enforcement
and origin-TLS limits stated above.

## Use the admitted repository

Enroll one repository and exact writable branch in the registry and bind it to
the Agent. For draft creation select `transport: git-and-draft-pr` and an explicit
`pullRequestBase`, such as `main`; Git-only grants do not enable draft creation.
The App installation needs the corresponding repository contents and pull request
permissions. GitHub permissions themselves are broader than the middleware's
branch and draft checks; keep independent GitHub branch protection.

[Codex OAuth](../../testing/openshell-oauth.md) does not grant Git access. OpenShell Git
binds a live revision to its installed credential and authorizes each request; other
sandbox repository bindings remain refused.

From the admitted Agent shell, use ordinary GitHub URLs. OpenShell strips proxy
variables and routes the sandbox's connections itself. Replace the repository and
branch below with the enrolled values:

```bash
git clone https://github.com/example-org/example-repo.git
cd example-repo
git switch -c review/agent-change origin/main
# Make and commit the requested change.
git push origin HEAD:refs/heads/review/agent-change
oce-github pr-create --draft --head review/agent-change --base main \
  --title 'Review the proposed change' --body 'Describe the change and validation.'
```

With `git-and-draft-pr`, the Sandbox can read the image's repository client and
its PATH ends with `/opt/oce/repository-credentials/bin`. If a login shell resets
PATH, call `/opt/oce/repository-credentials/bin/oce-github`. Like Git, the helper
sends its one draft-create request to `api.github.com` and OpenShell routes it
through the middleware; the helper ignores proxy variables. It accepts explicit `--body` text, not `--body-file`, and
records a local attempt ID before sending. A local ID does not make GitHub
creation idempotent. If a push or draft-create response is lost, inspect GitHub
for the commit or draft before any new attempt. Do not retry another way.

During the accepted trial, use an authorized test repository to verify clone,
pull of an independently known commit, push to the allowed branch, and draft
creation from the same admitted Agent. Independently
read back the pushed SHA and draft. In a disposable repository, verify refusal of
another repository, another writable branch and a non-draft create. Remove the
Agent repository binding, confirm a fresh fetch is denied, and confirm ordinary
chat still works. Withdrawal cannot erase an existing clone or recall a sent push.
These checks do not prove that every sandbox must use the middleware or that the
connection from OpenShell to GitHub uses verified TLS.

## Route state, restarts and recovery

The worker verifies each admitted Sandbox's Git route itself: the exact Sandbox,
its supervisor instance and the installed provider generation, re-read through the
Gateway every few seconds and on every request. A deployment waits as
`REPOSITORY_GIT_ROUTE_PENDING` until that route is verified. The prepared material
is issued only once the version is active and installs within a few seconds; an
active version that loses its material reports `REPOSITORY_GIT_ROUTE_PENDING`
again. A route the worker has closed for good (the Sandbox or its supervisor was
replaced, a provider write's outcome is unknown, or access was withdrawn) fails
the deployment with `REPOSITORY_GIT_ROUTE_BLOCKED`; an active version in that
state keeps serving chat, but every Git request answers 403 until a new version
deploys.

A read the worker cannot complete is not a verdict. While the Gateway Pod is being
replaced (an upgrade, node drain or restart), or a read times out, the route closes
and Git requests are denied; the worker reads again with a bounded backoff (1 s
doubling to 10 s) and reopens the route, without a new version, once the same
installation verifies. Nothing is rewritten or replayed meanwhile. A worker restart
still requires a new version: the restarted worker refuses to adopt a Sandbox it did
not prepare. The Agent stays active and chat works, but every Git request answers
403 (`no_binding`) until a new version deploys; meanwhile each maintenance pass logs
`worker.compute-prepare-failed` with `KUBERNETES_PREPARATION_FAILED`.

The worker log says which it was. `worker.error` with
`OPENSHELL_GIT_RECONCILIATION_REQUIRED` carries the `reason` (for example
`execution_replaced`, `supervisor_replaced`, `write_unknown`, `worker_restarted`
once per version when a restarted or other worker finds a Sandbox it did not prepare, or
`gateway_unauthorized` when the Gateway refuses the worker's identity), the Namespace,
Agent, revision and `repositoryRef`; `worker.openshell-git-route-warning` reports a
route closed by a failed read (`gateway_unavailable`, `timeout`, `read_failed`) and
`worker.openshell-git-route` its restoration with the outage's `durationMs`. When
the provider rejects the App key, preparation is quarantined and
`PREPARED_GITHUB_RECOVERY_REQUIRED` names the `reason`, revision and
`repositoryRef`. A new version still deploys (its material is requested only after
it activates); then Git answers 403 and the worker logs this line. Restore the key,
then deploy a new version. Each request the worker refuses logs one
`worker.openshell-git-denied` line with its `reason` (`route_unobserved`,
`route_blocked`, `ref_not_allowed`, `approval_denied`, and so on), the Sandbox ID
and the request ID the supervisor's own log shows.
