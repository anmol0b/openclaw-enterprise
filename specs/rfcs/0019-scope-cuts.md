---
status: Proposed
implementation_status: Not implemented
author: freeqaz
status_note: "Decision request. Nothing in this RFC removes code. Each cut needs a maintainer decision and a separate implementation PR."
---

# Proposal: Narrow launch support around the first Agent and its execution boundary

- **ID:** RFC-0019
- **Created:** 2026-10-02
- **Last updated:** 2026-10-15
- **Decision record:** [PR #898][pr-898]

<a id="problem-and-decision"></a>

## Two decisions set the order of work

**Make the first Agent the local default.** Today a contributor can run `occ dev up`,
see a ready control plane, then discover that its Docker Compute Driver refuses the
authentication binding every newly admitted Agent needs. The [quickstart] already
avoids that dead end by explicitly selecting Kubernetes for both the control plane and
Agent workloads. Approve that default for *new* installations now. Retiring Docker
Compute and retiring the useful Compose/Kubernetes combination are later, separate decisions.

**Decide where a dedicated Codex turn is allowed to run.** The Gateway holds trusted
channel and administration access. The Harness runs model-directed code we must treat as
hostile. [PR #830][pr-830] reports that adding ordinary request parameters such as
`temperature: 0` moved a turn into the Gateway without anyone asking to switch runtimes.
Compute and security owners need to state the required execution boundary before we
expand native administration or commit to another Gateway configuration rewrite.
This RFC does not choose between separate Pods and a shared Pod.

Record the local-default decision and the execution requirement, or the specific
unresolved condition, on [#898][pr-898]. They need not land together. The independent
SSH support decision is below. Source and PR states here are as of October 15, 2026,
with [OCE main at `00bbc7cd9`][source] as the source baseline. No runtime was tested for this RFC.

<a id="motivation"></a>
<a id="scope"></a>
<a id="goals"></a>
<a id="non-goals"></a>
<a id="design"></a>

## Change the local default first. Earn each removal separately.

The [CLI][cli] defaults Compute to Docker. Selecting Kubernetes changes only that
choice: the [launcher][startup] still defaults the *control plane* to Compose. Thus
[PR #519][pr-519], closed unmerged on October 13, is neither a prerequisite nor
evidence that contributors have migrated. Keep the existing loopback HTTPS and browser
trust instructions. This proposal concerns what runs locally, not a switch to HTTP.

1. **Default to the documented all-k3d profile.** Put PostgreSQL, the control plane
   and Agent workloads in the owned cluster. On a fresh installation, follow the
   printed URL, supply a model credential when deploying the first Agent, get a turn
   back, then clean up only that installation. A ready control plane alone would
   repeat the original mistake. Be up front about k3d, kubectl, Helm and roughly
   20 GB for the first build. [Podman needs root or a rootful machine][local]. Preserve
   the cleanup path recorded for existing installations. In particular, k3d teardown
   deletes its database and Agents, whereas Docker volume deletion is optional.
2. **Retire the development-only Docker Compute Driver after the default works.**
   Remove its tests, `docker-model` lane and preview documentation together. We lose a
   lighter control-plane-only loop, not production Docker support: the [Compute
   matrix][matrix] explicitly says this driver cannot deploy a newly admitted Agent.
   Contributors can still use Docker as the container engine under k3d.
3. **Keep Compose control plane plus Kubernetes Compute selectable through a migration
   release.** This hybrid *can* deploy Agents. In particular, its OpenShell profile
   provides a loopback browser endpoint, private routing and an operator-managed
   Workspace. Move the hybrid cases in `openshell` and `dev-up-k3d` to cover the
   replacement, including browser access, routing, readiness and owned cleanup.
   Publish the migration and ask who still needs Compose for controller work. Remove
   the hybrid-specific startup, routing and cleanup only after that coverage exists
   and one release passes with no reported dependency. A remaining user or coverage
   gap is a reason to keep the explicit profile, not to revert the new default.

## Decide the dedicated Codex boundary, then what we can safely expose

In the current single-cluster design, the trusted Gateway and Codex Harness occupy
separate Pods in the same tenant namespace, with separate storage and a paired
[workspace node][workspace]. The experimental two-cluster design puts the Gateway on
the control side. Separation costs us pairing, credential and policy plumbing, and
complicates [first-deploy activation][pr-855]. A shared Pod would share the network
namespace and node with hostile code. If owners want to evaluate it, use a separate
RFC to account for workload identity, the RFC-0003 storage boundary, placement,
channel credentials and transcripts. Neither embedded OpenClaw nor the proposed
[Gateway isolation RFC][pr-853] settles that decision for dedicated Codex.

### Support ordinary turns and handle operator overrides as distinct cases

As in [PR #824][pr-824], main deliberately points selected Gateway model transport at an unreachable address.
That can prevent a model call *after* fallback. It cannot require the Harness to run
the turn. The author of [open PR #830][pr-830] reports both consequences on an earlier
local installation, with the proposed configuration applied by hand:

- **Ordinary turn.** Authored request parameters triggered automatic fallback and a
  connection error. With the rewrite, the author observed the turn in the Harness.
  Before declining #830, the Compute owner owes affected users a supported path:
  preserve the parameters and run in the Harness, or reject an unsupported
  configuration before deployment with an actionable error. A failed turn or silently
  discarded owner setting is a real compatibility cost.
- **Deliberate switch.** Main restricts the `codex` and `openai` provider rows, but an
  operator with Configuration write access can add a third-party provider. Before the
  rewrite, the author selected that provider with `/model … --runtime openclaw`. The
  Gateway attempted the connection. The author attributed the refusal to that
  installation's network policy, and the proxy logged no request. After the rewrite,
  the third-party switch was refused, but an allowed Codex switch still ran in the
  Gateway and failed against the stub. The PR now covers channel overrides and image, PDF,
  utility and hook model selectors. It also documents selectors it cannot cover and
  Gateway-local features that stop working. This operator path is distinct from a
  capability granted to model-directed code. Any residual operator risk needs explicit
  owner acceptance.

Prefer an upstream runtime policy that forbids fallback, rejects session runtime
overrides and ignores a plugin's `fallbackRuntime`. The original proposal did not
file that upstream request. If owners require Harness-only execution, take the request
upstream and name the interim ordinary-turn behavior on #830 *before* closing it.
Do not describe either the current provider stub or the broader rewrite as enforcing
that policy.

### Offer native administration on first deploy only where an installation has enabled it

An administrator previously had to find the derived Agent origin in developer tools,
merge two JSON blocks and redeploy just to open chat. The [native administration
contract][native] now documents a first-Agent `--control-ui` option in the hybrid
OpenShell profile. Generalize the useful part: render the exact origin and managed
trusted-proxy configuration on first deploy. Decide first whether dedicated Gateways
should set `gateway.terminal.enabled: false`, removing the native debug shell while
leaving separately authorized `kubectl exec` available.

This is the full native administrator surface, not general browser chat. Keep
installation opt-in, private routing, trusted ingress across the explicit shared-cookie
domain, a human session, exact Agent `administer` permission and a matching active
Compute revision. GitHub, Google and OIDC sign-in cannot enable it under the current
session contract. [PR #873][pr-873] merged the handler extraction; it did not decide
who should get native administration. Remove the “pilot” label only when owners accept
this access and its support obligations.

<a id="alternatives-and-open-decisions"></a>
<a id="unresolved-questions"></a>

## Keep bundled SSH only with an accountable support owner

SSH is a [supported production choice][matrix]: one systemd unit per Agent on an
operator's Linux host, embedded OpenClaw, and `harnessAuth.method: runtime` with
host-managed credentials. It does not support dedicated Codex, OpenShell or OCC Secret
bindings, which is why [Slack cannot be enabled][issue-829]. Absence from our own
dogfooding tells us nothing about outside operators. Keep SSH bundled only if a named
maintainer owns the real-host test path and commits to resolving the Slack limitation
in [#829][issue-829]. Without that commitment, deprecate for a release and offer
Kubernetes or an external SSH package through the existing [Compute Driver package
interface][drivers]. Keep embedded OpenClaw and the Kubernetes/OpenShell path in scope.

The October 2 draft-PR triage is complete. By October 15, [#247], [#248], [#250],
[#458], [#460], [#574] and [#654] were all closed unmerged. Those closures do not
establish architecture or acceptance, and no triage decision is requested here.

[pr-898]: https://github.com/openclaw/openclaw-enterprise/pull/898
[source]: https://github.com/openclaw/openclaw-enterprise/tree/00bbc7cd976ab7be317ce1e0a9d36ad72ce10567
[quickstart]: ../../docs/guides/quickstart.md
[cli]: ../../internal/occcli/dev.go
[startup]: ../../docs/flows/docker-compose-development/startup.md
[local]: ../../docs/guides/deploy/local-kubernetes-development.md
[matrix]: ../../docs/reference/drivers/compute-matrix.md
[workspace]: ../../docs/flows/workspace-files.md
[native]: ../../docs/reference/agent-native-admin.md
[drivers]: ../../docs/flows/driver-plugin-loading.md
[pr-519]: https://github.com/openclaw/openclaw-enterprise/pull/519
[pr-824]: https://github.com/openclaw/openclaw-enterprise/pull/824
[pr-830]: https://github.com/openclaw/openclaw-enterprise/pull/830
[pr-853]: https://github.com/openclaw/openclaw-enterprise/pull/853
[pr-855]: https://github.com/openclaw/openclaw-enterprise/pull/855
[pr-873]: https://github.com/openclaw/openclaw-enterprise/pull/873
[issue-829]: https://github.com/openclaw/openclaw-enterprise/issues/829
[#247]: https://github.com/openclaw/openclaw-enterprise/pull/247
[#248]: https://github.com/openclaw/openclaw-enterprise/pull/248
[#250]: https://github.com/openclaw/openclaw-enterprise/pull/250
[#458]: https://github.com/openclaw/openclaw-enterprise/pull/458
[#460]: https://github.com/openclaw/openclaw-enterprise/pull/460
[#574]: https://github.com/openclaw/openclaw-enterprise/pull/574
[#654]: https://github.com/openclaw/openclaw-enterprise/pull/654
