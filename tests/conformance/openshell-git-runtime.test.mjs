import assert from "node:assert/strict";
import test from "node:test";
import {
  OpenShellGitRouteBlockedError,
  OpenShellGitRuntime,
  openShellGitRouteReadiness,
} from "../../apps/controller/src/drivers/egress-proxy/openshell-git-runtime.ts";
import { OpenShellPreparedGitProviderError } from "../../apps/controller/src/drivers/egress-proxy/openshell-prepared-git-provider.ts";
import {
  resolveGitHubRepositoryBinding,
  validateGitHubRepositoryRegistry,
} from "../../apps/controller/src/drivers/repo/github/credentials/registry.ts";
import {
  DependencyUnavailableError,
  SandboxGatewayUnavailableError,
} from "../../packages/occ/src/errors.ts";

// The worker-local runtime's reconcile and lookup, driven at the class boundary with a fake
// gateway client, provider and material owner: no OpenShell wire, no database. The provider's
// own wire behaviour is covered by openshell-prepared-git-provider.test.mjs.
const PUSH_REF = "refs/heads/review/task";
const registry = validateGitHubRepositoryRegistry(
  {
    version: 1,
    backendId: "github-primary",
    providerInstanceId: "github-com-primary",
    appId: "12345",
    githubInstallationId: "67890",
    maximumDurationSeconds: 86400,
    repositories: [
      {
        repositoryRef: "application",
        repositoryId: "34567",
        repository: "example/application",
        namespaces: [
          {
            namespaceId: "namespace-a",
            profiles: ["git-write"],
            pushRefAllowlist: [PUSH_REF],
            transport: "git-only",
          },
        ],
      },
    ],
  },
  "github-primary",
);
const admitted = resolveGitHubRepositoryBinding(registry, {
  namespaceId: "namespace-a",
  repositoryRef: "application",
  profile: "git-write",
});
const future = () => new Date(Date.now() + 600_000).toISOString();

function fixture() {
  const revision = Object.freeze({
    id: "rev-one",
    namespaceId: "namespace-a",
    agentId: "agent-one",
    harness: { id: "codex", mode: "dedicated" },
    repositoryCredentials: {
      driver: { id: "repo-driver", implementation: "github" },
      deadlineWallMs: Date.now() + 3_600_000,
      bindings: [admitted],
    },
  });
  const sandbox = {
    id: "sandbox-id-one",
    name: "git-execution",
    workspace: "team-workspace",
    phase: "SANDBOX_PHASE_READY",
    restartCount: 0,
    spec: { restart_policy: "SANDBOX_RESTART_POLICY_NEVER" },
  };
  const supervisor = {
    supervisorSessionId: "session-one",
    processInstanceId: "process-one",
    networkInstanceId: "network-one",
    attachmentEpoch: "epoch-one",
  };
  const calls = { getSandbox: 0, observe: 0, rotate: 0, material: 0 };
  const faults = {
    gateway: undefined,
    material: undefined,
    rotate: undefined,
    onRead: undefined,
    observe: undefined,
    observeAfterRotate: undefined,
  };
  const client = {
    getProvider: async () => ({ type: "openai", profileWorkspace: "" }),
    getProviderProfile: async () => ({
      definition: { endpoints: [{ host: "api.openai.com" }], credentials: [] },
    }),
    getSandbox: async () => {
      calls.getSandbox += 1;
      faults.onRead?.();
      if (faults.gateway) {
        throw faults.gateway;
      }
      return { ...sandbox };
    },
  };
  const provider = {
    observe: async (binding, sandboxId) => {
      calls.observe += 1;
      if (faults.observe) {
        // The provider status does not verify yet (observe() answers undefined, never throws).
        return undefined;
      }
      // Like the real observe(): the generation it reports is the one this binding holds.
      return Object.freeze({
        credentialState: binding.credentialState,
        providerResourceVersion: binding.resourceVersion,
        sandboxId,
        ...supervisor,
      });
    },
    rotate: async (binding, token) => {
      calls.rotate += 1;
      if (faults.rotate) {
        throw faults.rotate;
      }
      if (faults.observeAfterRotate) {
        // The supervisor has not applied the written generation yet: the verifying read
        // that follows reports nothing until the test clears faults.observe.
        faults.observe = true;
      }
      return {
        ...binding,
        credentialState: "active",
        expiresAt: token.expiresAt,
        resourceVersion: `${binding.resourceVersion}+`,
      };
    },
  };
  const material = {
    value: "synthetic-installation-token",
    expiresAt: future(),
    preparationAttemptId: "attempt-one",
    materialVersion: "version-one",
    repository: registry.repositories[0].repository,
    providerInstanceId: admitted.grant.providerInstanceId,
    repositoryId: admitted.grant.repositoryId,
    grantId: admitted.grant.grantId,
    pushRef: PUSH_REF,
    apiOrigin: "https://api.github.com",
    sessionId: "session-one",
  };
  const owner = {
    readOpenShellMaterial: async () => {
      calls.material += 1;
      if (faults.material) {
        throw faults.material;
      }
      return owner.material;
    },
    material,
    authorizeOpenShellRequest: async () => true,
  };
  const entry = {
    revision,
    client,
    provider,
    bindingId: "binding_0123456789abcdefghijklmn",
    repository: registry.repositories[0].repository,
    otherProviders: ["openai"],
    binding: {
      workspace: sandbox.workspace,
      sandbox: sandbox.name,
      provider: "oce-git",
      resourceVersion: "rv-1",
      credentialState: "bootstrap",
      expiresAt: future(),
    },
    verify: (observed) => {
      if (observed.name !== "git-execution") {
        throw new Error("Refusing OpenShell Sandbox without exact AgentRevision ownership.");
      }
    },
  };
  const events = [];
  const runtime = new OpenShellGitRuntime(
    { registrationName: "oce-prepared-git", authority: {} },
    registry,
  );
  runtime.owner = owner;
  runtime.emit = (event) => events.push(event);
  runtime.entries.set(revision.id, Promise.resolve(entry));
  runtime.states.set(revision.id, { entry });
  const identity = {
    sandboxId: sandbox.id,
    bindingId: entry.bindingId,
    workspace: sandbox.workspace,
    requestId: "request-one",
  };
  const reconcile = async () => {
    // Force the refresh and backoff clocks so each call observes now.
    entry.nextRefreshAt = 0;
    entry.nextObserveAt = 0;
    await runtime.reconcile(entry);
  };
  const lookup = () => runtime.lookup(identity, AbortSignal.timeout(2_000));
  const prepare = () =>
    runtime.prepare(revision, client, sandbox.workspace, sandbox.name, AbortSignal.timeout(2_000), [
      "openai",
    ]);
  const errors = () => events.filter((event) => event.event === "worker.error");
  const denials = () => events.filter((event) => event.event === "worker.openshell-git-denied");
  return {
    runtime,
    entry,
    sandbox,
    supervisor,
    calls,
    faults,
    owner,
    events,
    reconcile,
    lookup,
    prepare,
    identity,
    errors,
    denials,
    revision,
  };
}

test("a gateway that does not answer closes the Git route and restores it without a tombstone", async () => {
  const f = fixture();
  await f.reconcile();
  assert.deepEqual(f.runtime.route(f.revision.id), { state: "installed" });
  assert.equal(f.calls.rotate, 1);
  assert.equal((await f.lookup())?.executionId, f.revision.id);

  // The Gateway Pod is being replaced: grpc-js's own UNAVAILABLE for an unanswered call.
  f.faults.gateway = new SandboxGatewayUnavailableError("OpenShell GetSandbox failed.");
  await f.reconcile();
  assert.equal(f.entry.blocked, undefined);
  assert.equal(f.entry.installed, undefined);
  assert.deepEqual(f.runtime.route(f.revision.id), {
    state: "pending",
    reason: "unobserved",
    failure: "gateway_unavailable",
  });
  assert.deepEqual(f.errors(), []);
  assert.deepEqual(
    f.events.filter((event) => event.event === "worker.openshell-git-route-warning"),
    [
      {
        event: "worker.openshell-git-route-warning",
        status: "unobserved",
        reason: "gateway_unavailable",
        namespaceId: "namespace-a",
        agentId: "agent-one",
        revisionId: "rev-one",
        repositoryRef: "application",
      },
    ],
  );
  // Closed: a request is denied, and the denial says why.
  assert.equal(await f.lookup(), undefined);
  assert.equal(f.denials().at(-1).reason, "route_unobserved");
  assert.equal(f.denials().at(-1).sandboxId, f.sandbox.id);
  assert.equal(f.denials().at(-1).revisionId, "rev-one");

  // Bounded backoff: the next tick inside the backoff window reads nothing.
  const reads = f.calls.getSandbox;
  assert.ok(f.entry.nextObserveAt > performance.now());
  await f.runtime.reconcile(f.entry);
  assert.equal(f.calls.getSandbox, reads);
  // A later failed read doubles the wait and is not reported again.
  await f.reconcile();
  assert.equal(f.entry.unobserved.failures, 2);
  assert.ok(f.entry.nextObserveAt - performance.now() > 1_500);
  assert.equal(
    f.events.filter((event) => event.event === "worker.openshell-git-route-warning").length,
    1,
  );

  // The gateway answers again and the same installation verifies: the route is back, with
  // no new provider write and no token replay.
  f.faults.gateway = undefined;
  await f.reconcile();
  assert.deepEqual(f.runtime.route(f.revision.id), { state: "installed" });
  assert.equal(f.calls.rotate, 1);
  assert.equal((await f.lookup())?.executionId, f.revision.id);
  const restored = f.events.filter(
    (event) => event.event === "worker.openshell-git-route" && event.status === "restored",
  );
  assert.equal(restored.length, 1);
  assert.ok(Number.isFinite(restored[0].durationMs) && restored[0].durationMs >= 0);
  assert.equal(restored[0].revisionId, "rev-one");
  assert.deepEqual(f.errors(), []);

  // Other read failures close the route the same way: a timed-out read, another failed
  // gateway request, an answer the client could not parse, and a material store read.
  for (const [fault, failure] of [
    [Object.assign(new Error("timed out"), { name: "TimeoutError" }), "timeout"],
    [
      new DependencyUnavailableError("OpenShell GetSandbox failed with gRPC status 13."),
      "gateway_request_failed",
    ],
    [new Error("Invalid Sandbox status."), "read_failed"],
  ]) {
    f.faults.gateway = fault;
    await f.reconcile();
    assert.deepEqual(f.runtime.route(f.revision.id), {
      state: "pending",
      reason: "unobserved",
      failure,
    });
    f.faults.gateway = undefined;
    await f.reconcile();
    assert.deepEqual(f.runtime.route(f.revision.id), { state: "installed" });
  }
  f.faults.material = new Error("connection terminated");
  await f.reconcile();
  assert.deepEqual(f.runtime.route(f.revision.id), {
    state: "pending",
    reason: "unobserved",
    failure: "read_failed",
  });
  f.faults.material = undefined;
  await f.reconcile();
  assert.deepEqual(f.runtime.route(f.revision.id), { state: "installed" });
  assert.deepEqual(f.errors(), []);
  assert.equal(f.calls.rotate, 1);

  // A request arriving while the gateway is away closes the route too, and nothing more.
  f.faults.gateway = new SandboxGatewayUnavailableError("OpenShell GetSandbox failed.");
  assert.equal(await f.lookup(), undefined);
  assert.equal(f.denials().at(-1).reason, "route_unobserved");
  assert.equal(f.entry.blocked, undefined);
  f.faults.gateway = undefined;
  await f.reconcile();
  assert.equal((await f.lookup())?.executionId, f.revision.id);
  assert.deepEqual(f.errors(), []);

  // A request whose own budget runs out mid-read is denied, and the route it could not
  // observe stays as reconcile left it: no closure, no warning.
  const warnings = () =>
    f.events.filter((event) => event.event === "worker.openshell-git-route-warning").length;
  const before = warnings();
  const controller = new AbortController();
  f.faults.onRead = () => {
    controller.abort();
    throw Object.assign(new Error("aborted"), { name: "AbortError" });
  };
  assert.equal(await f.runtime.lookup(f.identity, controller.signal), undefined);
  f.faults.onRead = undefined;
  assert.equal(f.denials().at(-1).reason, "lookup_aborted");
  assert.deepEqual(f.runtime.route(f.revision.id), { state: "installed" });
  assert.equal(warnings(), before);

  // A plain material rotation is not an outage: it installs the new version and reports no
  // restoration.
  const restorations = () =>
    f.events.filter(
      (event) => event.event === "worker.openshell-git-route" && event.status === "restored",
    ).length;
  const restoredBefore = restorations();
  f.owner.material = { ...f.owner.material, materialVersion: "version-two" };
  await f.reconcile();
  assert.deepEqual(f.runtime.route(f.revision.id), { state: "installed" });
  assert.equal(f.calls.rotate, 2);
  assert.equal(restorations(), restoredBefore);
  assert.deepEqual(f.errors(), []);
});

// OpenShell resets every Sandbox connection when it installs a credential (finding 2141);
// Compute activation waits for the node to be back after the time the route reports here.
test("the route reports when it verified its current material installed", async () => {
  const f = fixture();
  assert.equal(f.runtime.materialInstalledAt(f.revision.id), undefined);
  const before = Date.now();
  await f.reconcile();
  assert.deepEqual(f.runtime.route(f.revision.id), { state: "installed" });
  const first = f.runtime.materialInstalledAt(f.revision.id);
  assert.ok(typeof first === "number" && first >= before && first <= Date.now());
  // The clock is the wall clock: let it move between verifications so a time refreshed on
  // every read, or kept across new material, would show.
  const later = () => new Promise((resolve) => setTimeout(resolve, 5));

  // Re-reading the same installation keeps its time.
  await later();
  await f.reconcile();
  assert.equal(f.runtime.materialInstalledAt(f.revision.id), first);

  // A closed route has no installed material to time; the same installation verifying
  // again reports the original time (no new install happened).
  f.faults.gateway = new SandboxGatewayUnavailableError("OpenShell GetSandbox failed.");
  await f.reconcile();
  assert.equal(f.runtime.route(f.revision.id).state, "pending");
  assert.equal(f.runtime.materialInstalledAt(f.revision.id), undefined);
  f.faults.gateway = undefined;
  await later();
  await f.reconcile();
  assert.equal(f.runtime.materialInstalledAt(f.revision.id), first);
  assert.equal(f.calls.rotate, 1);

  // New material installs at a new time.
  f.owner.material = { ...f.owner.material, materialVersion: "version-two" };
  await later();
  await f.reconcile();
  assert.equal(f.calls.rotate, 2);
  const second = f.runtime.materialInstalledAt(f.revision.id);
  assert.ok(typeof second === "number" && second > first, `${second} > ${first}`);

  // Lost material closes the route; its time goes with it.
  f.owner.material = undefined;
  await f.reconcile();
  assert.equal(f.runtime.route(f.revision.id).state, "pending");
  assert.equal(f.runtime.materialInstalledAt(f.revision.id), undefined);
  assert.deepEqual(f.errors(), []);
});

test("the same supervisor process reconnecting with a new session re-adopts the Git route", async () => {
  const restorations = (f) =>
    f.events.filter(
      (event) => event.event === "worker.openshell-git-route" && event.status === "restored",
    );

  // A replaced Gateway Pod: the read fails, then the same process reconnects to the new Pod
  // under a new control session. The route reopens on the next verified read, with no new
  // version, no provider write and no token replay (finding 2136, owner decision 10-20).
  let f = fixture();
  await f.reconcile();
  assert.deepEqual(f.runtime.route(f.revision.id), { state: "installed" });
  f.faults.gateway = new SandboxGatewayUnavailableError("OpenShell GetSandbox failed.");
  await f.reconcile();
  assert.deepEqual(f.runtime.route(f.revision.id), {
    state: "pending",
    reason: "unobserved",
    failure: "gateway_unavailable",
  });
  f.faults.gateway = undefined;
  f.supervisor.supervisorSessionId = "session-two";
  await f.reconcile();
  assert.deepEqual(f.runtime.route(f.revision.id), { state: "installed" });
  assert.equal(f.entry.blocked, undefined);
  assert.deepEqual(f.errors(), []);
  assert.equal(f.calls.rotate, 1);
  assert.equal(f.entry.supervisor.supervisorSessionId, "session-two");
  assert.equal((await f.lookup())?.executionId, f.revision.id);
  assert.equal(restorations(f).length, 1);
  assert.equal(restorations(f)[0].reason, "supervisor_reconnected");
  assert.ok(Number.isFinite(restorations(f)[0].durationMs) && restorations(f)[0].durationMs >= 0);
  assert.equal(restorations(f)[0].revisionId, "rev-one");
  assert.equal(restorations(f)[0].repositoryRef, "application");
  // The adopted session is the reference from here on: a later read reports nothing more.
  await f.reconcile();
  assert.equal((await f.lookup())?.executionId, f.revision.id);
  assert.equal(restorations(f).length, 1);
  assert.deepEqual(f.errors(), []);
  // A second reconnect (another Gateway restart) is adopted the same way.
  f.supervisor.supervisorSessionId = "session-three";
  await f.reconcile();
  assert.deepEqual(f.runtime.route(f.revision.id), { state: "installed" });
  assert.equal(restorations(f).length, 2);
  assert.deepEqual(f.errors(), []);

  // The reconnect is first seen by a request: that request is denied as a changed
  // installation, and the worker's own reconcile adopts the session and reopens the route.
  f = fixture();
  await f.reconcile();
  f.supervisor.supervisorSessionId = "session-two";
  assert.equal(await f.lookup(), undefined);
  assert.equal(f.denials().at(-1).reason, "installation_changed");
  assert.deepEqual(f.runtime.route(f.revision.id), { state: "pending", reason: "unverified" });
  assert.deepEqual(f.errors(), []);
  await f.reconcile();
  assert.deepEqual(f.runtime.route(f.revision.id), { state: "installed" });
  assert.equal((await f.lookup())?.executionId, f.revision.id);
  assert.equal(restorations(f).length, 1);
  assert.equal(restorations(f)[0].reason, "supervisor_reconnected");
  assert.equal(f.calls.rotate, 1);

  // The new session is adopted only once its observation verifies: while the provider
  // status does not, the route waits (no adoption, no tombstone); then it reopens.
  f = fixture();
  await f.reconcile();
  f.faults.gateway = new SandboxGatewayUnavailableError("OpenShell GetSandbox failed.");
  await f.reconcile();
  f.faults.gateway = undefined;
  f.faults.observe = true;
  f.supervisor.supervisorSessionId = "session-two";
  await f.reconcile();
  assert.deepEqual(f.runtime.route(f.revision.id), { state: "pending", reason: "unverified" });
  assert.equal(f.entry.supervisor.supervisorSessionId, "session-one");
  assert.equal(await f.lookup(), undefined);
  assert.equal(f.denials().at(-1).reason, "route_pending");
  assert.deepEqual(f.errors(), []);
  f.faults.observe = undefined;
  await f.reconcile();
  assert.deepEqual(f.runtime.route(f.revision.id), { state: "installed" });
  assert.equal(f.entry.supervisor.supervisorSessionId, "session-two");
  assert.equal(restorations(f).length, 1);
  assert.equal(restorations(f)[0].reason, "supervisor_reconnected");
  assert.equal(f.calls.rotate, 1);
  assert.deepEqual(f.errors(), []);

  // A Gateway restart that overlaps a credential rotation: the rotation wrote a new provider
  // generation, its verifying read lagged, then the supervisor reconnected. The adopted
  // observation carries the generation this worker wrote (observe() pins it to the binding),
  // not the one read before the rotation, so the route reopens instead of closing for good.
  f = fixture();
  await f.reconcile();
  assert.equal(f.entry.supervisor.providerResourceVersion, "rv-1+");
  f.owner.material = { ...f.owner.material, materialVersion: "version-two" };
  f.faults.observeAfterRotate = true;
  await f.reconcile();
  assert.equal(f.calls.rotate, 2);
  assert.deepEqual(f.runtime.route(f.revision.id), { state: "pending", reason: "unverified" });
  assert.equal(f.entry.supervisor.providerResourceVersion, "rv-1+");
  f.faults.gateway = new SandboxGatewayUnavailableError("OpenShell GetSandbox failed.");
  await f.reconcile();
  f.faults.gateway = undefined;
  f.faults.observe = undefined;
  f.supervisor.supervisorSessionId = "session-two";
  await f.reconcile();
  assert.deepEqual(f.runtime.route(f.revision.id), { state: "installed" });
  assert.equal(f.entry.supervisor.providerResourceVersion, "rv-1++");
  assert.equal(f.entry.supervisor.supervisorSessionId, "session-two");
  assert.equal(f.calls.rotate, 2);
  assert.deepEqual(f.errors(), []);
  assert.equal(restorations(f).length, 1);
  assert.equal(restorations(f)[0].reason, "supervisor_reconnected");

  // A reconnect before the route ever opened (a deploying version awaiting its material) is
  // adopted silently: the first install is not a restoration.
  f = fixture();
  f.owner.material = undefined;
  await f.reconcile();
  assert.deepEqual(f.runtime.route(f.revision.id), {
    state: "pending",
    reason: "awaiting_material",
  });
  f.supervisor.supervisorSessionId = "session-two";
  await f.reconcile();
  assert.equal(f.entry.supervisor.supervisorSessionId, "session-two");
  f.owner.material = fixture().owner.material;
  await f.reconcile();
  assert.deepEqual(f.runtime.route(f.revision.id), { state: "installed" });
  assert.deepEqual(restorations(f), []);
  assert.deepEqual(f.errors(), []);
});

test("another Agent's deploy leaves a running Agent's Git route open", async () => {
  // Finding 2146: a sibling Agent's deploy moves the running Sandbox's provider environment
  // revision (another attached provider changed). Its requests keep passing, before and after
  // the worker's reconcile adopts the new revision, with no denial and no provider write.
  const f = fixture();
  f.supervisor.providerEnvRevision = "env-one";
  f.supervisor.configRevision = "config-one";
  f.supervisor.policyHash = "policy-one";
  await f.reconcile();
  assert.deepEqual(f.runtime.route(f.revision.id), { state: "installed" });
  f.supervisor.providerEnvRevision = "env-two";
  assert.equal((await f.lookup())?.executionId, f.revision.id);
  assert.deepEqual(f.runtime.route(f.revision.id), { state: "installed" });
  await f.reconcile();
  assert.equal(f.entry.installed.providerEnvRevision, "env-two");
  assert.equal((await f.lookup())?.executionId, f.revision.id);
  assert.deepEqual(f.denials(), []);
  assert.equal(f.calls.rotate, 1);
  assert.deepEqual(f.errors(), []);

  // The installation itself still has to read the same: a changed policy or configuration
  // closes the route until the reconcile verifies it again.
  for (const [field, value] of [
    ["policyHash", "policy-two"],
    ["configRevision", "config-two"],
    ["attachmentEpoch", "epoch-two"],
  ]) {
    const g = fixture();
    g.supervisor.providerEnvRevision = "env-one";
    await g.reconcile();
    g.supervisor[field] = value;
    g.supervisor.providerEnvRevision = "env-two";
    assert.equal(await g.lookup(), undefined, field);
    assert.equal(g.denials().at(-1).reason, "installation_changed", field);
  }
});

test("an open Git route that loses its material says so once and names it in each denial", async () => {
  // The owner retired the active version's material (the App key was rotated or rejected and
  // preparation is quarantined, or access was withdrawn): the route closes, every request is
  // denied as material_unavailable, the first such denial logs one warning that names the
  // version, and the restoration reports the outage's length (finding 2135). A version
  // superseded by a newer one loses its material too, a moment before it is withdrawn, and
  // no request asks for it: the close alone is not reported.
  const warnings = (f) =>
    f.events.filter((event) => event.event === "worker.openshell-git-route-warning");
  const f = fixture();
  const material = f.owner.material;
  await f.reconcile();
  assert.deepEqual(f.runtime.route(f.revision.id), { state: "installed" });
  f.owner.material = undefined;
  await f.reconcile();
  assert.deepEqual(f.runtime.route(f.revision.id), {
    state: "pending",
    reason: "material_unavailable",
  });
  assert.equal(f.entry.blocked, undefined);
  assert.deepEqual(warnings(f), []);
  assert.equal(await f.lookup(), undefined);
  assert.deepEqual(warnings(f), [
    {
      event: "worker.openshell-git-route-warning",
      status: "pending",
      reason: "material_unavailable",
      namespaceId: "namespace-a",
      agentId: "agent-one",
      revisionId: "rev-one",
      repositoryRef: "application",
    },
  ]);
  assert.equal(f.denials().at(-1).reason, "material_unavailable");
  assert.equal(f.denials().at(-1).revisionId, "rev-one");
  // Still unavailable: no second warning, the same denial.
  await f.reconcile();
  assert.equal(await f.lookup(), undefined);
  assert.equal(f.denials().at(-1).reason, "material_unavailable");
  assert.equal(warnings(f).length, 1);
  assert.deepEqual(f.errors(), []);
  // Material again (a new preparation after recovery): the route reopens and reports it.
  f.owner.material = material;
  await f.reconcile();
  assert.deepEqual(f.runtime.route(f.revision.id), { state: "installed" });
  assert.equal((await f.lookup())?.executionId, f.revision.id);
  const restored = f.events.filter(
    (event) => event.event === "worker.openshell-git-route" && event.status === "restored",
  );
  assert.equal(restored.length, 1);
  assert.equal(restored[0].reason, undefined);
  assert.ok(Number.isFinite(restored[0].durationMs) && restored[0].durationMs >= 0);

  // Lost again after the restoration: reported again, once.
  f.owner.material = undefined;
  await f.reconcile();
  assert.equal(await f.lookup(), undefined);
  assert.equal(await f.lookup(), undefined);
  assert.equal(warnings(f).length, 2);

  // Material lost while the route is closed by a failed read: once the Gateway answers, the
  // route reads as material_unavailable, and the first refused request reports it.
  const h = fixture();
  await h.reconcile();
  h.faults.gateway = new SandboxGatewayUnavailableError("OpenShell GetSandbox failed.");
  await h.reconcile();
  h.owner.material = undefined;
  h.faults.gateway = undefined;
  await h.reconcile();
  assert.deepEqual(h.runtime.route(h.revision.id), {
    state: "pending",
    reason: "material_unavailable",
  });
  assert.equal(await h.lookup(), undefined);
  assert.equal(h.denials().at(-1).reason, "material_unavailable");
  assert.equal(warnings(h).filter((event) => event.reason === "material_unavailable").length, 1);

  // A version that never had material (deploying; it is issued once the version is active)
  // is not an outage: no warning, and its denial stays route_pending.
  const g = fixture();
  g.owner.material = undefined;
  await g.reconcile();
  assert.deepEqual(g.runtime.route(g.revision.id), {
    state: "pending",
    reason: "awaiting_material",
  });
  assert.equal(await g.lookup(), undefined);
  assert.equal(g.denials().at(-1).reason, "route_pending");
  assert.deepEqual(warnings(g), []);
});

test("the Git route tombstone stays for a replaced execution, an unknown write and withdrawal", async () => {
  const expectBlocked = async (f, reason) => {
    assert.deepEqual(f.runtime.route(f.revision.id), { state: "blocked", reason });
    assert.deepEqual(f.errors(), [
      {
        event: "worker.error",
        code: "OPENSHELL_GIT_RECONCILIATION_REQUIRED",
        reason,
        namespaceId: "namespace-a",
        agentId: "agent-one",
        revisionId: "rev-one",
        repositoryRef: "application",
      },
    ]);
    // A gateway that answers again never reopens a tombstone.
    f.faults.gateway = undefined;
    await f.reconcile();
    assert.deepEqual(f.runtime.route(f.revision.id), { state: "blocked", reason });
    assert.equal(await f.lookup(), undefined);
    assert.equal(f.denials().at(-1).reason, "route_blocked");
    assert.equal(f.errors().length, 1);
    // The next preparation pass fails with the typed cause Compute turns into held
    // runtime-failure evidence, instead of a retry that can never succeed.
    await assert.rejects(
      f.prepare(),
      (error) => error instanceof OpenShellGitRouteBlockedError && error.reason === reason,
    );
  };

  // The gateway answered and refused this worker's identity: never retried.
  let f = fixture();
  await f.reconcile();
  assert.equal(f.runtime.route(f.revision.id).state, "installed");
  f.faults.gateway = Object.assign(new Error("7 PERMISSION_DENIED: workspace"), { code: 7 });
  await f.reconcile();
  await expectBlocked(f, "gateway_unauthorized");

  // The sandbox restarted under the same name.
  f = fixture();
  await f.reconcile();
  f.sandbox.restartCount = 1;
  await f.reconcile();
  await expectBlocked(f, "execution_replaced");

  // Another supervisor process reports the installation under a new session.
  f = fixture();
  await f.reconcile();
  f.supervisor.supervisorSessionId = "session-two";
  f.supervisor.processInstanceId = "process-two";
  await f.reconcile();
  await expectBlocked(f, "supervisor_replaced");

  // The same process under a new session, but on another network instance.
  f = fixture();
  await f.reconcile();
  f.supervisor.supervisorSessionId = "session-two";
  f.supervisor.networkInstanceId = "network-two";
  await f.reconcile();
  await expectBlocked(f, "supervisor_replaced");

  // A changed process or network instance within the same session.
  for (const key of ["processInstanceId", "networkInstanceId"]) {
    f = fixture();
    await f.reconcile();
    f.supervisor[key] = `${key}-two`;
    await f.reconcile();
    await expectBlocked(f, "supervisor_replaced");
  }

  // A new session whose verified observation differs from the installation observed before
  // (here the provider attachment epoch): adopted only when everything else reads the same.
  f = fixture();
  await f.reconcile();
  f.supervisor.supervisorSessionId = "session-two";
  f.supervisor.attachmentEpoch = "epoch-two";
  await f.reconcile();
  await expectBlocked(f, "supervisor_replaced");

  // The sandbox no longer matches the admitted create request.
  f = fixture();
  await f.reconcile();
  f.sandbox.name = "another-sandbox";
  await f.reconcile();
  await expectBlocked(f, "sandbox_mismatch");

  // The provider write's outcome is unknown: no retry, replacement, or token replay.
  f = fixture();
  f.faults.rotate = new OpenShellPreparedGitProviderError("unknown");
  await f.reconcile();
  await expectBlocked(f, "write_unknown");
  assert.equal(f.calls.rotate, 1);

  // The provider refused the write for its own reason (a changed generation).
  f = fixture();
  f.faults.rotate = new OpenShellPreparedGitProviderError("refused");
  await f.reconcile();
  await expectBlocked(f, "write_refused");

  // Refused only because the gateway did not answer before the write: observed again, then
  // the rotation completes once.
  f = fixture();
  f.faults.rotate = new OpenShellPreparedGitProviderError("refused", "gateway_unavailable");
  await f.reconcile();
  assert.deepEqual(f.runtime.route(f.revision.id), {
    state: "pending",
    reason: "unobserved",
    failure: "gateway_unavailable",
  });
  assert.deepEqual(f.errors(), []);
  f.faults.rotate = undefined;
  await f.reconcile();
  assert.deepEqual(f.runtime.route(f.revision.id), { state: "installed" });
  assert.equal(f.calls.rotate, 2);

  // Material that no longer matches the admitted grant.
  f = fixture();
  await f.reconcile();
  f.owner.material = { ...f.owner.material, pushRef: "refs/heads/main" };
  await f.reconcile();
  await expectBlocked(f, "material_mismatch");

  // Withdrawal closes the route without a reconciliation report of its own.
  f = fixture();
  await f.reconcile();
  f.runtime.withdraw(f.revision.id);
  await Promise.resolve();
  assert.deepEqual(f.runtime.route(f.revision.id), { state: "blocked", reason: "withdrawn" });
  assert.deepEqual(f.errors(), []);
  assert.equal(await f.lookup(), undefined);
  assert.equal(f.denials().at(-1).reason, "route_blocked");
});

test("the Git route reports bootstrap, material and binding states for Compute readiness", async () => {
  const f = fixture();
  assert.equal(
    (await f.prepare()).middlewares["oce-prepared-git"].config.fields.binding_id.stringValue,
    f.entry.bindingId,
  );
  assert.deepEqual(f.runtime.route("unknown-revision"), { state: "none" });
  f.runtime.states.set("rev-two", {});
  assert.deepEqual(f.runtime.route("rev-two"), { state: "bootstrapping" });
  f.runtime.states.set("rev-three", { failed: true });
  assert.deepEqual(f.runtime.route("rev-three"), {
    state: "blocked",
    reason: "bootstrap_failed",
  });
  // No committed material yet (the revision is not active yet, or the App key was rotated
  // and preparation is quarantined): the route waits, nothing is written, and the state says so.
  f.owner.material = undefined;
  await f.reconcile();
  assert.deepEqual(f.runtime.route(f.revision.id), {
    state: "pending",
    reason: "awaiting_material",
  });
  assert.equal(f.calls.rotate, 0);
  assert.equal(await f.lookup(), undefined);
  assert.equal(f.denials().at(-1).reason, "route_pending");
  // A request from a sandbox that is not the admitted one, with this entry's binding.
  f.owner.material = fixture().owner.material;
  await f.reconcile();
  assert.deepEqual(f.runtime.route(f.revision.id), { state: "installed" });
  assert.equal(
    await f.runtime.lookup(
      {
        sandboxId: "another-sandbox-id",
        bindingId: f.entry.bindingId,
        workspace: f.sandbox.workspace,
        requestId: "request-two",
      },
      AbortSignal.timeout(2_000),
    ),
    undefined,
  );
  assert.equal(f.denials().at(-1).reason, "execution_mismatch");
  assert.equal(f.denials().at(-1).requestId, "request-two");
  // A binding this worker never prepared.
  assert.equal(
    await f.runtime.lookup(
      {
        sandboxId: f.sandbox.id,
        bindingId: "binding_zzzzzzzzzzzzzzzzzzzzzzzz",
        workspace: f.sandbox.workspace,
        requestId: "request-three",
      },
      AbortSignal.timeout(2_000),
    ),
    undefined,
  );
  assert.deepEqual(f.denials().at(-1), {
    event: "worker.openshell-git-denied",
    reason: "no_binding",
    sandboxId: f.sandbox.id,
    requestId: "request-three",
  });
  assert.deepEqual(f.errors(), []);
});

test("a deploying revision whose route verified is ready before its material exists", async () => {
  // Finding 2139: material is prepared and read only for the Agent's active revision, so a
  // revision Compute is still readying never gets any. Holding it until the route is
  // installed left every deployment with an OpenShell Git binding pending forever.
  const f = fixture();
  const readiness = () => openShellGitRouteReadiness(f.runtime.route(f.revision.id));
  assert.equal(openShellGitRouteReadiness(f.runtime.route("unknown-revision")), "pending");
  f.runtime.states.set("rev-two", {});
  assert.equal(openShellGitRouteReadiness(f.runtime.route("rev-two")), "pending");
  f.runtime.states.set("rev-three", { failed: true });
  assert.equal(openShellGitRouteReadiness(f.runtime.route("rev-three")), "blocked");
  // The Sandbox has not verified yet: wait.
  f.owner.material = undefined;
  f.sandbox.phase = "SANDBOX_PHASE_PROVISIONING";
  await f.reconcile();
  assert.deepEqual(f.runtime.route(f.revision.id), { state: "pending", reason: "unverified" });
  assert.equal(readiness(), "pending");
  // Verified, no material yet (not active): ready to activate, still nothing written or sent.
  f.sandbox.phase = "SANDBOX_PHASE_READY";
  await f.reconcile();
  assert.deepEqual(f.runtime.route(f.revision.id), {
    state: "pending",
    reason: "awaiting_material",
  });
  assert.equal(readiness(), "ready");
  assert.equal(f.calls.rotate, 0);
  assert.equal(await f.lookup(), undefined);
  // Activated: material arrives and installs.
  f.owner.material = fixture().owner.material;
  await f.reconcile();
  assert.deepEqual(f.runtime.route(f.revision.id), { state: "installed" });
  assert.equal(readiness(), "ready");
  // A failed read closes the route: wait, never fail.
  f.faults.gateway = new SandboxGatewayUnavailableError("OpenShell GetSandbox failed.");
  await f.reconcile();
  assert.equal(f.runtime.route(f.revision.id).reason, "unobserved");
  assert.equal(readiness(), "pending");
  f.faults.gateway = undefined;
  await f.reconcile();
  assert.equal(readiness(), "ready");
  // An active revision that loses its material (the attempt was retired or expired, the
  // App key was rejected) closes the route and is not ready again until material returns.
  f.owner.material = undefined;
  await f.reconcile();
  assert.deepEqual(f.runtime.route(f.revision.id), {
    state: "pending",
    reason: "material_unavailable",
  });
  assert.equal(readiness(), "pending");
  assert.equal(await f.lookup(), undefined);
  f.owner.material = fixture().owner.material;
  await f.reconcile();
  assert.equal(readiness(), "ready");
  // A replaced execution blocks the route for good.
  f.sandbox.id = "sandbox-id-two";
  await f.reconcile();
  assert.equal(f.runtime.route(f.revision.id).state, "blocked");
  assert.equal(readiness(), "blocked");
});

test("a restarted worker names why it cannot adopt a revision's Sandbox, once per revision", async () => {
  // Finding 2140: after a worker restart the Sandbox survives, but this worker never prepared
  // it. Each later pass rethrows the retained failure; the cause is logged once, with the
  // Agent, revision and repositoryRef, so the operator knows a new revision is required.
  const f = fixture();
  f.runtime.entries.clear();
  f.runtime.states.clear();
  for (let pass = 0; pass < 3; pass += 1) {
    await assert.rejects(f.prepare(), /requires a new revision after worker restart/);
  }
  assert.deepEqual(f.errors(), [
    {
      event: "worker.error",
      code: "OPENSHELL_GIT_RECONCILIATION_REQUIRED",
      reason: "worker_restarted",
      namespaceId: "namespace-a",
      agentId: "agent-one",
      revisionId: "rev-one",
      repositoryRef: "application",
    },
  ]);
  assert.equal(f.calls.getSandbox, 1, "the retained failure is not re-observed");
  assert.equal(openShellGitRouteReadiness(f.runtime.route(f.revision.id)), "blocked");
});

test("the Git route refuses overlapping policies at startup and again at deploy", async () => {
  // Finding 2131: the Sandbox Driver checks its configured policies when it is built; prepare()
  // keeps refusing hosts that reach github.com or api.github.com outside the route. Finding 2145:
  // an IP-address host may lead to GitHub as well, so it is refused outright and reported as one.
  const f = fixture();
  const policy = (name, host) => ({ name, endpoints: [{ host }] });
  assert.equal(
    f.runtime.overlappingPolicy([
      policy("model", "api.openai.com"),
      policy("docs", "docs.github.com"),
      policy("digits", "1password.com"),
      policy("label", "build.123abc"),
    ]),
    undefined,
  );
  const hosts = [
    ...[
      "github.com",
      "API.GITHUB.COM",
      "api.github.com.",
      "*.github.com",
      "bad host",
      "github.com:443",
    ].map((host) => [host, false]),
    ...[
      "140.82.112.3",
      "140.82.112.3.",
      "140.82.112.3:443",
      "127.0.0.1",
      "*.82.112.3",
      "0x8c.0x52.0x70.0x3",
      "0X8C.0X52.0X70.0X3",
      "2354212867",
      "140.82.112.0/20",
      "2606:50c0:8000::154",
      "[2606:50c0:8000::154]",
      "::ffff:140.82.112.3",
      "::/0",
    ].map((host) => [host, true]),
  ];
  for (const [host, ipAddress] of hosts) {
    assert.deepEqual(
      f.runtime.overlappingPolicy([policy("model", "api.openai.com"), policy("git", host)]),
      { name: "git", host, ipAddress },
      host,
    );
    await assert.rejects(
      f.runtime.prepare(
        f.revision,
        {},
        f.sandbox.workspace,
        f.sandbox.name,
        AbortSignal.timeout(2_000),
        ["openai"],
        ["api.openai.com", host],
      ),
      /OpenShell Git cannot share overlapping network policy/,
      host,
    );
  }
});
