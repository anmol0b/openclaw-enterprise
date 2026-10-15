import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import {
  assertNoConnectedAssistantOutput,
  protectedAgentBody,
  protectedConfigurationBody,
  protectedSourceBody,
  sourceAccessBindingBody,
} from "../helpers/egress-connected-inputs.mjs";

import {
  arrangeRealPrerequisites,
  observePreparedStack,
  createRunEvidence,
} from "../helpers/egress-installed-stack.mjs";
import {
  registerCleanupAndStartProvider,
  observeInstalledProtection,
} from "../helpers/egress-installed-agent.mjs";

const inputsPath = process.env.OCC_TEST_EGRESS_CONNECTED_INPUTS;
const selected = process.env.OCC_TEST_EGRESS_CONNECTED === "1" || inputsPath !== undefined;

function safeConnectedFailure(error, stage) {
  // Assertions and subprocess errors may embed response bytes. Keep a source
  // location and the durable phase, never raw error payloads or an unsafe cause.
  const location =
    String(error.stack).match(
      /(?:agent-openshell-static-egress-k3d-real\.test|egress-connected-inputs|openshell-kubernetes-real)\.mjs:\d+:\d+/,
    )?.[0] ?? "external-operation";
  const kind = error.code === "ERR_ASSERTION" ? "assertion" : "operation";
  return new Error(
    `Connected egress ${kind} failed at ${stage} (${location}); inspect the per-run ledger`,
  );
}

/**
 * @typedef {Awaited<ReturnType<typeof arrangeRealPrerequisites>>} Prerequisites
 * @typedef {Awaited<ReturnType<typeof createRunEvidence>>} RunEvidence
 * @typedef {Awaited<ReturnType<typeof observePreparedStack>>} PreparedStack
 * @typedef {Awaited<ReturnType<typeof registerCleanupAndStartProvider>>} OwnedResources
 * @typedef {Awaited<ReturnType<typeof deployProtectedAgent>>} Deployment
 * @typedef {Awaited<ReturnType<typeof observeInstalledProtection>>} InstalledProtection
 * @typedef {Awaited<ReturnType<typeof observeRunningAgent>>} AgentTurns
 */

test(
  "a protected OpenShell Agent uses fresh IAM, live Secret rotation and bounded Responses delivery",
  {
    skip: selected ? false : "Select OCC_TEST_EGRESS_CONNECTED=1 with a prepared protected stack.",
    timeout: 30 * 60_000,
  },
  async (t) => {
    const progress = { stage: "input-preflight" };
    try {
      const setup = await arrangeRealPrerequisites(t, progress, inputsPath);
      const evidence = await createRunEvidence(t, setup, progress);
      const stack = await observePreparedStack(t, setup, evidence, progress);
      const owned = await registerCleanupAndStartProvider(t, setup, stack, evidence);
      const deployment = await deployProtectedAgent(setup, stack, evidence, owned);
      const installed = await observeInstalledProtection(setup, stack, evidence, deployment);
      const turns = await observeRunningAgent(setup, stack, evidence, owned, deployment, installed);

      await verifyFirstTurnAndBinaryBypass(setup, stack, evidence, owned, installed, turns);
      await revokeExactGrantAndObserveDenial(stack, evidence, owned, deployment, turns);
      await regrantAndObserveRecovery(owned, deployment, turns);
      const rotatedSecret = await rotateSecretOnly(setup, stack, evidence, deployment, turns);
      await verifyHostileResponsesAndRecovery(owned, turns);
      await observeCredentialLeaks(setup, stack, evidence, owned, deployment, rotatedSecret);
      await withdrawAndObserveSandboxAbsence(setup, stack, evidence, deployment, installed);
      assert.equal(
        owned.provider.observations.length,
        16,
        "one startup probe and fifteen measured sends, with no background retries",
      );
    } catch (error) {
      throw safeConnectedFailure(error, progress.stage);
    }
  },
);

/**
 * @param {Prerequisites} setup
 * @param {PreparedStack} stack
 * @param {RunEvidence} evidence
 * @param {OwnedResources} owned
 */
async function deployProtectedAgent(setup, stack, evidence, owned) {
  const { controller, f } = setup;
  const { waitFor } = f;
  const { namespacePath, placement } = stack;
  const { runId, credentials, api, checkpoint } = evidence;
  const { create, recordSandbox } = owned;
  const secret = await create("secrets", {
    name: `egress-${runId}`,
    value: credentials.initial,
  });
  const source = await create(
    "credential-sources",
    protectedSourceBody(`egress-${runId}`, secret.ref, controller.providerOrigin),
  );
  assert.deepEqual(
    source.egress,
    { adoption: "live", retention: "none" },
    "legacy gateway-copy mode cannot qualify this test",
  );
  assert.equal(source.state, "ready");
  const configuration = await create(
    "configurations",
    protectedConfigurationBody(controller.model),
  );
  const agent = await create(
    "agents",
    protectedAgentBody(`egress-${runId}`, configuration.id, source.id),
  );
  const sourceRole = await create("iam/roles", {
    name: `egress-${runId}`,
    permissions: [{ action: "operate", resourceKind: "credential_source" }],
  });
  const binding = await create(
    "iam/access-bindings",
    sourceAccessBindingBody(agent, sourceRole, source),
  );
  const principalBindings = (await api("GET", `${namespacePath}/iam/access-bindings`)).filter(
    ({ subjectId }) => subjectId === agent.servicePrincipalId,
  );
  assert.deepEqual(
    principalBindings.map(({ id }) => id),
    [binding.id],
    "the new Agent gets only its exact source grant",
  );
  const transport = await api(
    "POST",
    `${namespacePath}/agents/${agent.id}/runtime-credentials`,
    {},
  );
  assert.equal(transport.transportConfigured, true);
  await checkpoint("deploy-request", { agentId: agent.id });
  const revision = await api("POST", `${namespacePath}/agents/${agent.id}/deploy`, undefined, 202);
  await checkpoint("deployed", { agentId: agent.id, revisionId: revision.id });
  const deploymentPath = `${namespacePath}/agents/${agent.id}/deployments/${revision.id}`;
  await waitFor(
    "protected Agent activation with genuine installed evidence",
    async () => {
      const deployment = await api("GET", deploymentPath);
      if (deployment.status === "failed") {
        // The status endpoint owns fixed deployment codes. Keep response text and
        // evidence out of the ledger, including when the error has no known code.
        const code = deployment.error?.code;
        await checkpoint("activation-failed", {
          code: typeof code === "string" && /^[A-Z][A-Z0-9_]{0,63}$/.test(code) ? code : "UNKNOWN",
        });
        assert.fail("The protected Agent deployment failed; inspect the safe checkpoint");
      }
      const current = await api("GET", `${namespacePath}/agents/${agent.id}`);
      return current.activeRevisionId === revision.id ? current : undefined;
    },
    12 * 60_000,
  );
  const sandbox = await f.waitForSandbox(placement, revision);
  const sandboxId = await recordSandbox(sandbox);
  return {
    secret,
    source,
    agent,
    sourceRole,
    binding,
    revision,
    deploymentPath,
    sandbox,
    sandboxId,
  };
}

/**
 * Captures process and receipt baselines once, before any measured user turn.
 * @param {Prerequisites} setup
 * @param {PreparedStack} stack
 * @param {RunEvidence} evidence
 * @param {OwnedResources} owned
 * @param {Deployment} deployment
 * @param {InstalledProtection} installed
 */
async function observeRunningAgent(setup, stack, evidence, owned, deployment, installed) {
  const { controller, f } = setup;
  const { resource, kubectl } = f;
  const { namespacePath, placement } = stack;
  const { checkpoint, api, excludesCredentials } = evidence;
  const { provider } = owned;
  const { agent, revision } = deployment;
  const { harness, readReceipt, receipt, gatewayPods } = installed;
  const identity = async () => {
    const current = await resource("pod", harness.metadata.name, placement);
    const processes = JSON.parse(
      await kubectl(
        "exec",
        harness.metadata.name,
        "--namespace",
        placement,
        "--container",
        "agent",
        "--",
        "node",
        "-e",
        String.raw`
      const fs = require("node:fs");
      const found = [];
      for (const pid of fs.readdirSync("/proc").filter(x => /^\d+$/.test(x))) {
        try {
          if (!fs.readlinkSync("/proc/" + pid + "/exe").endsWith("/codex")) continue;
          const stat = fs.readFileSync("/proc/" + pid + "/stat", "utf8");
          found.push({ pid, start: stat.slice(stat.lastIndexOf(")") + 2).split(" ")[19] });
        } catch (error) { if (error.code !== "ENOENT" && error.code !== "EACCES") throw error; }
      }
      if (found.length === 0) throw new Error("No running Codex process observed");
      process.stdout.write(JSON.stringify(found.sort((a,b) => Number(a.pid) - Number(b.pid))));`,
      ),
    );
    return {
      uid: current.metadata.uid,
      containers: current.status.containerStatuses.map(({ name, containerID, restartCount }) => ({
        name,
        containerID,
        restartCount,
      })),
      processes,
    };
  };
  const serving = await identity();
  const unchanged = async () => {
    assert.equal(
      (await api("GET", `${namespacePath}/agents/${agent.id}`)).activeRevisionId,
      revision.id,
    );
    assert.deepEqual(
      await identity(),
      serving,
      "this operation must not restart or redeploy the Harness",
    );
    assert.deepEqual(
      await readReceipt(),
      receipt,
      "the same registered supervisor must remain installed",
    );
  };
  const turn = async (phase, expected = "completed") => {
    const nonce = `OCE-EGRESS-${randomUUID()}`;
    await checkpoint("turn-start", {
      phase,
      nonce,
      upstreamBefore: provider.observations.length,
    });
    const result = await f.requestCodexTurnFromGatewayPod({
      namespace: placement,
      gatewayPod: gatewayPods[0].metadata.name,
      providerModel: controller.model,
      prompt: `Reply with exactly ${nonce}.`,
      observeFailure: true,
      timeoutMs: 90_000,
    });
    excludesCredentials(result, "Codex response/events");
    assert.equal(result.status, expected, `${phase}: actual Codex terminal status`);
    assert.equal(
      result.items.some((event) => event.params?.willRetry === true),
      false,
      "protected calls must not automatically retry",
    );
    if (expected === "completed") {
      assert.equal(result.assistant, nonce);
    } else {
      assertNoConnectedAssistantOutput(result);
      if (phase !== "fresh-iam-revoked") {
        // A malformed fixture, model error or EOF is not response-policy proof.
        // These markers are emitted by the supplier's pre-return HTTP refusal.
        const failure = JSON.stringify(result.error);
        assert.ok(
          typeof failure === "string" &&
            failure.includes("http_response_pre_return") &&
            failure.includes(
              phase === "oversize" ? "response_delivery_failed" : "egress_response_policy",
            ),
          "expected the supplier's explicit pre-return refusal in the terminal Codex error",
        );
      }
    }
    assert.deepEqual(provider.errors, [], "synthetic provider failed independently of enforcement");
    await checkpoint("turn-complete", {
      phase,
      status: result.status,
      upstreamAfter: provider.observations.length,
    });
    return nonce;
  };
  const successfulTurn = async (phase, version) => {
    const before = provider.observations.length;
    const nonce = await turn(phase);
    const sent = provider.observations.slice(before);
    assert.equal(sent.length, 1, "one Agent operation must cause exactly one provider send");
    assert.equal(sent[0].nonce, nonce);
    assert.equal(sent[0].credentialVersion, version);
    assert.equal(sent[0].model, controller.model);
    assert.equal(sent[0].stream, true);
    assert.equal(sent[0].store, false);
    assert.ok(
      sent[0].toolTypes.some((type) => type === "function" || type === "namespace"),
      "normal local tools must remain advertised",
    );
    assert.equal(sent[0].toolTypes.includes("web_search"), false);
    await unchanged();
  };
  return { turn, successfulTurn, unchanged };
}

/**
 * @param {Prerequisites} setup
 * @param {PreparedStack} stack
 * @param {RunEvidence} evidence
 * @param {OwnedResources} owned
 * @param {InstalledProtection} installed
 * @param {AgentTurns} turns
 */
async function verifyFirstTurnAndBinaryBypass(setup, stack, evidence, owned, installed, turns) {
  const {
    controller,
    f: { kubectl },
  } = setup;
  const { placement } = stack;
  const { checkpoint } = evidence;
  const { provider } = owned;
  const { harness } = installed;
  const { successfulTurn } = turns;
  // The normal Launcher may probe the model during activation. Keep those
  // requests visible and distinct from measured user turns; never reset counts.
  assert.deepEqual(provider.errors, [], "the normal startup probe must use the protected wire");
  assert.equal(
    provider.observations.length,
    1,
    "the normal Launcher must complete exactly one startup model probe",
  );
  assert.ok(
    provider.observations.every(
      ({ credentialVersion, status, mode }) =>
        credentialVersion === "initial" && status === 200 && mode === "answer",
    ),
  );
  await checkpoint("startup-provider-traffic", { sends: provider.observations.length });
  await successfulTurn("permitted", "initial");
  // An ordinary workload binary must not bypass the Codex-only protected route.
  // Check the real process outcome and the independent upstream counter together.
  const beforeBypass = provider.observations.length;
  const bypass = JSON.parse(
    await kubectl(
      "exec",
      harness.metadata.name,
      "--namespace",
      placement,
      "--container",
      "agent",
      "--",
      "node",
      "-e",
      String.raw`
      const { spawnSync } = require("node:child_process");
      const result = spawnSync("/usr/bin/curl", ["--silent", "--show-error", "--fail", "--max-time", "10",
        "--request", "POST", "--header", "content-type: application/json", "--data", process.argv[2], process.argv[1]],
        { encoding: "utf8", timeout: 15000, maxBuffer: 65536 });
      process.stdout.write(JSON.stringify({ status: result.status, errorCode: result.error?.code }));`,
      `${controller.providerOrigin}/responses`,
      JSON.stringify({ model: controller.model, input: "unapproved-binary", store: false }),
    ),
  );
  assert.equal(bypass.errorCode, undefined, "the bypass probe must execute, not fail to start");
  assert.ok(
    [7, 22, 28, 35, 56].includes(bypass.status),
    "curl must report a concrete network/proxy refusal",
  );
  assert.equal(
    provider.observations.length,
    beforeBypass,
    "unapproved workload egress reached the provider",
  );
  await checkpoint("unapproved-binary-denied", { curlStatus: bypass.status, providerSends: 0 });
}

/**
 * @param {PreparedStack} stack
 * @param {RunEvidence} evidence
 * @param {OwnedResources} owned
 * @param {Deployment} deployment
 * @param {AgentTurns} turns
 */
async function revokeExactGrantAndObserveDenial(stack, evidence, owned, deployment, turns) {
  const { namespacePath, namespace, pool } = stack;
  const { api, checkpoint } = evidence;
  const { provider } = owned;
  const { agent, source, binding, revision } = deployment;
  const { turn, unchanged } = turns;
  // Revoke only the exact native IAM grant. Do not withdraw the source, stop the
  // Agent, mutate its revision, or replace a production authority callback.
  await api("DELETE", `${namespacePath}/iam/access-bindings/${binding.id}`, undefined, 204);
  const beforeDenials = await pool.query(
    "SELECT id FROM occ.audit_events WHERE namespace_id = $1 AND actor_id = $2 AND resource_id = $3 AND action = 'openclaw.egress.authorize'",
    [namespace.id, agent.servicePrincipalId, source.id],
  );
  const knownDenials = new Set(beforeDenials.rows.map(({ id }) => id));
  const beforeDenied = provider.observations.length;
  await turn("fresh-iam-revoked", "failed");
  assert.equal(
    provider.observations.length,
    beforeDenied,
    "fresh IAM denial must precede every provider send",
  );
  const denials = await pool.query(
    "SELECT id, actor_id, resource_kind, resource_id, details, outcome FROM occ.audit_events WHERE namespace_id = $1 AND actor_id = $2 AND resource_id = $3 AND action = 'openclaw.egress.authorize'",
    [namespace.id, agent.servicePrincipalId, source.id],
  );
  const freshDenials = denials.rows.filter(({ id }) => !knownDenials.has(id));
  assert.equal(
    freshDenials.length,
    1,
    "one refused operation must produce one attributable authority denial",
  );
  const denied = freshDenials[0];
  assert.equal(denied.actor_id, agent.servicePrincipalId);
  assert.equal(denied.resource_kind, "credential_source");
  assert.equal(denied.resource_id, source.id);
  assert.equal(denied.details.code, "unauthorized");
  assert.equal(denied.details.phase, "before_access");
  assert.equal(denied.details.revisionId, revision.id);
  assert.equal(denied.outcome, "denied");
  assert.match(
    denied.details.requestId,
    /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
  );
  await unchanged();
  await checkpoint("fresh-iam-denial", {
    requestId: denied.details.requestId,
    phase: denied.details.phase,
    providerSends: 0,
  });
}

/**
 * @param {OwnedResources} owned
 * @param {Deployment} deployment
 * @param {AgentTurns} turns
 */
async function regrantAndObserveRecovery(owned, deployment, turns) {
  const { create } = owned;
  const { agent, sourceRole, source } = deployment;
  const { successfulTurn } = turns;
  await create("iam/access-bindings", sourceAccessBindingBody(agent, sourceRole, source));
  await successfulTurn("regranted", "initial");
}

/**
 * @param {Prerequisites} setup
 * @param {PreparedStack} stack
 * @param {RunEvidence} evidence
 * @param {Deployment} deployment
 * @param {AgentTurns} turns
 */
async function rotateSecretOnly(setup, stack, evidence, deployment, turns) {
  const {
    f: { kubectl },
  } = setup;
  const { namespacePath, placement } = stack;
  const { api, credentials, checkpoint } = evidence;
  const { secret, source } = deployment;
  const { successfulTurn } = turns;
  // Secret-only rotation deliberately avoids PATCH source and deploy. The same
  // admitted binding must select the new authoritative material on its next use.
  const secretVersion = async () => {
    // Ask kubectl to emit metadata only; credential values never enter this observer.
    const text = await kubectl(
      "get",
      "secrets",
      "--namespace",
      placement,
      "--selector",
      `openclaw.dev/secret=${secret.id}`,
      "-o",
      'jsonpath={range .items[*]}{.metadata.name}{"\\t"}{.metadata.uid}{"\\t"}{.metadata.resourceVersion}{"\\n"}{end}',
    );
    const found = text.trim().split("\n");
    assert.equal(found.length, 1);
    const [name, uid, version] = found[0].split("\t");
    assert.ok(name && uid && version);
    return { name, uid, version };
  };
  const oldVersion = await secretVersion();
  const sourceBeforeRotation = await api("GET", `${namespacePath}/credential-sources/${source.id}`);
  await api("PATCH", `${namespacePath}/secrets/${secret.id}`, { value: credentials.rotated });
  const newVersion = await secretVersion();
  assert.equal(newVersion.uid, oldVersion.uid);
  assert.notEqual(newVersion.version, oldVersion.version);
  assert.deepEqual(
    await api("GET", `${namespacePath}/credential-sources/${source.id}`),
    sourceBeforeRotation,
    "Secret-only rotation must leave source metadata unchanged",
  );
  await successfulTurn("secret-only-rotation", "rotated");
  await checkpoint("rotation", {
    materialId: newVersion.uid,
    previousVersion: oldVersion.version,
    materialVersion: newVersion.version,
  });
  return newVersion;
}

/**
 * @param {OwnedResources} owned
 * @param {AgentTurns} turns
 */
async function verifyHostileResponsesAndRecovery(owned, turns) {
  const { provider } = owned;
  const { turn, unchanged, successfulTurn } = turns;
  for (const mode of [
    "reflect-body",
    "reflect-header",
    "reflect-split-id",
    "reflect-encoded-arguments",
    "oversize",
    "incomplete",
  ]) {
    provider.setMode(mode);
    const before = provider.observations.length;
    const nonce = await turn(mode, "failed");
    assert.equal(
      provider.observations.length,
      before + 1,
      "rejected response must not trigger another upstream attempt",
    );
    assert.equal(provider.observations.at(-1).credentialVersion, "rotated");
    assert.equal(provider.observations.at(-1).nonce, nonce);
    assert.equal(provider.observations.at(-1).mode, mode);
    await unchanged();
    provider.setMode("answer");
    await successfulTurn(`${mode}-recovery`, "rotated");
  }
}

/**
 * @param {Prerequisites} setup
 * @param {PreparedStack} stack
 * @param {RunEvidence} evidence
 * @param {OwnedResources} owned
 * @param {Deployment} deployment
 * @param {{ name: string, uid: string, version: string }} newVersion
 */
async function observeCredentialLeaks(setup, stack, evidence, owned, deployment, newVersion) {
  const { f } = setup;
  const { resources } = f;
  const { namespace, placement, pool } = stack;
  const { api, ledger, excludesCredentials, credentials, directory, checkpoint } = evidence;
  const { provider } = owned;
  const { agent, deploymentPath } = deployment;
  const runtime = await api("GET", `${deploymentPath}/runtime`);
  const logs = runtime.sources.filter(({ available }) => available);
  assert.ok(logs.length > 0);
  for (const { id } of logs) {
    await api(
      "GET",
      `${deploymentPath}/runtime/logs?source=${encodeURIComponent(id)}&tailLines=1000`,
    );
  }
  await api("POST", `${deploymentPath}/diagnostics`);
  const audit = await pool.query(
    "SELECT row_to_json(event) AS event FROM occ.audit_events event WHERE namespace_id = $1 AND occurred_at >= $2",
    [namespace.id, ledger.startedAt],
  );
  excludesCredentials(audit.rows, "attributable audit");
  await f.assertNoSecretBytes(placement, Object.values(credentials));
  for (const pod of await resources("pods", placement)) {
    if (pod.metadata.labels?.["openclaw.dev/agent"] === agent.id) {
      excludesCredentials(pod, "Agent Pod");
      assert.equal(
        JSON.stringify(pod.spec).includes(newVersion.name),
        false,
        "no Agent Pod may mount or reference the canonical source Secret",
      );
    }
  }
  await writeFile(
    join(directory, "upstream.json"),
    JSON.stringify(provider.observations, null, 2) + "\n",
    { mode: 0o600 },
  );
  await checkpoint("enforcement-complete", {
    sends: provider.observations.length,
    auditEvents: audit.rowCount,
  });
}

/**
 * @param {Prerequisites} setup
 * @param {PreparedStack} stack
 * @param {RunEvidence} evidence
 * @param {Deployment} deployment
 * @param {InstalledProtection} installed
 */
async function withdrawAndObserveSandboxAbsence(setup, stack, evidence, deployment, installed) {
  const {
    f: { waitFor },
  } = setup;
  const { namespacePath, placement, gatewayClient } = stack;
  const { api, checkpoint } = evidence;
  const { agent, source } = deployment;
  const { sandboxName } = installed;
  // Initial withdrawal destroys the owned single-binding Sandbox. This is a
  // separate lifecycle limitation, not proof of fresh central grant revocation.
  await api(
    "POST",
    `${namespacePath}/agents/${agent.id}/credential-sources/${source.id}/withdraw`,
    undefined,
    202,
  );
  await waitFor(
    "owned stop-based withdrawal",
    async () => {
      const status = await api(
        "GET",
        `${namespacePath}/agents/${agent.id}/credential-sources/${source.id}/withdrawal`,
      );
      return status.state === "revoked" ? status : undefined;
    },
    180_000,
  );
  assert.equal(
    await gatewayClient.getSandbox(
      { workspace: placement, name: sandboxName },
      AbortSignal.timeout(10_000),
    ),
    undefined,
  );
  await checkpoint("stop-based-withdrawal", { sandboxAbsent: true });
}
