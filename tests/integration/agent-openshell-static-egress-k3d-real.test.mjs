import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { resolve, join } from "node:path";
import test from "node:test";
import { OpenShellGateway } from "../../apps/controller/src/backends/openshell.ts";
import { createRealKubernetesFixture } from "../helpers/kubernetes-real.mjs";
import { createOpenShellKubernetesFixture } from "../helpers/openshell-kubernetes-real.mjs";
import { startSyntheticEgressProvider } from "../fixtures/synthetic-egress-provider.mjs";
import {
  assertConnectedResponse,
  assertNoConnectedAssistantOutput,
  connectedReceiptRevision,
  protectedAgentBody,
  protectedConfigurationBody,
  protectedEgressCapability,
  protectedSourceBody,
  serializeConnectedRequest,
  sourceAccessBindingBody,
  validateConnectedInputs,
  validateConnectedDatabaseUrl,
} from "../helpers/egress-connected-inputs.mjs";

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

test(
  "a protected OpenShell Agent uses fresh IAM, live Secret rotation and bounded Responses delivery",
  {
    skip: selected ? false : "Select OCC_TEST_EGRESS_CONNECTED=1 with a prepared protected stack.",
    timeout: 30 * 60_000,
  },
  async (t) => {
    let stage = "input-preflight";
    try {
      assert.equal(process.env.OCC_TEST_EGRESS_CONNECTED, "1");
      assert.ok(inputsPath, "OCC_TEST_EGRESS_CONNECTED_INPUTS must name the exact prepared stack");
      const input = validateConnectedInputs(JSON.parse(await readFile(inputsPath, "utf8")));
      const databaseUrl = validateConnectedDatabaseUrl(process.env.OCC_TEST_DATABASE_URL);
      const selection = {
        kubeconfigPath: input.kubeconfigPath,
        kubernetesContext: input.kubernetesContext,
        gatewayImage: input.images.gateway,
        codexImage: input.images.agent,
        databaseUrl,
      };
      const base = createRealKubernetesFixture(selection);
      // Keep the existing loopback k3d and disposable-database guards. The legacy
      // fixture's real-provider-key prerequisite belongs to its separate smoke lane.
      stage = "cluster-prerequisites";
      await base.validatePrerequisites();
      const f = createOpenShellKubernetesFixture({
        ...selection,
        openShellGatewayImage: input.images.openShellGateway,
        openShellSandboxImage: input.images.sandbox,
        openShellSupervisorImage: input.images.supervisor,
        openShellRuntimeClass: input.runtimeClass,
        commandTimeoutMs: 120_000,
        signal: t.signal,
      });
      const { kubectl, resource, resources, waitFor } = f;
      const runId = randomUUID();
      const directory = resolve(".build/egress-connected", `runtime-${runId}`);
      await mkdir(directory, { recursive: true, mode: 0o700 });
      t.diagnostic(`egress-connected evidence-directory .build/egress-connected/runtime-${runId}`);
      const ledger = {
        runId,
        startedAt: new Date().toISOString(),
        oceCommit: input.oceCommit,
        supplierCommit: input.supplierCommit,
        images: input.images,
        namespaceId: input.namespaceId,
        resources: [],
        phases: [],
        cleanup: "pending",
      };
      const checkpoint = async (phase, details = {}) => {
        stage = phase;
        ledger.phases.push({ phase, at: new Date().toISOString(), ...details });
        await writeFile(
          join(directory, "observations.pending.json"),
          JSON.stringify(ledger, null, 2) + "\n",
          { mode: 0o600 },
        );
        await rename(
          join(directory, "observations.pending.json"),
          join(directory, "observations.json"),
        );
        t.diagnostic(`egress-connected ${phase} ${JSON.stringify(details)}`);
      };
      const credentials = {
        initial: `SYNTHETIC-OCE-EGRESS-${runId}-v1`,
        rotated: `SYNTHETIC-OCE-EGRESS-${runId}-v2`,
      };
      const excludesCredentials = (value, label) => {
        const text = typeof value === "string" ? value : JSON.stringify(value);
        for (const secret of Object.values(credentials)) {
          for (const encoded of [
            secret,
            encodeURIComponent(secret),
            Buffer.from(secret).toString("base64"),
            Buffer.from(secret).toString("base64url"),
          ]) {
            assert.equal(
              text.includes(encoded),
              false,
              `${label} leaked synthetic credential material`,
            );
          }
        }
      };
      const key = (await readFile(input.serviceKeyPath, "utf8")).trim();
      assert.ok(key.length > 0, "the explicitly provisioned controller service key is required");
      const request = async (method, path, body, cleanup = false) => {
        if (!cleanup) {
          t.signal.throwIfAborted();
        }
        const wire = serializeConnectedRequest(method, path, body);
        const response = await fetch(new URL(wire.path, input.apiOrigin), {
          method: wire.method,
          headers: { ...wire.headers, "x-api-key": key },
          ...(wire.body === undefined ? {} : { body: wire.body }),
          redirect: "error",
          signal: cleanup
            ? AbortSignal.timeout(20_000)
            : AbortSignal.any([t.signal, AbortSignal.timeout(20_000)]),
        });
        const raw = await response.text();
        excludesCredentials(raw, "controller response");
        assert.equal(raw.includes(key), false, "controller response leaked its service key");
        const captured = {
          status: response.status,
          body: raw === "" ? undefined : JSON.parse(raw),
        };
        if (captured.body !== undefined) {
          excludesCredentials(captured.body, "decoded controller response");
          assert.equal(
            JSON.stringify(captured.body).includes(key),
            false,
            "decoded controller response leaked its service key",
          );
        }
        // Retain only status/correlation, never request bodies, keys, or response diagnostics.
        ledger.lastApi = {
          method,
          path,
          status: captured.status,
          requestId: captured.body?.meta?.requestId,
        };
        return captured;
      };
      const api = async (method, path, body, status = 200) =>
        assertConnectedResponse(await request(method, path, body), status);
      const namespacePath = `/namespaces/${input.namespaceId}`;
      stage = "prepared-stack-observation";
      const namespace = await api("GET", namespacePath);
      assert.equal(namespace.status, "ready");
      const placements = JSON.parse(await kubectl("get", "namespaces", "-o", "json")).items.filter(
        ({ metadata }) => metadata.labels?.["openclaw.dev/namespace"] === namespace.id,
      );
      assert.equal(placements.length, 1, "select a single-cluster tenant placement");
      const placement = placements[0].metadata.name;
      const controllerPods = JSON.parse(
        await kubectl(
          "get",
          "pods",
          "--namespace",
          input.controllerNamespace,
          "--selector",
          input.controllerSelector,
          "-o",
          "json",
        ),
      ).items;
      assert.ok(controllerPods.length > 0, "candidate controller Pod is required");
      for (const component of ["api", "worker"]) {
        assert.ok(
          controllerPods.some(
            ({ metadata }) => metadata.labels?.["app.kubernetes.io/component"] === component,
          ),
          `the prepared controller selector must include the ${component} Pod`,
        );
      }
      for (const pod of controllerPods) {
        assert.ok(pod.spec.containers.some(({ image }) => image === input.images.controller));
        assert.ok(
          pod.status?.conditions?.some(({ type, status }) => type === "Ready" && status === "True"),
        );
      }
      const gateway = new OpenShellGateway(input.openShellBackend);
      t.after(() => gateway.close());
      const gatewayClient = gateway.clientForNamespace(placement);
      const info = await gatewayClient.getGatewayInfo(AbortSignal.timeout(10_000));
      assert.ok(
        info.extensions?.some(
          (extension) =>
            extension.required_capabilities?.includes(protectedEgressCapability) &&
            extension.supported_capabilities?.includes(protectedEgressCapability),
        ),
        "matching protected counterpart is required",
      );
      const { default: pg } = await import("pg");
      const pool = new pg.Pool({
        connectionString: databaseUrl,
        max: 2,
        connectionTimeoutMillis: 5_000,
        statement_timeout: 5_000,
      });
      t.after(() => pool.end());
      const role = await pool.query("SELECT current_user AS role");
      assert.equal(role.rows[0].role, "occ_app", "observe through the limited application role");
      const installation = await api("GET", "/installation");
      const persistedInstallation = await pool.query("SELECT id FROM occ.installation");
      assert.deepEqual(
        persistedInstallation.rows,
        [{ id: installation.id }],
        "the observer must use this controller's database",
      );
      const supplierPods = JSON.parse(
        await kubectl(
          "get",
          "pods",
          "--namespace",
          input.openShellGatewayNamespace,
          "--selector",
          input.openShellGatewaySelector,
          "-o",
          "json",
        ),
      ).items;
      assert.ok(supplierPods.length > 0, "candidate OpenShell gateway Pod is required");
      for (const pod of supplierPods) {
        assert.ok(pod.spec.containers.some(({ image }) => image === input.images.openShellGateway));
        assert.ok(
          pod.status?.conditions?.some(({ type, status }) => type === "Ready" && status === "True"),
        );
      }
      const providerCleanup = [];
      let provider;
      let ownedSandbox;
      let ownedSandboxId;
      // Register cleanup before the first creation request. An unknown create outcome
      // remains in the ledger for the parent; never replay a mutation to hide it.
      t.after(async () => {
        const failures = ledger.pendingCreate ? ["unconfirmed create; reconcile ledger"] : [];
        const clean = async (name, action) => {
          try {
            await action();
          } catch {
            failures.push(name);
          }
        };
        const ownedAgent = ledger.resources.find(({ kind }) => kind === "agents");
        if (ownedAgent) {
          await clean("Agent", async () => {
            const deleted = await request(
              "DELETE",
              `${namespacePath}/agents/${ownedAgent.id}`,
              undefined,
              true,
            );
            assert.ok([202, 404].includes(deleted.status));
            assertConnectedResponse(deleted, deleted.status);
            await waitFor(
              "owned Agent deletion",
              async () => {
                const observed = await request(
                  "GET",
                  `${namespacePath}/agents/${ownedAgent.id}`,
                  undefined,
                  true,
                );
                if (observed.status === 404) {
                  assertConnectedResponse(observed, 404);
                  return true;
                }
                assertConnectedResponse(observed, 200);
                return undefined;
              },
              180_000,
            );
            // API row deletion alone cannot prove that provider-owned workloads
            // disappeared. Cleanup gets its own bounded reads after test abort.
            const cleanupFixture = createOpenShellKubernetesFixture({
              ...selection,
              commandTimeoutMs: 20_000,
            });
            await cleanupFixture.waitFor(
              "owned Kubernetes workload deletion",
              async () => {
                const pods = await cleanupFixture.resources("pods", placement);
                const sandboxes = await cleanupFixture.customResources(
                  "sandboxes.agents.x-k8s.io",
                  placement,
                );
                return (
                  !pods.some(
                    ({ metadata }) =>
                      metadata.labels?.["openclaw.dev/agent"] === ownedAgent.id ||
                      (ownedSandboxId !== undefined &&
                        metadata.labels?.["openshell.ai/sandbox-id"] === ownedSandboxId),
                  ) && !sandboxes.some(({ metadata }) => metadata.name === ownedSandbox)
                );
              },
              180_000,
            );
            if (
              ledger.phases.some(({ phase }) => phase === "deploy-request") &&
              (ownedSandbox === undefined || ownedSandboxId === undefined)
            ) {
              failures.push("Sandbox identity not observed; parent reconciliation required");
            }
          });
        }
        for (const kind of [
          "iam/access-bindings",
          "credential-sources",
          "iam/roles",
          "secrets",
          "configurations",
        ]) {
          for (const owned of ledger.resources.filter((entry) => entry.kind === kind)) {
            await clean(`${kind}/${owned.id}`, async () => {
              const observed = await request(
                "DELETE",
                `${namespacePath}/${kind}/${owned.id}`,
                undefined,
                true,
              );
              assert.ok(
                [204, 404].includes(observed.status),
                `cleanup ${kind} returned HTTP ${observed.status}`,
              );
              assertConnectedResponse(observed, observed.status);
            });
          }
        }
        await clean("provider observations", () =>
          writeFile(
            join(directory, "upstream.json"),
            JSON.stringify(provider?.observations ?? [], null, 2) + "\n",
            { mode: 0o600 },
          ),
        );
        for (const close of providerCleanup) {
          await clean("synthetic HTTPS listener", close);
        }
        ledger.cleanup = failures.length ? "incomplete" : "complete";
        await checkpoint("cleanup", { failures });
        assert.deepEqual(failures, [], "owned resources remain; use the preserved ledger");
      });
      // Custody is registered before listen: failed setup must also close the
      // listener, and bind failures must not leave a pending cleanup unobserved.
      provider = await startSyntheticEgressProvider(
        { after: (close) => providerCleanup.push(close) },
        { ...input.provider, model: input.model },
        credentials,
      );
      const create = async (kind, body) => {
        t.signal.throwIfAborted();
        ledger.pendingCreate = { kind, name: body.name };
        await checkpoint("create-request", { kind, name: body.name });
        const value = await api("POST", `${namespacePath}/${kind}`, body, 201);
        ledger.resources.push({ kind, id: value.id, name: body.name });
        delete ledger.pendingCreate;
        await checkpoint("created", { kind, id: value.id });
        return value;
      };
      await checkpoint("prepared-stack-observed", {
        placement,
        controllerPods: controllerPods.map(({ metadata }) => metadata.uid),
      });
      const secret = await create("secrets", {
        name: `egress-${runId}`,
        value: credentials.initial,
      });
      const source = await create(
        "credential-sources",
        protectedSourceBody(`egress-${runId}`, secret.ref, input.provider.origin),
      );
      assert.deepEqual(
        source.egress,
        { adoption: "live", retention: "none" },
        "legacy gateway-copy mode cannot qualify this test",
      );
      assert.equal(source.state, "ready");
      const configuration = await create("configurations", protectedConfigurationBody(input.model));
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
      const revision = await api(
        "POST",
        `${namespacePath}/agents/${agent.id}/deploy`,
        undefined,
        202,
      );
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
              code:
                typeof code === "string" && /^[A-Z][A-Z0-9_]{0,63}$/.test(code) ? code : "UNKNOWN",
            });
            assert.fail("The protected Agent deployment failed; inspect the safe checkpoint");
          }
          const current = await api("GET", `${namespacePath}/agents/${agent.id}`);
          return current.activeRevisionId === revision.id ? current : undefined;
        },
        12 * 60_000,
      );
      const sandbox = await f.waitForSandbox(placement, revision);
      ownedSandbox = sandbox.metadata.name;
      ownedSandboxId = sandbox.metadata.labels?.["openshell.ai/sandbox-id"];
      assert.equal(
        typeof ownedSandboxId,
        "string",
        "the real Sandbox must identify its supplier owner",
      );
      await checkpoint("sandbox-observed", {
        sandboxName: ownedSandbox,
        sandboxId: ownedSandboxId,
      });
      const harness = await f.waitForProviderHarnessPod(placement, revision);
      await f.assertProviderOwnedHarness(placement, revision, sandbox, harness);
      f.assertWorkspaceMounts(harness);
      f.assertApprovedOpenShellPrivileges(harness);
      await f.assertGatewayBootstrapPolicies(placement);
      assert.equal(
        harness.spec.containers.find(({ name }) => name === "agent").image,
        input.images.agent,
      );
      assert.equal(
        harness.spec.initContainers.find(({ name }) => name === "openshell-sandbox-bootstrap")
          ?.image,
        input.images.sandbox,
        "the actual trusted bootstrap must use the selected supplier runtime",
      );
      const sandboxName = sandbox.metadata.labels["openshell.ai/sandbox-name"];
      const observedSandbox = await gatewayClient.getSandbox(
        { workspace: placement, name: sandboxName },
        AbortSignal.timeout(10_000),
      );
      assert.ok(observedSandbox?.id, "read the immutable Sandbox ID from the actual gateway");
      assert.equal(observedSandbox.id, ownedSandboxId);
      const installations = await pool.query(
        "SELECT installation FROM occ.egress_installations WHERE namespace_id = $1 AND revision_id = $2 AND agent_id = $3",
        [namespace.id, revision.id, agent.id],
      );
      assert.equal(
        installations.rowCount,
        1,
        "the real worker must record exactly one installed mapping",
      );
      const installed = installations.rows[0].installation;
      assert.equal(installed.sandboxId, observedSandbox.id);
      assert.equal(installed.plan.execution.installationId, installation.id);
      assert.equal(installed.plan.execution.servicePrincipalId, agent.servicePrincipalId);
      assert.ok(installed.plan.routes.length > 0, "an empty plan cannot prove protected routing");
      assert.ok(
        installed.plan.routes.every(
          ({ binding: routeBinding }) =>
            routeBinding.source.source.id === source.id &&
            routeBinding.grant.providerTools === "none",
        ),
      );
      const readReceipt = async () => {
        const status = await gatewayClient.getSandboxPolicyStatus(
          placement,
          sandboxName,
          AbortSignal.timeout(10_000),
        );
        const observation = status.loaded_policy_observation;
        assert.ok(observation, "LOADED or legacy field 3 cannot substitute for a V1 observation");
        const receipt = observation.enforcement;
        assert.ok(receipt, "V1 requires current supervisor enforcement evidence");
        assert.equal(receipt.sandbox_id, observedSandbox.id);
        assert.equal(receipt.instance_id, installed.enforcement?.instanceId);
        assert.equal(receipt.policy_version, installed.plan.generation);
        assert.equal(status.active_version, receipt.policy_version);
        assert.equal(status.revision.policy_hash, observation.source_policy_hash);
        assert.match(observation.source_policy_hash, /^[a-f0-9]{64}$/);
        assert.ok(observation.effective_policy);
        const effective = structuredClone(observation.effective_policy);
        const name = `_provider_oce_runtime_${createHash("sha256").update(revision.id).digest("hex").slice(0, 16)}`;
        assert.equal(observation.inert_provider_rule, name);
        assert.equal(Object.hasOwn(status.revision.policy.network_policies, name), false);
        assert.deepEqual(effective.network_policies[name], { name });
        delete effective.network_policies[name];
        assert.notEqual(observation.source_policy_hash, receipt.policy_hash);
        assert.equal(status.loaded_enforcement, undefined);
        assert.deepEqual(effective, status.revision.policy);
        assert.ok([2, "POLICY_STATUS_LOADED"].includes(status.revision.status));
        assert.match(
          receipt.instance_id,
          /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
        );
        assert.match(receipt.policy_hash, /^[a-f0-9]{64}$/);
        connectedReceiptRevision(receipt.config_revision);
        connectedReceiptRevision(receipt.provider_env_revision);
        assert.deepEqual(receipt.enforced_capabilities, [protectedEgressCapability]);
        // Retain both supplier identities and policies for the subsequent turn's
        // freshness comparison; enforcement.policy_hash identifies the effective policy.
        return observation;
      };
      const receipt = await readReceipt();
      await checkpoint("installed", {
        sourcePolicyHash: receipt.source_policy_hash,
        effectivePolicyHash: receipt.enforcement.policy_hash,
        policyVersion: String(receipt.enforcement.policy_version),
        configRevision: connectedReceiptRevision(receipt.enforcement.config_revision),
        providerEnvRevision: connectedReceiptRevision(receipt.enforcement.provider_env_revision),
        capability: protectedEgressCapability,
        derivation: "inert_runtime_provider_rule",
      });
      const pods = await resources("pods", placement);
      const gatewayPods = pods.filter(
        ({ metadata }) =>
          metadata.labels?.["openclaw.dev/agent"] === agent.id &&
          metadata.labels?.["openclaw.dev/workload-role"] === "gateway",
      );
      assert.equal(gatewayPods.length, 1);
      assert.ok(gatewayPods[0].spec.containers.some(({ image }) => image === input.images.gateway));
      const supervisors = pods.filter(
        ({ metadata }) =>
          metadata.labels?.["openshell.ai/sandbox-id"] === installed.sandboxId &&
          metadata.labels?.["openshell.ai/boundary-role"] === "supervisor",
      );
      assert.equal(supervisors.length, 1, "a separate selected supervisor must own forwarding");
      assert.ok(
        supervisors[0].spec.containers.some(({ image }) => image === input.images.supervisor),
      );
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
          containers: current.status.containerStatuses.map(
            ({ name, containerID, restartCount }) => ({
              name,
              containerID,
              restartCount,
            }),
          ),
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
          providerModel: input.model,
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
        assert.deepEqual(
          provider.errors,
          [],
          "synthetic provider failed independently of enforcement",
        );
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
        assert.equal(sent[0].model, input.model);
        assert.equal(sent[0].stream, true);
        assert.equal(sent[0].store, false);
        assert.ok(
          sent[0].toolTypes.some((type) => type === "function" || type === "namespace"),
          "normal local tools must remain advertised",
        );
        assert.equal(sent[0].toolTypes.includes("web_search"), false);
        await unchanged();
      };
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
          `${input.provider.origin}/responses`,
          JSON.stringify({ model: input.model, input: "unapproved-binary", store: false }),
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
      await create("iam/access-bindings", sourceAccessBindingBody(agent, sourceRole, source));
      await successfulTurn("regranted", "initial");
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
      const sourceBeforeRotation = await api(
        "GET",
        `${namespacePath}/credential-sources/${source.id}`,
      );
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
      assert.equal(
        provider.observations.length,
        16,
        "one startup probe and fifteen measured sends, with no background retries",
      );
    } catch (error) {
      throw safeConnectedFailure(error, stage);
    }
  },
);
