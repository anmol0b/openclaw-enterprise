import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { createFastifyApp } from "../../apps/controller/src/index.ts";
import { InMemoryAuditSink } from "../../packages/audit/src/index.ts";
import { NativeIAMDriver } from "../../packages/iam/src/index.ts";
import { InMemoryPlatformState, OpenClawController } from "../../packages/occ/src/index.ts";
import {
  createTestAuthPrincipal,
  authenticatedHeaders,
  signInToControllerApp,
} from "../helpers/auth-session.mjs";
import { createReadyComputeDriver } from "../helpers/development.mjs";
import { createTestConfigurationDriver } from "../helpers/configuration-driver.mjs";
import { createTestSecretDriver } from "../helpers/secret-driver.mjs";
import { syntheticCredentialUrl } from "../fixtures/synthetic-credential-url.mjs";
import {
  encodeSyntheticEvents,
  syntheticResponsesEvents,
} from "../fixtures/synthetic-egress-provider.mjs";
import {
  assertConnectedResponse,
  assertNoConnectedAssistantOutput,
  connectedReceiptRevision,
  protectedAgentBody,
  protectedConfigurationBody,
  protectedSourceBody,
  serializeConnectedRequest,
  sourceAccessBindingBody,
  validateConnectedDatabaseUrl,
  validateConnectedInputs,
} from "../helpers/egress-connected-inputs.mjs";

import {
  assertOpenShellHarnessBinding,
  openShellAgentName,
  openShellRevisionName,
} from "../helpers/openshell-kubernetes-real.mjs";

// These are oracle inputs, not simulated evidence of a running supplier. The
// selected account comes from the maintained launcher, independently of the Pod.
test("connected workload binding accepts only the maintained launcher identity and isolation", async (t) => {
  const revision = { namespaceId: "ns_fixture", agentId: "agent_fixture", id: "revision_fixture" };
  const sandbox = {
    apiVersion: "agents.x-k8s.io/v1alpha1",
    metadata: {
      namespace: "workspace",
      name: "sandbox-fixture",
      uid: "sandbox-uid",
      labels: { "openshell.ai/sandbox-id": "sandbox-id" },
    },
  };
  const valid = {
    metadata: {
      namespace: "workspace",
      labels: {
        "openclaw.dev/namespace": revision.namespaceId,
        "openclaw.dev/agent": revision.agentId,
        "openclaw.dev/revision": revision.id,
        "openclaw.dev/workload-role": "agent",
        "openclaw.dev/network-profile": "provider-fenced-v1",
        "app.kubernetes.io/name": openShellRevisionName(revision),
        "openshell.ai/boundary-pair": "sandbox-id",
        "openshell.ai/boundary-role": "workload",
      },
      annotations: { "openshell.ai/sandbox-id": "sandbox-id" },
      ownerReferences: [
        {
          apiVersion: sandbox.apiVersion,
          kind: "Sandbox",
          name: sandbox.metadata.name,
          uid: "sandbox-uid",
          controller: true,
        },
      ],
    },
    spec: {
      serviceAccountName: "openshell-sandbox",
      automountServiceAccountToken: false,
      volumes: [
        {
          name: "openshell-pod-identity",
          downwardAPI: {
            items: [{ path: "uid", fieldRef: { fieldPath: "metadata.uid" } }],
          },
        },
      ],
    },
  };
  const check = (pod, profile = "maintainedLauncher") =>
    assertOpenShellHarnessBinding("workspace", revision, sandbox, pod, profile);
  check(valid);
  // The shared helper must still reject the launcher account for per-Agent callers.
  assert.throws(() => assertOpenShellHarnessBinding("workspace", revision, sandbox, valid), {
    code: "ERR_ASSERTION",
  });
  const perAgent = structuredClone(valid);
  perAgent.spec.serviceAccountName = openShellAgentName(revision.agentId);
  assertOpenShellHarnessBinding("workspace", revision, sandbox, perAgent);
  assert.throws(() => check(valid, "unknown"), { code: "ERR_ASSERTION" });

  const mutations = {
    "wrong account": (pod) => {
      pod.spec.serviceAccountName = "default";
    },
    "per-Agent account in launcher profile": (pod) => {
      pod.spec.serviceAccountName = perAgent.spec.serviceAccountName;
    },
    "automount enabled": (pod) => {
      pod.spec.automountServiceAccountToken = true;
    },
    "automount unspecified": (pod) => {
      delete pod.spec.automountServiceAccountToken;
    },
    "token projection even without a workload mount": (pod) => {
      pod.spec.volumes.push({
        name: "bootstrap-token",
        projected: {
          sources: [
            {
              serviceAccountToken: {
                audience: "openshell-gateway",
                path: "token",
                expirationSeconds: 600,
              },
            },
          ],
        },
      });
    },
    "recreated Sandbox UID": (pod) => {
      pod.metadata.ownerReferences[0].uid = "stale-uid";
    },
    "wrong Sandbox name": (pod) => {
      pod.metadata.ownerReferences[0].name = "other";
    },
    "wrong owner API": (pod) => {
      pod.metadata.ownerReferences[0].apiVersion = "other/v1";
    },
    "noncontrolling owner": (pod) => {
      pod.metadata.ownerReferences[0].controller = false;
    },
    "wrong annotation": (pod) => {
      pod.metadata.annotations["openshell.ai/sandbox-id"] = "other";
    },
    "wrong pair": (pod) => {
      pod.metadata.labels["openshell.ai/boundary-pair"] = "other";
    },
    "supervisor instead of workload": (pod) => {
      pod.metadata.labels["openshell.ai/boundary-role"] = "supervisor";
    },
  };
  for (const label of [
    "openclaw.dev/namespace",
    "openclaw.dev/agent",
    "openclaw.dev/revision",
    "openclaw.dev/workload-role",
    "openclaw.dev/network-profile",
    "app.kubernetes.io/name",
  ]) {
    mutations[`wrong ${label}`] = (pod) => {
      pod.metadata.labels[label] = "other";
    };
  }
  for (const [name, mutate] of Object.entries(mutations)) {
    await t.test(name, () => {
      const pod = structuredClone(valid);
      mutate(pod);
      assert.throws(() => check(pod), { code: "ERR_ASSERTION" });
    });
  }
});

test("connected inputs accept exact bearer and mTLS shapes and only scoped HTTPS fixtures", () => {
  const inputs = () => ({
    version: 1,
    namespaceId: "ns_fixture",
    model: "fixture-model",
    apiOrigin: "http://127.0.0.1:3000",
    serviceKeyPath: "/fixture/service-key",
    kubeconfigPath: "/fixture/kubeconfig",
    kubernetesContext: "k3d-fixture",
    controllerNamespace: "oce-system",
    controllerSelector: "app=controller",
    openShellGatewayNamespace: "openshell",
    openShellGatewaySelector: "app=gateway",
    runtimeClass: "openshell",
    oceCommit: "a".repeat(40),
    supplierCommit: "b".repeat(40),
    images: Object.fromEntries(
      ["agent", "controller", "gateway", "openShellGateway", "sandbox", "supervisor"].map(
        (role) => [role, `fixture/${role}@sha256:${"a".repeat(64)}`],
      ),
    ),
    openShellBackend: {
      endpoint: "https://gateway.test:8443",
      rootCertificatePath: "/fixture/root.pem",
      auth: { mode: "bearerTokenFile", path: "/fixture/bearer" },
    },
    provider: {
      origin: "https://provider.test:9443/v1",
      bindHost: "127.0.0.1",
      bindPort: 9443,
      certificatePath: "/fixture/provider.pem",
      privateKeyPath: "/fixture/provider.key",
    },
  });
  const mtls = {
    mode: "mtls",
    certificatePath: "/fixture/client.pem",
    privateKeyPath: "/fixture/client.key",
  };
  for (const auth of [inputs().openShellBackend.auth, mtls]) {
    for (const host of ["provider.test", "host.openshell.internal"]) {
      const input = inputs();
      input.openShellBackend.auth = auth;
      input.provider.origin = `https://${host}:9443/v1`;
      assert.equal(validateConnectedInputs(input), input);
    }
  }
  const rejectedAuth = [
    undefined,
    { mode: "unauthenticated" },
    { mode: "bearerTokenFile", path: "relative" },
    { mode: "bearerTokenFile", path: "/fixture/token", privateKeyPath: "/fixture/key" },
    { mode: "mtls", certificatePath: "/fixture/client.pem" },
    { ...mtls, certificatePath: "relative.pem" },
    { ...mtls, privateKeyPath: "relative.key" },
    { ...mtls, path: "/fixture/token" },
    { ...mtls, rejectUnauthorized: false },
  ];
  for (const auth of rejectedAuth) {
    const input = inputs();
    input.openShellBackend.auth = auth;
    assert.throws(() => validateConnectedInputs(input));
  }
  // These guards precede credential reads and provider binding. Alias acceptance
  // must not admit ordinary providers, suffix lookalikes or implicit routing.
  for (const mutate of [
    (input) => {
      input.openShellBackend.endpoint = "http://gateway.test:8443";
    },
    (input) => {
      input.openShellBackend.rootCertificatePath = "relative.pem";
    },
    (input) => {
      input.openShellBackend.insecureTransport = true;
    },
    ...[
      "http://provider.test:9443/v1",
      "https://api.openai.com:9443/v1",
      "https://other.openshell.internal:9443/v1",
      "https://host.openshell.internal.example.com:9443/v1",
      "https://host.openshell.internal:9443/v1?override=1",
    ].map((origin) => (input) => {
      input.provider.origin = origin;
    }),
    (input) => {
      input.provider.bindHost = "host.openshell.internal";
    },
    (input) => {
      input.provider.bindPort = 9444;
    },
    (input) => {
      input.provider.certificatePath = "relative.pem";
    },
    (input) => {
      input.provider.privateKeyPath = "relative.key";
    },
  ]) {
    const input = inputs();
    mutate(input);
    assert.throws(() => validateConnectedInputs(input));
  }
});

test("connected database selection rejects missing, remote and redirected observers before effects", () => {
  const url = (overrides = {}) =>
    syntheticCredentialUrl({
      protocol: "postgresql",
      username: "occ_app",
      password: "synthetic-preflight-only",
      host: "127.0.0.1",
      port: 15432,
      pathname: "/openclaw_k8s_egress",
      ...overrides,
    });
  assert.equal(validateConnectedDatabaseUrl(url()), url());
  for (const rejected of [
    undefined,
    "invalid",
    url({ host: "database.test" }),
    url({ pathname: "/openclaw" }),
    url({ username: "occ_migrator" }),
    url({ search: "?host=database.test" }),
    url({ search: "?dbname=unowned" }),
  ]) {
    assert.throws(() => validateConnectedDatabaseUrl(rejected));
  }
});

test("connected receipt observation preserves proto3 zero and uint64 precision", () => {
  assert.equal(connectedReceiptRevision(undefined), "0");
  assert.equal(connectedReceiptRevision("0"), "0");
  assert.equal(connectedReceiptRevision("18446744073709551615"), "18446744073709551615");
  for (const rejected of [null, 1, 9007199254740992, "01", "-1", "18446744073709551616"]) {
    assert.throws(() => connectedReceiptRevision(rejected));
  }
});

test("connected failed-turn observation rejects partial text without a completed message", () => {
  assertNoConnectedAssistantOutput({ assistant: "", items: [] });
  // Codex can notify a delta before a later terminal failure. Looking only at
  // item/completed would falsely qualify that visible partial response.
  for (const event of [
    { method: "item/agentMessage/delta", params: { delta: "visible before failure" } },
    { method: "item/started", params: { item: { type: "agentMessage", text: "visible" } } },
    { method: "item/completed", params: { item: { type: "agentMessage", text: "visible" } } },
  ]) {
    assert.throws(() => assertNoConnectedAssistantOutput({ assistant: "", items: [event] }));
  }
});

test("connected adversarial wire carries split and nested-JSON material without raw reflection", () => {
  const credential = `SYNTHETIC-OCE-EGRESS-${randomUUID()}-v1`;
  for (const mode of ["reflect-split-id", "reflect-encoded-arguments"]) {
    const events = syntheticResponsesEvents("gpt-6", "SAFE", { mode, credential });
    const wire = encodeSyntheticEvents(events).toString("utf8");
    assert.equal(wire.includes(credential), false, "the vector must bypass a raw-byte-only scan");
    assert.equal(events.at(-1).type, "response.completed");
    if (mode === "reflect-split-id") {
      const deltas = events.filter(({ type }) => type === "response.output_text.delta");
      assert.equal(deltas.length, 2);
      assert.deepEqual(
        deltas.map(({ output_index }) => output_index),
        [0, 0],
      );
      assert.equal(deltas[0].item_id, "msg_synthetic_other");
      assert.equal(deltas[1].item_id, "msg_synthetic");
      assert.equal(deltas.map(({ delta }) => delta).join(""), credential);
    } else {
      const call = events.at(-1).response.output[0];
      assert.equal(call.type, "function_call");
      assert.equal(call.arguments.includes(credential), false);
      assert.equal(JSON.parse(call.arguments).value, credential);
    }
  }
});

test("connected request bytes pass the real Fastify parser and preserve missing-capability refusals", async (t) => {
  // This is offline HTTP admission proof only. In-memory storage/Compute keep
  // the parser test source-only; no installed receipt or provider is substituted.
  const auth = await createTestAuthPrincipal();
  const policy = {
    identities: [auth.seed.principal],
    groups: [],
    memberships: [],
    roles: auth.seed.roles,
    bindings: auth.seed.bindings,
    restrictions: [],
  };
  const auditSink = new InMemoryAuditSink();
  let controller;
  const app = createFastifyApp({
    createController(installation) {
      controller = new OpenClawController(installation, {
        state: new InMemoryPlatformState({ auditSink }),
        recordOperations: false,
      });
      return controller;
    },
    iamDriver: new NativeIAMDriver({ loadNativeIAMState: async () => policy }),
    configurationDriver: createTestConfigurationDriver(),
    secretDriver: createTestSecretDriver(),
    computeDriver: createReadyComputeDriver("egress-preflight-compute"),
    auditSink,
    auth: auth.auth,
    development: { enabled: true, installationId: auth.installationId },
  });
  t.after(() => app.close());
  const session = await signInToControllerApp(app, auth);
  const request = async (method, path, body) => {
    const wire = serializeConnectedRequest(method, path, body);
    const response = await app.inject({
      method: wire.method,
      url: wire.path,
      headers: authenticatedHeaders(session, wire.headers),
      ...(wire.body === undefined ? {} : { payload: wire.body }),
    });
    return {
      status: response.statusCode,
      body: response.body === "" ? undefined : response.json(),
    };
  };
  const api = async (method, path, body, status = 200) =>
    assertConnectedResponse(await request(method, path, body), status);
  await api("POST", "/installation/bootstrap", { name: "Connected wire preflight" }, 201);
  const namespace = await api("POST", "/namespaces", { name: "egress-preflight" }, 201);
  await controller.handleNamespaceLifecycle(auth.seed.principal.id, namespace.id, "ready");
  const prefix = `/namespaces/${namespace.id}`;
  const secret = await api(
    "POST",
    `${prefix}/secrets`,
    { name: "synthetic", value: "SYNTHETIC-preflight-only" },
    201,
  );
  const sourceBody = protectedSourceBody("synthetic", secret.ref, "https://provider.test:9443/v1");
  const unknownField = await api(
    "POST",
    `${prefix}/credential-sources`,
    { ...sourceBody, invented: true },
    400,
  );
  assert.equal(unknownField.code, "INVALID_REQUEST");
  // A schema-valid request must reach the missing real counterpart guard. An
  // undefined captured body or generic 400 cannot masquerade as that refusal.
  for (const origin of [
    "https://provider.test:9443/v1",
    "https://host.openshell.internal:9443/v1",
  ]) {
    const unsupported = await request(
      "POST",
      `${prefix}/credential-sources`,
      protectedSourceBody("synthetic", secret.ref, origin),
    );
    assertConnectedResponse(unsupported, 409);
    assert.equal(unsupported.body.error.code, "CREDENTIAL_GATEWAY_NOT_CONFIGURED");
  }
  const configuration = await api(
    "POST",
    `${prefix}/configurations`,
    protectedConfigurationBody("gpt-6"),
    201,
  );
  const agentBody = protectedAgentBody("synthetic", configuration.id, `cs_${randomUUID()}`);
  const unsupportedAgent = await request("POST", `${prefix}/agents`, agentBody);
  assertConnectedResponse(unsupportedAgent, 409);
  assert.equal(unsupportedAgent.body.error.code, "CREDENTIAL_GATEWAY_NOT_CONFIGURED");
  const role = await api(
    "POST",
    `${prefix}/iam/roles`,
    {
      name: "exact source only",
      permissions: [{ action: "operate", resourceKind: "credential_source" }],
    },
    201,
  );
  const principal = await api("POST", `${prefix}/iam/service-principals`, {}, 201);
  const bindingBody = sourceAccessBindingBody({ servicePrincipalId: principal.id }, role, {
    id: agentBody.harnessAuth.sourceId,
  });
  const missingBindingTarget = await request("POST", `${prefix}/iam/access-bindings`, bindingBody);
  assertConnectedResponse(missingBindingTarget, 400);
  assert.equal(missingBindingTarget.body.error.code, "INVALID_REQUEST");
  assert.deepEqual(missingBindingTarget.body.error.details, [
    { path: "/resourceId", code: "INVALID_VALUE" },
  ]);
});
