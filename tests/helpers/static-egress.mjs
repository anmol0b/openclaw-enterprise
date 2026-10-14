import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { createServer as createHttpsServer, request as httpsRequest } from "node:https";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createConsoleAppFixture } from "./console-app.mjs";
import { createDevelopmentComputeDriver } from "./development.mjs";
import { KubernetesSecretDriver } from "../../apps/controller/src/drivers/secret/kubernetes/index.ts";
import { createOpenShellBackend } from "../../apps/controller/src/backends/openshell.ts";
import { OpenShellSandboxDriver } from "../../apps/controller/src/drivers/sandbox/openshell.ts";
import { OpenShellCredentialGatewayDriver } from "../../apps/controller/src/drivers/credential-gateway/openshell.ts";
import { OpenShellEgressProxyDriver } from "../../apps/controller/src/drivers/egress-proxy/openshell.ts";
import { OpenShellEgressIdentity } from "../../apps/controller/src/drivers/egress-proxy/openshell-identity.ts";
import {
  createOpenShellEgressAuthority,
  bindOpenShellEgressAuthority,
} from "../../apps/controller/src/drivers/egress-proxy/openshell-authority.ts";

const require = createRequire(new URL("../../apps/controller/package.json", import.meta.url));
const grpc = require("@grpc/grpc-js");
const loader = require("@grpc/proto-loader");
const capability = "openshell.supervisor-middleware.http-credential-access.v1";
export const wireTime = (millis) => ({
  seconds: Math.floor(millis / 1000),
  nanos: (millis % 1000) * 1e6,
});
export const unary = (client, method, request, metadata) =>
  new Promise((resolve, reject) =>
    client[method](
      request,
      metadata ?? new grpc.Metadata(),
      { deadline: Date.now() + 5000 },
      (error, result) => (error ? reject(error) : resolve(result)),
    ),
  );
const listen = (server) =>
  new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server.address().port)));

/** Real app/auth/IAM/controller/Drivers. Storage and installed runtime observations are wire fixtures,
 * not a Kubernetes API server or an OpenShell supervisor. No authorization/provider logic is mocked. */
export async function staticEgressFixture(
  t,
  { appFactory = createConsoleAppFixture, includeLegacy = false } = {},
) {
  const directory = await mkdtemp(join(tmpdir(), "oce-egress-wire-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const keyPath = join(directory, "tls.key");
  const certPath = join(directory, "tls.crt");
  const generated = spawnSync(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-days",
      "1",
      "-keyout",
      keyPath,
      "-out",
      certPath,
      "-subj",
      "/CN=localhost",
      "-addext",
      "subjectAltName=DNS:localhost,DNS:provider.example.test,IP:127.0.0.1",
    ],
    { encoding: "utf8" },
  );
  assert.equal(generated.status, 0, generated.stderr);
  // Only ephemeral test-generated material is read; no operator credential files are involved.
  const [key, cert] = await Promise.all([readFile(keyPath), readFile(certPath)]);
  const objects = new Map();
  let namespace;
  let secretReads = 0;
  const kubeRequests = [];
  const kube = createHttpsServer({ key, cert }, async (request, response) => {
    response.setHeader("content-type", "application/json");
    const url = new URL(request.url, "http://localhost");
    kubeRequests.push([request.method, url.pathname]);
    if (url.pathname === "/api/v1/namespaces") {
      const nsId = namespace.id;
      assert.equal(url.searchParams.get("labelSelector"), `openclaw.dev/gateway-namespace=${nsId}`);
      response.end(
        JSON.stringify({
          apiVersion: "v1",
          kind: "NamespaceList",
          items: [
            {
              metadata: {
                name: `oce-${createHash("sha256").update(nsId).digest("hex").slice(0, 15)}`,
                labels: {
                  "app.kubernetes.io/managed-by": "openclaw-enterprise",
                  "openclaw.dev/gateway-namespace": nsId,
                  "openclaw.dev/namespace": nsId,
                },
                annotations: { "openclaw.dev/namespace-id": nsId },
              },
              status: { phase: "Active" },
            },
          ],
        }),
      );
      return;
    }
    const parts = url.pathname.split("/");
    const chunks = [];
    for await (const chunk of request) {
      chunks.push(chunk);
    }
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks)) : undefined;
    const name = parts[6] || body?.metadata?.name;
    const previous = objects.get(name);
    if (request.method === "POST" || request.method === "PUT") {
      if (
        previous &&
        request.method === "PUT" &&
        body.metadata.resourceVersion !== previous.metadata.resourceVersion
      ) {
        response.writeHead(409).end(JSON.stringify({ code: 409 }));
        return;
      }
      const stored = {
        ...body,
        metadata: {
          ...body.metadata,
          uid: previous?.metadata.uid ?? randomUUID(),
          resourceVersion: String(Number(previous?.metadata.resourceVersion ?? 0) + 1),
        },
        data: Object.fromEntries(
          Object.entries(body.stringData).map(([field, value]) => [
            field,
            Buffer.from(value).toString("base64"),
          ]),
        ),
      };
      delete stored.stringData;
      objects.set(name, stored);
      response.writeHead(request.method === "POST" ? 201 : 200).end(JSON.stringify(stored));
    } else if (request.method === "GET" && previous) {
      secretReads += 1;
      response.end(JSON.stringify(previous));
    } else {
      response.writeHead(404).end(JSON.stringify({ code: 404 }));
    }
  });
  const kubePort = await listen(kube);
  t.after(() => {
    kube.closeAllConnections();
    return new Promise((resolve) => kube.close(resolve));
  });
  const kubeconfigPath = join(directory, "fixture-kubeconfig.json");
  await writeFile(
    kubeconfigPath,
    JSON.stringify({
      apiVersion: "v1",
      kind: "Config",
      clusters: [
        {
          name: "fixture",
          cluster: {
            server: `https://127.0.0.1:${kubePort}`,
            "certificate-authority-data": cert.toString("base64"),
          },
        },
      ],
      users: [{ name: "fixture", user: {} }],
      contexts: [{ name: "fixture", context: { cluster: "fixture", user: "fixture" } }],
      "current-context": "fixture",
    }),
  );
  const secretDriver = new KubernetesSecretDriver({
    authentication: { mode: "kubeconfig", kubeconfigPath, context: "fixture" },
  });

  const gatewayDefinition = loader.loadSync(
    new URL(
      "../../apps/controller/src/drivers/sandbox/proto/openshell-gateway.proto",
      import.meta.url,
    ).pathname,
    { keepCase: true, enums: String, longs: String },
  );
  const Gateway = grpc.loadPackageDefinition(gatewayDefinition).openshell.v1.OpenShell;
  const gateway = new grpc.Server();
  const observed = { available: true, sandbox: undefined, policy: undefined, deleted: [] };
  const profiles = new Map();
  const providers = new Map();
  gateway.addService(Gateway.service, {
    GetProviderProfile(call, callback) {
      const profile = profiles.get(call.request.id);
      callback(profile ? null : { code: grpc.status.NOT_FOUND }, profile ? { profile } : undefined);
    },
    ImportProviderProfiles(call, callback) {
      for (const item of call.request.profiles) {
        profiles.set(item.profile.id, { ...item.profile, resource_version: "1" });
      }
      callback(null, { imported: true });
    },
    CreateProvider(call, callback) {
      const provider = {
        ...call.request.provider,
        metadata: { ...call.request.provider.metadata, id: randomUUID(), resource_version: "1" },
      };
      providers.set(provider.metadata.name, provider);
      callback(null, { provider });
    },
    GetProvider(call, callback) {
      const provider = providers.get(call.request.name);
      callback(
        provider ? null : { code: grpc.status.NOT_FOUND },
        provider ? { provider } : undefined,
      );
    },
    GetGatewayInfo(_call, callback) {
      callback(null, {
        status: 1,
        extensions: observed.available
          ? [
              {
                kind: 4,
                configured_name: "oce-authority",
                protocol_major: 1,
                supported_capabilities: [capability],
                required_capabilities: [capability],
              },
            ]
          : [],
      });
    },
    GetSandbox(call, callback) {
      if (!observed.sandbox) {
        callback({ code: grpc.status.NOT_FOUND });
        return;
      }
      assert.equal(call.request.workspace_scope.workspace, namespace.name);
      assert.equal(call.request.name, observed.sandbox.name);
      callback(null, {
        sandbox: { metadata: observed.sandbox, status: { phase: "SANDBOX_PHASE_READY" } },
      });
    },
    GetSandboxPolicyStatus(call, callback) {
      assert.equal(call.request.workspace_scope.workspace, namespace.name);
      callback(null, {
        revision: { version: 1, status: 2, policy: observed.policy },
        active_version: 1,
      });
    },
    DeleteSandbox(call, callback) {
      observed.deleted.push(call.request);
      const sandboxId = observed.sandbox?.id;
      observed.sandbox = undefined;
      callback(null, { outcome: "DELETION_OUTCOME_COMPLETED", sandbox_id: sandboxId });
    },
  });
  const gatewayPort = await new Promise((resolve, reject) =>
    gateway.bindAsync(
      "127.0.0.1:0",
      grpc.ServerCredentials.createSsl(null, [{ cert_chain: cert, private_key: key }], false),
      (error, port) => (error ? reject(error) : resolve(port)),
    ),
  );
  t.after(() => gateway.forceShutdown());
  const backend = createOpenShellBackend({
    id: "openshell-test",
    type: "openshell",
    configuration: { endpoint: `https://127.0.0.1:${gatewayPort}`, rootCertificatePath: certPath },
    drivers: {
      sandbox: "openshell-sandbox",
      credential_gateway: "openshell-credentials",
      egress_proxy: "openshell-egress",
    },
  });
  t.after(() => backend.client.close());
  const egressOptions = { middlewareName: "oce-authority", binaries: ["/usr/bin/model-client"] };
  const sandbox = new OpenShellSandboxDriver(
    {
      egress: egressOptions,
      gateway: { workspaceMode: "operator" },
      kubernetes: {
        runtimeClassName: "openshell-sandbox",
        serviceAccount: { mode: "gatewayConfigured" },
        sandboxDataMount: {
          subPath: "workspace",
          mountPath: "/sandbox/enterprise",
          readOnly: false,
        },
      },
      policy: {
        process: { runAsUser: "1000", runAsGroup: "1000" },
        networkPolicies: [
          {
            name: "inference",
            endpoints: [{ host: "provider.example.test", ports: [443] }],
            binaries: [{ path: "/usr/bin/model-client" }],
          },
        ],
      },
    },
    { id: "openshell-sandbox", backend },
  );
  const egress = new OpenShellEgressProxyDriver(egressOptions, {
    id: "openshell-egress",
    backend,
    sandbox,
  });
  const catalog = new OpenShellCredentialGatewayDriver(
    { binaries: egressOptions.binaries },
    { id: "openshell-credentials", backend },
  );
  const app = await appFactory(t, {
    provisionedPeople: [],
    secretDriver,
    computeDriver: {
      ...createDevelopmentComputeDriver(),
      async resolveSandboxNamespace(value) {
        return value;
      },
    },
  });
  await app.bootstrap();
  for (const driver of [catalog, sandbox]) {
    app.controller.registerDriver(driver);
    app.controller.selectDriver(driver.capability, driver.id);
  }
  namespace = await app.createNamespace(`egress-${randomUUID().slice(0, 8)}`, { ready: true });
  const createdSecret = await app.request("POST", `/namespaces/${namespace.id}/secrets`, {
    body: { name: "provider-key", value: "synthetic-key-initial" },
  });
  assert.equal(
    createdSecret.status,
    201,
    JSON.stringify({ body: createdSecret.body, kubeRequests }),
  );
  const secret = createdSecret.data;
  const path = `/namespaces/${namespace.id}/credential-sources`;
  const providerRequests = [];
  let providerResponse = { status: 200, body: { output: "fixture answer" } };
  const provider = createHttpsServer({ key, cert }, async (request, response) => {
    const body = [];
    for await (const part of request) {
      body.push(part);
    }
    providerRequests.push({
      method: request.method,
      path: request.url,
      authorization: request.headers.authorization,
      body: JSON.parse(Buffer.concat(body)),
    });
    response
      .writeHead(providerResponse.status, { "content-type": "application/json" })
      .end(providerResponse.rawBody ?? JSON.stringify(providerResponse.body));
  });
  const providerPort = await listen(provider);
  t.after(() => {
    provider.closeAllConnections();
    return new Promise((resolve) => provider.close(resolve));
  });
  let legacySource;
  if (includeLegacy) {
    const legacy = await app.request("POST", path, {
      body: { name: "approved-copy", type: "openai", secrets: { api_key: secret.ref } },
    });
    assert.equal(legacy.status, 201, JSON.stringify(legacy.body));
    legacySource = legacy.data;
  }
  app.controller.registerDriver(egress);
  app.controller.selectDriver("egress_proxy", egress.id);
  const created = await app.request("POST", path, {
    body: {
      name: "inference",
      type: "openai",
      config: { base_url: `https://provider.example.test:${providerPort}/v1` },
      secrets: { api_key: secret.ref },
    },
  });
  assert.equal(created.status, 201, JSON.stringify(created.body));
  const source = created.data;
  const config = await app.createConfiguration(namespace.id, {
    agents: {
      defaults: {
        model: { primary: "codex/fixture-model" },
        models: { "codex/fixture-model": { agentRuntime: { id: "codex" } } },
      },
    },
  });
  const createdAgent = await app.request("POST", `/namespaces/${namespace.id}/agents`, {
    body: {
      name: "inference-agent",
      configurationId: config.id,
      executionMode: "dedicated",
      harnessAuth: { method: "credential_source", sourceId: source.id },
      credentialSources: [{ sourceId: source.id }],
    },
  });
  assert.equal(createdAgent.status, 201, JSON.stringify(createdAgent.body));
  const agent = createdAgent.data;
  // Grant the real service principal through the supported policy API. Revocation later
  // commits between independent RPC transactions and must affect the final send check.
  const role = await app.request("POST", `/namespaces/${namespace.id}/iam/roles`, {
    body: {
      name: "inference-use",
      permissions: [{ action: "operate", resourceKind: "credential_source" }],
    },
  });
  assert.equal(role.status, 201, JSON.stringify(role.body));
  const grant = await app.request("POST", `/namespaces/${namespace.id}/iam/access-bindings`, {
    body: {
      subjectKind: "identity",
      subjectId: agent.servicePrincipalId,
      roleId: role.data.id,
      resourceKind: "credential_source",
      resourceId: source.id,
    },
  });
  assert.equal(grant.status, 201, JSON.stringify(grant.body));
  const revisionMetadata = await app.deployAgent(namespace.id, agent.id);
  const revision = await app.controller.transact((unit) =>
    unit.revisions.findRevision(namespace.id, agent.id, revisionMetadata.id),
  );
  assert.ok(revision.egressPlan, "deployment must admit the consumed protected plan");
  const context = {
    namespace,
    revision,
    plan: revision.egressPlan,
    signal: AbortSignal.timeout(5000),
  };
  const attachment = await egress.configureRevision(context);
  const ref = sandbox.harnessResource(context);
  const sandboxId = randomUUID();
  // This is an authenticated gateway-observation fixture, not supervisor execution proof.
  observed.sandbox = {
    id: sandboxId,
    name: ref.resourceName,
    phase: "SANDBOX_PHASE_READY",
    annotations: {
      "openclaw.dev/namespace-id": namespace.id,
      "openclaw.dev/agent-id": agent.id,
      "openclaw.dev/revision-id": revision.id,
    },
  };
  observed.policy = structuredClone({ version: 1, ...attachment.configuration });
  const installation = await egress.attachmentStatus(context, attachment);
  assert.ok(installation, "loaded exact policy must be observed through the real gateway client");
  await app.controller.transact((unit) =>
    unit.credentialSources.recordEgressInstallation(installation),
  );
  await app.activateRevision(namespace.id, agent.id, revision.id);

  const keys = generateKeyPairSync("ed25519");
  const identity = new OpenShellEgressIdentity({
    issuer: "https://gateway.example.test",
    audience: "oce-egress",
    keyId: "fixture-key",
    publicKey: keys.publicKey.export({ format: "pem", type: "spki" }),
    sender: egress.sourceControl.sender,
  });
  const authority = createOpenShellEgressAuthority(
    identity,
    app.controller.createEgressForwarder(identity),
  );
  const authorityPort = await bindOpenShellEgressAuthority(authority, "127.0.0.1:0", cert, key);
  t.after(() => authority.forceShutdown());
  const definition = loader.loadSync(
    new URL(
      "../../apps/controller/src/drivers/egress-proxy/proto/supervisor_middleware.proto",
      import.meta.url,
    ).pathname,
    { keepCase: true, longs: String, enums: Number, defaults: false, oneofs: true },
  );
  const services = grpc.loadPackageDefinition(definition).openshell.middleware.v1;
  const clients = Object.fromEntries(
    ["HttpCredentialAccess", "HttpResponsePreReturn", "SupervisorMiddleware"].map((name) => [
      name,
      new services[name](`127.0.0.1:${authorityPort}`, grpc.credentials.createSsl(cert)),
    ]),
  );
  t.after(() => {
    for (const client of Object.values(clients)) {
      client.close();
    }
  });
  const metadata = (overrides = {}) => {
    const now = Math.floor(Date.now() / 1000);
    const header = Buffer.from(
      JSON.stringify({ alg: "EdDSA", typ: "openshell-ext+jwt", kid: "fixture-key" }),
    ).toString("base64url");
    const payload = Buffer.from(
      JSON.stringify({
        iss: "https://gateway.example.test",
        aud: "oce-egress",
        sub: `spiffe://openshell/sandbox/${sandboxId}`,
        iat: now,
        exp: now + 60,
        jti: randomUUID(),
        caller_kind: "supervisor",
        sandbox_id: sandboxId,
        ...overrides,
      }),
    ).toString("base64url");
    const token = `${header}.${payload}.${sign(null, Buffer.from(`${header}.${payload}`), keys.privateKey).toString("base64url")}`;
    const result = new grpc.Metadata();
    result.set("authorization", `Bearer ${token}`);
    return result;
  };
  const capture = (body = { model: "fixture-model", input: "hello", store: false }) => ({
    audience: "oce-egress",
    deadline: wireTime(Date.now() + 20_000),
    request: {
      context: { request_id: randomUUID(), sandbox_id: sandboxId },
      target: {
        scheme: "https",
        host: "provider.example.test",
        port: providerPort,
        method: "POST",
        path: "/v1/responses",
      },
      headers: [{ name: "content-type", value: "application/json" }],
      body: Buffer.from(JSON.stringify(body)),
    },
  });
  function permitRequest(captured, ready) {
    const hash = createHash("sha256");
    for (const header of ready.credential_headers) {
      for (const value of [header.name, header.value]) {
        const bytes = Buffer.from(value);
        const length = Buffer.alloc(8);
        length.writeBigUInt64BE(BigInt(bytes.length));
        hash.update(length).update(bytes);
      }
    }
    return {
      context: captured.request.context,
      operation_handle: ready.operation_handle,
      audience: "oce-egress",
      deadline: captured.deadline,
      evidence: ready.evidence,
      credential_headers_sha256: hash.digest(),
    };
  }
  async function send(captured, ready) {
    return new Promise((resolve, reject) => {
      const outgoing = httpsRequest(
        {
          hostname: "127.0.0.1",
          servername: "provider.example.test",
          ca: cert,
          port: providerPort,
          method: "POST",
          path: captured.request.target.path,
          headers: {
            "content-type": "application/json",
            ...Object.fromEntries(ready.credential_headers.map(({ name, value }) => [name, value])),
          },
        },
        async (response) => {
          const chunks = [];
          for await (const chunk of response) {
            chunks.push(chunk);
          }
          resolve({
            status: response.statusCode,
            headers: [{ name: "content-type", value: response.headers["content-type"] }],
            body: Buffer.concat(chunks),
          });
        },
      );
      outgoing.on("error", reject);
      outgoing.end(captured.request.body);
    });
  }
  async function protect(captured, response) {
    const stream = clients.HttpResponsePreReturn.Evaluate(metadata());
    const messages = [];
    return new Promise((resolve, reject) => {
      stream.on("error", reject);
      stream.on("data", (message) => {
        messages.push(message);
        if (message.preflight_result?.inspect) {
          stream.write({ body: { sequence: 1, data: response.body, end_of_stream: true } });
        } else {
          stream.end();
        }
      });
      stream.on("end", () => resolve(messages.at(-1)));
      stream.write({
        preflight: {
          context: captured.request.context,
          status_code: response.status,
          headers: response.headers,
          permitted_body_modes: [2],
        },
      });
    });
  }
  return {
    ...app,
    namespace,
    secret,
    source,
    legacySource,
    providers,
    path,
    agent,
    revision,
    context,
    attachment,
    egress,
    observed,
    clients,
    metadata,
    capture,
    permitRequest,
    send,
    protect,
    providerRequests,
    setResponse(value) {
      providerResponse = value;
    },
    get secretReads() {
      return secretReads;
    },
    async revoke() {
      const result = await app.request(
        "DELETE",
        `/namespaces/${namespace.id}/iam/access-bindings/${grant.data.id}`,
      );
      assert.equal(result.status, 204, JSON.stringify(result.body));
    },
  };
}
