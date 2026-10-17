import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFile, mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { GrpcOpenShellGatewayClient } from "../../apps/controller/src/drivers/sandbox/openshell-gateway-client.ts";
import {
  OpenShellPreparedGitProvider,
  OpenShellPreparedGitProviderError,
} from "../../apps/controller/src/drivers/egress-proxy/openshell-prepared-git-provider.ts";

const require = createRequire(new URL("../../apps/controller/package.json", import.meta.url));
const grpc = require("@grpc/grpc-js");
const loader = require("@grpc/proto-loader");
const scope = {
  workspace: "git-dogfood",
  workspaceId: "workspace-id",
  sandbox: "git-execution",
  executionId: "execution-one",
  repository: "example/project",
  gitOrigin: "https://github.com",
  apiOrigin: "https://api.github.com",
  binaries: ["/usr/bin/git", "/usr/bin/gh"],
};
const token = (suffix = "first") => ({
  value: `synthetic-installation-token_${suffix}`,
  expiresAt: new Date(Date.now() + 600_000).toISOString(),
});
const signal = () => AbortSignal.timeout(5_000);

async function wire(t) {
  const directory = await mkdtemp(join(tmpdir(), "prepared-git-wire-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  // Independent pinned v0.1.4 oracle, extended with fields copied from released
  // openshell.proto/datamodel.proto at 5a7728c30; never load the client schema.
  let proto = await readFile(
    new URL("../fixtures/openshell-v0.1.4-wire.proto", import.meta.url),
    "utf8",
  );
  proto = proto.replace(
    "service OpenShell {",
    `service OpenShell {
    rpc GetWorkspace(GetWorkspaceRequest) returns (GetWorkspaceResponse);
    rpc GetProvider(GetProviderRequest) returns (ProviderResponse);
    rpc GetProviderProfile(GetProviderProfileRequest) returns (ProviderProfileResponse);`,
  );
  proto = proto.replace(
    "  string path_template = 9;",
    "  string path_template = 9;\n  bool stable_placeholder = 12;",
  );
  proto += `
    message GetWorkspaceRequest { string name = 1; }
    message Workspace { ObjectMeta metadata = 1; }
    message GetWorkspaceResponse { Workspace workspace = 1; }
    message GetProviderRequest { string name = 1; WorkspaceSelector workspace_scope = 2; }
    message GetProviderProfileRequest { string id = 1; WorkspaceSelector workspace_scope = 2; }
    message ProviderProfileResponse { ProviderProfile profile = 1; }
  `;
  const path = join(directory, "wire.proto");
  await writeFile(path, proto);
  const definition = await loader.load(path, {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: false,
    oneofs: true,
  });
  const OpenShell = grpc.loadPackageDefinition(definition).openshell.v1.OpenShell;
  const state = {
    requests: [],
    profile: undefined,
    provider: undefined,
    conflict: false,
    lost: false,
    workspaceId: scope.workspaceId,
  };
  const server = new grpc.Server();
  const record = (call) => {
    state.requests.push(call.request);
    assert.equal(call.request.workspace_scope.workspace, scope.workspace);
  };
  server.addService(OpenShell.service, {
    GetWorkspace(call, callback) {
      assert.equal(call.request.name, scope.workspace);
      callback(null, { workspace: { metadata: { name: scope.workspace, id: state.workspaceId } } });
    },
    GetProviderProfile(call, callback) {
      record(call);
      if (!state.profile) {
        callback({ code: grpc.status.NOT_FOUND });
        return;
      }
      callback(null, { profile: state.profile });
    },
    ImportProviderProfiles(call, callback) {
      record(call);
      assert.equal(call.request.profiles.length, 1);
      assert.match(call.request.request_id, /^[a-f0-9-]{36}$/);
      state.profile = { ...call.request.profiles[0].profile, resource_version: "1" };
      callback(null, { imported: true, profiles: [state.profile] });
    },
    GetProvider(call, callback) {
      record(call);
      if (!state.provider) {
        callback({ code: grpc.status.NOT_FOUND });
        return;
      }
      callback(null, { provider: state.provider });
    },
    CreateProvider(call, callback) {
      record(call);
      state.provider = {
        ...call.request.provider,
        metadata: {
          ...call.request.provider.metadata,
          id: "provider-id",
          workspace: scope.workspace,
          resource_version: "1",
        },
      };
      callback(null, { provider: state.provider });
    },
    UpdateProvider(call, callback) {
      record(call);
      // The independent server enforces the released resource-version precondition.
      if (
        state.conflict ||
        call.request.provider.metadata.resource_version !== state.provider.metadata.resource_version
      ) {
        callback({ code: grpc.status.ABORTED, details: "concurrent writer" });
        return;
      }
      state.provider = {
        ...state.provider,
        credentials: call.request.provider.credentials,
        credential_expiration_times: call.request.credential_expiration_times,
        metadata: { ...state.provider.metadata, resource_version: "2" },
      };
      if (state.lost) {
        callback({
          code: grpc.status.UNAVAILABLE,
          details: state.provider.credentials.GITHUB_TOKEN,
        });
        return;
      }
      callback(null, { provider: state.provider });
    },
  });
  const port = await new Promise((resolve, reject) =>
    server.bindAsync("127.0.0.1:0", grpc.ServerCredentials.createInsecure(), (error, port) =>
      error ? reject(error) : resolve(port),
    ),
  );
  const client = new GrpcOpenShellGatewayClient({ endpoint: `127.0.0.1:${port}` });
  t.after(() => {
    client.close();
    server.forceShutdown();
  });
  return { state, binding: new OpenShellPreparedGitProvider(client, scope), client };
}

// These are protocol conformance checks over a real gRPC socket with synthetic
// material, not an installed supervisor, Git sender, or live-provider proof.
test("prepared Git static token and rotation use released fields without returning credentials or readiness", async (t) => {
  const { state, binding } = await wire(t);
  const first = token();
  const receipt = await binding.prepare(first, signal());
  assert.equal(receipt.update, "accepted");
  assert.equal(receipt.supervisor, "unknown");
  assert.equal(receipt.providerId, "provider-id");
  assert.equal(receipt.resourceVersion, "1");
  assert.equal(receipt.readiness.rpc, "GetSandboxProviderStatus");
  assert.equal(JSON.stringify(receipt).includes(first.value), false);
  assert.deepEqual(state.profile.credentials, [
    {
      name: "installation_token",
      env_vars: ["GITHUB_TOKEN"],
      required: true,
      auth_style: "bearer",
      header_name: "authorization",
      stable_placeholder: true,
    },
  ]);
  assert.deepEqual(
    state.profile.endpoints.map(({ host, port, path, tls }) => ({ host, port, path, tls })),
    [
      {
        host: "github.com",
        port: 443,
        path: "/example/project.git/**",
        tls: undefined,
      },
      {
        host: "api.github.com",
        port: 443,
        path: "/repos/example/project/pulls",
        tls: undefined,
      },
    ],
  );
  assert.equal(state.provider.credentials.GITHUB_TOKEN, first.value);
  assert.equal(state.provider.profile_workspace, scope.workspace);
  assert.equal(
    state.provider.credential_expiration_times.GITHUB_TOKEN.seconds,
    String(Math.floor(Date.parse(first.expiresAt) / 1000)),
  );
  const next = token("successor");
  const rotated = await binding.rotate(receipt, next, signal());
  assert.equal(rotated.resourceVersion, "2");
  assert.equal(rotated.supervisor, "unknown");
  assert.equal(JSON.stringify(rotated).includes(next.value), false);
  const update = state.requests.at(-1);
  assert.equal(update.provider.metadata.resource_version, "1");
  assert.equal(update.provider.credentials.GITHUB_TOKEN, next.value);
  assert.equal(
    update.credential_expiration_times.GITHUB_TOKEN.seconds,
    String(Math.floor(Date.parse(next.expiresAt) / 1000)),
  );
});

test("prepared Git refuses foreign, stale, changed-profile and replaced-workspace bindings before token update", async (t) => {
  const { state, binding, client } = await wire(t);
  const receipt = await binding.prepare(token(), signal());
  const original = structuredClone(state.provider);
  for (const mutation of [
    () => {
      state.provider.metadata.id = "foreign-provider";
    },
    () => {
      state.provider.metadata.resource_version = "2";
    },
    () => {
      state.provider.metadata.labels = {};
    },
    () => {
      state.profile.resource_version = "2";
    },
    () => {
      state.workspaceId = "replacement-workspace";
    },
  ]) {
    state.provider = structuredClone(original);
    state.profile.resource_version = "1";
    state.workspaceId = scope.workspaceId;
    mutation();
    await assert.rejects(
      binding.rotate(receipt, token("rejected"), signal()),
      (error) => error instanceof OpenShellPreparedGitProviderError && error.outcome === "refused",
    );
    assert.equal(
      state.requests.some((request) => request.provider?.metadata?.resource_version),
      false,
    );
  }
  const replacement = new OpenShellPreparedGitProvider(client, {
    ...scope,
    executionId: "successor",
  });
  await assert.rejects(replacement.rotate(receipt, token(), signal()), /refused/);
});

test("prepared Git preserves uncertain write outcomes and redacts private gateway failures", async (t) => {
  const { state, binding } = await wire(t);
  const receipt = await binding.prepare(token(), signal());
  state.lost = true;
  const next = token("private_successor");
  await assert.rejects(
    binding.rotate(receipt, next, signal()),
    (error) =>
      error.outcome === "unknown" &&
      !String(error.stack).includes(next.value) &&
      error.cause === undefined,
  );
  assert.equal(
    state.requests.filter((request) => request.provider?.metadata?.resource_version).length,
    1,
  );
  assert.equal(
    state.provider.metadata.resource_version,
    "2",
    "lost reply cannot justify resubmission",
  );
});

test("prepared Git sends a CAS precondition and fails closed on a concurrent gateway update", async (t) => {
  const { state, binding } = await wire(t);
  const receipt = await binding.prepare(token(), signal());
  state.conflict = true;
  await assert.rejects(binding.rotate(receipt, token("racing"), signal()), /unknown/);
  assert.equal(state.provider.metadata.resource_version, "1");
  assert.equal(
    state.requests.filter((request) => request.provider?.metadata?.resource_version).length,
    1,
  );
});

test("prepared Git rejects credential and scope widening before provisioning", async (t) => {
  const { state, binding, client } = await wire(t);
  for (const invalid of [
    { ...token(), expiresAt: new Date(Date.now() + 7_200_000).toISOString() },
    { ...token(), value: "-----BEGIN PRIVATE KEY-----" },
    { ...token(), value: "openshell:resolve:env:NOT_A_TOKEN" },
  ]) {
    await assert.rejects(binding.prepare(invalid, signal()), /refused/);
  }
  for (const widened of [
    { binaries: [] },
    { repository: "example/../project" },
    { gitOrigin: "http://github.com" },
    { apiOrigin: "https://*.github.com" },
    { workspace: "" },
  ]) {
    assert.throws(() => new OpenShellPreparedGitProvider(client, { ...scope, ...widened }));
  }
  assert.equal(state.requests.length, 0);
});
