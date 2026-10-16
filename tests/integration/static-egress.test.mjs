import assert from "node:assert/strict";
import test from "node:test";
import { createTestKubernetesComputeDriver } from "../helpers/kubernetes-compute.mjs";
import { createConsoleAppFixture } from "../helpers/console-app.mjs";
import { readFileSync } from "node:fs";
import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { createRequire } from "node:module";
import { EgressSendReceipts } from "../../packages/occ/src/egress-send-receipts.ts";
import { InMemoryPlatformState } from "../../packages/occ/src/state/platform-state.ts";
import { OpenShellEgressIdentity } from "../../apps/controller/src/drivers/egress-proxy/openshell-identity.ts";
import { CredentialProxy, egressInjectionDigest } from "../../packages/occ/src/credential-proxy.ts";
import { deploymentErrorForWork } from "../../packages/occ/src/state/controller-work.ts";
import {
  pluginRuntimeSpecForRevision,
  pluginRuntimeConfigMapData,
} from "../../apps/controller/src/drivers/compute/plugin-runtime.ts";
import { openShellExchangeCapabilities } from "../../apps/controller/src/drivers/egress-proxy/openshell-exchange-capabilities.ts";
import {
  staticEgressFixture,
  syntheticDispatchFixture,
  requestId,
  unary,
  wireTime,
} from "../helpers/static-egress.mjs";

test("credential header digest uses ordered UTF-8 bytes and u64 lengths", () => {
  assert.equal(
    egressInjectionDigest([
      ["authorization", "Bearer synthetic-vector"],
      ["x-api-key", "key-é"],
    ]),
    "d1e3baea080e3a4d5ec5ac5feb168ded341a545d201aea2d1d1104dca7ec6b23",
  );
});

test("supplier-produced receipt protobuf and registered-instance claims decode through the consumer contract", async () => {
  const vector = JSON.parse(
    readFileSync(new URL("../fixtures/static-egress/openshell-receipt.json", import.meta.url)),
  );
  const require = createRequire(new URL("../../apps/controller/package.json", import.meta.url));
  const definition = require("@grpc/proto-loader").loadSync(
    new URL(
      "../../apps/controller/src/drivers/sandbox/proto/openshell-gateway.proto",
      import.meta.url,
    ).pathname,
    { keepCase: true, longs: String, enums: String },
  );
  // Bytes were produced by Rust's actual OPA/registry/gateway fixture, independently
  // of this decoder. In particular, uint64 generations must not round through Number.
  const receipt = definition["openshell.v1.LoadedEnforcementEvidence"].deserialize(
    Buffer.from(vector.protobuf_hex, "hex"),
  );
  assert.deepEqual(receipt, vector.receipt);
  assert.equal(receipt.instance_id, vector.verified_extension_claims.instance_id);
  assert.equal(receipt.sandbox_id, vector.verified_extension_claims.sandbox_id);
  const keys = generateKeyPairSync("ed25519");
  const identity = new OpenShellEgressIdentity({
    issuer: vector.verified_extension_claims.iss,
    audience: vector.verified_extension_claims.aud,
    keyId: "fixture-key",
    publicKey: keys.publicKey.export({ type: "spki", format: "pem" }),
    sender: { id: "fixture-sender", generation: 1 },
  });
  // The capture has no bearer or signing key. Re-sign its claim shape with a local
  // fixture key and fresh times; this checks compatibility, not producer key custody.
  const header = Buffer.from(
    JSON.stringify({ alg: "EdDSA", typ: "openshell-ext+jwt", kid: "fixture-key" }),
  ).toString("base64url");
  const current = Math.floor(Date.now() / 1000);
  const claims = { ...vector.verified_extension_claims, iat: current, exp: current + 60 };
  const token = (value) => {
    const payload = Buffer.from(JSON.stringify(value)).toString("base64url");
    const signed = `${header}.${payload}`;
    return `Bearer ${signed}.${sign(null, Buffer.from(signed), keys.privateKey).toString("base64url")}`;
  };
  const peer = identity.supervisor(token(claims));
  assert.equal(
    await identity.verify(token(claims)),
    undefined,
    "a valid bearer is not an exchange",
  );
  assert.equal(peer.instanceId, receipt.instance_id);
  assert.equal(peer.sandboxId, receipt.sandbox_id);
  assert.equal(identity.supervisor(token({ ...claims, instance_id: undefined })), undefined);
});

test("protected inference uses real admission, fresh IAM, versioned Secret reads and TLS authority/provider wires", async (t) => {
  const f = await staticEgressFixture(t, { physicalPlacement: true });
  assert.notEqual(f.namespace.name, f.runtimeNamespace.name);
  assert.equal(f.namespace.id, f.runtimeNamespace.id);
  assert.deepEqual(f.source.egress, { adoption: "live", retention: "none" });
  assert.throws(
    () => pluginRuntimeConfigMapData(pluginRuntimeSpecForRevision(f.revision)),
    /explicit normalized model endpoint/,
    "protected configuration cannot silently use default retry or transport behavior",
  );
  const runtime = pluginRuntimeSpecForRevision(
    f.revision,
    undefined,
    "https://provider.example.test/v1",
  );
  const config = pluginRuntimeConfigMapData(runtime)["config.toml"];
  assert.match(config, /^web_search = "disabled"/m);
  assert.match(config, /supports_websockets = false/);
  assert.match(config, /request_max_retries = 0\nstream_max_retries = 0/);
  assert.deepEqual(
    runtime.selections,
    {},
    "protected grant does not replace local plugin selection",
  );
  // Deleting the plan must never downgrade an admitted protected execution.
  const withoutPlan = { ...f.revision };
  delete withoutPlan.egressPlan;
  assert.throws(() => pluginRuntimeSpecForRevision(withoutPlan), /Inconsistent durable/);
  const missing = { ...withoutPlan };
  delete missing.executionAdmission;
  assert.throws(() => pluginRuntimeSpecForRevision(missing), /Missing or unsupported durable/);
  assert.throws(
    () =>
      pluginRuntimeSpecForRevision({
        ...withoutPlan,
        executionAdmission: { version: 3, mode: "unprotected" },
      }),
    /Missing or unsupported durable/,
  );
  assert.throws(
    () =>
      pluginRuntimeSpecForRevision({
        ...f.revision,
        executionAdmission: { version: 2, mode: "unprotected" },
      }),
    /Inconsistent durable/,
  );
  const unprotected = {
    ...withoutPlan,
    executionAdmission: { version: 2, mode: "unprotected" },
  };
  assert.doesNotMatch(
    pluginRuntimeConfigMapData(pluginRuntimeSpecForRevision(unprotected))["config.toml"],
    /web_search/,
  );
  const capture = f.capture();
  const result = await f.resolve(capture);
  assert.ok(result.ready, JSON.stringify(result));
  const permit = f.permitRequest(capture, result.ready);
  assert.ok((await f.authorize(permit)).allowed);
  const response = await f.send(capture, result.ready);
  assert.deepEqual(f.providerRequests[0].body, {
    model: "fixture-model",
    input: "hello",
    store: false,
  });
  assert.equal(f.providerRequests[0].authorization, "Bearer synthetic-key-initial");
  const protectedResponse = await f.protect(capture, response);
  assert.deepEqual(JSON.parse(protectedResponse.body), {
    output: "fixture answer",
  });
  const replay = await f.beginExchange();
  replay.stream.write({ authorize: permit });
  await assert.rejects(replay.next(), { code: 7 });

  // Rotation changes material version without replacing source configuration or grants.
  const updated = await f.request("PATCH", `/namespaces/${f.namespace.id}/secrets/${f.secret.id}`, {
    body: { value: "synthetic-key-rotated" },
  });
  assert.equal(updated.status, 200, JSON.stringify(updated.body));
  const next = f.capture();
  const resolved = await f.resolve(next);
  assert.ok(resolved.ready, JSON.stringify(resolved));
  assert.notEqual(resolved.ready.evidence.material_version, result.ready.evidence.material_version);
  assert.equal(resolved.ready.credential_headers[0].value, "Bearer synthetic-key-rotated");
  await f.revoke();
  assert.ok(
    (await f.authorize(f.permitRequest(next, resolved.ready))).refused,
    "revocation after access must deny selected material at send",
  );
  assert.equal(f.providerRequests.length, 1);
  const beforeReads = f.secretReads;
  assert.ok((await f.resolve(f.capture())).refused);
  assert.equal(f.secretReads, beforeReads, "current IAM denial must precede Secret access");
  const denials = (await f.controller.transact((unit) => unit.audit.list())).filter(
    (event) => event.action === "openclaw.egress.authorize",
  );
  assert.deepEqual(
    denials.map(({ namespaceId, actorId, resource, details }) => ({
      namespaceId,
      actorId,
      resource,
      phase: details.phase,
    })),
    ["before_send", "before_access"].map((phase) => ({
      namespaceId: f.namespace.id,
      actorId: f.revision.servicePrincipalId,
      resource: { kind: "credential_source", namespaceId: f.namespace.id, id: f.source.id },
      phase,
    })),
    "runtime placement must not replace logical IAM or audit identity",
  );
});

test("protected authority refuses forged execution, unsupported operations, replay and changed selected-material evidence", async (t) => {
  const f = await staticEgressFixture(t);
  const before = f.secretReads;
  for (const body of [
    { model: "other-model", input: "hello", store: false },
    { model: "fixture-model", input: "hello" },
    { model: "fixture-model", input: "hello", store: false, stream: "true" },
    { model: "fixture-model", input: "hello", store: false, tools: [{ type: "web_search" }] },
  ]) {
    assert.ok((await f.resolve(f.capture(body))).refused);
  }
  const ambiguous = f.capture();
  ambiguous.request.body = Buffer.from(
    '{"model":"other-model","model":"fixture-model","input":"hello","store":false}',
  );
  assert.ok((await f.resolve(ambiguous)).refused);
  const wrongPeer = f.metadata({
    sandbox_id: "other-sandbox",
    sub: "spiffe://openshell/sandbox/other-sandbox",
  });
  await assert.rejects(f.resolve(f.capture(), wrongPeer), { code: 7 });
  await assert.rejects(f.resolve(f.capture(), f.metadata({ aud: "different-authority" })), {
    code: 7,
  });
  assert.equal(
    f.secretReads,
    before,
    "identity and operation refusals must not touch credential material",
  );
  const captured = f.capture();
  const ready = (await f.resolve(captured)).ready;
  assert.ok(ready);
  assert.ok(
    (await f.resolve({ ...captured, response_custody: randomBytes(32) })).refused,
    "a new signed opening and custody cannot replay the captured use",
  );
  for (const change of [
    (p) => {
      p.evidence.material_version = "not-selected";
    },
    (p) => {
      p.deadline.seconds = String(Number(p.deadline.seconds) + 1);
    },
    (p) => {
      p.credential_headers_sha256 = Buffer.alloc(32);
    },
    (p) => {
      p.context.verified_credential_connector = { path: "/usr/bin/not-authority" };
    },
  ]) {
    // A malformed authorization consumes the one exchange. Start the next negative
    // with a genuinely resolved sibling so it reaches the specific evidence guard.
    const sibling = f.capture();
    const resolved = await f.resolve(sibling);
    const permit = f.permitRequest(sibling, resolved.ready);
    change(permit);
    assert.ok((await f.authorize(permit)).refused);
  }
  const permit = f.permitRequest(captured, ready);
  const decisions = await Promise.allSettled([f.authorize(permit), f.authorize(permit)]);
  assert.ok(decisions.filter((d) => d.value?.allowed).length <= 1);
  assert.ok(
    decisions.some((d) => d.status === "rejected" && d.reason.code === 7),
    "pipelined authorizations are refused on the actual exchange",
  );
  assert.equal(f.providerRequests.length, 0);
});

test("provider authentication rejection fences the exact material version and encoded credential reflection is withheld", async (t) => {
  const f = await staticEgressFixture(t);
  async function exchange() {
    const captured = f.capture();
    const ready = (await f.resolve(captured)).ready;
    assert.ok(ready);
    assert.ok((await f.authorize(f.permitRequest(captured, ready))).allowed);
    return f.protect(captured, await f.send(captured, ready));
  }
  f.setResponse({
    status: 200,
    body: { output: Buffer.from("synthetic-key-initial").toString("base64") },
  });
  assert.ok(
    (await exchange()).blocked,
    "the actual provider response must pass conservative protection",
  );
  f.setResponse({
    status: 200,
    rawBody: '{"output":"synthetic-key-initial","output":"hidden duplicate"}',
  });
  assert.ok(
    (await exchange()).blocked,
    "duplicate JSON keys cannot conceal reflected material from parsing",
  );
  // Function arguments have their own protocol-defined JSON layer. Ordinary tool
  // decoding must never recover the protected value from escaped response text.
  const escaped = [..."synthetic-key-initial"]
    .map((character) => "\\u" + character.charCodeAt(0).toString(16).padStart(4, "0"))
    .join("");
  f.setResponse({
    status: 200,
    body: {
      output: [
        {
          type: "function_call",
          id: "call-escaped",
          call_id: "tool-escaped",
          name: "fixture_function_0",
          arguments: '{"cmd":"' + escaped + '"}',
        },
      ],
    },
  });
  assert.ok(
    (await exchange()).blocked,
    "decoding supported JSON function arguments cannot expose credential material",
  );
  f.setResponse({
    status: 401,
    body: {
      error: {
        code: "invalid_api_key",
        type: "invalid_request_error",
        message: "Invalid credential",
      },
    },
  });
  assert.ok((await exchange()).body);
  const captured = f.capture();
  const ready = (await f.resolve(captured)).ready;
  assert.ok(ready);
  assert.ok(
    (await f.authorize(f.permitRequest(captured, ready))).refused,
    "authoritative reread cannot resurrect a rejected version",
  );
  const updated = await f.request("PATCH", `/namespaces/${f.namespace.id}/secrets/${f.secret.id}`, {
    body: { value: "synthetic-key-new-version" },
  });
  assert.equal(updated.status, 200);
  f.setResponse({ status: 200, body: { output: "after rotation" } });
  assert.ok(
    (await exchange()).body,
    "new authoritative version does not inherit the old rejection",
  );
});

test("protected admission requires the actual counterpart and exact loaded policy; withdrawal removes only its owned Sandbox", async (t) => {
  const f = await staticEgressFixture(t);
  // Inspect the production attachment before protobuf can erase an explicit zero.
  // OpenShell requires omission for automatic TLS termination, not TERMINATE or SKIP.
  for (const [index, route] of f.context.plan.routes.entries()) {
    const endpoints = f.attachment.configuration.network_policies[`oce-egress-${index}`].endpoints;
    assert.equal(Object.hasOwn(endpoints[0], "tls"), false);
    const origin = new URL(route.origin);
    assert.deepEqual(endpoints, [
      {
        host: origin.hostname,
        ports: [Number(origin.port || 443)],
        protocol: "rest",
        enforcement: "NETWORK_ENFORCEMENT_MODE_ENFORCE",
        access: "NETWORK_ACCESS_PRESET_FULL",
        path: route.path,
      },
    ]);
  }
  const middleware = f.attachment.configuration.network_middlewares["oce-egress"];
  assert.equal(middleware.on_error, "fail_closed");
  assert.equal(middleware.credential_authority, true);
  assert.equal(Object.hasOwn(middleware, "config"), false);
  assert.equal(Object.hasOwn(middleware, "order"), false);
  assert.equal(Object.hasOwn(middleware.endpoints, "exclude"), false);
  // Strict Sandbox adoption compares the outgoing policy with its decoded form.
  // Use the production schema and decoder options without normalizing either side.
  const require = createRequire(new URL("../../apps/controller/package.json", import.meta.url));
  const definition = require("@grpc/proto-loader").loadSync(
    new URL(
      "../../apps/controller/src/drivers/sandbox/proto/openshell-gateway.proto",
      import.meta.url,
    ).pathname,
    { keepCase: true, longs: String, enums: String, defaults: false, oneofs: true },
  );
  const policy = definition["openshell.v1.SandboxPolicy"];
  assert.deepStrictEqual(
    policy.deserialize(policy.serialize(f.attachment.configuration)),
    f.attachment.configuration,
  );
  const contract = "openshell.supervisor-middleware.contract";
  const capability = "openshell.supervisor-middleware.http-credential-access.v1";
  // The supervisor performs its own Describe with locally compiled capabilities. An
  // old sender cannot merely inherit the upgraded gateway's negotiation result.
  await assert.rejects(
    unary(
      f.clients.SupervisorMiddleware,
      "Describe",
      {
        gateway: { protocol_version: { major: 1 }, supported_capabilities: [contract] },
      },
      f.metadata(),
    ),
    { code: 14 },
  );
  const manifest = await unary(
    f.clients.SupervisorMiddleware,
    "Describe",
    {
      gateway: {
        protocol_version: { major: 1 },
        supported_capabilities: [contract, ...openShellExchangeCapabilities],
        required_capabilities: [contract],
      },
    },
    f.metadata(),
  );
  assert.ok(manifest.extension.required_capabilities.includes(capability));
  f.observed.available = false;
  const refused = await f.request("POST", f.path, {
    body: { name: "unsupported-peer", type: "openai", secrets: { api_key: f.secret.ref } },
  });
  assert.equal(refused.status, 503, JSON.stringify(refused.body));
  assert.equal(
    (await f.request("GET", f.path)).data.length,
    1,
    "failed candidate cannot leave admitted source metadata",
  );
  await assert.rejects(f.egress.configureRevision(f.context));
  f.observed.available = true;
  const expectedPolicy = structuredClone(f.observed.policy);
  assert.equal(await f.egress.verifyInstallation(f.context, f.installation), true);
  // A reported TLS bypass must fail both initial installation and receipt revalidation,
  // even when the supplier still reports the original loaded-enforcement evidence.
  f.observed.policy.network_policies["oce-egress-0"].endpoints[0].tls = "NETWORK_TLS_MODE_SKIP";
  await assert.rejects(f.egress.wiringStatus(f.context, f.attachment), /differs/);
  assert.equal(await f.egress.verifyInstallation(f.context, f.installation), false);
  f.observed.policy = structuredClone(expectedPolicy);
  assert.equal(await f.egress.verifyInstallation(f.context, f.installation), true);
  f.observed.policy.network_middlewares["oce-egress"].credential_authority = false;
  assert.equal(await f.egress.wiringStatus(f.context, f.attachment), undefined);
  f.observed.policy = structuredClone(expectedPolicy);
  f.observed.policy.network_policies["oce-egress-0"].endpoints[0].allow_uninspected_credentials =
    true;
  await assert.rejects(f.egress.wiringStatus(f.context, f.attachment), /differs/);
  f.observed.policy = structuredClone(expectedPolicy);
  f.observed.policy.network_policies["workspace-node-enrollment"] = {
    name: "workspace-node-enrollment",
    binaries: [{ path: "/usr/local/bin/node" }],
    endpoints: [{ host: "unexpected.example.test", ports: [443] }],
  };
  await assert.rejects(f.egress.wiringStatus(f.context, f.attachment), /differs/);
  f.observed.policy = expectedPolicy;
  // Matching network maps cannot hide a change to the admitted process/filesystem.
  for (const change of [
    { process: { run_as_user: "0", run_as_group: "0" } },
    { filesystem: { read_only: ["/usr"], read_write: ["/"] } },
    { landlock: { compatibility: "best_effort" } },
    { version: 2 },
  ]) {
    f.observed.policy = { ...structuredClone(expectedPolicy), ...change };
    await assert.rejects(f.egress.wiringStatus(f.context, f.attachment), /differs/);
    assert.equal(await f.egress.verifyInstallation(f.context, f.installation), false);
  }
  f.observed.policy = expectedPolicy;
  const originalAnnotations = f.observed.sandbox.annotations;
  f.observed.sandbox.annotations = {
    ...originalAnnotations,
    "openclaw.dev/agent-id": "other-agent",
  };
  await assert.rejects(
    f.egress.withdrawBinding(f.context, f.context.plan.routes[0].binding.binding),
  );
  assert.equal(f.observed.deleted.length, 0);
  f.observed.sandbox.annotations = originalAnnotations;
  assert.equal(
    await f.egress.withdrawBinding(f.context, f.context.plan.routes[0].binding.binding),
    true,
  );
  assert.equal(f.observed.deleted.length, 1);
});

test("legacy approved copies survive Secret rotation and failed live adoption; only exact source update opts in", async (t) => {
  const f = await staticEgressFixture(t, { includeLegacy: true });
  const path = `${f.path}/${f.legacySource.id}`;
  const before = structuredClone([...f.providers.values()]);
  assert.equal(before.length, 1);
  assert.equal(before[0].credentials.OPENAI_API_KEY, "synthetic-key-initial");
  assert.equal(f.legacySource.egress, undefined);
  assert.equal(
    (
      await f.request("PATCH", `/namespaces/${f.namespace.id}/secrets/${f.secret.id}`, {
        body: { value: "synthetic-key-replacement" },
      })
    ).status,
    200,
  );
  assert.equal((await f.request("GET", path)).data.egress, undefined);
  assert.deepEqual(
    [...f.providers.values()],
    before,
    "editing the input Secret must not reinterpret a legacy approved copy as live",
  );
  f.observed.available = false;
  const consent = { adoption: "live", authorityScope: "execution" };
  assert.equal(
    (await f.request("PATCH", path, { body: { adoption: "live" } })).status,
    409,
    "live reads alone are not consent to whole-execution authority",
  );
  assert.equal((await f.request("PATCH", path, { body: consent })).status, 503);
  assert.equal((await f.request("GET", path)).data.egress, undefined);
  assert.deepEqual([...f.providers.values()], before);
  f.observed.available = true;
  const adopted = await f.request("PATCH", path, { body: consent });
  assert.equal(adopted.status, 200, JSON.stringify(adopted.body));
  assert.deepEqual(adopted.data.egress, { adoption: "live", retention: "none" });
  assert.deepEqual(
    [...f.providers.values()],
    before,
    "adoption never overwrites the previous gateway material",
  );
  // Restore a fixture in the *persisted* prior narrow provider generation. An
  // old PATCH must not be able to turn that approval into whole-execution use.
  const { id, namespaceId } = f.legacySource;
  await f.controller.transact(async ({ credentialSources: sources }) => {
    const { egress } = await sources.findCredentialSource(namespaceId, id);
    assert.equal(egress.key.provider.generation, 2);
    const key = {
      ...egress.key,
      source: { id, generation: egress.key.source.generation + 1 },
      provider: { ...egress.key.provider, generation: 1 },
    };
    await sources.admitEgressSource(namespaceId, id, egress.key.source.generation, {
      ...egress,
      key,
    });
  });
  assert.equal((await f.request("PATCH", path, { body: { adoption: "live" } })).status, 409);
  assert.equal((await f.request("PATCH", path, { body: consent })).status, 200);
  const bound = await f.request("PATCH", `${f.path}/${f.source.id}`, {
    body: { adoption: "live" },
  });
  assert.equal(bound.status, 409, "running source cutover is explicitly unsupported");
});

test("current supplier evidence is required at access and send; stored receipts cannot authorize a replacement", async (t) => {
  const f = await staticEgressFixture(t);
  const original = structuredClone(f.observed.evidence);
  const observation = f.observed.observation;
  const beforeLegacy = f.secretReads;
  delete f.observed.observation;
  // LOADED and valid legacy field 3 remain present; neither substitutes for V1.
  assert.equal(await f.egress.wiringStatus(f.context, f.attachment), undefined);
  assert.ok((await f.resolve(f.capture())).refused);
  assert.equal(f.secretReads, beforeLegacy);
  f.observed.observation = observation;
  // Proto3 scalar zeros can be omitted on the wire; both encodings have one fingerprint.
  f.observed.evidence = { ...original, config_revision: "0", provider_env_revision: "0" };
  const zero = await f.egress.wiringStatus(f.context, f.attachment);
  assert.ok(zero);
  delete f.observed.evidence.config_revision;
  delete f.observed.evidence.provider_env_revision;
  assert.deepEqual(
    (await f.egress.wiringStatus(f.context, f.attachment)).enforcement,
    zero.enforcement,
  );
  const reads = f.secretReads;
  // Missing/old/failed receipts and mismatched generations must fail before material access.
  for (const evidence of [
    undefined,
    { ...original, enforced_capabilities: [] },
    { ...original, sandbox_id: "another-sandbox" },
    { ...original, policy_hash: "2b".repeat(32) },
    { ...original, policy_version: 2 },
    { ...original, config_revision: "17395563786422800000" },
    { ...original, provider_env_revision: "9019556378642280000" },
    { ...original, instance_id: "10000000-0000-4000-8000-000000000001" },
  ]) {
    f.observed.evidence = evidence;
    assert.ok((await f.resolve(f.capture())).refused);
    assert.equal(f.secretReads, reads, "historical installation must not permit credential access");
  }
  f.observed.evidence = original;
  const captured = f.capture();
  const ready = (await f.resolve(captured)).ready;
  assert.ok(ready, "restoring the original current observation permits a new operation");
  // Replacement happens after material access, while the operation still holds the old receipt.
  f.observed.evidence = { ...original, instance_id: "10000000-0000-4000-8000-000000000001" };
  assert.ok((await f.authorize(f.permitRequest(captured, ready))).refused);
  assert.equal(f.providerRequests.length, 0);
  const replacement = await f.egress.wiringStatus(f.context, f.attachment);
  assert.ok(replacement);
  await assert.rejects(
    f.controller.transact((unit) => unit.credentialSources.recordEgressInstallation(replacement)),
    /already bound/,
  );
});

test("V1 permits only the exact inert runtime rule and fences both policies before Secret access and send", async (t) => {
  const f = await staticEgressFixture(t, { inertProviderRule: true });
  const observation = structuredClone(f.observed.observation);
  const originalEvidence = structuredClone(f.observed.evidence);
  const source = structuredClone(f.observed.policy);
  const ruleName = observation.inert_provider_rule;
  assert.notEqual(observation.source_policy_hash, originalEvidence.policy_hash);
  assert.equal(observation.source_policy_hash, f.observed.policyHash);
  assert.deepEqual(observation.effective_policy.network_policies[ruleName], { name: ruleName });
  assert.equal(await f.egress.verifyInstallation(f.context, f.installation), true);
  const capture = f.capture();
  const ready = (await f.resolve(capture)).ready;
  assert.ok(ready, "the real consumer accepts the passive source != effective wire fixture");
  assert.ok((await f.authorize(f.permitRequest(capture, ready))).allowed);
  const reads = f.secretReads;
  // Each independently malformed derivation must refuse installation and current
  // authority before the versioned Secret Driver is called.
  for (const change of [
    (value) => {
      value.source_policy_hash = "4d".repeat(32);
    },
    (value) => {
      delete value.effective_policy;
    },
    (value) => {
      value.inert_provider_rule = "";
    },
    (value) => {
      value.inert_provider_rule = `${ruleName}_other`;
    },
    (value) => {
      value.effective_policy.network_policies[ruleName].name = "other";
    },
    (value) => {
      value.effective_policy.network_policies[ruleName].endpoints = [
        { host: "unexpected.example.test", ports: [443] },
      ];
    },
    (value) => {
      value.effective_policy.network_policies[ruleName].binaries = [{ path: "/usr/bin/extra" }];
    },
    (value) => {
      value.effective_policy.network_policies[ruleName] = {
        name: ruleName,
        endpoints: [{ host: "unexpected.example.test", ports: [443] }],
        binaries: [{ path: "/usr/bin/model-client" }],
      };
    },
    (value) => {
      value.effective_policy.network_policies["oce-egress-0"].endpoints.push({
        host: "unexpected.example.test",
        ports: [443],
      });
    },
    (value) => {
      value.effective_policy.network_policies.extra = {};
    },
    (value) => {
      value.effective_policy.process.run_as_user = "0";
    },
    (value) => {
      value.effective_policy.filesystem.read_write = ["/"];
    },
    (value) => {
      value.effective_policy.landlock.compatibility = "best_effort";
    },
    (value) => {
      value.effective_policy.version = 2;
    },
    (value) => {
      value.effective_policy.network_policies["oce-egress-0"].endpoints[0].rules = [
        Buffer.from([0]),
      ];
    },
    (value) => {
      value.effective_policy.network_middlewares["oce-egress"].config = {
        fields: { enabled: { bool_value: false } },
      };
    },
  ]) {
    f.observed.observation = structuredClone(observation);
    change(f.observed.observation);
    assert.equal(await f.egress.wiringStatus(f.context, f.attachment), undefined);
    assert.ok((await f.resolve(f.capture())).refused);
    assert.equal(f.secretReads, reads, "a widened or stale observation cannot read a Secret");
  }
  f.observed.observation = structuredClone(observation);
  // Individually valid replacement identities/policies still cannot replace the
  // saved installation fence, even when source and effective change together.
  for (const change of [
    () => {
      f.observed.evidence.policy_hash = "5e".repeat(32);
    },
    () => {
      f.observed.policyHash = "6f".repeat(32);
      f.observed.observation.source_policy_hash = f.observed.policyHash;
    },
    () => {
      f.observed.policy.process.run_as_user = "2000";
      f.observed.observation.effective_policy.process.run_as_user = "2000";
    },
  ]) {
    change();
    assert.ok((await f.resolve(f.capture())).refused);
    assert.equal(f.secretReads, reads);
    f.observed.evidence = structuredClone(originalEvidence);
    f.observed.policyHash = observation.source_policy_hash;
    f.observed.policy = structuredClone(source);
    f.observed.observation = structuredClone(observation);
  }
  assert.equal(await f.egress.verifyInstallation(f.context, f.installation), true);
  const sendCapture = f.capture();
  const sendReady = (await f.resolve(sendCapture)).ready;
  assert.ok(sendReady, "Resolve succeeds while the runtime rule is still inert");
  // Widen after material resolution: the fresh send check must reject a usable
  // endpoint even though this operation already holds valid access evidence.
  const widenedRule = f.observed.observation.effective_policy.network_policies[ruleName];
  const protectedRule = source.network_policies["oce-egress-0"];
  widenedRule.endpoints = structuredClone(protectedRule.endpoints);
  widenedRule.binaries = structuredClone(protectedRule.binaries);
  assert.ok((await f.authorize(f.permitRequest(sendCapture, sendReady))).refused);
  assert.equal(f.providerRequests.length, 0, "send-side widening must not permit a provider send");
});

test("Responses output text assembled across parts and messages cannot reveal selected material", async (t) => {
  const f = await staticEgressFixture(t);
  const wire = JSON.parse(
    readFileSync(new URL("../fixtures/static-egress/codex-responses.json", import.meta.url)),
  );
  const template = wire.responseEvents.at(-1).response;
  const message = (id, parts) => ({
    type: "message",
    id,
    status: "completed",
    role: "assistant",
    content: parts.map((text) => ({ type: "output_text", text, annotations: [] })),
  });
  const output = (parts, acrossMessages) =>
    acrossMessages
      ? parts.map((text, index) => message(`msg_${index}`, [text]))
      : [message("msg_0", parts)];
  const encode = (events) =>
    events.map((event) => `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`).join("");
  async function exchange(result, streaming) {
    const request = streaming
      ? wire.request
      : { model: "fixture-model", input: "hello", store: false };
    const captured = f.capture(request);
    const ready = (await f.resolve(captured)).ready;
    assert.ok(ready);
    assert.ok((await f.authorize(f.permitRequest(captured, ready))).allowed);
    if (streaming) {
      const events = structuredClone(wire.responseEvents);
      // The deltas and completed item remain harmless. Only the response
      // envelope contains the candidate, so delta protection cannot mask this test.
      events.at(-1).response.output = result.output;
      f.setResponse({ status: 200, contentType: "text/event-stream", rawBody: encode(events) });
    } else {
      f.setResponse({ status: 200, body: result });
    }
    return f.protect(captured, await f.send(captured, ready));
  }
  for (const streaming of [false, true]) {
    for (const acrossMessages of [false, true]) {
      for (const candidate of [
        "synthetic-key-initial",
        Buffer.from("synthetic-key-initial").toString("base64"),
      ]) {
        const midpoint = Math.floor(candidate.length / 2);
        const parts = [candidate.slice(0, midpoint), candidate.slice(midpoint)];
        assert.ok(
          (await exchange({ ...template, output: output(parts, acrossMessages) }, streaming))
            .blocked,
          `split selected material must not be released (streaming=${streaming}, acrossMessages=${acrossMessages})`,
        );
      }
      const safe = { ...template, output: output(["ordinary ", "response"], acrossMessages) };
      assert.ok(
        (await exchange(safe, streaming)).body,
        `benign multipart output remains available (streaming=${streaming}, acrossMessages=${acrossMessages})`,
      );
    }
  }
});

test("Responses incremental text snapshots cannot reveal selected material", async (t) => {
  const f = await staticEgressFixture(t);
  const wire = JSON.parse(
    readFileSync(new URL("../fixtures/static-egress/codex-responses.json", import.meta.url)),
  );
  const encode = (events) =>
    events.map((event) => `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`).join("");
  const events = (candidate, kind) => {
    const [created, item, part, delta, ...rest] = structuredClone(wire.responseEvents);
    const middle = Math.floor(candidate.length / 2);
    const prefix = candidate.slice(0, middle);
    const suffix = candidate.slice(middle);
    if (kind === "item") {
      item.item.content = [{ ...part.part, text: prefix }];
      return [created, item, { ...delta, delta: suffix }, ...rest];
    }
    if (kind === "parts") {
      return [
        created,
        item,
        part,
        { ...delta, delta: prefix },
        { ...part, content_index: 1 },
        { ...delta, content_index: 1, delta: "distraction" },
        { ...delta, delta: suffix },
        ...rest,
      ];
    }
    if (kind === "duplicate") {
      part.part.text = prefix;
      return [
        created,
        item,
        part,
        { ...part, part: { ...part.part, text: "distraction" } },
        { ...delta, delta: suffix },
        ...rest,
      ];
    }
    if (kind === "initial") {
      created.response.output = [{ ...item.item, content: [{ ...part.part, text: prefix }] }];
      return [created, item, part, { ...delta, delta: suffix }, ...rest];
    }
    part.part.text = prefix;
    return [created, item, part, { ...delta, delta: suffix }, ...rest];
  };
  async function exchange(responseEvents) {
    const captured = f.capture(wire.request);
    const ready = (await f.resolve(captured)).ready;
    assert.ok(ready);
    assert.ok((await f.authorize(f.permitRequest(captured, ready))).allowed);
    f.setResponse({
      status: 200,
      contentType: "text/event-stream",
      rawBody: encode(responseEvents),
    });
    return f.protect(captured, await f.send(captured, ready));
  }
  // The harmless final response cannot erase a credential exposed in an earlier
  // SDK snapshot assembled from an added part and later indexed deltas.
  for (const candidate of [
    "synthetic-key-initial",
    Buffer.from("synthetic-key-initial").toString("base64"),
  ]) {
    for (const kind of ["part", "item", "parts", "duplicate", "initial"]) {
      assert.ok(
        (await exchange(events(candidate, kind))).blocked,
        `${kind} snapshot must be withheld`,
      );
    }
  }
  for (const kind of ["part", "item", "parts"]) {
    const safe = events("ordinary response", kind);
    assert.equal(
      (await exchange(safe)).body.toString(),
      encode(safe),
      `benign ${kind} remains available`,
    );
  }
  const laterProgress = events("ordinary response", "part");
  const progress = structuredClone(laterProgress[0]);
  progress.type = "response.in_progress";
  progress.response.output = [structuredClone(laterProgress.at(-2).item)];
  laterProgress.splice(2, 0, progress);
  assert.equal((await exchange(laterProgress)).body.toString(), encode(laterProgress));
});

test("selected Codex Responses wire admits local tools and finite SSE while rejecting remote tools and unprotected events", async (t) => {
  const f = await staticEgressFixture(t);
  // Sanitized packaged 0.163.0-alpha.2 request and synthetic response consumed by that
  // binary. This exercises OCE's real transport, not a model provider or installed Harness.
  const wire = JSON.parse(
    readFileSync(new URL("../fixtures/static-egress/codex-responses.json", import.meta.url)),
  );
  const encode = (events) =>
    events.map((event) => `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`).join("");
  async function exchange(rawBody) {
    const captured = f.capture(wire.request);
    const ready = (await f.resolve(captured)).ready;
    assert.ok(ready);
    assert.ok((await f.authorize(f.permitRequest(captured, ready))).allowed);
    f.setResponse({ status: 200, contentType: "text/event-stream", rawBody });
    return f.protect(captured, await f.send(captured, ready));
  }
  const body = encode(wire.responseEvents);
  const delivered = await exchange(body);
  assert.equal(delivered.body.toString(), body);
  assert.deepEqual(f.providerRequests[0].body, wire.request);
  const crlf = body.replaceAll("\n", "\r\n");
  assert.equal((await exchange(crlf)).body.toString(), crlf);
  const beforeReads = f.secretReads;
  for (const body of [
    { ...wire.request, tools: [...wire.request.tools, ...wire.refusedTools] },
    { ...wire.request, tools: [{ type: "mcp", server_url: "https://remote.example.test" }] },
    { ...wire.request, tools: [{ type: "namespace", name: "remote", tools: wire.refusedTools }] },
    { ...wire.request, previous_response_id: "unadmitted-state" },
    {
      ...wire.request,
      input: [
        {
          type: "message",
          role: "user",
          content: [{ type: "input_image", image_url: "https://remote.example.test/image" }],
        },
      ],
    },
    { ...wire.request, client_metadata: { namespace_id: f.namespace.id } },
  ]) {
    assert.ok((await f.resolve(f.capture(body))).refused);
  }
  assert.equal(
    f.secretReads,
    beforeReads,
    "unsupported provider operations cannot read credentials",
  );

  const split = structuredClone(wire.responseEvents);
  const deltaIndex = split.findIndex((event) => event.type === "response.output_text.delta");
  const delta = split[deltaIndex];
  split.splice(
    deltaIndex,
    1,
    { ...delta, delta: "synthetic-key-" },
    { ...delta, delta: "initial" },
  );
  const switched = structuredClone(wire.responseEvents);
  const firstMessage = switched
    .slice(1, -1)
    .map((event) => JSON.parse(JSON.stringify(event).replaceAll("READY", "synthetic-key-")));
  const secondMessage = switched.slice(1, -1).map((event) => ({
    ...JSON.parse(
      JSON.stringify(event)
        .replaceAll("READY", "initial")
        .replaceAll("msg_runtime_probe", "msg_second"),
    ),
    output_index: 1,
  }));
  switched.splice(1, switched.length - 2, ...firstMessage, ...secondMessage);
  // Keep the terminal snapshot harmless so only cross-item deltas trigger refusal.
  assert.ok(
    (await exchange(encode(switched))).blocked,
    "OutputTextDelta drops item IDs, so the consumer-observable concatenation must be scanned",
  );
  // Function arguments have a protocol-defined JSON layer, including when
  // unicode escapes straddle deltas. A harmless terminal snapshot cannot erase
  // arguments that a local tool consumer already accumulated.
  const functionEvents = (argumentsText) => {
    const item = {
      type: "function_call",
      id: "fc_local",
      call_id: "call_local",
      name: "fixture_function_0",
      arguments: argumentsText,
      status: "completed",
    };
    const end = structuredClone(wire.responseEvents.at(-1));
    end.response.output = [item];
    const middle = Math.floor(argumentsText.length / 2);
    return [
      structuredClone(wire.responseEvents[0]),
      {
        type: "response.output_item.added",
        output_index: 0,
        item: { ...item, arguments: "", status: "in_progress" },
      },
      ...[argumentsText.slice(0, middle), argumentsText.slice(middle)].map((delta) => ({
        type: "response.function_call_arguments.delta",
        output_index: 0,
        item_id: item.id,
        delta,
      })),
      {
        type: "response.function_call_arguments.done",
        output_index: 0,
        item_id: item.id,
        arguments: argumentsText,
      },
      { type: "response.output_item.done", output_index: 0, item },
      end,
    ];
  };
  const safeFunction = functionEvents('{"cmd":"printf READY"}');
  assert.ok(
    (await exchange(encode(safeFunction))).body,
    "ordinary Harness-local function tools remain supported",
  );
  // Providers can omit argument deltas. The two completion events must still agree
  // on which arguments the Harness would execute.
  const withoutDeltas = structuredClone(safeFunction);
  withoutDeltas.splice(2, 2);
  assert.ok((await exchange(encode(withoutDeltas))).body);
  withoutDeltas[2].arguments = '{"cmd":"different arguments"}';
  assert.ok(
    (await exchange(encode(withoutDeltas))).blocked,
    "function_call_arguments.done and output_item.done cannot disagree about the arguments",
  );
  const escapedCredential = [..."synthetic-key-initial"]
    .map((character) => "\\u" + character.charCodeAt(0).toString(16).padStart(4, "0"))
    .join("");
  const escapedFunction = functionEvents('{"cmd":"' + escapedCredential + '"}');
  const disguisedFunction = structuredClone(escapedFunction);
  disguisedFunction.splice(4, 1);
  disguisedFunction.at(-2).item.arguments = '{"cmd":"printf READY"}';
  disguisedFunction.at(-1).response.output = [];
  const wrongAssociation = structuredClone(safeFunction);
  wrongAssociation[3].item_id = "fc_unassociated";
  const afterDone = structuredClone(safeFunction);
  afterDone.splice(-1, 0, safeFunction[2]);
  for (const events of [
    escapedFunction,
    disguisedFunction,
    wrongAssociation,
    afterDone,
    functionEvents('{"cmd":"unterminated'),
    functionEvents('{"cmd":"ok","cmd":"other"}'),
  ]) {
    assert.ok(
      (await exchange(encode(events))).blocked,
      "argument decoding, item association and completion all precede release",
    );
  }
  const remote = structuredClone(wire.responseEvents);
  remote[1].item = { type: "web_search_call", id: "remote-effect", status: "completed" };
  const wrongModel = structuredClone(wire.responseEvents);
  wrongModel.at(-1).response.model = "unadmitted-model";
  for (const unsafe of [
    encode(wire.responseEvents.slice(0, -1)),
    encode(split),
    encode(remote),
    encode(wrongModel),
    body + 'event: response.future_event\ndata: {"type":"response.future_event"}\n\n',
    body.replace('"delta":"READY"', '"delta":"synthetic-key-initial","delta":"READY"'),
    body.replace("event: response.created", "event: response.completed"),
    ":ignored\rcomment\n" + body,
    body.replace("\n\n", "\n\n\n"),
    body.replace(/\n\n$/, "\n"),
  ]) {
    assert.ok(
      (await exchange(unsafe)).blocked,
      "the whole finite stream must pass response policy before any delivery",
    );
  }
});

test("signed supervisor instance and UUIDv7 creation horizon refuse old callers and deadline-extension replay", async (t) => {
  let elapsed = 0;
  const now = () => new Date(Date.now() + elapsed);
  const f = await staticEgressFixture(t, { now });
  const reads = f.secretReads;
  const operation = JSON.parse(
    readFileSync(new URL("../fixtures/static-egress/openshell-operation.json", import.meta.url)),
  );
  const serializedCreation = Number.parseInt(
    operation.request_context.request_id.replaceAll("-", "").slice(0, 12),
    16,
  );
  const serializedDeadline =
    Number(operation.deadline.seconds) * 1000 + operation.deadline.nanos / 1e6;
  assert.equal(serializedCreation, operation.creation_ms);
  assert.equal(serializedDeadline, serializedCreation + 30_000);
  assert.equal(operation.capture_delay_ms, 100);
  // The independently captured delayed sender wire is historical, never a reusable
  // authorization. Rebind only the fixture Sandbox to reach the real horizon check.
  const historical = f.capture();
  historical.request.context.request_id = operation.request_context.request_id;
  historical.deadline = operation.deadline;
  assert.ok((await f.resolve(historical)).refused);
  assert.equal(f.secretReads, reads);
  for (const claims of [
    { instance_id: undefined },
    { instance_id: "10000000-0000-4000-8000-000000000001" },
    { instance_id: f.namespace.id },
  ]) {
    if (claims.instance_id?.startsWith("10000000-")) {
      assert.ok((await f.resolve(f.capture(), f.metadata(claims))).refused);
    } else {
      await assert.rejects(f.resolve(f.capture(), f.metadata(claims)), { code: 7 });
    }
  }
  assert.equal(f.secretReads, reads);
  const captured = f.capture();
  captured.deadline = wireTime(now().getTime() + 1000);
  const ready = (await f.resolve(captured)).ready;
  assert.ok(ready);
  // A short submitted deadline does not shorten replay retention for this immutable operation ID.
  elapsed = 2000;
  captured.deadline = wireTime(now().getTime() + 20_000);
  assert.ok((await f.resolve({ ...captured, response_custody: randomBytes(32) })).refused);
  elapsed = 31_000;
  captured.deadline = wireTime(now().getTime() + 1000);
  assert.ok((await f.resolve({ ...captured, response_custody: randomBytes(32) })).refused);
  assert.equal(
    f.secretReads,
    reads + 1,
    "eviction cannot make an expired UUID into a new operation",
  );
  assert.ok((await f.resolve(f.capture())).ready);
});

test(
  "sustained sequential operations outlive replay capacity without waiting for JWT expiry",
  { timeout: 180_000 },
  async (t) => {
    let elapsed = 0;
    const f = await staticEgressFixture(t, { now: () => new Date(Date.now() + elapsed) });
    const peer = f.metadata({ exp: Math.floor(Date.now() / 1000) + 3600 });
    // Advance the controller's supported clock while keeping genuine signed identity, IAM,
    // Secret SDK, authority transport and HTTPS provider. Completion must release active capacity;
    // fixed operation horizons must release replay capacity during the same long-lived JWT.
    for (let i = 0; i < 4200; i += 1) {
      elapsed += 25;
      const captured = f.capture();
      const ready = (await f.resolve(captured, peer)).ready;
      assert.ok(ready, `sequential operation ${i} should resolve`);
      assert.ok((await f.authorize(f.permitRequest(captured, ready))).allowed);
      assert.ok((await f.protect(captured, await f.send(captured, ready))).body);
    }
    assert.equal(f.providerRequests.length, 4200);
    assert.ok(
      f.providerRequests.every(
        (request) => request.authorization === "Bearer synthetic-key-initial",
      ),
    );
  },
);

test("send receipt records the digest of the accepted request", async (t) => {
  const receipts = new EgressSendReceipts(new InMemoryPlatformState());
  const f = await syntheticDispatchFixture(t, receipts);
  // In this request, body precedes deadlineAt. Moving it to the end while copying the
  // request must not silently change the digest we commit to the authorization receipt.
  const accepted = { ...f.request, body: f.request.body.toString("base64") };
  const expectedDigest = createHash("sha256").update(JSON.stringify(accepted)).digest("hex");

  assert.equal((await f.resolve()).kind, "ready");
  assert.equal((await f.authorizeSend()).kind, "allow");
  const stored = await receipts.recover(f.sender, f.attempt());
  assert.equal(stored.authorization.requestDigest, expectedDigest);
  assert.equal(f.arrivals, 0, "committing the authorization is not evidence of a send");
});

for (const bodyType of ["Uint8Array", "Buffer"]) {
  test(`credential proxy detaches ${bodyType} and request fields before identity verification`, async (t) => {
    const f = await syntheticDispatchFixture(t);
    const verification = Promise.withResolvers();
    const entered = Promise.withResolvers();
    const callerRequest = {
      ...f.request,
      headers: f.request.headers.map((pair) => [...pair]),
      body: bodyType === "Buffer" ? Buffer.from(f.request.body) : new Uint8Array(f.request.body),
    };
    const proxy = new CredentialProxy({
      ...f.ports,
      exchangeOwner: {
        ...f.ports.exchangeOwner,
        async verify(authorization) {
          entered.resolve();
          await verification.promise;
          return f.ports.exchangeOwner.verify(authorization);
        },
      },
    });
    const cancellation = new AbortController();
    t.after(() => cancellation.abort());
    const resolving = proxy.resolve(
      "synthetic-peer",
      f.association.installation.sandboxId,
      callerRequest,
      cancellation.signal,
    );
    await entered.promise;
    // The caller reuses its buffers while authentication is pending. Classification and
    // custody must still use the originally accepted request, including Buffer bytes.
    callerRequest.body.fill(0);
    callerRequest.headers[0][1] = "application/octet-stream";
    callerRequest.headers.push(["authorization", "caller-controlled"]);
    callerRequest.url = "https://changed.example.test/";
    callerRequest.deadlineAt = "invalid";
    verification.resolve();
    assert.equal((await resolving).kind, "ready");
    assert.equal(f.reads, 1);
  });
}

test("credential proxy rejects an oversized body before copying request fields", async (t) => {
  const f = await syntheticDispatchFixture(t);
  const proxy = new CredentialProxy(f.ports);
  const request = {
    ...f.request,
    body: new Uint8Array(1024 * 1024 + 1),
    get headers() {
      throw new Error("an oversized request must not be copied");
    },
  };
  assert.deepEqual(
    await proxy.resolve(
      "synthetic-peer",
      f.association.installation.sandboxId,
      request,
      new AbortController().signal,
    ),
    { kind: "refused", error: { kind: "denied", code: "unsupported_operation" } },
  );
  assert.equal(f.reads, 0);
});

test("in-flight Secret selection and outstanding handles consume the same bounded capacity", async (t) => {
  // Exercise the actual 1024-slot registry, not a race to finish 1024 TLS handshakes,
  // native IAM checks and Kubernetes reads inside their intentionally short deadlines.
  const f = await syntheticDispatchFixture(t);
  const ids = new Set();
  let reads = 0;
  const full = Promise.withResolvers();
  const gate = Promise.withResolvers();
  const forwarder = new CredentialProxy({
    ...f.ports,
    exchangeOwner: {
      verify: f.ports.exchangeOwner.verify,
      capture: (use) => {
        ids.add(use.id);
        return { ...f.association, responseId: use.id };
      },
      owns: (value, use) => ids.has(use.id) && value.responseId === use.id,
    },
    read: async (...args) => {
      if (++reads === 1024) {
        full.resolve();
      }
      await gate.promise;
      return f.ports.read(...args);
    },
  });
  const use = (signal) =>
    forwarder.resolve(
      "synthetic-peer",
      f.association.installation.sandboxId,
      { ...f.request, id: requestId(f.ports.now()) },
      signal,
    );
  const first = new AbortController();
  const other = new AbortController().signal;
  const pending = Array.from({ length: 1024 }, (_, i) => use(i === 0 ? first.signal : other));
  await full.promise;
  const saturated = { kind: "refused", error: { kind: "unavailable", code: "resolver" } };
  assert.deepEqual(
    await use(other),
    saturated,
    "pending selection is charged before material returns",
  );
  assert.deepEqual(
    await forwarder.resolve(
      "synthetic-peer",
      f.association.installation.sandboxId,
      {
        ...f.request,
        get headers() {
          throw new Error("an exhausted registry must reject before copying request fields");
        },
      },
      other,
    ),
    saturated,
  );
  assert.equal(reads, 1024, "the excess resolution never starts selection");
  gate.resolve();
  assert.ok((await Promise.all(pending)).every((decision) => decision.kind === "ready"));
  assert.deepEqual(await use(other), saturated, "ready handles remain charged");
  first.abort();
  assert.equal(
    (await use(other)).kind,
    "ready",
    "closing the owning sender frees exactly its slot",
  );
  assert.deepEqual(await use(other), saturated);
});

test("cancelled and denied exchanges retain capacity until receipt work settles", async (t) => {
  for (const phase of ["begin", "authorize", "deny", "observe", "expiry"]) {
    await t.test(phase, async (t) => {
      const f = await syntheticDispatchFixture(t);
      const waiting = Promise.withResolvers();
      const entered = Promise.withResolvers();
      const fillerGate = Promise.withResolvers();
      const cancellation = new AbortController();
      const fillerCancellation = new AbortController();
      let now = f.ports.now();
      let filling = 0;
      const pause = async (name) => {
        if (phase === name || (phase === "expiry" && name === "authorize")) {
          entered.resolve();
          await waiting.promise;
        }
      };
      const proxy = new CredentialProxy({
        ...f.ports,
        now: () => now,
        exchangeOwner: {
          ...f.ports.exchangeOwner,
          async verify(authorization) {
            if (authorization === "filler") {
              filling += 1;
              return fillerGate.promise;
            }
            if (authorization === "probe") {
              return undefined;
            }
            return f.ports.exchangeOwner.verify(authorization);
          },
        },
        check: async (use, evidence) =>
          phase === "deny" && evidence
            ? { kind: "denied", code: "withdrawn" }
            : f.ports.check(use, evidence),
        receipts: {
          async begin() {
            await pause("begin");
            return { created: true };
          },
          async authorize(_sender, _attempt, authorization) {
            await pause("authorize");
            return { authorization };
          },
          async record() {
            await pause("deny");
          },
          async observe() {
            await pause("observe");
          },
        },
      });
      const sandboxId = f.association.installation.sandboxId;
      const resolve = (authorization, signal) =>
        proxy.resolve(authorization, sandboxId, f.request, signal);
      const fillers = Array.from({ length: 1023 }, () =>
        resolve("filler", fillerCancellation.signal),
      );
      assert.equal(filling, 1023);
      const saturated = { kind: "refused", error: { kind: "unavailable", code: "resolver" } };
      const target = (async () => {
        const ready = await resolve("synthetic-peer", cancellation.signal);
        assert.equal(ready.kind, "ready");
        assert.deepEqual(await resolve("probe", fillerCancellation.signal), saturated);
        const decision = await proxy.authorizeSend(
          "synthetic-peer",
          sandboxId,
          f.request.id,
          ready.handle,
          ready.evidence,
          ready.injectionDigest,
          f.request.deadlineAt,
          cancellation.signal,
        );
        if (phase !== "observe") {
          assert.equal(decision.kind, "refused");
          return;
        }
        assert.equal(decision.kind, "allow");
        const handle = await proxy.beginResponse("synthetic-peer", sandboxId, f.request.id);
        assert.ok(handle);
        assert.equal(
          await proxy.protectResponse(
            handle,
            { status: 200, headers: [], body: new Uint8Array(), trailers: [] },
            cancellation.signal,
            false,
          ),
          undefined,
        );
      })();
      try {
        await Promise.race([
          entered.promise,
          target.then(() => {
            throw new Error("receipt work did not reach the expected phase");
          }),
        ]);
        if (phase === "expiry") {
          now = Date.parse(f.request.deadlineAt);
        } else if (phase !== "deny") {
          cancellation.abort();
        }
        assert.deepEqual(
          await resolve("probe", fillerCancellation.signal),
          saturated,
          "revoking the handle must not release pending receipt work",
        );
        waiting.resolve();
        await target;
        assert.deepEqual(
          await resolve("probe", fillerCancellation.signal),
          { kind: "refused", error: { kind: "denied", code: "identity" } },
          "capacity returns when the final outstanding work settles",
        );
        assert.equal(f.arrivals, 0);
      } finally {
        cancellation.abort();
        fillerCancellation.abort();
        waiting.resolve();
        fillerGate.resolve(undefined);
        await Promise.allSettled([target, ...fillers]);
      }
    });
  }
});

function receiptAttempt(f, captured, ready) {
  return {
    sender: f.egress.sourceControl.sender,
    instanceId: f.installation.enforcement.instanceId,
    useId: captured.request.context.request_id,
    attemptId: captured.request.context.request_id,
    material: JSON.parse(ready.evidence.authority_evidence.toString()),
    deadlineAt: new Date(
      Number(captured.deadline.seconds) * 1000 + captured.deadline.nanos / 1e6,
    ).toISOString(),
  };
}

const readReceipt = (f, input) =>
  f.controller.transact((unit) => unit.egressSendReceipts.find(input));

// Faults wrap the real state transaction owner: operations and rollback still run in the
// actual memory adapter. Lost acknowledgments here are scheduling proof, not real PG proof.
function receiptPersistenceFaults() {
  let armed;
  return {
    arm(method, kind = "pause") {
      const reached = Promise.withResolvers();
      const release = Promise.withResolvers();
      armed = { method, kind, reached, release };
      return { reached: reached.promise, release: () => release.resolve() };
    },
    wrap(state) {
      return {
        read: (work) => state.read(work),
        async transact(work) {
          let effect;
          const intercept = (repository) =>
            Object.fromEntries(
              Object.entries(repository).map(([name, method]) => [
                name,
                async (...args) => {
                  if (armed?.method === name) {
                    effect = armed;
                    armed = undefined;
                    if (effect.kind === "reject") {
                      throw new Error("receipt persistence unavailable");
                    }
                  }
                  return method(...args);
                },
              ]),
            );
          const result = await state.transact((unit) =>
            work({
              ...unit,
              egressSendReceipts: intercept(unit.egressSendReceipts),
              credentialSources: intercept(unit.credentialSources),
            }),
          );
          if (effect) {
            effect.reached.resolve();
            await effect.release.promise;
            if (effect.kind === "lost_ack") {
              throw new Error("receipt commit acknowledgment unavailable");
            }
          }
          return result;
        },
      };
    },
  };
}

test("closing the accepted duplex while its policy check is queued prevents the Secret read", async (t) => {
  const fault = receiptPersistenceFaults();
  const finished = Promise.withResolvers();
  const f = await staticEgressFixture(t, {
    resolutionFinished: finished.resolve,
    appFactory: (t, options) =>
      createConsoleAppFixture(t, { ...options, wrapState: (state) => fault.wrap(state) }),
  });
  const gate = fault.arm("findCredentialWithdrawal", "pause");
  t.after(gate.release);
  const before = f.secretReads;
  const captured = f.capture();
  const exchange = await f.beginExchange();
  exchange.stream.write(exchange.opening(captured));
  await gate.reached;
  // Graceful half-close, with server OK status, proves the real handler saw loss of
  // this sender before the queued authority returns. No timing sleep or reset inference.
  const ended = Promise.withResolvers();
  exchange.stream.once("status", ended.resolve);
  exchange.stream.end();
  assert.equal((await ended.promise).code, 0);
  gate.release();
  assert.deepEqual(await finished.promise, { kind: "refused", error: { kind: "cancelled" } });
  assert.equal(f.secretReads, before);
  assert.equal(f.providerRequests.length, 0);
  assert.deepEqual(
    exchange.received.map((message) => message.event),
    ["challenge"],
  );
});

test("closing the accepted duplex during Kubernetes namespace verification prevents the Secret GET", async (t) => {
  const finished = Promise.withResolvers();
  const f = await staticEgressFixture(t, { resolutionFinished: finished.resolve });
  const captured = f.capture();
  const exchange = await f.beginExchange();
  const before = f.secretReads;
  const placement = f.pauseNamespaceVerification();
  t.after(placement.release);
  exchange.stream.write(exchange.opening(captured));
  await placement.reached;

  // Wait for the real authority to acknowledge the half-close, then let namespace lookup
  // finish. Checking the eventual wire response alone would miss an unnecessary Secret GET.
  const ended = Promise.withResolvers();
  exchange.stream.once("status", ended.resolve);
  exchange.stream.end();
  assert.equal((await ended.promise).code, 0);
  placement.release();
  const result = await finished.promise;
  assert.equal(f.secretReads, before, "a lost response owner cannot start a new Secret GET");
  assert.deepEqual(result, { kind: "refused", error: { kind: "cancelled" } });
  assert.equal(f.providerRequests.length, 0);
  assert.deepEqual(
    exchange.received.map((message) => message.event),
    ["challenge"],
  );

  assert.ok(
    (await f.resolve(f.capture())).ready,
    "an independently accepted exchange can still resolve",
  );
});

test("an elapsed deadline prevents the Kubernetes Secret GET even before the timeout callback runs", async (t) => {
  const f = await staticEgressFixture(t);
  const captured = f.capture();
  const before = f.secretReads;
  const placement = f.pauseNamespaceVerification();
  t.after(placement.release);
  const pending = f.resolve(captured);
  await placement.reached;

  // Advance only wall time. This separates the absolute deadline from a timeout callback
  // that may not have run yet, for example when an event-loop turn takes too long.
  const { seconds, nanos } = captured.deadline;
  const deadline = Number(seconds) * 1000 + nanos / 1e6;
  const clock = t.mock.method(Date, "now", () => deadline);
  placement.release();
  const result = await pending;
  clock.mock.restore();
  assert.ok(result.refused);
  assert.equal(f.secretReads, before, "no Secret GET reached Kubernetes after the deadline");
  assert.equal(f.providerRequests.length, 0);
});

test("policy verification crossing the request deadline cannot start material selection", async (t) => {
  const f = await syntheticDispatchFixture(t);
  const forwarder = new CredentialProxy({
    ...f.ports,
    check: async (...args) => {
      const decision = await f.ports.check(...args);
      f.advance(Date.parse(f.request.deadlineAt) - f.ports.now());
      return decision;
    },
  });
  const result = await forwarder.resolve(
    "synthetic-peer",
    f.association.installation.sandboxId,
    f.request,
    new AbortController().signal,
  );
  assert.equal(f.reads, 0, "the material owner must not be called on an expired access decision");
  assert.deepEqual(result, { kind: "refused", error: { kind: "deadline_exceeded" } });
  assert.equal(f.arrivals, 0);
});

test("a selection returning at the request deadline reports deadline exceeded, not material readiness", async (t) => {
  const f = await syntheticDispatchFixture(t);
  const forwarder = new CredentialProxy({
    ...f.ports,
    read: async (...args) => {
      const material = await f.ports.read(...args);
      f.advance(Date.parse(f.request.deadlineAt) - f.ports.now());
      return material;
    },
  });
  const result = await forwarder.resolve(
    "synthetic-peer",
    f.association.installation.sandboxId,
    f.request,
    new AbortController().signal,
  );
  assert.deepEqual(result, { kind: "refused", error: { kind: "deadline_exceeded" } });
  assert.equal(f.reads, 1, "selection legitimately started before the deadline");
  assert.equal(f.arrivals, 0);
});

test("authenticated sender receipts survive authority restart without replay permission and distinguish observations", async (t) => {
  const f = await staticEgressFixture(t);
  const captured = f.capture();
  const ready = (await f.resolve(captured)).ready;
  const input = receiptAttempt(f, captured, ready);
  assert.ok((await f.authorize(f.permitRequest(captured, ready))).allowed);
  const possible = await readReceipt(f, input);
  assert.deepEqual(possible.outcome, { kind: "uncertain", dispatch: "possible" });
  assert.equal(possible.observation, null);
  const response = await f.send(captured, ready);
  const foreign = await f.beginExchange(
    f.metadata({ instance_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" }),
  );
  foreign.stream.write({ response });
  await assert.rejects(
    foreign.next(),
    { code: 7 },
    "another response stream cannot claim the accepted reply",
  );
  assert.ok((await f.protect(captured, response)).body);
  const observed = await readReceipt(f, input);
  assert.deepEqual(observed.observation, { kind: "response", dispatch: "confirmed", status: 200 });
  assert.deepEqual(observed.outcome, possible.outcome);
  assert.deepEqual(observed.authorization, possible.authorization);
  assert.equal(
    observed.settled,
    false,
    "body decision bytes are not final supplier application proof",
  );
  assert.equal(observed.feedback, null);
  assert.deepEqual(
    Object.keys(observed).sort(),
    [
      "sender",
      "instanceId",
      "useId",
      "attemptId",
      "material",
      "deadlineAt",
      "authorization",
      "observation",
      "outcome",
      "settled",
      "feedback",
    ].sort(),
  );
  assert.ok(!JSON.stringify(observed).includes("synthetic-key-initial"));
  await f.restartAuthority();
  const replay = (await f.resolve(captured)).ready;
  assert.ok(replay, "restarted authority has no transient operation registry");
  assert.ok((await f.authorize(f.permitRequest(captured, replay))).refused);
  assert.deepEqual(await readReceipt(f, input), observed);
  assert.equal(f.providerRequests.length, 1, "recovery never dispatches another request");
});

test("receipt observation fences only positive credential rejection, including blocked provider responses", async (t) => {
  const f = await staticEgressFixture(t);
  async function exchange(status, body) {
    f.setResponse({ status, body });
    const captured = f.capture();
    const ready = (await f.resolve(captured)).ready;
    assert.ok(ready);
    assert.ok((await f.authorize(f.permitRequest(captured, ready))).allowed);
    const result = await f.protect(captured, await f.send(captured, ready));
    return { result, receipt: await readReceipt(f, receiptAttempt(f, captured, ready)) };
  }
  for (const [status, body] of [
    [401, { error: "invalid credential" }],
    [401, { error: { code: "insufficient_quota", type: "invalid_request_error" } }],
    [403, { error: { code: "invalid_api_key", type: "invalid_request_error" } }],
  ]) {
    const value = await exchange(status, body);
    assert.ok(value.result.body);
    assert.deepEqual(value.receipt.observation, {
      kind: "response",
      dispatch: "confirmed",
      status,
    });
    assert.equal(value.receipt.feedback, null, "HTTP failure alone is not credential rejection");
  }
  // Even recognizable bytes in an unfinished supplier unit do not establish a
  // complete provider rejection. Block the response without fencing the credential.
  f.setResponse({
    status: 401,
    body: { error: { code: "invalid_api_key", type: "invalid_request_error" } },
  });
  const partialCapture = f.capture();
  const partialReady = (await f.resolve(partialCapture)).ready;
  assert.ok((await f.authorize(f.permitRequest(partialCapture, partialReady))).allowed);
  const partialResponse = await f.send(partialCapture, partialReady);
  const incomplete = await f.protect(partialCapture, {
    ...partialResponse,
    response_complete: false,
  });
  assert.equal(incomplete.blocked, true);
  const partialReceipt = await readReceipt(f, receiptAttempt(f, partialCapture, partialReady));
  assert.equal(partialReceipt.observation.kind, "response_blocked");
  assert.equal(partialReceipt.feedback, null);
  const acceptedRejection = await exchange(401, {
    error: { code: "invalid_api_key", type: "invalid_request_error" },
  });
  assert.ok(acceptedRejection.result.body);
  assert.deepEqual(acceptedRejection.receipt.observation, {
    kind: "provider_rejected",
    dispatch: "confirmed",
    status: 401,
  });
  assert.equal(acceptedRejection.receipt.feedback, "fenced");
  const rotated = await f.request("PATCH", `/namespaces/${f.namespace.id}/secrets/${f.secret.id}`, {
    body: { value: "synthetic-key-next-version" },
  });
  assert.equal(rotated.status, 200);
  const rejection = {
    error: {
      code: "invalid_api_key",
      type: "invalid_request_error",
      message: "synthetic-key-next-version",
    },
  };
  const blocked = await exchange(401, rejection);
  assert.ok(blocked.result.blocked);
  assert.deepEqual(blocked.receipt.observation, {
    kind: "response_blocked",
    dispatch: "confirmed",
    code: "response_policy",
  });
  assert.equal(
    blocked.receipt.feedback,
    "fenced",
    "actual rejection fences even when response bytes cannot be returned",
  );
  assert.equal(blocked.receipt.settled, false);
  assert.ok(!JSON.stringify(blocked.receipt).includes("synthetic-key-next-version"));
  const next = f.capture();
  const ready = (await f.resolve(next)).ready;
  assert.ok((await f.authorize(f.permitRequest(next, ready))).refused);
  assert.equal(f.providerRequests.length, 6);
});

test("receipt persistence failure, lost acknowledgment and late authorization never grant send permission", async (t) => {
  const { createConsoleAppFixture } = await import("../helpers/console-app.mjs");
  for (const scenario of [
    "reject",
    "lost_ack",
    "revoke",
    "deny_lost_ack",
    "deadline",
    "check_deadline",
    "cancel",
  ]) {
    await t.test(scenario, async (t) => {
      let elapsed = 0;
      const fault = receiptPersistenceFaults();
      const f = await staticEgressFixture(t, {
        now: () => new Date(Date.now() + elapsed),
        appFactory: (t, options) =>
          createConsoleAppFixture(t, { ...options, wrapState: (state) => fault.wrap(state) }),
      });
      const captured = f.capture();
      const ready = (await f.resolve(captured)).ready;
      const input = receiptAttempt(f, captured, ready);
      const gate = fault.arm(
        scenario === "check_deadline"
          ? "isEgressMaterialRejected"
          : scenario === "lost_ack"
            ? "authorize"
            : "insert",
        ["reject", "lost_ack"].includes(scenario) ? scenario : "pause",
      );
      t.after(gate.release);
      const result = f.authorize(f.permitRequest(captured, ready), {
        cancelAfterMs: scenario === "cancel" ? 50 : undefined,
      });
      if (scenario !== "reject") {
        const cancellation =
          scenario === "cancel" ? assert.rejects(result, { code: 1 }) : undefined;
        await gate.reached;
        if (scenario === "revoke" || scenario === "deny_lost_ack") {
          await f.revoke();
        }
        // The refused settlement commits but its acknowledgment is lost: the sender sees
        // unavailable, while the receipt records the committed refusal.
        const settlement = scenario === "deny_lost_ack" ? fault.arm("save", "lost_ack") : undefined;
        if (settlement) {
          t.after(settlement.release);
        }
        if (scenario === "deadline" || scenario === "check_deadline") {
          elapsed = 31_000;
        }
        if (scenario === "check_deadline") {
          // The actual successful final policy transaction has committed. A new
          // capture prunes the expired handle before that check returns to its owner.
          assert.ok((await f.resolve(f.capture())).ready);
        }
        if (cancellation) {
          await cancellation;
        }
        gate.release();
        if (settlement) {
          await settlement.reached;
          settlement.release();
        }
      }
      if (scenario !== "cancel") {
        const { refused } = await result;
        assert.ok(refused, scenario);
        if (scenario === "deny_lost_ack") {
          assert.equal(refused.code, f.refusalCode("UNAVAILABLE"));
        }
      }
      const stored = await readReceipt(f, input);
      if (scenario === "reject") {
        assert.equal(stored, undefined);
      }
      if (scenario === "lost_ack") {
        assert.ok(
          stored.authorization?.association.custodyId,
          "lost the exact authorized dispatch acknowledgment, not an earlier begin",
        );
        assert.equal(stored.settled, false);
        assert.deepEqual(stored.outcome, { kind: "uncertain", dispatch: "possible" });
        await f.restartAuthority();
        const replay = (await f.resolve(captured)).ready;
        assert.ok((await f.authorize(f.permitRequest(captured, replay))).refused);
      }
      if (["revoke", "deadline", "check_deadline"].includes(scenario)) {
        assert.equal(stored.outcome.kind, "refused");
        assert.equal(stored.outcome.dispatched, false);
      }
      if (scenario === "deny_lost_ack") {
        assert.equal(stored.settled, true, "refusal committed before its acknowledgment was lost");
        assert.equal(stored.authorization, null);
        assert.deepEqual(stored.outcome, {
          kind: "refused",
          dispatched: false,
          error: { kind: "denied", code: "unauthorized" },
        });
      }
      assert.equal(f.providerRequests.length, 0);
    });
  }
});

test("response persistence must commit its observation and fence before policy bytes are acknowledged", async (t) => {
  const { createConsoleAppFixture } = await import("../helpers/console-app.mjs");
  for (const scenario of ["reject", "lost_ack", "deadline"]) {
    await t.test(scenario, async (t) => {
      let elapsed = 0;
      const fault = receiptPersistenceFaults();
      const f = await staticEgressFixture(t, {
        now: () => new Date(Date.now() + elapsed),
        appFactory: (t, options) =>
          createConsoleAppFixture(t, { ...options, wrapState: (state) => fault.wrap(state) }),
      });
      f.setResponse({
        status: 401,
        body: { error: { code: "invalid_api_key", type: "invalid_request_error" } },
      });
      const captured = f.capture();
      const ready = (await f.resolve(captured)).ready;
      const input = receiptAttempt(f, captured, ready);
      assert.ok((await f.authorize(f.permitRequest(captured, ready))).allowed);
      const response = await f.send(captured, ready);
      const gate = fault.arm("save", scenario === "deadline" ? "pause" : scenario);
      t.after(gate.release);
      const pending = f.protect(captured, response);
      const failed = scenario === "deadline" ? undefined : assert.rejects(pending, { code: 14 });
      if (scenario !== "reject") {
        await gate.reached;
        if (scenario === "deadline") {
          elapsed = 31_000;
        }
        gate.release();
      }
      if (failed) {
        await failed;
      } else {
        assert.ok((await pending).blocked);
      }
      const receipt = await readReceipt(f, input);
      assert.deepEqual(receipt.outcome, { kind: "uncertain", dispatch: "possible" });
      assert.equal(receipt.settled, false);
      const fenced = await f.controller.transact((unit) =>
        unit.credentialSources.isEgressMaterialRejected(input.material),
      );
      assert.equal(
        fenced,
        scenario !== "reject",
        "observation and exact-version fence share one real state transaction",
      );
      assert.equal(receipt.feedback, fenced ? "fenced" : null);
      assert.equal(receipt.observation?.kind, fenced ? "provider_rejected" : undefined);
      assert.equal(f.providerRequests.length, 1);
    });
  }
});

test("production Compute refuses protected admission and release, including empty plans", async (t) => {
  const compute = createTestKubernetesComputeDriver("admission-cutoff");
  const f = await staticEgressFixture(t);
  const withoutPlan = { ...f.revision };
  delete withoutPlan.egressPlan;
  const missing = { ...withoutPlan };
  delete missing.executionAdmission;
  const unprotected = {
    ...withoutPlan,
    executionAdmission: { version: 2, mode: "unprotected" },
  };
  const cases = [
    [missing, /Missing or unsupported durable/],
    [
      { ...unprotected, executionAdmission: { version: 1, mode: "unprotected" } },
      /Missing or unsupported durable/,
    ],
    [withoutPlan, /Inconsistent durable/],
    [{ ...f.revision, executionAdmission: unprotected.executionAdmission }, /Inconsistent durable/],
    [f.revision, /Protected execution is unavailable/],
    [
      {
        ...f.revision,
        credentialSources: [],
        egressPlan: { ...f.revision.egressPlan, routes: [] },
      },
      /Protected execution is unavailable/,
    ],
  ];
  // Actual shipped Compute entrypoints: no clients are initialized and no cluster exists.
  // Even its runtime-disabled activation fast path must recognize admission first.
  for (const [revision, expected] of cases) {
    assert.throws(() => compute.validateExecutionAdmission(revision), expected);
    await assert.rejects(compute.prepareRevision(revision), expected);
    await assert.rejects(compute.activateRevision(revision), expected);
  }
  assert.doesNotThrow(() => compute.validateExecutionAdmission(unprotected));
  await assert.rejects(
    compute.activateRevision(unprotected),
    /AgentRevision Compute ownership is invalid/,
  );
  assert.equal((await compute.prepareRevision(unprotected)).ready, false);
  await compute.activateRevision({
    ...unprotected,
    compute: { id: compute.id, implementation: compute.implementation },
  });

  // Protection comes from the selected execution policy, not the number of credentials.
  // Runtime-auth fixtures carry no credential source; their durable plan remains deny-all.
  const emptyAgent = await f.createAgent(
    f.namespace.id,
    "credential-free",
    f.revision.configuration,
    {
      executionMode: "dedicated",
      harnessAuth: { method: "runtime" },
    },
  );
  const emptyMetadata = await f.deployAgent(f.namespace.id, emptyAgent.id);
  const emptyRevision = await f.controller.transact((unit) =>
    unit.revisions.findRevision(f.namespace.id, emptyAgent.id, emptyMetadata.id),
  );
  assert.deepEqual(emptyRevision.executionAdmission, { version: 2, mode: "protected" });
  assert.deepEqual(emptyRevision.egressPlan.routes, []);
  await assert.rejects(
    compute.prepareRevision(emptyRevision),
    /Protected execution is unavailable/,
  );

  // Exercise the real OCC deploy route with the shipped Compute admission policy.
  // Other Compute operations remain deterministic fixtures; this is not cluster proof.
  let admissionChecks = 0;
  const admission = await staticEgressFixture(t, {
    admitRevision: false,
    appFactory: (context, options) =>
      createConsoleAppFixture(context, {
        ...options,
        computeDriver: {
          ...options.computeDriver,
          validateExecutionAdmission(revision) {
            admissionChecks += 1;
            compute.validateExecutionAdmission(revision);
          },
        },
      }),
  });
  const response = await admission.request(
    "POST",
    `/namespaces/${admission.namespace.id}/agents/${admission.agent.id}/deploy`,
  );
  assert.equal(response.status, 503, JSON.stringify(response.body));
  assert.equal(response.body.error.code, "DEPENDENCY_UNAVAILABLE");
  assert.equal(admissionChecks, 1, "the OCC route must reach the shipped Compute admission gate");
  assert.deepEqual(
    await admission.controller.transact((unit) =>
      unit.revisions.listRevisions(admission.namespace.id, admission.agent.id),
    ),
    [],
  );
});

test("an unavailable protected egress provider fails the deployment with an operator message", () => {
  const error = deploymentErrorForWork({
    state: "failed_permanent",
    reasonCode: "EGRESS_PROVIDER_UNAVAILABLE",
  });
  assert.equal(error.code, "EGRESS_PROVIDER_UNAVAILABLE");
  assert.notEqual(error.message, "Deployment reconciliation failed.");
  assert.match(error.message, /protected egress provider/);
});
