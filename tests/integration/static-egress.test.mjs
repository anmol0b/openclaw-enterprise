import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { egressInjectionDigest } from "../../packages/occ/src/egress.ts";
import {
  pluginRuntimeSpecForRevision,
  pluginRuntimeConfigMapData,
} from "../../apps/controller/src/drivers/compute/plugin-runtime.ts";
import { staticEgressFixture, unary, wireTime } from "../helpers/static-egress.mjs";

test("credential header digest uses ordered UTF-8 bytes and u64 lengths", () => {
  assert.equal(
    egressInjectionDigest([
      ["authorization", "Bearer synthetic-vector"],
      ["x-api-key", "key-é"],
    ]),
    "d1e3baea080e3a4d5ec5ac5feb168ded341a545d201aea2d1d1104dca7ec6b23",
  );
});

test("protected inference uses real admission, fresh IAM, versioned Secret reads and TLS authority/provider wires", async (t) => {
  const f = await staticEgressFixture(t);
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
  const unprotected = { ...f.revision };
  delete unprotected.egressPlan;
  assert.doesNotMatch(
    pluginRuntimeConfigMapData(pluginRuntimeSpecForRevision(unprotected))["config.toml"],
    /web_search/,
  );
  const capture = f.capture();
  const result = await unary(f.clients.HttpCredentialAccess, "Resolve", capture, f.metadata());
  assert.ok(result.ready, JSON.stringify(result));
  const permit = f.permitRequest(capture, result.ready);
  assert.ok(
    (await unary(f.clients.HttpCredentialAccess, "AuthorizeSend", permit, f.metadata())).allowed,
  );
  const response = await f.send(capture, result.ready);
  assert.deepEqual(f.providerRequests[0].body, {
    model: "fixture-model",
    input: "hello",
    store: false,
  });
  assert.equal(f.providerRequests[0].authorization, "Bearer synthetic-key-initial");
  const protectedResponse = await f.protect(capture, response);
  assert.deepEqual(JSON.parse(protectedResponse.body_result.transform.data), {
    output: "fixture answer",
  });
  assert.ok(
    (await unary(f.clients.HttpCredentialAccess, "AuthorizeSend", permit, f.metadata())).refused,
  );

  // Rotation changes material version without replacing source configuration or grants.
  const updated = await f.request("PATCH", `/namespaces/${f.namespace.id}/secrets/${f.secret.id}`, {
    body: { value: "synthetic-key-rotated" },
  });
  assert.equal(updated.status, 200, JSON.stringify(updated.body));
  const next = f.capture();
  const resolved = await unary(f.clients.HttpCredentialAccess, "Resolve", next, f.metadata());
  assert.ok(resolved.ready, JSON.stringify(resolved));
  assert.notEqual(resolved.ready.evidence.material_version, result.ready.evidence.material_version);
  assert.equal(resolved.ready.credential_headers[0].value, "Bearer synthetic-key-rotated");
  await f.revoke();
  assert.ok(
    (
      await unary(
        f.clients.HttpCredentialAccess,
        "AuthorizeSend",
        f.permitRequest(next, resolved.ready),
        f.metadata(),
      )
    ).refused,
    "revocation after access must deny selected material at send",
  );
  assert.equal(f.providerRequests.length, 1);
  const beforeReads = f.secretReads;
  assert.ok(
    (await unary(f.clients.HttpCredentialAccess, "Resolve", f.capture(), f.metadata())).refused,
  );
  assert.equal(f.secretReads, beforeReads, "current IAM denial must precede Secret access");
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
    assert.ok(
      (await unary(f.clients.HttpCredentialAccess, "Resolve", f.capture(body), f.metadata()))
        .refused,
    );
  }
  const ambiguous = f.capture();
  ambiguous.request.body = Buffer.from(
    '{"model":"other-model","model":"fixture-model","input":"hello","store":false}',
  );
  assert.ok(
    (await unary(f.clients.HttpCredentialAccess, "Resolve", ambiguous, f.metadata())).refused,
  );
  const wrongPeer = f.metadata({
    sandbox_id: "other-sandbox",
    sub: "spiffe://openshell/sandbox/other-sandbox",
  });
  assert.ok(
    (await unary(f.clients.HttpCredentialAccess, "Resolve", f.capture(), wrongPeer)).refused,
  );
  assert.ok(
    (
      await unary(
        f.clients.HttpCredentialAccess,
        "Resolve",
        f.capture(),
        f.metadata({ aud: "different-authority" }),
      )
    ).refused,
  );
  assert.equal(
    f.secretReads,
    before,
    "identity and operation refusals must not touch credential material",
  );
  const captured = f.capture();
  const ready = (await unary(f.clients.HttpCredentialAccess, "Resolve", captured, f.metadata()))
    .ready;
  assert.ok(ready);
  assert.ok(
    (await unary(f.clients.HttpCredentialAccess, "Resolve", captured, f.metadata())).refused,
  );
  const permit = f.permitRequest(captured, ready);
  assert.ok(
    (
      await unary(
        f.clients.HttpCredentialAccess,
        "AuthorizeSend",
        { ...permit, evidence: { ...permit.evidence, material_version: "not-selected" } },
        f.metadata(),
      )
    ).refused,
  );
  assert.ok(
    (
      await unary(
        f.clients.HttpCredentialAccess,
        "AuthorizeSend",
        {
          ...permit,
          deadline: { ...permit.deadline, seconds: String(Number(permit.deadline.seconds) + 1) },
        },
        f.metadata(),
      )
    ).refused,
  );
  assert.ok(
    (
      await unary(
        f.clients.HttpCredentialAccess,
        "AuthorizeSend",
        { ...permit, credential_headers_sha256: Buffer.alloc(32) },
        f.metadata(),
      )
    ).refused,
  );
  const decisions = await Promise.all(
    [1, 2].map(() => unary(f.clients.HttpCredentialAccess, "AuthorizeSend", permit, f.metadata())),
  );
  assert.equal(
    decisions.filter((decision) => decision.allowed).length,
    1,
    "concurrent final checks cannot duplicate a send permit",
  );
  assert.equal(f.providerRequests.length, 0);
});

test("provider authentication rejection fences the exact material version and encoded credential reflection is withheld", async (t) => {
  const f = await staticEgressFixture(t);
  async function exchange() {
    const captured = f.capture();
    const ready = (await unary(f.clients.HttpCredentialAccess, "Resolve", captured, f.metadata()))
      .ready;
    assert.ok(ready);
    assert.ok(
      (
        await unary(
          f.clients.HttpCredentialAccess,
          "AuthorizeSend",
          f.permitRequest(captured, ready),
          f.metadata(),
        )
      ).allowed,
    );
    return f.protect(captured, await f.send(captured, ready));
  }
  f.setResponse({
    status: 200,
    body: { output: Buffer.from("synthetic-key-initial").toString("base64") },
  });
  assert.ok(
    (await exchange()).body_result.block_delivery,
    "the actual provider response must pass conservative protection",
  );
  f.setResponse({
    status: 200,
    rawBody: '{"output":"synthetic-key-initial","output":"hidden duplicate"}',
  });
  assert.ok(
    (await exchange()).body_result.block_delivery,
    "duplicate JSON keys cannot conceal reflected material from parsing",
  );
  f.setResponse({ status: 401, body: { error: "invalid credential" } });
  assert.ok((await exchange()).body_result.transform);
  const captured = f.capture();
  const ready = (await unary(f.clients.HttpCredentialAccess, "Resolve", captured, f.metadata()))
    .ready;
  assert.ok(ready);
  assert.ok(
    (
      await unary(
        f.clients.HttpCredentialAccess,
        "AuthorizeSend",
        f.permitRequest(captured, ready),
        f.metadata(),
      )
    ).refused,
    "authoritative reread cannot resurrect a rejected version",
  );
  const updated = await f.request("PATCH", `/namespaces/${f.namespace.id}/secrets/${f.secret.id}`, {
    body: { value: "synthetic-key-new-version" },
  });
  assert.equal(updated.status, 200);
  f.setResponse({ status: 200, body: { output: "after rotation" } });
  assert.ok(
    (await exchange()).body_result.transform,
    "new authoritative version does not inherit the old rejection",
  );
});

test("protected admission requires the actual counterpart and exact loaded policy; withdrawal removes only its owned Sandbox", async (t) => {
  const f = await staticEgressFixture(t);
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
      gateway: { protocol_version: { major: 1 }, supported_capabilities: [contract, capability] },
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
  f.observed.policy.network_middlewares["oce-egress"].credential_authority = false;
  assert.equal(await f.egress.attachmentStatus(f.context, f.attachment), undefined);
  f.observed.policy = structuredClone(expectedPolicy);
  f.observed.policy.network_policies["oce-egress-0"].endpoints[0].allow_uninspected_credentials =
    true;
  await assert.rejects(f.egress.attachmentStatus(f.context, f.attachment), /differs/);
  f.observed.policy = structuredClone(expectedPolicy);
  f.observed.policy.network_policies["workspace-node-enrollment"] = {
    name: "workspace-node-enrollment",
    binaries: [{ path: "/usr/local/bin/node" }],
    endpoints: [{ host: "unexpected.example.test", ports: [443] }],
  };
  await assert.rejects(f.egress.attachmentStatus(f.context, f.attachment), /differs/);
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
  assert.equal((await f.request("PATCH", path, { body: { adoption: "live" } })).status, 503);
  assert.equal((await f.request("GET", path)).data.egress, undefined);
  assert.deepEqual([...f.providers.values()], before);
  f.observed.available = true;
  const adopted = await f.request("PATCH", path, { body: { adoption: "live" } });
  assert.equal(adopted.status, 200, JSON.stringify(adopted.body));
  assert.deepEqual(adopted.data.egress, { adoption: "live", retention: "none" });
  assert.deepEqual(
    [...f.providers.values()],
    before,
    "adoption never overwrites the previous gateway material",
  );
  const bound = await f.request("PATCH", `${f.path}/${f.source.id}`, {
    body: { adoption: "live" },
  });
  assert.equal(bound.status, 409, "running source cutover is explicitly unsupported");
});

test("current supplier evidence is required at access and send; stored receipts cannot authorize a replacement", async (t) => {
  const f = await staticEgressFixture(t);
  const original = structuredClone(f.observed.evidence);
  // Proto3 scalar zeros can be omitted on the wire; both encodings have one fingerprint.
  f.observed.evidence = { ...original, config_revision: "0", provider_env_revision: "0" };
  const zero = await f.egress.attachmentStatus(f.context, f.attachment);
  assert.ok(zero);
  delete f.observed.evidence.config_revision;
  delete f.observed.evidence.provider_env_revision;
  assert.deepEqual(
    (await f.egress.attachmentStatus(f.context, f.attachment)).enforcement,
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
    assert.ok(
      (await unary(f.clients.HttpCredentialAccess, "Resolve", f.capture(), f.metadata())).refused,
    );
    assert.equal(f.secretReads, reads, "historical installation must not permit credential access");
  }
  f.observed.evidence = original;
  const captured = f.capture();
  const ready = (await unary(f.clients.HttpCredentialAccess, "Resolve", captured, f.metadata()))
    .ready;
  assert.ok(ready, "restoring the original current observation permits a new operation");
  // Replacement happens after material access, while the operation still holds the old receipt.
  f.observed.evidence = { ...original, instance_id: "10000000-0000-4000-8000-000000000001" };
  assert.ok(
    (
      await unary(
        f.clients.HttpCredentialAccess,
        "AuthorizeSend",
        f.permitRequest(captured, ready),
        f.metadata(),
      )
    ).refused,
  );
  assert.equal(f.providerRequests.length, 0);
  const replacement = await f.egress.attachmentStatus(f.context, f.attachment);
  assert.ok(replacement);
  await assert.rejects(
    f.controller.transact((unit) => unit.credentialSources.recordEgressInstallation(replacement)),
    /already bound/,
  );
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
    const ready = (await unary(f.clients.HttpCredentialAccess, "Resolve", captured, f.metadata()))
      .ready;
    assert.ok(ready);
    assert.ok(
      (
        await unary(
          f.clients.HttpCredentialAccess,
          "AuthorizeSend",
          f.permitRequest(captured, ready),
          f.metadata(),
        )
      ).allowed,
    );
    f.setResponse({ status: 200, contentType: "text/event-stream", rawBody });
    return f.protect(captured, await f.send(captured, ready));
  }
  const body = encode(wire.responseEvents);
  const delivered = await exchange(body);
  assert.equal(delivered.body_result.transform.data.toString(), body);
  assert.deepEqual(f.providerRequests[0].body, wire.request);
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
    assert.ok(
      (await unary(f.clients.HttpCredentialAccess, "Resolve", f.capture(body), f.metadata()))
        .refused,
    );
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
    body.replace(/\n\n$/, "\n"),
  ]) {
    assert.ok(
      (await exchange(unsafe)).body_result.block_delivery,
      "the whole finite stream must pass response policy before any delivery",
    );
  }
});

test("signed supervisor instance and UUIDv7 creation horizon refuse old callers and deadline-extension replay", async (t) => {
  let elapsed = 0;
  const now = () => new Date(Date.now() + elapsed);
  const f = await staticEgressFixture(t, { now });
  const reads = f.secretReads;
  for (const claims of [
    { instance_id: undefined },
    { instance_id: "10000000-0000-4000-8000-000000000001" },
    { instance_id: f.namespace.id },
  ]) {
    assert.ok(
      (await unary(f.clients.HttpCredentialAccess, "Resolve", f.capture(), f.metadata(claims)))
        .refused,
    );
  }
  assert.equal(f.secretReads, reads);
  const captured = f.capture();
  captured.deadline = wireTime(now().getTime() + 1000);
  const ready = (await unary(f.clients.HttpCredentialAccess, "Resolve", captured, f.metadata()))
    .ready;
  assert.ok(ready);
  // A short submitted deadline does not shorten replay retention for this immutable operation ID.
  elapsed = 2000;
  captured.deadline = wireTime(now().getTime() + 20_000);
  assert.ok(
    (await unary(f.clients.HttpCredentialAccess, "Resolve", captured, f.metadata())).refused,
  );
  elapsed = 31_000;
  captured.deadline = wireTime(now().getTime() + 1000);
  assert.ok(
    (await unary(f.clients.HttpCredentialAccess, "Resolve", captured, f.metadata())).refused,
  );
  assert.equal(
    f.secretReads,
    reads + 1,
    "eviction cannot make an expired UUID into a new operation",
  );
  assert.ok(
    (await unary(f.clients.HttpCredentialAccess, "Resolve", f.capture(), f.metadata())).ready,
  );
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
      const ready = (await unary(f.clients.HttpCredentialAccess, "Resolve", captured, peer)).ready;
      assert.ok(ready, `sequential operation ${i} should resolve`);
      assert.ok(
        (
          await unary(
            f.clients.HttpCredentialAccess,
            "AuthorizeSend",
            f.permitRequest(captured, ready),
            peer,
          )
        ).allowed,
      );
      assert.ok((await f.protect(captured, await f.send(captured, ready))).body_result.transform);
    }
    assert.equal(f.providerRequests.length, 4200);
    assert.ok(
      f.providerRequests.every(
        (request) => request.authorization === "Bearer synthetic-key-initial",
      ),
    );
  },
);

test(
  "pending Secret reads consume operation capacity before completion and release it after delivery",
  { timeout: 60_000 },
  async (t) => {
    const f = await staticEgressFixture(t);
    const before = f.secretReads;
    const release = f.pauseSecretReads();
    t.after(release);
    const peer = f.metadata();
    const captured = Array.from({ length: 1024 }, () => f.capture());
    const pending = captured.map((request) =>
      unary(f.clients.HttpCredentialAccess, "Resolve", request, peer, 30_000),
    );
    const until = Date.now() + 15_000;
    while (f.secretReads !== before + 1024 && Date.now() < until) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.equal(
      f.secretReads,
      before + 1024,
      "all admitted operations must reach the real Secret SDK read",
    );
    assert.ok((await unary(f.clients.HttpCredentialAccess, "Resolve", f.capture(), peer)).refused);
    assert.equal(
      f.secretReads,
      before + 1024,
      "the excess operation must refuse before dependency I/O",
    );
    release();
    const decisions = await Promise.all(pending);
    assert.ok(decisions.every((decision) => decision.ready));
    const ready = decisions[0].ready;
    assert.ok(
      (
        await unary(
          f.clients.HttpCredentialAccess,
          "AuthorizeSend",
          f.permitRequest(captured[0], ready),
          peer,
        )
      ).allowed,
    );
    assert.ok(
      (await f.protect(captured[0], await f.send(captured[0], ready))).body_result.transform,
    );
    assert.ok(
      (await unary(f.clients.HttpCredentialAccess, "Resolve", f.capture(), peer)).ready,
      "delivery frees an operation slot without an expiry wait",
    );
    assert.equal(f.providerRequests.length, 1);
  },
);
