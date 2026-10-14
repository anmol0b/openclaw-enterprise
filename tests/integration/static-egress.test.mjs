import assert from "node:assert/strict";
import test from "node:test";
import { egressInjectionDigest } from "../../packages/occ/src/egress.ts";
import { staticEgressFixture, unary } from "../helpers/static-egress.mjs";

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
    { model: "fixture-model", input: "hello", store: false, stream: true },
    { model: "fixture-model", input: "hello", store: false, tools: [] },
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
