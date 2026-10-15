import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync } from "node:crypto";
import { staticEgressFixture, unary } from "../helpers/static-egress.mjs";

// Real TLS gRPC, issuer/possession verification, OCC capture, IAM, material read,
// synthetic HTTPS origin, and actual gRPC reply stream. Installed policy is a
// fixture; this does not prove supervisor downstream custody or network fencing.
test("installation exchange rejects stolen bearer, changed request and swapped stream before material", async (t) => {
  const f = await staticEgressFixture(t);
  const foreign = generateKeyPairSync("ed25519");
  const baselineReads = f.secretReads;
  const captured = f.capture();
  const b = await f.beginExchange();
  b.stream.write(b.opening(captured, foreign.privateKey));
  await assert.rejects(b.next(), /Installation exchange refused/);
  assert.equal(f.secretReads, baselineReads);
  assert.equal(f.providerRequests.length, 0);
  assert.deepEqual(
    b.received.map((message) => message.event),
    ["challenge"],
  );

  // Even A's valid proof cannot authorize the same request on a different sink.
  const a = await f.beginExchange();
  const swapped = await f.beginExchange();
  swapped.stream.write(a.opening(captured));
  await assert.rejects(swapped.next(), /Installation exchange refused/);
  assert.equal(f.secretReads, baselineReads);

  const changed = await f.beginExchange();
  const opening = changed.opening(captured);
  opening.open.resolve_request = changed.opening(f.capture()).open.resolve_request;
  changed.stream.write(opening);
  await assert.rejects(changed.next(), /Installation exchange refused/);
  assert.equal(f.secretReads, baselineReads);
  assert.equal(f.providerRequests.length, 0);

  // A key in an exchange is never enrollment; a legacy issuer token is insufficient.
  const old = await f.beginExchange(f.metadata({ exchange_key: undefined }));
  old.stream.write(old.opening(f.capture()));
  await assert.rejects(old.next(), /Installation exchange refused/);
  const legacy = await unary(f.clients.HttpCredentialAccess, "Resolve", f.capture(), f.metadata());
  assert.ok(legacy.refused);
  await assert.rejects(
    unary(
      f.clients.SupervisorMiddleware,
      "Describe",
      {
        gateway: {
          protocol_version: { major: 1, minor: 0 },
          supported_capabilities: [
            "openshell.supervisor-middleware.contract",
            "openshell.supervisor-middleware.http-credential-access.v1",
            "openshell.supervisor-middleware.http-credential-verified-connector.v1",
          ],
        },
      },
      f.metadata(),
    ),
    /unavailable/,
  );
  assert.equal(f.secretReads, baselineReads);
});

test("A resolves, authorizes and receives the protected actual reply on its accepted stream", async (t) => {
  const f = await staticEgressFixture(t);
  const baselineReads = f.secretReads;
  const captured = f.capture();
  const a = await f.beginExchange();
  a.stream.write(a.opening(captured));
  const { resolved } = await a.next();
  assert.ok(resolved.ready);
  assert.equal(f.secretReads, baselineReads + 1);

  // Another authenticated A stream cannot substitute its handle or reply association.
  const other = await f.beginExchange();
  const otherCapture = f.capture();
  other.stream.write(other.opening(otherCapture));
  assert.ok((await other.next()).resolved.ready);
  other.stream.write({ authorize: f.permitRequest(captured, resolved.ready) });
  assert.ok((await other.next()).authorized.refused);
  assert.equal(f.providerRequests.length, 0);

  a.stream.write({ authorize: f.permitRequest(captured, resolved.ready) });
  assert.ok((await a.next()).authorized.allowed);
  const response = await f.send(captured, resolved.ready);
  assert.equal(f.providerRequests.length, 1);
  a.stream.write({ response });
  const returned = await a.next();
  assert.ok(returned.response.body.length > 0);
  assert.equal(returned.response.status, 200);
  assert.doesNotMatch(returned.response.body.toString(), /Bearer/);
});

test("current installation replacement revokes captured A without reassigning its request", async (t) => {
  const f = await staticEgressFixture(t);
  const captured = f.capture();
  const a = await f.beginExchange();
  a.stream.write(a.opening(captured));
  const { resolved } = await a.next();
  assert.ok(resolved.ready);
  const reads = f.secretReads;
  // The authoritative status wire now reports a different installed supervisor.
  f.observed.evidence.instance_id = "00000000-0000-4000-8000-000000000001";
  a.stream.write({ authorize: f.permitRequest(captured, resolved.ready) });
  assert.ok((await a.next()).authorized.refused);
  assert.equal(f.secretReads, reads);
  assert.equal(f.providerRequests.length, 0);
  assert.equal(a.received.filter((message) => message.response).length, 0);
});

test("a second gateway-issued key for the same admitted instance cannot inherit its authority", async (t) => {
  const f = await staticEgressFixture(t);
  const before = f.secretReads;
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const exchange_key = { profile: "openshell-exchange-v1", ...publicKey.export({ format: "jwk" }) };
  const b = await f.beginExchange(f.metadata({ exchange_key }));
  b.stream.write(b.opening(f.capture(), privateKey));
  assert.ok((await b.next()).resolved.refused);
  assert.equal(f.secretReads, before);
  assert.equal(f.providerRequests.length, 0);

  const c = f.capture();
  const a = await f.beginExchange();
  a.stream.write(a.opening(c));
  const { resolved } = await a.next();
  assert.ok(resolved.ready);
  const afterA = f.secretReads;
  // A reconnect may keep the instance UUID but must not replace the pinned key.
  f.observed.observation.registered_exchange_public_key = Buffer.from(exchange_key.x, "base64url");
  a.stream.write({ authorize: f.permitRequest(c, resolved.ready) });
  assert.ok((await a.next()).authorized.refused);
  assert.equal(f.secretReads, afterA);
  assert.equal(f.providerRequests.length, 0);
});
