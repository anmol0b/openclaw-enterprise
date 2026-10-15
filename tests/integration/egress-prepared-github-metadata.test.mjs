import test from "node:test";
import assert from "node:assert/strict";
import { captureMetadata, dispatchMetadata } from "../helpers/github-metadata-exchange.mjs";
import { staticEgressFixture } from "../helpers/static-egress.mjs";
import { createPreparedStore } from "../fixtures/repository-credentials/github/prepared-store.mjs";
import {
  startGitHubFixture,
  fixtureRepository,
  fixtureRepositoryId,
  fixtureInstallationId,
  fixtureAppId,
} from "../fixtures/repository-credentials/github.mjs";
import { createSystemClock } from "../../apps/controller/src/drivers/repo/credentials/clock.ts";
import {
  createGitHubPreparationOwner,
  createGitHubWarmReader,
  createGitHubKeyOwner,
} from "../../apps/controller/src/drivers/repo/github/credentials/index.ts";

// Real source/Agent/binding/deployment APIs, IAM, protected forwarder, preparation owner,
// scoped GitHub issuance, HTTPS GET and actual last trailer. The test plays the enrolled supervisor and the store is in-memory;
// installed custody and PostgreSQL recovery have their own qualifications.
test("consented protected repository read uses only exact, already prepared metadata grant", async (t) => {
  let forbiddenTrailer = false;
  const clock = createSystemClock();
  const gh = await startGitHubFixture(t, {
    clock,
    beforeMetadataResponse({ response }) {
      if (forbiddenTrailer) {
        response.addTrailers({ "x-forbidden-last": "last" });
      }
    },
  });
  const key = createGitHubKeyOwner({ appId: fixtureAppId, clock, privateKey: gh.privateKey });
  t.after(() => key.close());
  let reads = 0;
  let sendChecks = 0;
  let store;
  let admission;
  let reader;
  let owner;
  const config = {
    app_id: fixtureAppId,
    installation_id: fixtureInstallationId,
    repository_id: fixtureRepositoryId,
    repository: fixtureRepository,
  };
  const f = await staticEgressFixture(t, {
    preparedGitHub: {
      apiOrigin: gh.origin,
      async configure(source, secret) {
        assert.equal(secret.name, "provider-key");
        const { grant } = source;
        const { id, generation } = source.key.source;
        admission = {
          familyId: id,
          generation,
          ownerEpoch: 1,
          inputVersion: "fixture-key-1",
          grant: { ...grant, id },
        };
        store = createPreparedStore(admission).connect();
        reader = createGitHubWarmReader(store, clock.wallNow);
        owner = createGitHubPreparationOwner({
          admission,
          store,
          clock,
          getKey: async () => key,
          apiOrigin: gh.origin,
          ca: gh.tls.ca,
          renewBeforeMs: 120000,
          minimumValidityMs: 10000,
        });
      },
      async readWarm(source) {
        reads++;
        assert.equal(source.origin, gh.origin);
        const result = await reader.readWarm(admission);
        if (result.kind !== "warm") {
          return undefined;
        }
        const { materialVersion, providerExpiresAt, usableUntil, bytes, attemptId } =
          result.material;
        try {
          return {
            value: Buffer.from(bytes).toString(),
            materialVersion,
            providerExpiresAt: new Date(providerExpiresAt).toISOString(),
            usableUntil: new Date(usableUntil).toISOString(),
            materialId: admission.familyId,
            family: source.key.source,
            preparationAttemptId: attemptId,
            ownerEpoch: 1,
            inputVersion: admission.inputVersion,
          };
        } finally {
          bytes.fill(0);
        }
      },
      async current(_source, evidence) {
        sendChecks++;
        return store.readCurrent(
          admission.familyId,
          (row) =>
            row?.enabled === true &&
            row.committed.materialVersion === evidence.materialVersion &&
            row.committed.attemptId === evidence.preparationAttemptId,
        );
      },
    },
    async admitSource({ app, agent, namespace, secret, path }) {
      const input = {
        name: "protected-repository-read",
        type: "github-app-metadata",
        config: { ...config, agent_id: agent.id },
        secrets: { private_key: secret.ref },
      };
      const missingConsent = await app.request("POST", path, { body: input });
      // OCC intentionally hides out-of-scope catalog fields. No lifecycle was configured; the only added field is consent.
      assert.equal(missingConsent.status, 404);
      assert.equal(owner, undefined);
      input.config.authority = "execution";
      const created = await app.request("POST", path, { body: input });
      assert.equal(created.status, 201, JSON.stringify(created.body));
      const source = created.data;
      const bound = await app.request("PATCH", `/namespaces/${namespace.id}/agents/${agent.id}`, {
        body: {
          configurationId: agent.configurationId,
          harnessAuth: { method: "runtime" },
          credentialSources: [{ sourceId: source.id }],
        },
      });
      assert.equal(bound.status, 200, JSON.stringify(bound.body));
      return { agent: bound.data, source };
    },
  });

  const { installation } = f;
  const [route] = installation.plan.routes;
  assert.equal(route.binding.grant.profile, "metadata-read");
  assert.equal(f.attachment.configuration.network_policies["oce-egress-0"].binaries, undefined);
  const signal = new AbortController().signal;
  const resolve = (changed) => f.resolve(captureMetadata(f, changed));
  assert.equal((await resolve()).refused.code, 2, "cold material must return not ready");
  assert.equal(reads, 1);
  assert.equal(gh.issuesOfTokens.length, 0, "cold capture must not issue or schedule");
  for (const changed of [
    { body: Buffer.from("x") },
    { target: { method: "POST" } },
    { headers: [{ name: "transfer-encoding", value: "chunked" }] },
    { target: { path: "/repos/other/repo" } },
    ...[
      "/fixture/repository.git/info/refs?service=git-upload-pack",
      "/fixture/repository.git/git-upload-pack",
      "/fixture/repository.git/git-receive-pack",
    ].map((path) => ({ target: { path } })),
  ]) {
    assert.equal((await resolve(changed)).refused.code, 1);
  }
  assert.equal(reads, 1, "wrong body, target or method touched prepared material");
  assert.equal(
    await owner.run("managed-prepare-1", { signal, deadlineMonoMs: clock.monotonicNow() + 20000 }),
    "committed",
  );
  assert.equal(gh.issuesOfTokens.length, 1);

  for (const block of [false, true]) {
    forbiddenTrailer = block;
    const captured = captureMetadata(f);
    const { ready } = await f.resolve(captured);
    assert.ok(ready);
    const safe = await dispatchMetadata(f, gh, captured, ready, block);
    if (!block) {
      assert.equal(
        safe.body.toString(),
        JSON.stringify({ id: Number(fixtureRepositoryId), full_name: fixtureRepository }),
      );
    }
  }
  const captured = captureMetadata(f);
  const { ready } = await f.resolve(captured);
  await store.transact(admission.familyId, (row) => {
    row.enabled = false;
  });
  assert.equal((await f.authorize(f.permitRequest(captured, ready))).refused.code, 1);
  assert.equal(sendChecks, 3);
  assert.equal(gh.issuesOfTokens.length, 1, "no request may renew or issue");
});
