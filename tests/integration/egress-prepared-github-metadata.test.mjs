import test from "node:test";
import assert from "node:assert/strict";
import { get } from "node:https";
import { randomUUID } from "node:crypto";
import { requestId, staticEgressFixture } from "../helpers/static-egress.mjs";
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
// scoped GitHub issuance, HTTPS GET and actual last trailer. Store, installed observation
// and accepted transport owner are fixtures; installed custody and durable recovery are separate tests.
test("consented protected repository read uses only exact, already prepared metadata grant", async (t) => {
  let forbiddenTrailer = false;
  const clock = createSystemClock();
  const gh = await startGitHubFixture(t, {
    clock,
    beforeMetadataResponse({ response }) {
      if (forbiddenTrailer) {
        response.addTrailers({ "x-allowed-first": "one", "x-forbidden-last": "last" });
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
  assert.deepEqual(f.attachment.configuration.network_policies["oce-egress-0"].binaries, []);
  const peer = {
    ...installation.enforcement,
    sender: installation.sender,
    sandboxId: installation.sandboxId,
    expiresAt: new Date(Date.now() + 120000).toISOString(),
  };
  const { plan, enforcement } = installation;
  const associations = new Map();
  const fixtureAcceptance = {
    capture(use) {
      const accepted = {
        execution: plan.execution,
        installation: {
          sandboxId: peer.sandboxId,
          ...enforcement,
          plan: { id: plan.id, generation: plan.generation },
        },
        exchangeId: randomUUID(),
        responseId: randomUUID(),
        custodyId: randomUUID(),
      };
      associations.set(use.id, accepted);
      return accepted;
    },
    owns(value, use) {
      return JSON.stringify(value) === JSON.stringify(associations.get(use.id));
    },
  };
  const forwarder = f.controller.createEgressForwarder(
    { verify: async () => peer },
    fixtureAcceptance,
  );
  const signal = new AbortController().signal;
  async function resolve(overrides) {
    const input = {
      id: requestId(),
      method: "GET",
      url: route.origin + route.path,
      headers: [],
      body: new Uint8Array(),
      deadlineAt: new Date(Date.now() + 20000).toISOString(),
      ...overrides,
    };
    const ready = await forwarder.resolve("fixture peer", peer.sandboxId, input, signal);
    return {
      id: input.id,
      ready,
      authorize: () =>
        forwarder.authorizeSend(
          "fixture peer",
          peer.sandboxId,
          input.id,
          ready.handle,
          ready.evidence,
          ready.injectionDigest,
          input.deadlineAt,
          signal,
        ),
    };
  }

  assert.equal((await resolve()).ready.error.kind, "not_ready");
  assert.equal(reads, 1);
  assert.equal(gh.issuesOfTokens.length, 0, "cold capture must not issue or schedule");
  for (const changed of [
    { body: Buffer.from("x") },
    { method: "POST" },
    { headers: [["transfer-encoding", "chunked"]] },
    { url: route.origin + "/repos/other/repo" },
    ...[
      "/fixture/repository.git/info/refs?service=git-upload-pack",
      "/fixture/repository.git/git-upload-pack",
      "/fixture/repository.git/git-receive-pack",
    ].map((path) => ({ url: route.origin + path })),
  ]) {
    assert.equal((await resolve(changed)).ready.error.code, "unsupported_operation");
  }
  assert.equal(reads, 1, "wrong body, target or method touched prepared material");
  assert.equal(
    await owner.run("managed-prepare-1", { signal, deadlineMonoMs: clock.monotonicNow() + 20000 }),
    "committed",
  );
  assert.equal(gh.issuesOfTokens.length, 1);

  for (const block of [false, true]) {
    forbiddenTrailer = block;
    const { id, ready, authorize } = await resolve();
    assert.equal(ready.kind, "ready");
    const sent = await authorize();
    assert.equal(sent.kind, "allow");
    const { response, chunks } = await new Promise((resolve, reject) => {
      get(
        route.origin + route.path,
        { ca: gh.tls.ca, headers: Object.fromEntries(ready.headers) },
        async (response) => {
          const chunks = [];
          for await (const chunk of response) {
            chunks.push(chunk);
          }
          resolve({ response, chunks });
        },
      ).on("error", reject);
    });
    assert.equal(response.statusCode, 200, "real provider must accept prepared credential");
    assert.equal(response.trailers["x-forbidden-last"], block ? "last" : undefined);
    const handle = await forwarder.beginResponse("fixture peer", peer.sandboxId, id);
    const safe = await forwarder.protectResponse(
      handle,
      {
        status: response.statusCode,
        headers: Object.entries(response.headers),
        body: Buffer.concat(chunks),
        trailers: Object.entries(response.trailers),
      },
      signal,
    );
    if (block) {
      assert.equal(safe, undefined);
    } else {
      assert.equal(
        safe.body.toString(),
        JSON.stringify({ id: Number(fixtureRepositoryId), full_name: fixtureRepository }),
      );
    }
  }
  const { authorize } = await resolve();
  await store.transact(admission.familyId, (row) => {
    row.enabled = false;
  });
  const withdrawn = await authorize();
  assert.equal(withdrawn.kind, "refused");
  assert.equal(withdrawn.error.code, "withdrawn");
  assert.equal(sendChecks, 3);
  assert.equal(gh.issuesOfTokens.length, 1, "no request may renew or issue");
});
