import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { createServer, get } from "node:https";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { captureMetadata, dispatchMetadata } from "../helpers/github-metadata-exchange.mjs";
import { postgresApp } from "../helpers/postgres-egress-app.mjs";
import { requiresPostgres } from "../helpers/postgres-database.mjs";
import { staticEgressFixture, wireTime } from "../helpers/static-egress.mjs";
import {
  startGitHubFixture,
  fixtureAppId,
  fixtureInstallationId,
  fixtureRepositoryId,
  fixtureRepository,
} from "../fixtures/repository-credentials/github.mjs";
import { listen } from "../fixtures/repository-credentials/process.mjs";
import { createSystemClock } from "../../apps/controller/src/drivers/repo/credentials/clock.ts";
import { PostgresPreparedGitHubLifecycle } from "../../apps/controller/src/drivers/repo/github/credentials/prepared-lifecycle.ts";

test(
  "PostgreSQL prepared custody: source consent, proactive renewal, restart, issuer rotation and withdrawal",
  requiresPostgres,
  async (t) => {
    // Both keys are generated here. Only the dedicated issuer Secret receives the private App key.
    const dir = await mkdtemp(join(tmpdir(), "occ-prepared-gh-"));
    t.after(() => rm(dir, { recursive: true, force: true }));
    const key = join(dir, "custody.key");
    await writeFile(key, randomBytes(32), { mode: 0o600 });
    // A nine-minute provider lifetime puts renewal inside the owner's ten-minute lead.
    let invalidScope = false;
    const gh = await startGitHubFixture(t, {
      clock: createSystemClock(),
      tokenLifetimeMs: 9 * 60_000,
      tokenResponse: (packet) => (invalidScope ? { ...packet, repositories: [] } : packet),
    });
    const secretValue = gh.privateKey.export({ format: "pem", type: "pkcs8" });
    let lifecycle;
    let secretDriver;
    let issuer;
    let source;
    let registration;
    const createOwner = (origin = gh.origin) =>
      new PostgresPreparedGitHubLifecycle(key, secretDriver, origin, gh.tls.ca);
    const f = await staticEgressFixture(t, {
      secretValue,
      createPreparedGitHub(opts) {
        secretDriver = opts.secretDriver;
        lifecycle = createOwner();
        return lifecycle;
      },
      async appFactory(t, opts) {
        const app = await postgresApp(t, opts);
        await lifecycle.connect(app.pool);
        t.after(() => lifecycle.close());
        return app;
      },
      async admitSource({ app, agent, namespace, secret, path }) {
        issuer = secret;
        const created = await app.request("POST", path, {
          body: (registration = {
            type: "github-app-metadata",
            name: "prepared-repository",
            config: {
              authority: "execution",
              app_id: fixtureAppId,
              installation_id: fixtureInstallationId,
              repository_id: fixtureRepositoryId,
              repository: fixtureRepository,
              agent_id: agent.id,
            },
            secrets: { private_key: secret.ref },
          }),
        });
        assert.equal(created.status, 201);
        source = created.data;
        const bound = await app.request("PATCH", `/namespaces/${namespace.id}/agents/${agent.id}`, {
          body: {
            configurationId: agent.configurationId,
            harnessAuth: { method: "runtime" },
            credentialSources: [{ sourceId: source.id }],
          },
        });
        assert.equal(bound.status, 200);
        return { agent: bound.data, source };
      },
    });
    source = (
      await f.state.read((v) => v.credentialSources.findCredentialSource(f.namespace.id, source.id))
    ).egress;
    const signal = new AbortController().signal;
    const deadlineAt = () => new Date(Date.now() + 20_000).toISOString();
    const firstReads = f.secretReads;
    assert.equal(await lifecycle.ready(source, signal), false);
    assert.equal(await lifecycle.readWarm(source, { signal, deadlineAt: deadlineAt() }), undefined);
    assert.equal(f.secretReads, firstReads, "cold request read the issuer Secret");
    assert.equal(
      gh.issuesOfTokens.length,
      0,
      "source registration or cold access issued at provider",
    );

    // Two workers race over a real family. Only the durable claim holder reaches the issuer.
    const results = await Promise.all([lifecycle.maintain(signal), lifecycle.maintain(signal)]);
    assert.deepEqual(results.sort(), ["committed", "idle"]);
    const old = await lifecycle.readWarm(source, { signal, deadlineAt: deadlineAt() });
    assert.equal(old.ownerEpoch, 1);
    assert.deepEqual(gh.issuesOfTokens[0].permissions, { metadata: "read" });
    // Use OCE's actual signed exchange owner, not a second fixture acceptance or a unary sender.
    const captured = captureMetadata(f);
    const { ready } = await f.resolve(captured);
    assert.ok(ready, "signed resolve must select the prepared family");
    const evidence = JSON.parse(ready.evidence.authority_evidence);
    assert.equal(await lifecycle.current(source, evidence, signal), true);
    await t.test(
      "signed PostgreSQL dispatch permits exact prepared material on the accepted exchange",
      async () => {
        const safe = await dispatchMetadata(f, gh, captured, ready);
        assert.equal(
          safe.body.toString(),
          JSON.stringify({ id: Number(fixtureRepositoryId), full_name: fixtureRepository }),
        );
      },
    );
    await t.test(
      "signed access and material expiry bound ciphertext selection, projection and decryption",
      async (t) => {
        const repo = lifecycle.repository;
        const transaction = repo.transaction.bind(repo);
        const open = t.mock.method(repo, "open");
        let deadline;
        let arm;
        const pastDeadline = () => delay(Math.max(0, deadline - Date.now() + 100));
        let projected;
        let queryInTime;
        // Delay real PostgreSQL at three distinct boundaries. Record presence, never the bytes.
        t.mock.method(repo, "transaction", (work) =>
          transaction((client) =>
            work({
              async query(sql, args) {
                const material = sql.includes("END AS sealed");
                if (material) {
                  queryInTime = Date.now() < deadline;
                  if (arm === "before projection") {
                    await pastDeadline();
                  }
                }
                const result = await client.query(sql, args);
                if (material) {
                  projected = result.rows.some((row) => row.sealed != null);
                  if (arm === "after projection") {
                    await pastDeadline();
                  }
                } else if (arm === "after metadata" && sql.startsWith("SELECT f.admission,id,")) {
                  await pastDeadline();
                }
                return result;
              },
            }),
          ),
        );
        for (const bound of ["signed deadline", "material expiry"]) {
          for (const boundary of [
            "control",
            "after metadata",
            "before projection",
            "after projection",
          ]) {
            await t.test(`${bound}: ${boundary}`, async () => {
              arm = boundary;
              const request = captureMetadata(f);
              deadline = Date.now() + 1300;
              request.deadline = wireTime(
                bound === "signed deadline" ? deadline : Date.now() + 20_000,
              );
              queryInTime = projected = undefined;
              open.mock.resetCalls();
              const issues = gh.issuesOfTokens.length;
              const reads = f.secretReads;
              try {
                if (bound === "material expiry") {
                  // Shorten the real committed row before selection. Both reads see this same
                  // bound; the gate then lets time expire on the designated side of projection.
                  await f.pool.query(
                    "UPDATE occ.prepared_github_attempts SET usable_until=$1 WHERE material_version=$2",
                    [new Date(deadline), old.materialVersion],
                  );
                }
                const result = await f.resolve(request);
                if (arm === "control") {
                  assert.ok(
                    result.ready && queryInTime && projected,
                    "ordinary signed access must work",
                  );
                  assert.equal(open.mock.callCount(), 1);
                } else {
                  assert.equal(
                    result.refused?.code,
                    f.refusalCode(bound === "signed deadline" ? "DEADLINE_EXCEEDED" : "NOT_READY"),
                    arm + ": refusal follows the bound that expired",
                  );
                  const queried = arm !== "after metadata";
                  assert.deepEqual(
                    { queryInTime, projected, opens: open.mock.callCount() },
                    {
                      queryInTime: queried ? true : undefined,
                      projected: queried ? arm === "after projection" : undefined,
                      opens: 0,
                    },
                    arm + ": no late ciphertext access or decryption",
                  );
                }
                assert.equal(gh.issuesOfTokens.length, issues, "request must not issue");
                assert.equal(f.secretReads, reads, "request must not read issuer Secret");
              } finally {
                if (bound === "material expiry") {
                  await f.pool.query(
                    "UPDATE occ.prepared_github_attempts SET usable_until=$1 WHERE material_version=$2",
                    [new Date(old.usableUntil), old.materialVersion],
                  );
                }
              }
            });
          }
        }
      },
    );
    const status = (value) =>
      new Promise((resolve, reject) => {
        get(
          `${gh.origin}/repos/${fixtureRepository}`,
          { ca: gh.tls.ca, headers: { authorization: "Bearer " + value } },
          (res) => {
            res.resume();
            res.once("end", () => resolve(res.statusCode));
          },
        ).once("error", reject);
      });
    assert.equal(
      await status(old.value),
      200,
      "actual token must be accepted for the exact metadata read",
    );
    const {
      rows: [{ sealed }],
    } = await f.pool.query(
      "SELECT sealed FROM occ.prepared_github_attempts WHERE material_version=$1",
      [old.materialVersion],
    );
    assert.equal(
      sealed.includes(Buffer.from(old.value)),
      false,
      "database stored bearer in plaintext",
    );

    // A new lifecycle instance has only the custody mount and PostgreSQL; warm access neither reads the root nor issues.
    const fresh = createOwner();
    await fresh.connect(f.pool);
    t.after(() => fresh.close());
    const beforeRestartRead = f.secretReads;
    assert.equal(await fresh.ready(source, signal), true);
    assert.equal(
      (await fresh.readWarm(source, { signal, deadlineAt: deadlineAt() })).materialVersion,
      old.materialVersion,
    );
    assert.equal(f.secretReads, beforeRestartRead);
    assert.equal(gh.issuesOfTokens.length, 1);
    const due = () =>
      f.pool.query(
        "UPDATE occ.prepared_github_families SET next_check_at=now() WHERE source_id=$1",
        [source.key.source.id],
      );
    let renewed;
    await t.test(
      "renewal after committed metadata cannot open replacement for the old request",
      async (t) => {
        const repo = lifecycle.repository;
        const metadata = repo.metadata.bind(repo);
        const transaction = repo.transaction.bind(repo);
        const selected = Promise.withResolvers();
        const resume = Promise.withResolvers();
        const open = t.mock.method(repo, "open");
        let projected = false;
        t.mock.method(
          repo,
          "metadata",
          async (...args) => {
            const result = await metadata(...args); // The real metadata transaction has committed.
            selected.resolve(result);
            await resume.promise;
            return result;
          },
          { times: 1 },
        );
        t.mock.method(repo, "transaction", (work) =>
          transaction((client) =>
            work({
              async query(sql, args) {
                const result = await client.query(sql, args);
                if (sql.includes("END AS sealed")) {
                  projected ||= result.rows.some((row) => row.sealed != null);
                }
                return result;
              },
            }),
          ),
        );
        const pending = f.resolve(captureMetadata(f));
        try {
          const selection = await Promise.race([
            selected.promise,
            pending.then(() => {
              throw new Error("request ended before selecting metadata");
            }),
          ]);
          assert.equal(selection.material_version, old.materialVersion);
          await due(); // Only advance the periodic scan, not eligibility, owner or any token bytes.
          const reports = [];
          fresh.startWorker((code) => reports.push(code));
          // Observe only the ledger. No request or readiness call drives this proactive renewal.
          const pollDeadline = Date.now() + 15_000;
          for (;;) {
            const {
              rows: [{ changed }],
            } = await f.pool.query(
              "SELECT count(*)=1 AS changed FROM occ.prepared_github_attempts WHERE custody='current' AND source_id=$1 AND material_version <> $2",
              [source.key.source.id, old.materialVersion],
            );
            if (changed) {
              break;
            }
            assert.ok(Date.now() < pollDeadline, "background loop did not proactively renew");
            await new Promise((resolve) => setTimeout(resolve, 50));
          }
          await fresh.close();
          await fresh.connect(f.pool);
          assert.deepEqual(reports, []);
          renewed = await fresh.readWarm(source, { signal, deadlineAt: deadlineAt() });
          assert.notEqual(renewed.materialVersion, old.materialVersion);
          const issues = gh.issuesOfTokens.length;
          const reads = f.secretReads;
          resume.resolve();
          const result = await pending;
          assert.equal(result.refused?.code, f.refusalCode("NOT_READY"));
          assert.deepEqual(
            { projected, opens: open.mock.callCount() },
            { projected: false, opens: 0 },
            "old selection must neither project nor open the replacement",
          );
          const next = await f.resolve(captureMetadata(f));
          assert.ok(next.ready, "a new request can select the replacement");
          assert.equal(
            JSON.parse(next.ready.evidence.authority_evidence).materialVersion,
            renewed.materialVersion,
          );
          assert.equal(open.mock.callCount(), 1);
          assert.equal(gh.issuesOfTokens.length, issues, "requests must not issue");
          assert.equal(f.secretReads, reads, "requests must not read issuer Secret");
        } finally {
          resume.resolve();
          await pending;
        }
      },
    );
    // B is reachable with the same trusted CA and would falsely acknowledge A's revocation.
    // Record only whether a credential arrived. A client must not rely on B rejecting A's token.
    let credentialRequestsAtB = 0;
    const originB = await listen(
      t,
      createServer(gh.tls, (req, res) => {
        if (req.headers.authorization) {
          credentialRequestsAtB++;
        }
        res.writeHead(204).end();
      }),
    );
    const probeB = await new Promise((resolve, reject) => {
      get(originB, { ca: gh.tls.ca }, (res) => {
        res.resume();
        resolve(res.statusCode);
      }).once("error", reject);
    });
    assert.equal(probeB, 204);
    const restartedAtB = createOwner(originB);
    await restartedAtB.connect(f.pool);
    t.after(() => restartedAtB.close());
    const pendingRetirements = async () =>
      (
        await f.pool.query(
          `SELECT id, state, encode(sha256(sealed), 'hex') AS envelope FROM occ.prepared_github_attempts
           WHERE source_id=$1 AND custody='retire' ORDER BY id`,
          [source.key.source.id],
        )
      ).rows;
    await t.test(
      "worker restart at B cannot disclose or settle A's routine retirement",
      async () => {
        const pendingAtA = await pendingRetirements();
        assert.deepEqual(
          pendingAtA.map((r) => r.state),
          ["committed"],
        );
        const attemptsAtA = gh.trace.length;
        const checksAtB = await restartedAtB.maintain(signal);
        assert.equal(credentialRequestsAtB, 0, "B received a credential from A");
        assert.equal(checksAtB, "issuer-mismatch");
        assert.equal(gh.trace.length, attemptsAtA, "stored origin must not redirect a worker to A");
        assert.deepEqual(
          await pendingRetirements(),
          pendingAtA,
          "custody or outcome changed under B",
        );
        assert.equal(await restartedAtB.ready(source, signal), false);
        assert.equal(
          Boolean(await restartedAtB.readWarm(source, { signal, deadlineAt: deadlineAt() })),
          false,
        );
        assert.equal(await status(old.value), 200, "A still accepts the displaced token");
      },
    );
    await fresh.maintain(signal); // Drains the displaced token. GitHub confirms DELETE independently.
    assert.equal(await status(old.value), 401);
    assert.equal(await status(renewed.value), 200);

    // A genuine update advances the authoritative issuer resourceVersion even with identical PEM.
    const changed = await f.request("PATCH", `/namespaces/${f.namespace.id}/secrets/${issuer.id}`, {
      body: { value: secretValue },
    });
    assert.equal(changed.status, 200);
    await due();
    assert.equal(await fresh.maintain(signal), "committed");
    const rotated = await fresh.readWarm(source, { signal, deadlineAt: deadlineAt() });
    assert.equal(rotated.ownerEpoch, 2);
    assert.notEqual(rotated.inputVersion, old.inputVersion);
    assert.equal(await status(rotated.value), 200);
    // A issued a real token, but its response cannot qualify the token for use. Withdrawal
    // under B must preserve that exceptional cleanup candidate and A's now-displaced current token.
    invalidScope = true;
    await due();
    assert.equal(await fresh.maintain(signal), "quarantined");
    invalidScope = false;
    await t.test(
      "API restart at B cannot disclose A's quarantined issuance during withdrawal",
      async () => {
        const pending = await pendingRetirements();
        assert.deepEqual(
          pending.map((r) => r.state),
          ["quarantined"],
        );
        const attemptsAtA = gh.trace.length;
        await assert.rejects(restartedAtB.withdraw(source, signal), /unsettled provider attempt/);
        assert.equal(credentialRequestsAtB, 0, "B received A's exceptional pending credential");
        assert.equal(gh.trace.length, attemptsAtA);
        const kept = await pendingRetirements();
        assert.deepEqual(kept.map((r) => r.state).sort(), ["committed", "quarantined"]);
        assert.deepEqual(
          kept.find((r) => r.id === pending[0].id),
          pending[0],
        );
        assert.equal(
          gh.tokenState().filter((r) => !r.revoked).length,
          2,
          "A still owns both live tokens",
        );
      },
    );
    await fresh.withdraw(source, signal);
    assert.equal(
      gh.tokenState().every((r) => r.revoked),
      true,
      "only A can confirm both retirements",
    );
    assert.deepEqual(await pendingRetirements(), []);
    assert.equal(await fresh.ready(source, signal), false);
    assert.equal(await fresh.readWarm(source, { signal, deadlineAt: deadlineAt() }), undefined);
    assert.equal(
      await status(rotated.value),
      401,
      "withdrawal must revoke the actual provider credential",
    );
    // Lose the response *after* the synthetic provider owns the token. A different worker must
    // observe the durable quarantine, never issue again, and never claim remote revocation.
    const path = `/namespaces/${f.namespace.id}/credential-sources`;
    const second = await f.request("POST", path, {
      body: { ...registration, name: "prepared-lost-response" },
    });
    assert.equal(second.status, 201);
    const lost = (
      await f.state.read((v) =>
        v.credentialSources.findCredentialSource(f.namespace.id, second.data.id),
      )
    ).egress;
    const issuedBefore = gh.issuesOfTokens.length;
    gh.disconnectAfterMutation("POST", `/app/installations/${fixtureInstallationId}/access_tokens`);
    assert.equal(await fresh.maintain(signal), "quarantined");
    assert.equal(
      gh.issuesOfTokens.length,
      issuedBefore + 1,
      "provider must have issued before disconnect",
    );
    source = lost;
    await due();
    assert.equal(
      await lifecycle.maintain(signal),
      "blocked",
      "must not replay the uncertain issuance",
    );
    assert.equal(gh.issuesOfTokens.length, issuedBefore + 1);
    assert.equal(await lifecycle.readWarm(lost, { signal, deadlineAt: deadlineAt() }), undefined);
    await assert.rejects(lifecycle.withdraw(lost, signal), /unsettled provider attempt/);
    await t.test("a lost retirement commit receipt clears the unreceived candidate", async (t) => {
      // An out-of-scope issuance leaves a real cleanup candidate for the next worker pass.
      const retiring = await f.request("POST", path, {
        body: { ...registration, name: "prepared-lost-retirement-commit" },
      });
      assert.equal(retiring.status, 201);
      invalidScope = true;
      assert.equal(await fresh.maintain(signal), "quarantined");

      // Let PostgreSQL commit the claim, then lose its acknowledgment at the client boundary.
      // Observe the exact buffer open() returned, without copying or printing its contents.
      const open = t.mock.method(fresh.repository, "open");
      const client = await f.pool.connect();
      const query = client.query.bind(client);
      let bytes;
      t.mock.method(client, "query", async (sql, ...args) => {
        const result = await query(sql, ...args);
        if (sql === "COMMIT") {
          bytes = open.mock.calls[0].result;
          assert.ok(
            bytes.some((byte) => byte !== 0),
            "claim must have opened live bytes",
          );
          throw Object.assign(new Error("commit acknowledgment lost"), { code: "08007" });
        }
        return result;
      });
      t.mock.method(f.pool, "connect", () => client, { times: 1 });
      const providerCalls = gh.trace.length;
      await assert.rejects(
        fresh.maintain(signal),
        /custody transaction did not complete \(08007\)/,
      );
      assert.equal(gh.trace.length, providerCalls, "an uncertain claim must not reach the issuer");
      assert.ok(
        bytes.every((byte) => byte === 0),
        "unreceived retirement bytes were not cleared",
      );
    });
    assert.deepEqual(gh.errors, []);
  },
);
