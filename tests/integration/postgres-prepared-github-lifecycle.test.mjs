import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { get } from "node:https";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { captureMetadata, dispatchMetadata } from "../helpers/github-metadata-exchange.mjs";
import { postgresApp } from "../helpers/postgres-egress-app.mjs";
import { requiresPostgres } from "../helpers/postgres-database.mjs";
import { staticEgressFixture } from "../helpers/static-egress.mjs";
import {
  startGitHubFixture,
  fixtureAppId,
  fixtureInstallationId,
  fixtureRepositoryId,
  fixtureRepository,
} from "../fixtures/repository-credentials/github.mjs";
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
    const gh = await startGitHubFixture(t, {
      clock: createSystemClock(),
      tokenLifetimeMs: 9 * 60_000,
    });
    const secretValue = gh.privateKey.export({ format: "pem", type: "pkcs8" });
    let lifecycle;
    let secretDriver;
    let issuer;
    let source;
    let registration;
    const createOwner = () =>
      new PostgresPreparedGitHubLifecycle(key, secretDriver, gh.origin, gh.tls.ca);
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
    const firstReads = f.secretReads;
    assert.equal(await lifecycle.ready(source, signal), false);
    assert.equal(await lifecycle.readWarm(source, signal), undefined);
    assert.equal(f.secretReads, firstReads, "cold request read the issuer Secret");
    assert.equal(
      gh.issuesOfTokens.length,
      0,
      "source registration or cold access issued at provider",
    );

    // Two workers race over a real family. Only the durable claim holder reaches the issuer.
    const results = await Promise.all([lifecycle.maintain(signal), lifecycle.maintain(signal)]);
    assert.deepEqual(results.sort(), ["committed", "idle"]);
    const old = await lifecycle.readWarm(source, signal);
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
    assert.equal((await fresh.readWarm(source, signal)).materialVersion, old.materialVersion);
    assert.equal(f.secretReads, beforeRestartRead);
    assert.equal(gh.issuesOfTokens.length, 1);
    const due = () =>
      f.pool.query(
        "UPDATE occ.prepared_github_families SET next_check_at=now() WHERE source_id=$1",
        [source.key.source.id],
      );
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
    const renewed = await fresh.readWarm(source, signal);
    assert.notEqual(renewed.materialVersion, old.materialVersion);
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
    const rotated = await fresh.readWarm(source, signal);
    assert.equal(rotated.ownerEpoch, 2);
    assert.notEqual(rotated.inputVersion, old.inputVersion);
    assert.equal(await status(rotated.value), 200);
    await fresh.withdraw(source, signal);
    assert.equal(await fresh.ready(source, signal), false);
    assert.equal(await fresh.readWarm(source, signal), undefined);
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
    assert.equal(await lifecycle.readWarm(lost, signal), undefined);
    await assert.rejects(lifecycle.withdraw(lost, signal), /unsettled provider attempt/);
    assert.deepEqual(gh.errors, []);
  },
);
