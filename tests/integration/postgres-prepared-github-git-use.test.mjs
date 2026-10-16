import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { requiresPostgres } from "../helpers/postgres-database.mjs";
import { fixture, prepare } from "../fixtures/prepared-repository-git.mjs";

test(
  "prepared Git use binds durable admission, exact ref, session and one exchange before retirement",
  {
    ...requiresPostgres,
    timeout: 60_000,
  },
  async (t) => {
    const f = await fixture(t);
    const familyRows = () =>
      f.pool.query("SELECT enabled FROM occ.prepared_github_families WHERE source_id=$1", [
        f.familyId,
      ]);
    assert.deepEqual((await familyRows()).rows, []);
    const beforeCold = f.gh.trace.length;
    await assert.rejects(
      f.owner.use(f.request()),
      /custody transaction did not complete \(guard\)/,
    );
    assert.equal(f.gh.trace.length, beforeCold, "cold use must not call the provider");
    assert.equal(f.gh.issuesOfTokens.length, 0);
    assert.deepEqual((await familyRows()).rows, [], "cold use must not enroll a family");

    await prepare(f);
    const request = f.request({ operation: "receive-pack" });
    const beforeUse = f.gh.trace.length;
    const used = await f.owner.use(request);
    assert.equal(used.exchangeId, request.exchangeId);
    assert.equal(typeof used.value, "string");
    assert.ok(used.value.length > 0);
    assert.ok(used.preparationAttemptId);
    assert.ok(used.materialVersion);
    const receipt = (
      await f.pool.query(
        `SELECT admission_id, attempt_id, material_version, operation, request_digest_sha256
       FROM occ.prepared_repository_git_uses WHERE exchange_id=$1`,
        [request.exchangeId],
      )
    ).rows;
    assert.deepEqual(receipt, [
      {
        admission_id: f.admissionId,
        attempt_id: used.preparationAttemptId,
        material_version: used.materialVersion,
        operation: request.operation,
        request_digest_sha256: request.requestDigestSha256,
      },
    ]);
    const material = (
      await f.pool.query("SELECT sealed FROM occ.prepared_github_attempts WHERE id=$1", [
        used.preparationAttemptId,
      ])
    ).rows[0];
    assert.ok(material.sealed instanceof Uint8Array);
    assert.equal(
      material.sealed.includes(Buffer.from(used.value)),
      false,
      "custody must not persist plaintext bearer",
    );
    const sendStartBy = Date.parse(used.sendStartBy);
    assert.ok(sendStartBy > Date.now() && sendStartBy <= Date.parse(request.deadlineAt));
    assert.equal(f.gh.trace.length, beforeUse, "warm use must not contact the issuer");

    for (const [name, rejected, code] of [
      ["cross ref", f.request({ operation: "receive-pack", pushRef: "refs/heads/other" }), "guard"],
      ["cross session", f.request({ sessionId: `session-${randomUUID()}` }), "guard"],
      ["duplicate exchange", request, "23505"],
    ]) {
      await t.test(name, async () =>
        assert.rejects(f.owner.use(rejected), {
          message: `Prepared GitHub custody transaction did not complete (${code}).`,
        }),
      );
    }
    assert.equal(f.gh.trace.length, beforeUse, "denials must not issue or retire provider tokens");
    assert.equal(
      await f.providerStatus(used.value),
      200,
      "returned material is an actual issued token",
    );

    // Closing the authoritative attempt denies immediately, before the periodic worker runs.
    await f.withdraw();
    const beforeWithdrawalUse = f.gh.trace.length;
    await assert.rejects(
      f.owner.use(f.request()),
      /custody transaction did not complete \(guard\)/,
    );
    assert.equal(f.gh.trace.length, beforeWithdrawalUse);
    await f.owner.maintain();
    assert.equal(await f.providerStatus(used.value), 401, "withdrawal retires the provider token");
    assert.equal(f.gh.issuesOfTokens.length, 1, "withdrawal must never replace the token");
    assert.deepEqual(f.gh.errors, []);
  },
);

test(
  "prepared Git retirement with a lost provider acknowledgment never restores use or reissues",
  {
    ...requiresPostgres,
    timeout: 60_000,
  },
  async (t) => {
    const f = await fixture(t);
    await prepare(f);
    const used = await f.owner.use(f.request());
    await f.withdraw();
    // GitHub commits DELETE then drops its response. Real provider state, rather
    // than a patched owner return value, establishes the ambiguous outcome.
    f.gh.disconnectAfterMutation("DELETE", "/installation/token");
    await assert.rejects(f.owner.maintain());
    const retained = () =>
      f.pool.query(
        "SELECT custody, sealed IS NOT NULL AS retained FROM occ.prepared_github_attempts WHERE id=$1",
        [used.preparationAttemptId],
      );
    assert.deepEqual((await retained()).rows, [{ custody: "unknown", retained: true }]);
    assert.ok(
      f.gh.trace.some(
        (entry) => entry.method === "DELETE" && entry.target === "/installation/token",
      ),
    );
    assert.equal(await f.providerStatus(used.value), 401);
    await assert.rejects(
      f.owner.use(f.request()),
      /custody transaction did not complete \(guard\)/,
    );
    await f.owner.maintain();
    assert.deepEqual((await retained()).rows, [{ custody: "unknown", retained: true }]);
    await assert.rejects(
      f.owner.use(f.request()),
      /custody transaction did not complete \(guard\)/,
    );
    assert.equal(
      f.gh.issuesOfTokens.length,
      1,
      "ambiguous retirement cannot authorize replacement issuance",
    );
    assert.deepEqual(f.gh.errors, []);
  },
);

for (const change of ["repository binding withdrawn", "revision superseded", "session expired"]) {
  test(
    "prepared Git refuses the same open broker session after " + change,
    requiresPostgres,
    async (t) => {
      const f = await fixture(t, change === "session expired" ? { sessionLifetimeMs: 4200 } : {});
      await prepare(f);
      await f.owner.use(f.request());
      const { agent, revision, sessionId } = f;
      if (change === "session expired") {
        await new Promise((resolve) =>
          setTimeout(resolve, Math.max(0, f.deadlineWallMs + 25 - Date.now())),
        );
      } else {
        await f.state.transact(async (unit) => {
          if (change === "revision superseded") {
            const id = "rev_" + randomUUID();
            await unit.revisions.createRevision({ ...revision, id, revision: 2 });
            assert.ok(
              await unit.agents.compareAndSetActiveRevision(
                agent.namespaceId,
                agent.id,
                revision.id,
                id,
              ),
            );
          } else {
            // The State update made by PATCH Agent with its existing configurationId and repositoryBindings: [].
            // Do not close the broker, redeploy, or wait for background reconciliation to obtain this denial.
            const updated = await unit.agents.updateConfiguration(
              agent.namespaceId,
              agent.id,
              agent.configurationId,
              undefined,
              undefined,
              undefined,
              undefined,
              [],
            );
            assert.equal(updated.activeRevisionId, revision.id);
            assert.deepEqual(updated.repositoryBindings ?? [], []);
          }
        });
      }
      const before = f.gh.trace.length;
      const denied = () =>
        assert.rejects(f.owner.use(f.request()), /custody transaction did not complete \(guard\)/);
      await denied();
      const receipt = await f.pool.query(
        "SELECT state FROM occ.repository_broker_receipts WHERE session_id=$1",
        [sessionId],
      );
      assert.equal(receipt.rows[0].state, "active");
      assert.equal(f.gh.trace.length, before, "use contacted the provider");
      await f.owner.maintain();
      await denied();
      const family = await f.pool.query(
        "SELECT enabled FROM occ.prepared_github_families WHERE source_id=$1",
        [f.familyId],
      );
      assert.equal(
        family.rows[0].enabled,
        false,
        "withdrawal must fence the old family, not re-arm it",
      );
    },
  );
}
