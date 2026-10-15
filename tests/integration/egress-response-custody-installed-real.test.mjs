import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { isAbsolute } from "node:path";
import test from "node:test";
import {
  repository,
  startCustodyRepositoryOrigin,
} from "../fixtures/egress-custody-repository-origin.mjs";
import {
  arrangeRealPrerequisites,
  createRunEvidence,
  observePreparedStack,
} from "../helpers/egress-installed-stack.mjs";
import { registerCleanupAndStartProvider } from "../helpers/egress-installed-agent.mjs";
import {
  admitRepositoryAgent,
  activateRepositoryAgent,
  restartDedicatedAuthority,
} from "../helpers/egress-custody-installed-agent.mjs";
import {
  agentClients,
  assertIdentityResponse,
  exactTransitions,
  faultObserver,
  receipts,
  refusal,
  supplierEvents,
  tryDirectTcp,
} from "../helpers/egress-custody-observations.mjs";

const selected = process.env.OCC_TEST_EGRESS_CUSTODY_INSTALLED === "1";
test(
  "installed protected repository read binds execution, exact dispatch and final response",
  {
    skip: selected ? false : "Dedicated installed-custody lane requires a fresh disposable pair.",
    timeout: 36 * 60_000,
  },
  async (t) => {
    const progress = { stage: "input-preflight" };
    // Assertions/subprocess errors may carry provider or proof bytes. Only disclose a
    // source location and durable phase. Abort after a failed child; do not replay it.
    const safeError = (error) => {
      const at = error.stack?.match(/egress-[\w.-]+\.mjs:\d+:\d+/)?.[0] ?? "external-operation";
      return Error(
        "Installed custody failed at " +
          progress.stage +
          " (" +
          at +
          "); inspect private phase ledger",
      );
    };
    const stage = async (name, fn) => {
      let failure;
      await t.test(name, async () => {
        progress.stage = name;
        try {
          await fn();
        } catch (error) {
          failure = safeError(error);
          throw failure;
        }
      });
      if (failure) {
        throw failure;
      }
    };
    try {
      const socket = process.env.OCC_TEST_EGRESS_DISPATCH_OBSERVER_SOCKET;
      assert.ok(isAbsolute(socket));
      const fault = (cmd) => faultObserver(socket, cmd);
      assert.deepEqual(
        await fault(),
        { authorizations: 0, observed: false, armed: false },
        "fresh dedicated dispatch observer",
      );
      const setup = await arrangeRealPrerequisites(
        t,
        progress,
        process.env.OCC_TEST_EGRESS_CONNECTED_INPUTS,
        { wholeExecution: true },
      );
      assert.equal(
        execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim(),
        setup.input.oceCommit,
      );
      const evidence = await createRunEvidence(t, setup, progress);
      const stack = await observePreparedStack(t, setup, evidence, progress);
      const owned = await registerCleanupAndStartProvider(
        t,
        setup,
        stack,
        evidence,
        startCustodyRepositoryOrigin,
      );
      const { provider } = owned;
      const admitted = await admitRepositoryAgent(setup, stack, evidence, owned);
      const activate = () => activateRepositoryAgent(setup, stack, evidence, owned, admitted);
      const installed = await activate();
      const clientFor = ({ harness }) =>
        agentClients(setup, stack, harness, provider.businessOrigin);
      const { curl, node, inAgent } = clientFor(installed);
      const events = (i = installed) => supplierEvents(setup, stack.placement, i.supervisor);
      const rows = (i = installed) => receipts(stack.pool, i.installation);
      const { checkpoint } = evidence;

      const exchange = async (client, expected, getResponse) => {
        const before = await events();
        const origin = provider.observations.length;
        const prior = await rows();
        const raw = await client();
        getResponse(raw);
        const id = exactTransitions(await events(), before, expected);
        const fresh = (await rows()).filter((row) => !prior.some((old) => old.id === row.id));
        assert.equal(fresh.length, 1, "one dispatch authorization for exactly this request");
        const [receipt] = fresh;
        assert.equal(receipt.id, id);
        assert.equal(
          receipt.exact,
          true,
          "receipt binds exact execution, installed peer, unique response custody and material family",
        );
        return { id, receipt, sends: provider.observations.slice(origin) };
      };
      const accepted = ["resolve_accepted", "permit_accepted", "response_released"];
      const verifyRead = async (client) => {
        const { id, receipt, sends } = await exchange(
          client,
          accepted,
          client === curl
            ? assertIdentityResponse
            : (raw) => {
                const result = JSON.parse(raw);
                assert.equal(result.status, 200);
                assert.ok(
                  result.body === JSON.stringify(repository),
                  "sibling receives exactly the approved repository identity",
                );
              },
        );
        assert.equal(sends.length, 1);
        assert.ok(sends[0].exactRead && sends[0].finished);
        assert.equal(receipt.observation.kind, "response");
        return id;
      };
      await stage(
        "two ordinary clients in the admitted execution receive only the selected repository identity",
        async () => {
          const first = await verifyRead(curl);
          const sibling = await verifyRead(node);
          assert.notEqual(first, sibling);
          assert.equal(
            (await fault()).authorizations,
            2,
            "positive control: target observer sees both actual installed dispatches",
          );
          await checkpoint("two-client-custody", {
            clientOperations: [first, sibling],
            authenticatedOriginReads: 2,
          });
        },
      );

      await stage(
        "unmanaged direct TCP cannot reach the independently observed permitted target",
        async () => {
          const observed = await tryDirectTcp(provider, setup.input.provider, inAgent);
          await checkpoint("direct-bypass", observed);
        },
      );

      await stage(
        "a forbidden final actual trailer reaches origin once and releases zero provider bytes",
        async () => {
          provider.forbiddenFinal();
          const expected = ["resolve_accepted", "permit_accepted", "response_blocked"];
          const { id, receipt, sends } = await exchange(curl, expected, (raw) =>
            assert.ok(raw === refusal, "complete fixed local error only"),
          );
          assert.equal(sends.length, 1, "one origin send, no retries");
          assert.ok(
            sends[0].exactRead &&
              sends[0].finished &&
              sends[0].actualLastTrailer === "x-fixture-forbidden-last",
            "origin flushed body, then forbidden final trailer on the actual TLS socket",
          );
          assert.deepEqual(receipt.observation, {
            kind: "response_blocked",
            dispatch: "confirmed",
            code: "response_policy",
          });
          provider.normal();
          await checkpoint("forbidden-final-actual-trailer", {
            requestId: id,
            authenticatedOriginReads: 1,
            providerBytesAtClient: 0,
          });
        },
      );

      await stage(
        "loss of the exact authorized dispatch COMMIT acknowledgement and authority restart produce no send",
        async () => {
          const instanceId = installed.installation.enforcement.instanceId;
          assert.equal((await fault("drop " + instanceId)).armed, true);
          const { id, receipt, sends } = await exchange(
            curl,
            ["resolve_accepted", "no_permit", "response_blocked"],
            (raw) => assert.ok(raw === refusal),
          );
          const proof = await fault();
          assert.deepEqual(proof.dropped, { instanceId, useId: id, attemptId: id });
          assert.equal(
            proof.observed,
            true,
            "real server COMMIT acknowledgement consumed, not an arbitrary disconnect",
          );
          assert.deepEqual(sends, []);
          assert.deepEqual(receipt.outcome, { kind: "uncertain", dispatch: "possible" });
          assert.equal(receipt.observation, null);
          assert.equal(receipt.settled, false);
          const before = provider.observations.length;
          const original = await rows();
          const transitions = await events();
          await checkpoint("exact-dispatch-commit-ack-consumed", {
            requestId: id,
            supplierNoPermit: 1,
            originReads: 0,
          });
          const restarted = await restartDedicatedAuthority(setup);
          assert.deepEqual(
            await rows(),
            original,
            "restart preserves uncertain dispatch, no repair/replay",
          );
          assert.deepEqual(await events(), transitions);
          // A new operation after restart bounds the no-retry observation and proves the
          // actual transport recovered. Never submit the uncertain operation a second time.
          assert.notEqual(await verifyRead(curl), id);
          assert.equal(
            provider.observations.length,
            before + 1,
            "post-restart positive control only, no replay of uncertain dispatch",
          );
          assert.deepEqual(
            (await rows()).find((r) => r.id === id),
            receipt,
          );
          await checkpoint("authority-restarted-uncertain-preserved", {
            ...restarted,
            requestId: id,
            oldPermits: 0,
            oldOriginReads: 0,
            newControlReads: 1,
          });
        },
      );

      await stage(
        "a replacement execution cannot inherit the old pending request or receive its late response",
        async () => {
          await verifyReplacement({
            activate,
            admitted,
            checkpoint,
            clientFor,
            curl,
            evidence,
            events,
            installed,
            owned,
            rows,
            setup,
            stack,
          });
        },
      );
      await checkpoint("installed-custody-observations-complete", { requiredObservations: 5 });
    } catch (error) {
      throw safeError(error);
    }
  },
);

async function verifyReplacement({
  activate,
  admitted,
  checkpoint,
  clientFor,
  curl,
  evidence,
  events,
  installed,
  owned,
  rows,
  setup,
  stack,
}) {
  const { provider } = owned;
  const held = provider.holdNext();
  const count = provider.observations.length;
  const baseline = await events();
  const start = Date.now();
  // Keep the *real* provider response unresolved across replacement. A transport
  // closing during rollout is safe; it must never be reassociated with the new sink.
  const original = curl().then(
    (raw) => {
      assert.ok(
        raw === refusal,
        "old sink may only observe the fixed refusal while its response is still withheld",
      );
      return "complete-local-refusal";
    },
    () => "old-client-transport-closed",
  );
  await held;
  const [atOrigin] = provider.observations.slice(count);
  assert.ok(
    atOrigin?.exactRead && !atOrigin.finished,
    "old authorized read actually pending at provider",
  );
  const old = exactTransitions(await events(), baseline, ["resolve_accepted", "permit_accepted"]);
  assert.ok((await rows()).some((r) => r.id === old && r.exact && !r.observation));
  await checkpoint("old-response-suspended-at-origin", { requestId: old, originReads: 1 });

  const replacement = await activate();
  assert.notEqual(installed.installation.sandboxId, replacement.installation.sandboxId);
  assert.notEqual(installed.harness.metadata.uid, replacement.harness.metadata.uid);
  assert.notEqual(installed.supervisor.metadata.uid, replacement.supervisor.metadata.uid);
  assert.notEqual(
    installed.installation.enforcement.instanceId,
    replacement.installation.enforcement.instanceId,
  );
  const pods = await setup.f.resources("pods", stack.placement);
  assert.ok(
    !pods.some((p) => p.metadata.uid === installed.harness.metadata.uid),
    "old workload gone, not merely another sibling",
  );
  const oldClient = await original;
  // A legitimate replacement with its own live installation. Remove the exact
  // grant to make inheriting the old operation distinguishable from fresh authorization.
  await evidence.api(
    "DELETE",
    stack.namespacePath + "/iam/access-bindings/" + admitted.binding.id,
    undefined,
    204,
  );
  const first = await events(replacement);
  const prior = await rows(replacement);
  const attempt = clientFor(replacement).curl();
  provider.release();
  const raw = await attempt;
  assert.ok(
    raw === refusal,
    "replacement client receives complete fixed local error and zero old provider bytes",
  );
  const id = exactTransitions(await events(replacement), first, [
    "resolve_refused",
    "no_permit",
    "response_blocked",
  ]);
  assert.notEqual(id, old);
  assert.equal(
    provider.observations.length,
    count + 1,
    "only the old read reached origin; no inherited request or autonomous retry",
  );
  assert.deepEqual(
    await rows(replacement),
    prior,
    "refused before selecting material or reserving dispatch in new installation",
  );
  const denied = (
    await stack.pool.query(
      `
    SELECT outcome, details->>'phase' AS phase, details->>'code' AS code FROM occ.audit_events
    WHERE namespace_id=$1 AND actor_id=$2 AND resource_id=$3 AND action='openclaw.egress.authorize'
          AND details->>'requestId'=$4 AND details->>'revisionId'=$5`,
      [
        stack.namespace.id,
        admitted.agent.servicePrincipalId,
        admitted.source.id,
        id,
        replacement.revision.id,
      ],
    )
  ).rows;
  assert.deepEqual(
    denied,
    [{ outcome: "denied", phase: "before_access", code: "unauthorized" }],
    "affirmative OCC denial before material access for this actual replacement request",
  );
  const oldReceipt = (await rows()).find((r) => r.id === old);
  assert.ok(
    oldReceipt?.exact && oldReceipt.observation?.kind !== "response",
    "late old response not transferred",
  );
  await checkpoint("replacement-denied-before-material", {
    oldRequestId: old,
    replacementRequestId: id,
    responseHeldThroughReplacementMs: Date.now() - start,
    oldClient,
    replacementMaterialAccess: 0,
    replacementOriginReads: 0,
    replacementProviderBytes: 0,
  });
}
