import assert from "node:assert/strict";
import test from "node:test";
import { grpc, invoke, openShellOnlineWire, token } from "../helpers/openshell-online-wire.mjs";

const contract = "openshell.supervisor-middleware.contract";
const registrationName = "online-authorization";
const binding = { fields: { binding_id: { stringValue: "binding_0123456789abcdefghijklmn" } } };

test(
  "stock pre-credential wire rechecks a current grant and rejects identity and request mismatches",
  { timeout: 10000 },
  async (t) => {
    const seen = [];
    const cancellationStarted = Promise.withResolvers();
    const cancellationObserved = Promise.withResolvers();
    let grant = true;
    const { client, keys } = await openShellOnlineWire(t, registrationName, {
      budgetMs: 100,
      authorize: async (request, signal) => {
        seen.push(request);
        if (request.requestId === "error") {
          throw new Error("authorization unavailable");
        }
        if (request.requestId === "cancel") {
          cancellationStarted.resolve();
          await new Promise((resolve) =>
            signal.addEventListener(
              "abort",
              () => {
                cancellationObserved.resolve();
                resolve();
              },
              { once: true },
            ),
          );
        }
        if (request.requestId === "budget") {
          await new Promise((resolve) => signal.addEventListener("abort", resolve, { once: true }));
        }
        if (request.requestId === "late-allow") {
          // A synchronous authorizer can outlast the budget before its timer callback runs.
          Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 150);
        }
        return grant &&
          request.sandboxId === "immutable-sandbox-id" &&
          request.bindingId === "binding_0123456789abcdefghijklmn" &&
          request.target.path === "/v1/status"
          ? "allow"
          : "deny";
      },
    });
    const gateway = token(keys, "gateway");
    const supervisor = token(keys, "supervisor", "immutable-sandbox-id");
    const describe = {
      gateway: {
        protocol_version: { major: 1, minor: 0 },
        supported_capabilities: [contract],
        required_capabilities: [contract],
      },
    };
    const manifest = await invoke(client, "Describe", describe, gateway);
    assert.equal(manifest.expected_audience, "online-authorizer");
    assert.deepEqual(
      manifest.bindings.map(({ operation, phase }) => [operation, phase]),
      [[1, 1]],
    );
    assert.deepEqual(manifest.extension.required_capabilities, [contract]);
    assert.deepEqual(
      (await invoke(client, "Describe", describe, supervisor)).bindings,
      manifest.bindings,
    );
    await assert.rejects(
      invoke(client, "Describe", describe, token(keys, "gateway", undefined, "wrong-audience")),
      { code: grpc.status.PERMISSION_DENIED },
    );
    assert.equal(
      (
        await invoke(
          client,
          "ValidateConfig",
          { middleware_name: registrationName, config: binding },
          gateway,
        )
      ).valid,
      true,
    );
    assert.equal(
      (
        await invoke(
          client,
          "ValidateConfig",
          { middleware_name: registrationName, config: { fields: {} } },
          gateway,
        )
      ).valid,
      false,
    );
    const request = {
      phase: 1,
      middleware_name: registrationName,
      context: {
        request_id: "request-1",
        sandbox_id: "immutable-sandbox-id",
        sandbox: "reusable-name",
      },
      config: binding,
      target: {
        scheme: "https",
        host: "api.example.test",
        port: 443,
        method: "GET",
        path: "/v1/status",
      },
    };
    assert.deepEqual(await invoke(client, "EvaluateHttpRequest", request, supervisor), {
      decision: 1,
    });
    assert.deepEqual(seen[0], {
      sandboxId: "immutable-sandbox-id",
      bindingId: "binding_0123456789abcdefghijklmn",
      requestId: "request-1",
      target: {
        reportedScheme: "https",
        host: "api.example.test",
        port: 443,
        method: "GET",
        path: "/v1/status",
        query: "absent_or_empty",
      },
    });
    // The same unexpired bearer cannot retain an allowance after the grant is withdrawn.
    grant = false;
    assert.equal((await invoke(client, "EvaluateHttpRequest", request, supervisor)).decision, 2);
    assert.equal(seen.length, 2);
    grant = true;
    const spoofed = { ...request, context: { ...request.context, sandbox_id: "different-id" } };
    assert.equal((await invoke(client, "EvaluateHttpRequest", spoofed, supervisor)).decision, 2);
    assert.equal((await invoke(client, "EvaluateHttpRequest", request, gateway)).decision, 2);
    for (const changed of [
      { ...request, body: Buffer.from("payload") },
      { ...request, target: { ...request.target, query: "scope=other" } },
      { ...request, target: { ...request.target, method: "POST" } },
      { ...request, target: { ...request.target, scheme: "http" } },
    ]) {
      assert.equal((await invoke(client, "EvaluateHttpRequest", changed, supervisor)).decision, 2);
    }
    assert.equal(
      seen.length,
      2,
      "unsupported and unauthenticated requests never reach current authority",
    );
    const differentSandbox = token(keys, "supervisor", "different-id");
    assert.equal(
      (await invoke(client, "EvaluateHttpRequest", spoofed, differentSandbox)).decision,
      2,
    );
    // Independently issued tokens for the same sandbox cannot distinguish supervisor instances.
    const sameSandbox = token(keys, "supervisor", "immutable-sandbox-id");
    assert.notEqual(sameSandbox, supervisor);
    assert.equal((await invoke(client, "EvaluateHttpRequest", request, sameSandbox)).decision, 1);
    const unknownBinding = {
      ...request,
      config: { fields: { binding_id: { stringValue: "unknown_0123456789abcdefghijklmn" } } },
    };
    assert.equal(
      (await invoke(client, "EvaluateHttpRequest", unknownBinding, supervisor)).decision,
      2,
    );
    const error = { ...request, context: { ...request.context, request_id: "error" } };
    assert.equal((await invoke(client, "EvaluateHttpRequest", error, supervisor)).decision, 2);
    const budget = { ...request, context: { ...request.context, request_id: "budget" } };
    assert.equal((await invoke(client, "EvaluateHttpRequest", budget, supervisor)).decision, 2);
    const lateAllow = { ...request, context: { ...request.context, request_id: "late-allow" } };
    assert.equal((await invoke(client, "EvaluateHttpRequest", lateAllow, supervisor)).decision, 2);
    const metadata = new grpc.Metadata();
    metadata.set("authorization", supervisor);
    let pendingCall;
    const cancelledResult = new Promise((resolve, reject) => {
      pendingCall = client.EvaluateHttpRequest(
        { ...request, context: { ...request.context, request_id: "cancel" } },
        metadata,
        { deadline: Date.now() + 5000 },
        (failure, result) => (failure ? reject(failure) : resolve(result)),
      );
    });
    await Promise.race([cancellationStarted.promise, cancelledResult]);
    pendingCall.cancel();
    await assert.rejects(cancelledResult, { code: grpc.status.CANCELLED });
    await cancellationObserved.promise;
  },
);
