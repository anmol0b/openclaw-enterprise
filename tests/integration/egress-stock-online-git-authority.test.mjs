import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { gzipSync } from "node:zlib";
import { createOpenShellOnlineGitAuthority } from "../../apps/controller/src/drivers/egress-proxy/openshell-online-git-authority.ts";
import { openShellOnlineGitWire } from "../helpers/openshell-online-git-wire.mjs";
import { invoke, token } from "../helpers/openshell-online-wire.mjs";

const binding = {
  sandboxId: "immutable-sandbox-id",
  bindingId: "binding_0123456789abcdefghijklmn",
  workspace: "team-workspace",
  executionId: "execution-one",
  sessionId: "session-one",
  providerInstanceId: "github-one",
  repositoryId: "42",
  grantId: "grant-one",
  repository: "example/project",
  pushRef: "refs/heads/review/task",
  pullRequestBase: "main",
  installed: { preparationAttemptId: "prepared-one", materialVersion: "version-one" },
};
const packet = (value) =>
  Buffer.from((Buffer.byteLength(value) + 4).toString(16).padStart(4, "0") + value);
function push(refs) {
  return Buffer.concat([
    ...refs.map((ref, i) =>
      packet(`${"0".repeat(40)} ${"1".repeat(40)} ${ref}${i === 0 ? "\0report-status" : ""}\n`),
    ),
    Buffer.from("0000"),
  ]);
}
function request(path, method = "GET", body = Buffer.alloc(0), headers = []) {
  return {
    phase: 1,
    middleware_name: "online-git",
    context: {
      sandbox_id: binding.sandboxId,
      request_id: randomUUID(),
      workspace: binding.workspace,
    },
    config: { fields: { binding_id: { stringValue: binding.bindingId } } },
    target: { scheme: "https", host: "github.com", port: 443, method, path },
    body,
    headers,
  };
}
const pushRequest = () =>
  request("/example/project.git/git-receive-pack", "POST", push([binding.pushRef]), [
    { name: "content-type", value: "application/x-git-receive-pack-request" },
  ]);

// Callback implementations deliberately model only the trusted owner boundary. These cases
// prove the RPC's parsing and decision handling, not database custody or actual OpenShell sends.
test(
  "signed stock Git RPC admits discovery, fetch and push, then honors live denial",
  { timeout: 10000 },
  async (t) => {
    const approvals = [];
    const identities = [];
    let current = true;
    let unavailable = false;
    const { client, keys } = await openShellOnlineGitWire(t, {
      lookupBinding: async (identity) => {
        identities.push(identity);
        return binding;
      },
      approve: async (q, installed) => {
        if (unavailable) {
          throw new Error("owner unavailable");
        }
        approvals.push({ q, installed });
        return current;
      },
    });
    const bearer = token(keys, "supervisor", binding.sandboxId);
    const evaluate = async (q, auth = bearer) =>
      (await invoke(client, "EvaluateHttpRequest", q, auth)).decision;
    for (const [service, expected] of [
      ["git-upload-pack", "advertise-upload-pack"],
      ["git-receive-pack", "advertise-receive-pack"],
    ]) {
      const discovery = request("/example/project.git/info/refs", "GET", Buffer.alloc(0), [
        { name: "user-agent", value: "git/2.55.0" },
        { name: "accept", value: "*/*" },
        { name: "accept-language", value: "en, *;q=0.9" },
        { name: "accept-encoding", value: "deflate, gzip, br, zstd" },
        { name: "pragma", value: "no-cache" },
        { name: "git-protocol", value: "version=2" },
      ]);
      discovery.target.query = `service=${service}`;
      assert.equal(await evaluate(discovery), 1);
      assert.equal(approvals.at(-1).q.operation, expected);
    }
    const fetch = request(
      "/example/project.git/git-upload-pack",
      "POST",
      Buffer.concat([packet(`want ${"1".repeat(40)}\n`), Buffer.from("0000"), packet("done\n")]),
      [{ name: "content-type", value: "application/x-git-upload-pack-request" }],
    );
    assert.equal(await evaluate(fetch), 1);
    assert.equal(approvals.at(-1).q.operation, "upload-pack");
    const send = pushRequest();
    assert.equal(await evaluate(send), 1);
    const { q, installed } = approvals.at(-1);
    assert.equal(q.operation, "receive-pack");
    assert.equal(q.sessionId, binding.sessionId);
    assert.equal(q.providerInstanceId, binding.providerInstanceId);
    assert.equal(q.repositoryId, binding.repositoryId);
    assert.equal(q.grantId, binding.grantId);
    assert.equal(q.pushRef, binding.pushRef);
    assert.deepEqual(installed, binding.installed);
    assert.match(q.exchangeId, /^[0-9a-f-]{36}$/);
    assert.match(q.requestDigestSha256, /^[0-9a-f]{64}$/);
    assert.deepEqual(identities.at(-1), {
      sandboxId: binding.sandboxId,
      bindingId: binding.bindingId,
      workspace: binding.workspace,
      requestId: send.context.request_id,
    });
    assert.ok(Date.parse(q.deadlineAt) > Date.now());
    // A new request using the same valid supervisor token must ask the owner again.
    current = false;
    assert.equal(await evaluate(pushRequest()), 2);
    assert.equal(
      await evaluate({ ...fetch, context: { ...fetch.context, request_id: randomUUID() } }),
      2,
    );
    current = true;
    unavailable = true;
    assert.equal(await evaluate(pushRequest()), 2);
  },
);

test(
  "stock Git refuses mixed refs, identity substitution and unsupported or ambiguous input before approval",
  { timeout: 10000 },
  async (t) => {
    let approvals = 0;
    const { client, keys } = await openShellOnlineGitWire(t, {
      lookupBinding: async () => binding,
      approve: async () => {
        approvals++;
        return true;
      },
    });
    const bearer = token(keys, "supervisor", binding.sandboxId);
    const evaluate = async (q, auth = bearer) =>
      (await invoke(client, "EvaluateHttpRequest", q, auth)).decision;
    const baseline = pushRequest();
    const cases = [
      { ...baseline, body: push([binding.pushRef, "refs/heads/main"]) },
      { ...baseline, body: push(["refs/heads/main", binding.pushRef]) },
      { ...baseline, body: Buffer.from("[REDACTED]") },
      { ...baseline, body: Buffer.alloc(4 * 1024 * 1024 + 1) },
      { ...baseline, context: { ...baseline.context, sandbox_id: "another-sandbox" } },
      { ...baseline, context: { ...baseline.context, workspace: "another-workspace" } },
      { ...baseline, context: { ...baseline.context, request_id: "" } },
      {
        ...baseline,
        config: { fields: { binding_id: { stringValue: "wrong_0123456789abcdefghijklmn" } } },
      },
      { ...baseline, target: { ...baseline.target, path: "/example/other.git/git-receive-pack" } },
      { ...baseline, target: { ...baseline.target, host: "other.example.test" } },
      { ...baseline, target: { ...baseline.target, scheme: "http" } },
      { ...baseline, target: { ...baseline.target, query: "extra=operation" } },
      { ...baseline, headers: [...baseline.headers, ...baseline.headers] },
      { ...baseline, headers: [...baseline.headers, { name: "content-encoding", value: "gzip" }] },
      {
        ...baseline,
        headers: [...baseline.headers, { name: "x-http-method-override", value: "DELETE" }],
      },
      { ...baseline, phase: 2 },
    ];
    for (const q of cases) {
      assert.equal(await evaluate(q), 2);
    }
    for (const query of [
      "service=[REDACTED]",
      "service=git-upload-pack&service=git-receive-pack",
      "service=git-upload-pack&extra=1",
    ]) {
      const q = request("/example/project.git/info/refs");
      q.target.query = query;
      assert.equal(await evaluate(q), 2);
    }
    assert.equal(await evaluate(baseline, token(keys, "gateway")), 2);
    const other = { ...baseline, context: { ...baseline.context, sandbox_id: "another-sandbox" } };
    assert.equal(await evaluate(other, token(keys, "supervisor", "another-sandbox")), 2);
    assert.equal(approvals, 0);
  },
);

test(
  "stock draft preconditions require exact canonical body and give the durable owner fresh server identities",
  { timeout: 10000 },
  async (t) => {
    const approvals = [];
    let allow = true;
    const { client, keys } = await openShellOnlineGitWire(t, {
      lookupBinding: async () => binding,
      approve: async (q) => {
        approvals.push(q);
        return allow;
      },
    });
    const bearer = token(keys, "supervisor", binding.sandboxId);
    const payload = {
      title: "Review task",
      head: "review/task",
      base: "main",
      body: "Ready for review.",
      draft: true,
      maintainer_can_modify: false,
    };
    const draft = (value) => {
      const q = request(
        "/repos/example/project/pulls",
        "POST",
        Buffer.from(typeof value === "string" ? value : JSON.stringify(value)),
        [{ name: "content-type", value: "application/json" }],
      );
      q.target.host = "api.github.com";
      return q;
    };
    const evaluate = async (q) => (await invoke(client, "EvaluateHttpRequest", q, bearer)).decision;
    const missingCanonical = { ...payload };
    delete missingCanonical.maintainer_can_modify;
    for (const value of [
      missingCanonical,
      { ...payload, draft: false },
      { ...payload, base: "release" },
      { ...payload, head: "other:review/task" },
      { ...payload, maintainer_can_modify: true },
      { ...payload, issue: 1 },
      `{"title":"Other",${JSON.stringify(payload).slice(1)}`,
      JSON.stringify(payload, null, 2),
      { ...payload, body: "x".repeat(64 * 1024) },
    ]) {
      assert.equal(await evaluate(draft(value)), 2);
    }
    assert.equal(approvals.length, 0);
    const q = draft(payload);
    assert.equal(await evaluate(q), 1);
    const first = approvals[0];
    assert.equal(first.operation, "create-draft-pull");
    assert.deepEqual(
      { ...first.pull, operationId: undefined },
      {
        apiOrigin: "https://api.github.com",
        repository: binding.repository,
        head: "review/task",
        base: "main",
        operationId: undefined,
      },
    );
    assert.match(
      first.pull.operationId,
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
    // The durable owner's refusal is final; this RPC neither retries nor claims a PR outcome.
    allow = false;
    assert.equal(await evaluate(q), 2);
    assert.equal(approvals.length, 2);
    assert.notEqual(first.pull.operationId, approvals[1].pull.operationId);
    assert.notEqual(first.exchangeId, approvals[1].exchangeId);
    assert.equal(first.requestDigestSha256, approvals[1].requestDigestSha256);
  },
);

test(
  "stock Git admits gzip only on the upload-pack negotiation, which it never inspects",
  { timeout: 10000 },
  async (t) => {
    const approvals = [];
    const { client, keys } = await openShellOnlineGitWire(t, {
      lookupBinding: async () => binding,
      approve: async (q) => {
        approvals.push(q);
        return true;
      },
    });
    const bearer = token(keys, "supervisor", binding.sandboxId);
    const evaluate = async (q) => (await invoke(client, "EvaluateHttpRequest", q, bearer)).decision;
    // Git's remote-curl gzips every upload-pack body over 1024 bytes (a clone of a repository
    // with ~20+ refs, or a fetch with a longer have list); stock OpenShell shows the header.
    const negotiation = Buffer.concat([
      ...Array.from({ length: 30 }, (_, i) => packet(`want ${i.toString(16).padStart(40, "0")}\n`)),
      Buffer.from("0000"),
      packet("done\n"),
    ]);
    assert.ok(negotiation.length > 1024);
    const fetch = (encoding, body = gzipSync(negotiation)) =>
      request("/example/project.git/git-upload-pack", "POST", body, [
        { name: "user-agent", value: "git/2.56.0" },
        { name: "accept", value: "application/x-git-upload-pack-result" },
        { name: "accept-encoding", value: "deflate, gzip, br, zstd" },
        { name: "content-type", value: "application/x-git-upload-pack-request" },
        ...[encoding].flat().map((value) => ({ name: "content-encoding", value })),
      ]);
    const plain = fetch([], negotiation);
    assert.equal(await evaluate(plain), 1);
    assert.equal(approvals.at(-1).operation, "upload-pack");
    for (const encoding of ["gzip", "GZip"]) {
      assert.equal(await evaluate(fetch(encoding)), 1);
      assert.equal(approvals.at(-1).operation, "upload-pack");
    }
    // The body is opaque to this route: a declared gzip body is not decoded or validated here.
    assert.equal(await evaluate(fetch("gzip", Buffer.from("not gzip"))), 1);
    // The digest binds the declared encoding, so it differs from the identical plain bytes.
    const digests = new Set(approvals.map((q) => q.requestDigestSha256));
    assert.equal(digests.size, approvals.length);
    const granted = approvals.length;
    const discovery = request("/example/project.git/info/refs", "GET", Buffer.alloc(0), [
      { name: "content-encoding", value: "gzip" },
    ]);
    discovery.target.query = "service=git-upload-pack";
    const send = pushRequest();
    const draft = request(
      "/repos/example/project/pulls",
      "POST",
      Buffer.from(
        JSON.stringify({
          title: "Review task",
          head: "review/task",
          base: "main",
          body: "Ready for review.",
          draft: true,
          maintainer_can_modify: false,
        }),
      ),
      [{ name: "content-type", value: "application/json" }],
    );
    draft.target.host = "api.github.com";
    assert.equal(await evaluate(draft), 1);
    const denied = [
      ...["br", "deflate", "x-gzip", "identity", "gzip, gzip", "gzip,gzip", " gzip", ""].map(
        (encoding) => fetch(encoding),
      ),
      fetch(["gzip", "gzip"]),
      fetch("gzip", Buffer.alloc(1024 * 1024 + 1)),
      discovery,
      { ...send, headers: [...send.headers, { name: "content-encoding", value: "gzip" }] },
      {
        ...send,
        body: gzipSync(send.body),
        headers: [...send.headers, { name: "content-encoding", value: "gzip" }],
      },
      { ...draft, headers: [...draft.headers, { name: "content-encoding", value: "gzip" }] },
    ];
    for (const q of denied) {
      assert.equal(await evaluate(q), 2);
    }
    assert.equal(approvals.length, granted + 1);
  },
);

test("Git authority cannot be constructed without both trusted owner callbacks", () => {
  assert.throws(() => createOpenShellOnlineGitAuthority({}), /live binding and durable approval/);
  assert.throws(
    () => createOpenShellOnlineGitAuthority({ lookupBinding: async () => binding }),
    /live binding and durable approval/,
  );
});

test("expired binding lookup cannot begin durable Git approval", { timeout: 10000 }, async (t) => {
  let approvals = 0;
  const lookupAborted = Promise.withResolvers();
  const { client, keys } = await openShellOnlineGitWire(t, {
    budgetMs: 30,
    lookupBinding: async (_identity, signal) => {
      await new Promise((resolve) => signal.addEventListener("abort", resolve, { once: true }));
      lookupAborted.resolve();
      return binding;
    },
    approve: async () => {
      approvals++;
      return true;
    },
  });
  const result = await invoke(
    client,
    "EvaluateHttpRequest",
    pushRequest(),
    token(keys, "supervisor", binding.sandboxId),
  );
  assert.equal(result.decision, 2);
  await lookupAborted.promise;
  assert.equal(approvals, 0);
});
