import type { EgressExecution, EgressPlan, EgressRef } from "@openclaw-enterprise/contracts";

export const HARNESS_EGRESS_ENROLLMENT_PATH = "/openclaw/runtime/egress-enrollment";

export interface HarnessEgressEnrollment {
  readonly plan: EgressRef;
  readonly execution: EgressExecution;
}

export function harnessEgressEnrollment(plan: EgressPlan): HarnessEgressEnrollment {
  return { plan: { id: plan.id, generation: plan.generation }, execution: plan.execution };
}

// This runs in the generated Harness, before its first model probe. The exact
// transport peer releases startup only after Compute commits installation evidence.
export const HARNESS_EGRESS_ENROLLMENT_HELPER = String.raw`
function waitForHarnessEgressEnrollment(enrollment) {
  const { createHash, randomUUID, timingSafeEqual } = require("node:crypto");
  const { isDeepStrictEqual } = require("node:util");
  const { createServer } = require("node:http");
  const verifier = process.env.APP_TOKEN_SHA;
  const port = Number(process.env.APP_SERVER_PORT);
  const executionKeys = ["installationId", "namespaceId", "agentId", "servicePrincipalId", "revisionId", "executionId"];
  if (typeof verifier !== "string" || !/^[a-f0-9]{64}$/.test(verifier) ||
      !Number.isSafeInteger(port) || port < 1 || port > 65535 ||
      !isPlainObject(enrollment) || Object.keys(enrollment).length !== 2 ||
      !isPlainObject(enrollment.plan) || Object.keys(enrollment.plan).length !== 2 ||
      typeof enrollment.plan.id !== "string" || !enrollment.plan.id || enrollment.plan.id.length > 256 ||
      !Number.isSafeInteger(enrollment.plan.generation) || enrollment.plan.generation < 1 ||
      !isPlainObject(enrollment.execution) || Object.keys(enrollment.execution).length !== executionKeys.length ||
      executionKeys.some((key) => typeof enrollment.execution[key] !== "string" ||
        !enrollment.execution[key] || enrollment.execution[key].length > 256) ||
      enrollment.execution.revisionId !== process.env.OPENCLAW_AGENT_REVISION_ID) {
    return Promise.reject(new Error("Protected Harness enrollment configuration is invalid."));
  }
  const expected = Buffer.from(verifier, "hex");
  const challenge = { ...enrollment, startupId: randomUUID() };
  const deadline = performance.now() + 180000;
  return new Promise((resolve, reject) => {
    let settled = false;
    let released = false;
    const finish = (enrolled) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      // Close the temporary listener before Codex or the held-failure server binds.
      server.close(() => {
        if (enrolled) {
          resolve();
        } else {
          reject(new Error("Protected Harness enrollment failed."));
        }
      });
      server.closeAllConnections();
    };
    const server = createServer(async (request, response) => {
      const answer = (status, body) => {
        response.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", connection: "close" });
        response.end(JSON.stringify(body));
      };
      const authorization = typeof request.headers.authorization === "string"
        ? /^Bearer ([A-Za-z0-9\-._~+/]+=*)$/i.exec(request.headers.authorization) : null;
      if (authorization === null || !timingSafeEqual(createHash("sha256").update(authorization[1]).digest(), expected)) {
        answer(401, { error: "unauthorized" });
        return;
      }
      if (settled || released || performance.now() >= deadline) {
        answer(410, { error: "expired" });
        return;
      }
      if (request.url !== ${JSON.stringify(HARNESS_EGRESS_ENROLLMENT_PATH)}) {
        answer(404, { error: "not_found" });
        return;
      }
      if (request.method === "GET") {
        answer(200, challenge);
        return;
      }
      if (request.method !== "POST" || request.headers["content-type"] !== "application/json") {
        answer(400, { error: "invalid_request" });
        return;
      }
      try {
        const chunks = [];
        let bytes = 0;
        for await (const chunk of request) {
          bytes += chunk.length;
          if (bytes > 4096) {
            answer(413, { error: "invalid_request" });
            return;
          }
          chunks.push(chunk);
        }
        const release = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        if (settled || released || performance.now() >= deadline || !isDeepStrictEqual(release, challenge)) {
          answer(409, { error: "stale_enrollment" });
          return;
        }
        // A release is only startup coordination. Both per-request authority
        // checks still run before any material access or business send.
        released = true;
        response.on("finish", () => finish(true));
        answer(200, { enrolled: true, startupId: challenge.startupId });
      } catch {
        if (!response.destroyed) {
          answer(400, { error: "invalid_request" });
        }
      }
    });
    server.requestTimeout = 5000;
    server.headersTimeout = 5000;
    server.maxConnections = 16;
    const timer = setTimeout(() => finish(false), 180000);
    server.on("error", () => finish(false));
    server.listen(port, "0.0.0.0");
  });
}
`;
