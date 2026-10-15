import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { loadSync } from "@grpc/proto-loader";
import {
  loadPackageDefinition,
  Server,
  ServerCredentials,
  status,
  type Metadata,
  type ServiceDefinition,
  type ServerUnaryCall,
  type sendUnaryData,
  type ServerDuplexStream,
} from "@grpc/grpc-js";
import type { EgressMaterialEvidence } from "@openclaw-enterprise/contracts";
import type { OpenClawController } from "@openclaw-enterprise/occ";
import { asRecord } from "@openclaw-enterprise/utils";
import { OpenShellEgressIdentity } from "./openshell-identity.ts";
import { openShellExchangeCapabilities } from "./openshell-exchange-capabilities.ts";

type Wire = Record<string, unknown>;
type AuthorityCall = {
  request: Wire;
  authorization: string;
  signal: AbortSignal;
};
const contractCapability = "openshell.supervisor-middleware.contract";
const capabilities = [contractCapability, ...openShellExchangeCapabilities];
const record = (input: unknown): Wire => asRecord(input) ?? {};
const string = (input: unknown): string => (typeof input === "string" ? input : "");
const bytes = (input: unknown): Buffer =>
  input instanceof Uint8Array ? Buffer.from(input) : Buffer.alloc(0);
const authorization = (metadata: Metadata): string => {
  const values = metadata.get("authorization");
  return values.length === 1 ? string(values[0]) : "";
};
const headers = (input: unknown): readonly (readonly [string, string])[] =>
  Array.isArray(input)
    ? input.map((item) => [string(record(item).name), string(record(item).value)] as const)
    : [];

function timestamp(value: unknown): string {
  const item = record(value);
  const seconds = Number(item.seconds);
  const nanos = Number(item.nanos ?? 0);
  const millis = seconds * 1000 + nanos / 1_000_000;
  return Number.isSafeInteger(seconds) &&
    Number.isInteger(nanos) &&
    nanos >= 0 &&
    nanos < 1_000_000_000 &&
    Number.isFinite(millis) &&
    Math.abs(millis) < 8.64e15
    ? new Date(millis).toISOString()
    : "";
}

function wireTimestamp(value: string): Wire {
  const time = Date.parse(value);
  return { seconds: Math.floor(time / 1000), nanos: (time % 1000) * 1_000_000 };
}

function refused(kind: string): Wire {
  const codes: Record<string, number> = {
    denied: 1,
    not_ready: 2,
    unavailable: 3,
    cancelled: 4,
    deadline_exceeded: 5,
  };
  return { refused: { code: codes[kind] ?? 1 } };
}

/** Actual gRPC adapter for the supervisor's exclusive static-credential authority. */
export function createOpenShellEgressAuthority(
  identity: OpenShellEgressIdentity,
  controller: Pick<OpenClawController, "createConduit">,
): Server {
  // The verifier owns acceptance on the actual stream. No separate synthetic owner,
  // bearer-only profile or caller-selected response destination can enter this composition.
  const forwarder = controller.createConduit(identity, identity);
  const definition = loadSync(
    fileURLToPath(new URL("./proto/supervisor_middleware.proto", import.meta.url)),
    { keepCase: true, longs: String, enums: Number, defaults: false, oneofs: true },
  );
  const loaded = loadPackageDefinition(definition) as unknown as {
    openshell: { middleware: { v1: Record<string, { service: ServiceDefinition }> } };
  };
  const service = loaded.openshell.middleware.v1;
  const server = new Server({
    "grpc.max_receive_message_length": 5 * 1024 * 1024,
    "grpc.max_send_message_length": 5 * 1024 * 1024,
  });
  const unary =
    (work: (call: ServerUnaryCall<Wire, Wire>) => Promise<Wire>) =>
    (call: ServerUnaryCall<Wire, Wire>, callback: sendUnaryData<Wire>) => {
      void work(call).then(
        (result) => callback(null, result),
        () =>
          callback({ code: status.UNAVAILABLE, message: "Egress authority unavailable." }, null),
      );
    };
  server.addService(service.SupervisorMiddleware!.service, {
    Describe: unary(async (call) => {
      const peer = record(call.request.gateway);
      const supported = peer.supported_capabilities;
      const required = peer.required_capabilities;
      if (
        !identity.verifyControl(authorization(call.metadata)) ||
        record(peer.protocol_version).major !== 1 ||
        !Array.isArray(supported) ||
        !capabilities.every((capability) => supported.includes(capability)) ||
        !Array.isArray(required) ||
        // Generic Describe runs before protected policy selection. Rust sends all
        // supported capabilities, requires the base contract here, then verifies our
        // complete required profile at protected-policy selection and installation.
        !required.includes(contractCapability) ||
        required.some((capability) => !capabilities.includes(String(capability)))
      ) {
        throw new Error("Unsupported or unauthenticated counterpart.");
      }
      return {
        name: "oce-static-egress",
        expected_audience: identity.audience,
        extension: {
          protocol_version: { major: 1, minor: 0 },
          implementation_name: "oce/static-egress",
          implementation_version: "1",
          supported_capabilities: capabilities,
          required_capabilities: capabilities,
        },
        bindings: [
          { operation: 1, phase: 1, max_payload_bytes: 4 * 1024 * 1024 },
          { operation: 4, phase: 1, max_payload_bytes: 4 * 1024 * 1024 },
          { operation: 3, phase: 2, max_payload_bytes: 4 * 1024 * 1024 },
        ],
      };
    }),
    ValidateConfig: unary(async (call) => ({
      valid:
        identity.verifyControl(authorization(call.metadata)) &&
        Object.keys(record(record(call.request.config).fields)).length === 0,
    })),
    EvaluateHttpRequest: unary(async (call) => ({
      decision: identity.supervisor(authorization(call.metadata)) ? 1 : 2,
      reason_code: "egress_identity",
    })),
  });
  const resolve = async (call: AuthorityCall): Promise<Wire> => {
    if (call.request.audience !== identity.audience) {
      return refused("denied");
    }
    const evaluation = record(call.request.request);
    const context = record(evaluation.context);
    const target = record(evaluation.target);
    const port = Number(target.port);
    const host = string(target.host);
    const path = string(target.path);
    if (
      context.verified_credential_connector !== undefined ||
      target.scheme !== "https" ||
      !/^[a-z0-9.-]+$/.test(host) ||
      !Number.isSafeInteger(port) ||
      port < 1 ||
      port > 65535 ||
      !path.startsWith("/") ||
      string(target.query) !== ""
    ) {
      return refused("denied");
    }
    const result = await forwarder.resolve(
      call.authorization,
      string(context.sandbox_id),
      {
        id: string(context.request_id),
        verifiedExecutionPolicyHash: string(call.request.verified_execution_policy_hash),
        method: string(target.method),
        url: `https://${host}${port === 443 ? "" : `:${port}`}${path}`,
        headers: headers(evaluation.headers),
        body: bytes(evaluation.body),
        deadlineAt: timestamp(call.request.deadline),
      },
      call.signal,
    );
    if (result.kind === "refused") {
      return refused(result.error.kind);
    }
    return {
      ready: {
        request_id: context.request_id,
        operation_handle: Buffer.from(result.handle),
        audience: identity.audience,
        evidence: {
          material_id: result.evidence.materialId,
          material_version: result.evidence.materialVersion,
          usable_until: wireTimestamp(result.evidence.usableUntil),
          authority_evidence: Buffer.from(JSON.stringify(result.evidence)),
        },
        credential_headers: result.headers.map(([name, value]) => ({ name, value })),
      },
    };
  };
  const authorizeSend = async (call: AuthorityCall): Promise<Wire> => {
    if (call.request.audience !== identity.audience) {
      return refused("denied");
    }
    const context = record(call.request.context);
    const wireEvidence = record(call.request.evidence);
    let evidence: EgressMaterialEvidence;
    try {
      evidence = JSON.parse(
        bytes(wireEvidence.authority_evidence).toString("utf8"),
      ) as EgressMaterialEvidence;
    } catch {
      return refused("denied");
    }
    if (
      evidence.materialId !== wireEvidence.material_id ||
      evidence.materialVersion !== wireEvidence.material_version ||
      evidence.usableUntil !== timestamp(wireEvidence.usable_until) ||
      Date.parse(timestamp(call.request.deadline)) < Date.parse(evidence.usableUntil)
    ) {
      return refused("denied");
    }
    if (context.verified_credential_connector !== undefined) {
      return refused("denied");
    }
    const result = await forwarder.authorizeSend(
      call.authorization,
      string(context.sandbox_id),
      string(context.request_id),
      bytes(call.request.operation_handle).toString("utf8"),
      evidence,
      bytes(call.request.credential_headers_sha256).toString("hex"),
      timestamp(call.request.deadline),
      call.signal,
    );
    if (result.kind === "refused") {
      return refused(result.error.kind);
    }
    const responseCustody = identity.responseCustody(
      call.authorization,
      result.authorization.association,
    );
    return responseCustody === undefined
      ? refused("cancelled")
      : {
          allowed: {
            request_id: context.request_id,
            operation_handle: call.request.operation_handle,
            credential_headers_sha256: Buffer.from(result.injectionDigest, "hex"),
            send_start_by: wireTimestamp(result.sendStartBy),
            response_custody: responseCustody,
          },
        };
  };
  server.addService(service.HttpCredentialAccess!.service, {
    Resolve: unary(async () => refused("denied")),
    AuthorizeSend: unary(async () => refused("denied")),
  });
  server.addService(service.HttpResponsePreReturn!.service, {
    Evaluate(call: ServerDuplexStream<Wire, Wire>) {
      call.emit("error", {
        code: status.PERMISSION_DENIED,
        message: "Installation exchange required.",
      });
    },
  });
  server.addService(service.HttpInstallationExchange!.service, {
    Exchange(call: ServerDuplexStream<Wire, Wire>) {
      const challenge = randomBytes(32);
      const bearer = authorization(call.metadata);
      const signal = new AbortController();
      let capability: string | undefined;
      let context: Wire = {};
      let phase: "open" | "authorize" | "response" | "done" = "open";
      let busy = false;
      const timer = setTimeout(() => fail(), 30_000).unref();
      const close = () => {
        clearTimeout(timer);
        signal.abort();
        phase = "done";
      };
      const fail = () => {
        close();
        call.emit("error", {
          message: "Installation exchange refused.",
          code: status.PERMISSION_DENIED,
        });
      };
      call.on("cancelled", close);
      call.on("error", close);
      call.on("end", () => {
        close();
        call.end();
      });
      call.write({ challenge });
      call.on("data", (event: Wire) => {
        // Capture and authenticate before any queued work; pipelining is forbidden.
        if (busy || phase === "done") {
          fail();
          return;
        }
        let request: Wire;
        if (phase === "open" && event.open !== undefined) {
          const opening = record(event.open);
          const encoded = bytes(opening.resolve_request);
          const codec = definition[
            "openshell.middleware.v1.HttpCredentialResolveRequest"
          ] as unknown as { deserialize(value: Buffer): Wire };
          capability = identity.acceptExchange(
            bearer,
            challenge,
            encoded,
            bytes(opening.signature),
            () => {
              request = codec.deserialize(encoded);
              context = record(record(request.request).context);
              return {
                requestId: string(context.request_id),
                sandboxId: string(context.sandbox_id),
                responseCustody: bytes(request.response_custody),
              };
            },
            signal.signal,
          );
          if (!capability) {
            fail();
            return;
          }
        } else if (phase === "authorize" && event.authorize !== undefined) {
          request = record(event.authorize);
        } else if (phase === "response" && event.response !== undefined) {
          request = record(event.response);
        } else {
          fail();
          return;
        }
        busy = true;
        const acceptedPhase = phase;
        // The internal credential is created only by the real stream verifier.
        const acceptedCall: AuthorityCall = {
          request: request!,
          authorization: capability!,
          signal: signal.signal,
        };
        void (async () => {
          if (acceptedPhase === "open") {
            const result = await resolve(acceptedCall);
            if (signal.signal.aborted) {
              return;
            }
            phase = result.ready ? "authorize" : "done";
            call.write({ resolved: result });
          } else if (acceptedPhase === "authorize") {
            const result = await authorizeSend(acceptedCall);
            if (signal.signal.aborted) {
              return;
            }
            phase = result.allowed ? "response" : "done";
            call.write({ authorized: result });
          } else {
            const handle = await forwarder.beginResponse(
              capability!,
              string(context.sandbox_id),
              string(context.request_id),
            );
            if (!handle) {
              fail();
              return;
            }
            const complete = acceptedCall.request;
            const response = await forwarder.protectResponse(
              handle,
              {
                status: Number(complete.status),
                headers: headers(complete.headers),
                body: bytes(complete.body),
                trailers: headers(complete.trailers),
              },
              signal.signal,
              complete.response_complete === true,
            );
            if (!response || signal.signal.aborted) {
              fail();
              return;
            }
            call.write({
              response: {
                status: response.status,
                headers: response.headers.map(([name, value]) => ({ name, value })),
                body: response.body,
                trailers: response.trailers.map(([name, value]) => ({ name, value })),
                response_complete: true,
              },
            });
            phase = "done";
          }
          busy = false;
          if (phase === "done") {
            close();
            call.end();
          }
        })().catch(() => {
          if (signal.signal.aborted) {
            return;
          }
          close();
          call.emit("error", {
            code: status.UNAVAILABLE,
            message: "Installation exchange unavailable.",
          });
        });
      });
    },
  });
  return server;
}

/** TLS is mandatory even on loopback; the JWT authenticates the supervisor separately. */
export function bindOpenShellEgressAuthority(
  server: Server,
  address: string,
  certificate: Buffer,
  privateKey: Buffer,
): Promise<number> {
  const credentials = ServerCredentials.createSsl(
    null,
    [{ cert_chain: certificate, private_key: privateKey }],
    false,
  );
  return new Promise((resolve, reject) =>
    server.bindAsync(address, credentials, (error, port) =>
      error ? reject(error) : resolve(port),
    ),
  );
}
