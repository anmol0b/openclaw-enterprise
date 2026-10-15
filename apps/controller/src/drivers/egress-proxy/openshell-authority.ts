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
import type { EgressResponse, StaticMaterialEvidence } from "@openclaw-enterprise/contracts";
import type { Conduit } from "@openclaw-enterprise/occ";
import { asRecord } from "@openclaw-enterprise/utils";
import { OpenShellEgressIdentity } from "./openshell-identity.ts";

type Wire = Record<string, unknown>;
const credentialCapability = "openshell.supervisor-middleware.http-credential-access.v1";
const contractCapability = "openshell.supervisor-middleware.contract";
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
  conduit: Conduit,
): Server {
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
      if (
        !identity.verifyControl(authorization(call.metadata)) ||
        record(peer.protocol_version).major !== 1 ||
        !Array.isArray(peer.supported_capabilities) ||
        !peer.supported_capabilities.includes(contractCapability) ||
        !peer.supported_capabilities.includes(credentialCapability) ||
        (Array.isArray(peer.required_capabilities) &&
          peer.required_capabilities.some(
            (capability) =>
              ![contractCapability, credentialCapability].includes(String(capability)),
          ))
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
          supported_capabilities: [contractCapability, credentialCapability],
          required_capabilities: [contractCapability, credentialCapability],
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
      decision: (await identity.verify(authorization(call.metadata))) ? 1 : 2,
      reason_code: "egress_identity",
    })),
  });
  server.addService(service.HttpCredentialAccess!.service, {
    Resolve: unary(async (call) => {
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
      const signal = new AbortController();
      call.once("cancelled", () => signal.abort());
      const result = await conduit.resolve(
        authorization(call.metadata),
        string(context.sandbox_id),
        {
          id: string(context.request_id),
          method: string(target.method),
          url: `https://${host}${port === 443 ? "" : `:${port}`}${path}`,
          headers: headers(evaluation.headers),
          body: bytes(evaluation.body),
          deadlineAt: timestamp(call.request.deadline),
        },
        signal.signal,
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
    }),
    AuthorizeSend: unary(async (call) => {
      if (call.request.audience !== identity.audience) {
        return refused("denied");
      }
      const context = record(call.request.context);
      const wireEvidence = record(call.request.evidence);
      let evidence: StaticMaterialEvidence;
      try {
        evidence = JSON.parse(
          bytes(wireEvidence.authority_evidence).toString("utf8"),
        ) as StaticMaterialEvidence;
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
      const result = await conduit.authorizeSend(
        authorization(call.metadata),
        string(context.sandbox_id),
        string(context.request_id),
        bytes(call.request.operation_handle).toString("utf8"),
        evidence,
        bytes(call.request.credential_headers_sha256).toString("hex"),
        timestamp(call.request.deadline),
      );
      return result.kind === "refused"
        ? refused(result.error.kind)
        : {
            allowed: {
              request_id: context.request_id,
              operation_handle: call.request.operation_handle,
              credential_headers_sha256: Buffer.from(result.injectionDigest, "hex"),
              send_start_by: wireTimestamp(result.sendStartBy),
            },
          };
    }),
  });
  server.addService(service.HttpResponsePreReturn!.service, {
    Evaluate(call: ServerDuplexStream<Wire, Wire>) {
      let head: { context: Wire; response: Omit<EgressResponse, "body"> } | undefined;
      let phase: "head" | "body" | "trailers" | "done" = "head";
      let work = Promise.resolve();
      const block = (body: boolean, sequence?: unknown) =>
        call.write(
          body
            ? {
                body_result: {
                  sequence,
                  block_delivery: {},
                  reason_code: "egress_response_policy",
                },
              }
            : { preflight_result: { block_delivery: {}, reason_code: "egress_response_policy" } },
        );
      call.on("data", (event: Wire) => {
        work = work
          .then(async () => {
            if (event.preflight !== undefined && phase === "head") {
              const preflight = record(event.preflight);
              const context = record(preflight.context);
              const peer = await identity.verify(authorization(call.metadata));
              const responseHeaders = headers(preflight.headers);
              if (
                !peer ||
                peer.sandboxId !== context.sandbox_id ||
                !Array.isArray(preflight.permitted_body_modes) ||
                !preflight.permitted_body_modes.includes(2) ||
                responseHeaders.some(([name]) =>
                  ["content-encoding", "trailer", "upgrade"].includes(name.toLowerCase()),
                )
              ) {
                phase = "done";
                block(false);
                return;
              }
              head = {
                context,
                response: { status: Number(preflight.status_code), headers: responseHeaders },
              };
              phase = "body";
              // Remove visible headers before commitment; the supplier must strip protected
              // credential/framing headers and forbid trailers on this protected path.
              call.write({
                preflight_result: {
                  inspect: {
                    body_mode: 2,
                    header_mutations: responseHeaders
                      .filter(
                        ([name]) =>
                          !["content-type", "content-length"].includes(name.toLowerCase()),
                      )
                      .map(([name]) => ({ remove: { name } })),
                  },
                },
              });
            } else if (event.body !== undefined && phase === "body" && head !== undefined) {
              const body = record(event.body);
              phase = "trailers";
              const safe =
                body.end_of_stream === true && Number(body.sequence) === 1
                  ? await conduit.protectResponse(
                      authorization(call.metadata),
                      string(head.context.sandbox_id),
                      string(head.context.request_id),
                      { ...head.response, body: bytes(body.data) },
                    )
                  : undefined;
              if (!safe) {
                phase = "done";
                block(true, body.sequence);
              } else {
                call.write({
                  body_result: {
                    sequence: body.sequence,
                    transform: { data: Buffer.from(safe.body) },
                  },
                });
              }
            } else if (
              event.trailers !== undefined &&
              phase === "trailers" &&
              headers(record(event.trailers).headers).length === 0
            ) {
              phase = "done";
              call.write({ trailers_result: {} });
            } else if (event.session_end === undefined) {
              call.destroy(new Error("Egress response policy refused."));
            }
          })
          .catch(() => {
            call.destroy(new Error("Egress response policy unavailable."));
          });
      });
      call.on("end", () => {
        void work.finally(() => call.end());
      });
      call.on("error", () => {
        phase = "done";
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
