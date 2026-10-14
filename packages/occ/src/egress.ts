import type {
  EgressSendReceipts,
  SendAttempt,
  SendObservation,
} from "./state/egress-send-receipts.ts";
import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import type {
  CredentialProviderDefinition,
  EgressInstallation,
  EgressRef,
  EgressRefusal,
  EgressRequest,
  EgressResponse,
  EgressRoute,
  InferenceOperation,
  StaticEgressSource,
  StaticMaterialEvidence,
  VersionedSecretValue,
} from "@openclaw-enterprise/contracts";
import { immutableCopy } from "@openclaw-enterprise/utils";

export interface EgressPeer {
  readonly sender: EgressRef;
  readonly sandboxId: string;
  readonly instanceId: string;
  readonly expiresAt: string;
}

/** Only installed transport verifiers implement this interface, never workload input. */
export interface EgressPeerVerifier {
  verify(authorization: string): Promise<EgressPeer | undefined>;
}

export interface CapturedEgressUse {
  readonly id: string;
  readonly peer: EgressPeer;
  readonly installation: EgressInstallation;
  readonly route: EgressRoute;
  readonly request: EgressRequest;
  readonly operation: InferenceOperation;
}

export interface EgressAuthorityPorts {
  readonly verifier: EgressPeerVerifier;
  readonly now: () => number;
  installation(peer: EgressPeer): Promise<EgressInstallation | undefined>;
  provider(route: EgressRoute): CredentialProviderDefinition | undefined;
  /** Each call must open a new policy unit, independent of the capture and Secret read. */
  check(
    use: CapturedEgressUse,
    material?: StaticMaterialEvidence,
  ): Promise<StaticEgressSource | EgressRefusal>;
  read(
    source: StaticEgressSource,
    signal: AbortSignal,
    deadlineAt: string,
  ): Promise<VersionedSecretValue & { readonly materialId: string }>;
  readonly receipts: Pick<EgressSendReceipts, "begin" | "record" | "observe">;
}

export type EgressResolution =
  | { readonly kind: "refused"; readonly error: EgressRefusal }
  | {
      readonly kind: "ready";
      readonly handle: string;
      readonly evidence: StaticMaterialEvidence;
      readonly headers: readonly (readonly [string, string])[];
      readonly injectionDigest: string;
    };

export type EgressSendDecision =
  | { readonly kind: "refused"; readonly error: EgressRefusal }
  | { readonly kind: "allow"; readonly sendStartBy: string; readonly injectionDigest: string };

interface OperationRecord {
  readonly use: CapturedEgressUse;
  readonly provider: CredentialProviderDefinition;
  readonly source: StaticEgressSource;
  readonly evidence: StaticMaterialEvidence;
  readonly attempt: SendAttempt;
  readonly digest: string;
  value: string;
  phase: "resolved" | "checking" | "permitted" | "protecting" | "observing";
  timer?: ReturnType<typeof setTimeout>;
}

function refuse(
  code: Extract<EgressRefusal, { kind: "denied" }>["code"],
): EgressResolution & { kind: "refused" } {
  return { kind: "refused", error: { kind: "denied", code } };
}

function sameSecret(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

/** UUIDv7 creation time fixes the replay horizon independently of a resubmitted deadline. */
function operationCreatedAt(id: string): number | undefined {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(id)
    ? Number.parseInt(id.slice(0, 8) + id.slice(9, 13), 16)
    : undefined;
}

/** Matches the wire contract: ordered UTF-8 names and values with u64 big-endian lengths. */
export function egressInjectionDigest(headers: readonly (readonly [string, string])[]): string {
  const hash = createHash("sha256");
  for (const pair of headers) {
    for (const item of pair) {
      const bytes = Buffer.from(item, "utf8");
      const size = Buffer.alloc(8);
      size.writeBigUInt64BE(BigInt(bytes.length));
      hash.update(size).update(bytes);
    }
  }
  return hash.digest("hex");
}

/**
 * Trusted request registry shared by the transport's resolve, send and response phases.
 * Restart loses outstanding handles and fails closed. No permit or material is reusable.
 */
export class EgressForwarder {
  private readonly records = new Map<string, OperationRecord>();
  private readonly requests = new Map<string, number>();
  private pendingResolutions = 0;
  private readonly ports: EgressAuthorityPorts;

  constructor(ports: EgressAuthorityPorts) {
    this.ports = ports;
  }

  private discard(handle: string, record: OperationRecord): void {
    clearTimeout(record.timer);
    record.value = "";
    this.records.delete(handle);
  }

  private prune(): void {
    const now = this.ports.now();
    for (const [handle, record] of this.records) {
      if (Date.parse(record.use.request.deadlineAt) <= now) {
        this.discard(handle, record);
      }
    }
    for (const [key, expiresAt] of this.requests) {
      if (expiresAt <= now) {
        this.requests.delete(key);
      }
    }
  }

  async resolve(
    authorization: string,
    sandboxId: string,
    input: EgressRequest,
    signal: AbortSignal,
  ): Promise<EgressResolution> {
    this.prune();
    // Reserve before authentication or any other await. Pending Secret/policy I/O
    // consumes the same capacity as an outstanding material handle.
    if (this.pendingResolutions + this.records.size >= 1024) {
      return { kind: "refused", error: { kind: "unavailable", code: "resolver" } };
    }
    this.pendingResolutions += 1;
    try {
      return await this.resolveReserved(authorization, sandboxId, input, signal);
    } finally {
      this.pendingResolutions -= 1;
    }
  }

  private async resolveReserved(
    authorization: string,
    sandboxId: string,
    input: EgressRequest,
    signal: AbortSignal,
  ): Promise<EgressResolution> {
    if (signal.aborted) {
      return { kind: "refused", error: { kind: "cancelled" } };
    }
    const peer = await this.ports.verifier.verify(authorization);
    const now = this.ports.now();
    if (!peer || peer.sandboxId !== sandboxId || Date.parse(peer.expiresAt) <= now) {
      return refuse("identity");
    }
    const deadline = Date.parse(input.deadlineAt);
    const createdAt = operationCreatedAt(input.id);
    if (
      createdAt === undefined ||
      createdAt > now + 1000 ||
      !Number.isFinite(deadline) ||
      deadline <= now ||
      deadline <= createdAt ||
      deadline > createdAt + 30_000 ||
      deadline > Date.parse(peer.expiresAt)
    ) {
      return { kind: "refused", error: { kind: "deadline_exceeded" } };
    }
    if (input.body.byteLength > 1024 * 1024) {
      return refuse("unsupported_operation");
    }
    const replayKey = JSON.stringify([peer.sender, sandboxId, peer.instanceId, input.id]);
    if (this.requests.has(replayKey)) {
      return refuse("invalid_handle");
    }
    if (this.requests.size >= 4096) {
      return { kind: "refused", error: { kind: "unavailable", code: "resolver" } };
    }
    // Reserve before the first await. Failed attempts cannot reuse their transport request ID.
    this.requests.set(replayKey, createdAt + 30_000);
    const request = {
      ...immutableCopy({ ...input, body: undefined }),
      body: new Uint8Array(input.body),
    } as EgressRequest;
    const installation = await this.ports.installation(peer);
    if (
      !installation ||
      !isDeepStrictEqual(installation.sender, peer.sender) ||
      installation.enforcement?.instanceId !== peer.instanceId
    ) {
      return { kind: "refused", error: { kind: "not_ready", code: "attachment_pending" } };
    }
    const matches = installation.plan.routes.flatMap((route) => {
      if (request.bindingId !== undefined && route.binding.binding.id !== request.bindingId) {
        return [];
      }
      const provider = this.ports.provider(route);
      const operation = provider?.classify(route, request);
      return provider && operation ? [{ route, provider, operation }] : [];
    });
    if (matches.length !== 1) {
      return refuse(matches.length > 1 ? "ambiguous_route" : "unsupported_operation");
    }
    const { route, provider, operation } = matches[0]!;
    if (deadline > createdAt + route.deadlineMs) {
      return { kind: "refused", error: { kind: "deadline_exceeded" } };
    }
    const use = immutableCopy({
      id: input.id,
      peer,
      installation,
      route,
      request: { ...request, body: undefined },
      operation,
    }) as unknown as CapturedEgressUse;
    // Keep captured bytes private and detached from the transport's mutable buffer.
    const captured = { ...use, request };
    let source: StaticEgressSource | EgressRefusal;
    try {
      source = await this.ports.check(captured);
    } catch {
      return { kind: "refused", error: { kind: "unavailable", code: "authority" } };
    }
    if (!("key" in source)) {
      return { kind: "refused", error: source };
    }
    try {
      const material = await this.ports.read(source, signal, request.deadlineAt);
      const observed = Date.parse(material.authoritativeObservedAt);
      const usableUntil = Math.min(
        deadline,
        material.expiresAt === undefined ? deadline : Date.parse(material.expiresAt),
      );
      if (
        !material.version ||
        !material.materialId ||
        !Number.isFinite(observed) ||
        observed > this.ports.now() ||
        !Number.isFinite(usableUntil) ||
        usableUntil <= this.ports.now()
      ) {
        return { kind: "refused", error: { kind: "not_ready", code: "expired" } };
      }
      if (signal.aborted) {
        return { kind: "refused", error: { kind: "cancelled" } };
      }
      const evidence: StaticMaterialEvidence = immutableCopy({
        kind: "static",
        source: source.key,
        binding: route.binding.binding,
        grantHash: route.binding.grantHash,
        isolationId: route.binding.isolationId,
        adoption: source.adoption,
        materialRefId: source.materialRefId,
        secret: source.secret,
        secretDriver: source.secretDriver,
        materialId: material.materialId,
        materialVersion: material.version,
        authoritativeObservedAt: material.authoritativeObservedAt,
        usableUntil: new Date(usableUntil).toISOString(),
        retention: "none",
      });
      const headers = provider.inject(material.value);
      const digest = egressInjectionDigest(headers);
      const handle = randomUUID();
      const record: OperationRecord = {
        use: captured,
        provider,
        source,
        evidence,
        digest,
        attempt: immutableCopy({
          sender: peer.sender,
          instanceId: peer.instanceId,
          useId: captured.id,
          // OpenShell has one attempt per UUIDv7 use. Keep that ID across authority restarts.
          attemptId: captured.id,
          material: evidence,
          deadlineAt: request.deadlineAt,
        }),
        value: material.value,
        phase: "resolved",
      };
      this.records.set(handle, record);
      record.timer = setTimeout(
        () => {
          this.discard(handle, record);
        },
        Math.max(1, deadline - this.ports.now()),
      ).unref();
      return { kind: "ready", handle, evidence, headers, injectionDigest: digest };
    } catch {
      return { kind: "refused", error: { kind: "unavailable", code: "secret_store" } };
    }
  }

  async authorizeSend(
    authorization: string,
    sandboxId: string,
    requestId: string,
    handle: string,
    evidence: StaticMaterialEvidence,
    injectionDigest: string,
    deadlineAt: string,
    signal: AbortSignal,
  ): Promise<EgressSendDecision> {
    this.prune();
    const record = this.records.get(handle);
    const peer = await this.ports.verifier.verify(authorization);
    if (
      !record ||
      this.records.get(handle) !== record ||
      record.phase !== "resolved" ||
      !peer ||
      peer.sandboxId !== sandboxId ||
      !isDeepStrictEqual(peer.sender, record.use.peer.sender) ||
      peer.instanceId !== record.use.peer.instanceId ||
      sandboxId !== record.use.peer.sandboxId ||
      requestId !== record.use.request.id ||
      deadlineAt !== record.use.request.deadlineAt ||
      !isDeepStrictEqual(record.evidence, evidence) ||
      !sameSecret(record.digest, injectionDigest)
    ) {
      return refuse("invalid_handle");
    }
    // Reserve before any persistence/policy I/O. A duplicate or unknown commit never permits send.
    record.phase = "checking";
    try {
      const begun = await this.ports.receipts.begin(peer.sender, record.attempt);
      if (!begun.created) {
        this.discard(handle, record);
        return refuse("invalid_handle");
      }
    } catch {
      this.discard(handle, record);
      return { kind: "refused", error: { kind: "unavailable", code: "authority" } };
    }
    const deny = async (error: EgressRefusal): Promise<EgressSendDecision> => {
      this.discard(handle, record);
      try {
        await this.ports.receipts.record(peer.sender, record.attempt, {
          kind: "refused",
          dispatched: false,
          error,
        });
        return { kind: "refused", error };
      } catch {
        return { kind: "refused", error: { kind: "unavailable", code: "authority" } };
      }
    };
    if (signal.aborted) {
      return deny({ kind: "cancelled" });
    }
    // Fresh transport and policy checks follow possibly slow durable persistence and exact selection.
    let decision: StaticEgressSource | EgressRefusal;
    let finalPeer: EgressPeer | undefined;
    try {
      finalPeer = await this.ports.verifier.verify(authorization);
      if (!finalPeer || !isDeepStrictEqual(finalPeer, peer)) {
        return deny({ kind: "denied", code: "identity" });
      }
      decision = await this.ports.check(record.use, record.evidence);
    } catch {
      return deny({ kind: "unavailable", code: "authority" });
    }
    if (!("key" in decision) || !isDeepStrictEqual(decision, record.source)) {
      return deny("key" in decision ? { kind: "denied", code: "stale_configuration" } : decision);
    }
    if (signal.aborted) {
      return deny({ kind: "cancelled" });
    }
    const now = this.ports.now();
    const sendStartBy = Math.min(
      now + 1000,
      Date.parse(record.use.request.deadlineAt),
      Date.parse(record.evidence.usableUntil),
      Date.parse(finalPeer.expiresAt),
    );
    if (sendStartBy <= now || this.records.get(handle) !== record || record.phase !== "checking") {
      return deny({ kind: "deadline_exceeded" });
    }
    // This means permission issued, NOT confirmed dispatch. The durable receipt stays possible.
    record.phase = "permitted";
    return {
      kind: "allow",
      sendStartBy: new Date(sendStartBy).toISOString(),
      injectionDigest: record.digest,
    };
  }

  /** Claim exactly one authenticated response stream before its preflight decision. */
  async beginResponse(
    authorization: string,
    sandboxId: string,
    requestId: string,
  ): Promise<string | undefined> {
    this.prune();
    const peer = await this.ports.verifier.verify(authorization);
    if (!peer || peer.sandboxId !== sandboxId || Date.parse(peer.expiresAt) <= this.ports.now()) {
      return undefined;
    }
    const entry = [...this.records].find(
      ([, record]) =>
        record.phase === "permitted" &&
        record.use.request.id === requestId &&
        record.use.peer.sandboxId === sandboxId &&
        record.use.peer.instanceId === peer.instanceId &&
        isDeepStrictEqual(record.use.peer.sender, peer.sender),
    );
    if (!entry) {
      return undefined;
    }
    const [handle, record] = entry;
    record.phase = "protecting";
    return handle;
  }

  /** Store only observation metadata. Returning policy bytes is not supplier application proof. */
  async protectResponse(
    handle: string,
    response: EgressResponse,
    signal: AbortSignal,
    inspect = true,
  ): Promise<EgressResponse | undefined> {
    const record = this.records.get(handle);
    if (!record || record.phase !== "protecting") {
      return undefined;
    }
    // Consume even while persistence is pending; no second stream/body can reuse this response.
    record.phase = "observing";
    try {
      const rejected = inspect && record.provider.credentialRejected(response);
      const safe =
        inspect && !signal.aborted && Date.parse(record.use.request.deadlineAt) > this.ports.now()
          ? record.provider.protectResponse(
              response,
              record.value,
              record.use.request,
              record.use.operation,
            )
          : undefined;
      const observed: SendObservation =
        safe === undefined
          ? { kind: "response_blocked", dispatch: "confirmed", code: "response_policy" }
          : {
              kind: rejected ? "provider_rejected" : "response",
              dispatch: "confirmed",
              status: safe.status,
            };
      await this.ports.receipts.observe(
        record.use.peer.sender,
        record.attempt,
        observed,
        rejected ? { classification: "credential_rejected", evidence: record.evidence } : undefined,
      );
      // Persistence may outlive the original deadline or cancellation. Never release late bytes.
      return this.records.get(handle) === record &&
        !signal.aborted &&
        Date.parse(record.use.request.deadlineAt) > this.ports.now()
        ? safe
        : undefined;
    } finally {
      this.discard(handle, record);
    }
  }
}
