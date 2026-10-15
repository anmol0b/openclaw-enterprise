import { isDeepStrictEqual } from "node:util";
import type {
  EgressExecution,
  EgressRef,
  EgressMaterialEvidence,
} from "@openclaw-enterprise/contracts";
import { ResourceStateConflictError } from "./errors.ts";

/** Metadata from trusted acceptance, never from workload headers or a bearer. */
export interface AcceptedEgressAssociation {
  readonly execution: EgressExecution;
  readonly installation: {
    readonly sandboxId: string;
    readonly instanceId: string;
    readonly configurationId: string;
    readonly peerKeyId?: string;
    readonly plan: EgressRef;
  };
  readonly exchangeId: string;
  readonly responseId: string;
  readonly custodyId: string;
}

export interface AuthorizedSend {
  readonly association: AcceptedEgressAssociation;
  readonly requestDigest: string;
  readonly injectionDigest: string;
  readonly authorizedAt: string;
  readonly sendStartBy: string;
}

export interface SendAttempt {
  readonly sender: EgressRef;
  readonly instanceId: string;
  readonly useId: string;
  readonly attemptId: string;
  readonly material: EgressMaterialEvidence | null;
  readonly deadlineAt: string;
}

/** Safe metadata only. The caller retains the policy-processed response. */
export type SendOutcome =
  | { readonly kind: "refused"; readonly dispatched: false; readonly error: Refusal }
  | {
      readonly kind: "response" | "provider_rejected";
      readonly dispatch: "confirmed";
      readonly status: number;
    }
  | {
      readonly kind: "response_blocked";
      readonly dispatch: "confirmed";
      readonly code: "response_policy";
    }
  | { readonly kind: "uncertain"; readonly dispatch: "possible" };

type Refusal =
  | { readonly kind: "denied" | "not_ready" | "unavailable"; readonly code: string }
  | { readonly kind: "cancelled" | "deadline_exceeded" };

export type SendObservation = Extract<SendOutcome, { dispatch: "confirmed" }>;

export interface StoredSendReceipt extends SendAttempt {
  readonly authorization: AuthorizedSend | null;
  /** Observed response/policy decision, never proof the sender applied that decision. */
  readonly observation: SendObservation | null;
  readonly outcome: SendOutcome;
  readonly settled: boolean;
  readonly feedback: "fenced" | null;
}

interface TransactionOwner {
  transact<T>(
    work: (unit: {
      readonly egressSendReceipts: EgressSendReceiptRepository;
      readonly credentialSources: {
        rejectEgressMaterial(evidence: EgressMaterialEvidence): Promise<void>;
      };
    }) => Promise<T>,
  ): Promise<T>;
}

export interface EgressSendReceiptRepository {
  find(input: SendAttempt): Promise<StoredSendReceipt | undefined>;
  insert(input: SendAttempt): Promise<boolean>;
  save(receipt: StoredSendReceipt): Promise<void>;
  authorize(input: SendAttempt, authorization: AuthorizedSend): Promise<boolean>;
}

function invalid(): never {
  throw new ResourceStateConflictError("The send receipt input or recorded state conflicts.");
}

export function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return invalid();
  }
  return value as Record<string, unknown>;
}

function exact(value: unknown, keys: readonly string[]): Record<string, unknown> {
  const result = object(value);
  if (Object.keys(result).length !== keys.length || keys.some((key) => !(key in result))) {
    return invalid();
  }
  return result;
}

function text(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) {
    return invalid();
  }
  return value;
}

function date(value: unknown): string {
  const result = text(value);
  if (!Number.isFinite(Date.parse(result))) {
    return invalid();
  }
  return result;
}

function ref(value: unknown): EgressRef {
  const item = exact(value, ["id", "generation"]);
  if (
    typeof item.generation !== "number" ||
    !Number.isSafeInteger(item.generation) ||
    item.generation < 1
  ) {
    return invalid();
  }
  return { id: text(item.id), generation: item.generation };
}

function material(value: unknown): EgressMaterialEvidence {
  const item = object(value);
  const common = [
    "kind",
    "source",
    "binding",
    "grantHash",
    "isolationId",
    "materialId",
    "materialVersion",
    "usableUntil",
  ];
  const source = exact(item.source, [
    "installationId",
    "namespaceId",
    "source",
    "backend",
    "provider",
  ]);
  if (item.kind === "prepared_github") {
    exact(item, [
      ...common,
      "family",
      "ownerEpoch",
      "inputVersion",
      "preparationAttemptId",
      "providerExpiresAt",
    ]);
    const epoch = item.ownerEpoch;
    const usableUntil = date(item.usableUntil);
    const providerExpiresAt = date(item.providerExpiresAt);
    if (
      typeof epoch !== "number" ||
      !Number.isSafeInteger(epoch) ||
      epoch < 1 ||
      Date.parse(usableUntil) > Date.parse(providerExpiresAt)
    ) {
      return invalid();
    }
    return {
      kind: "prepared_github",
      source: {
        installationId: text(source.installationId),
        namespaceId: text(source.namespaceId),
        source: ref(source.source),
        backend: ref(source.backend),
        provider: ref(source.provider),
      },
      binding: ref(item.binding),
      grantHash: text(item.grantHash),
      isolationId: text(item.isolationId),
      family: ref(item.family),
      ownerEpoch: epoch,
      inputVersion: text(item.inputVersion),
      preparationAttemptId: text(item.preparationAttemptId),
      materialId: text(item.materialId),
      materialVersion: text(item.materialVersion),
      providerExpiresAt,
      usableUntil,
    };
  }
  exact(item, [
    ...common,
    "adoption",
    "materialRefId",
    "secret",
    "secretDriver",
    "authoritativeObservedAt",
    "retention",
  ]);
  const secret = exact(item.secret, ["kind", "namespaceId", "id"]);
  if (
    secret.kind !== "secret" ||
    item.kind !== "static" ||
    item.adoption !== "live" ||
    item.retention !== "none" ||
    secret.namespaceId !== source.namespaceId
  ) {
    return invalid();
  }
  return {
    kind: "static",
    source: {
      installationId: text(source.installationId),
      namespaceId: text(source.namespaceId),
      source: ref(source.source),
      backend: ref(source.backend),
      provider: ref(source.provider),
    },
    binding: ref(item.binding),
    grantHash: text(item.grantHash),
    isolationId: text(item.isolationId),
    adoption: "live",
    materialRefId: text(item.materialRefId),
    secret: { kind: "secret", namespaceId: text(secret.namespaceId), id: text(secret.id) },
    secretDriver: ref(item.secretDriver),
    materialId: text(item.materialId),
    materialVersion: text(item.materialVersion),
    authoritativeObservedAt: date(item.authoritativeObservedAt),
    usableUntil: date(item.usableUntil),
    retention: "none",
  };
}

export function attempt(value: unknown, authenticatedSender: EgressRef): SendAttempt {
  const item = exact(value, [
    "sender",
    "instanceId",
    "useId",
    "attemptId",
    "material",
    "deadlineAt",
  ]);
  const sender = ref(item.sender);
  if (!isDeepStrictEqual(sender, ref(authenticatedSender))) {
    return invalid();
  }
  return {
    sender,
    instanceId: text(item.instanceId),
    useId: text(item.useId),
    attemptId: text(item.attemptId),
    material: item.material === null ? null : material(item.material),
    deadlineAt: date(item.deadlineAt),
  };
}

const refusalCodes: Readonly<Record<string, readonly string[]>> = {
  denied: [
    "identity",
    "unauthorized",
    "withdrawn",
    "stale_configuration",
    "scope_mismatch",
    "ambiguous_route",
    "invalid_handle",
    "unsupported_operation",
  ],
  not_ready: [
    "cold",
    "expired",
    "insufficient_validity",
    "material_missing",
    "attachment_pending",
    "recovery_required",
  ],
  unavailable: ["authority", "resolver", "secret_store", "lifecycle"],
};

export function outcome(value: unknown): SendOutcome {
  const item = object(value);
  if (item.kind === "uncertain") {
    exact(item, ["kind", "dispatch"]);
    if (item.dispatch !== "possible") {
      return invalid();
    }
    return { kind: "uncertain", dispatch: "possible" };
  }
  if (item.kind === "refused") {
    exact(item, ["kind", "dispatched", "error"]);
    if (item.dispatched !== false) {
      return invalid();
    }
    const error = object(item.error);
    if (error.kind === "cancelled" || error.kind === "deadline_exceeded") {
      exact(error, ["kind"]);
      return { kind: "refused", dispatched: false, error: { kind: error.kind } };
    }
    exact(error, ["kind", "code"]);
    if (
      (error.kind !== "denied" && error.kind !== "not_ready" && error.kind !== "unavailable") ||
      !refusalCodes[error.kind]?.includes(text(error.code))
    ) {
      return invalid();
    }
    return {
      kind: "refused",
      dispatched: false,
      error: { kind: error.kind, code: text(error.code) },
    };
  }
  if (item.kind === "response_blocked") {
    exact(item, ["kind", "dispatch", "code"]);
    if (item.dispatch !== "confirmed" || item.code !== "response_policy") {
      return invalid();
    }
    return { kind: "response_blocked", dispatch: "confirmed", code: "response_policy" };
  }
  if (item.kind === "response" || item.kind === "provider_rejected") {
    exact(item, ["kind", "dispatch", "status"]);
    if (
      item.dispatch !== "confirmed" ||
      typeof item.status !== "number" ||
      !Number.isInteger(item.status) ||
      item.status < 100 ||
      item.status > 599
    ) {
      return invalid();
    }
    return { kind: item.kind, dispatch: "confirmed", status: item.status };
  }
  return invalid();
}

export function receipt(row: unknown, input: SendAttempt): StoredSendReceipt {
  const value = object(row);
  const {
    authorization: _authorization,
    outcome: _outcome,
    observation: _observation,
    settled: _settled,
    feedback: _feedback,
    ...binding
  } = value;
  const recorded = attempt(binding, input.sender);
  if (
    !isDeepStrictEqual(recorded, input) ||
    typeof value.settled !== "boolean" ||
    (value.feedback !== null && value.feedback !== "fenced")
  ) {
    return invalid();
  }
  return {
    ...recorded,
    authorization: value.authorization === null ? null : authorizedSend(value.authorization),
    observation: value.observation === null ? null : observation(value.observation),
    outcome: outcome(value.outcome),
    settled: value.settled,
    feedback: value.feedback,
  };
}

export function observation(value: unknown): SendObservation {
  const result = outcome(value);
  return result.kind === "refused" || result.kind === "uncertain" ? invalid() : result;
}

export function authorizedSend(value: unknown): AuthorizedSend {
  const item = exact(value, [
    "association",
    "requestDigest",
    "injectionDigest",
    "authorizedAt",
    "sendStartBy",
  ]);
  const association = exact(item.association, [
    "execution",
    "installation",
    "exchangeId",
    "responseId",
    "custodyId",
  ]);
  const execution = exact(association.execution, [
    "installationId",
    "namespaceId",
    "agentId",
    "servicePrincipalId",
    "revisionId",
    "executionId",
  ]);
  const claimedInstallation = object(association.installation);
  const boundKey = "peerKeyId" in claimedInstallation;
  const installation = exact(claimedInstallation, [
    "sandboxId",
    "instanceId",
    "configurationId",
    ...(boundKey ? ["peerKeyId"] : []),
    "plan",
  ]);
  return {
    association: {
      execution: {
        installationId: text(execution.installationId),
        namespaceId: text(execution.namespaceId),
        agentId: text(execution.agentId),
        servicePrincipalId: text(execution.servicePrincipalId),
        revisionId: text(execution.revisionId),
        executionId: text(execution.executionId),
      },
      installation: {
        sandboxId: text(installation.sandboxId),
        instanceId: text(installation.instanceId),
        configurationId: text(installation.configurationId),
        ...(boundKey ? { peerKeyId: text(installation.peerKeyId) } : {}),
        plan: ref(installation.plan),
      },
      exchangeId: text(association.exchangeId),
      responseId: text(association.responseId),
      custodyId: text(association.custodyId),
    },
    requestDigest: text(item.requestDigest),
    injectionDigest: text(item.injectionDigest),
    authorizedAt: date(item.authorizedAt),
    sendStartBy: date(item.sendStartBy),
  };
}

/** Trusted sender persistence. Receipts never authorize sending or retries. */
export class EgressSendReceipts {
  private readonly state: TransactionOwner;

  constructor(state: TransactionOwner) {
    this.state = state;
  }

  async begin(
    authenticatedSender: EgressRef,
    value: unknown,
  ): Promise<{ created: boolean; receipt: StoredSendReceipt }> {
    const input = attempt(value, authenticatedSender);
    return this.state.transact(async (unit) => {
      const created = await unit.egressSendReceipts.insert(input);
      return { created, receipt: receipt(await unit.egressSendReceipts.find(input), input) };
    });
  }

  /** A separate, non-replayable transition. Unknown COMMIT must propagate unchanged. */
  async authorize(
    authenticatedSender: EgressRef,
    value: unknown,
    authorization: AuthorizedSend,
  ): Promise<StoredSendReceipt> {
    const input = attempt(value, authenticatedSender);
    const selected = authorizedSend(authorization);
    return this.state.transact(async (unit) => {
      const previous = receipt(await unit.egressSendReceipts.find(input), input);
      if (
        previous.authorization !== null ||
        previous.settled ||
        previous.observation !== null ||
        !(await unit.egressSendReceipts.authorize(input, selected))
      ) {
        return invalid();
      }
      return receipt(await unit.egressSendReceipts.find(input), input);
    });
  }

  async recover(
    authenticatedSender: EgressRef,
    value: unknown,
  ): Promise<StoredSendReceipt | undefined> {
    const input = attempt(value, authenticatedSender);
    return this.state.transact(async (unit) => {
      const found = await unit.egressSendReceipts.find(input);
      return found === undefined ? undefined : receipt(found, input);
    });
  }

  /** Commit the observation and exact rejection fence before replying to the sender.
   * It does not establish that the supplier accepted/applied the policy decision. */
  async observe(
    authenticatedSender: EgressRef,
    value: unknown,
    result: unknown,
    rejection?: { readonly classification: "credential_rejected"; readonly evidence: unknown },
  ): Promise<StoredSendReceipt> {
    return this.write(authenticatedSender, value, observation(result), false, rejection);
  }

  /** Final settlement requires independent trusted evidence; unknown COMMIT propagates. */
  async record(
    authenticatedSender: EgressRef,
    value: unknown,
    result: unknown,
    rejection?: { readonly classification: "credential_rejected"; readonly evidence: unknown },
  ): Promise<StoredSendReceipt> {
    return this.write(authenticatedSender, value, outcome(result), true, rejection);
  }

  private async write(
    authenticatedSender: EgressRef,
    value: unknown,
    final: SendOutcome,
    settle: boolean,
    rejection?: { readonly classification: "credential_rejected"; readonly evidence: unknown },
  ): Promise<StoredSendReceipt> {
    const input = attempt(value, authenticatedSender);
    const feedback =
      rejection === undefined ? undefined : exact(rejection, ["classification", "evidence"]);
    const evidence = feedback === undefined ? undefined : material(feedback.evidence);
    if (
      feedback !== undefined &&
      (feedback.classification !== "credential_rejected" ||
        !isDeepStrictEqual(evidence, input.material) ||
        final.kind === "refused" ||
        final.kind === "uncertain")
    ) {
      return invalid();
    }
    if (final.kind === "provider_rejected" && evidence === undefined) {
      return invalid();
    }
    return this.state.transact(async (unit) => {
      const previous = receipt(await unit.egressSendReceipts.find(input), input);
      if (previous.authorization !== null && final.kind === "refused") {
        return invalid();
      }
      if (previous.settled && (!settle || !isDeepStrictEqual(previous.outcome, final))) {
        return invalid();
      }
      if (
        previous.observation !== null &&
        (final.kind === "refused" ||
          (final.kind !== "uncertain" && !isDeepStrictEqual(previous.observation, final)))
      ) {
        return invalid();
      }
      if (evidence !== undefined && previous.feedback !== "fenced") {
        await unit.credentialSources.rejectEgressMaterial(evidence);
      }
      const saved: StoredSendReceipt = {
        ...previous,
        outcome: settle ? final : previous.outcome,
        observation: settle ? previous.observation : observation(final),
        settled: settle,
        feedback: evidence === undefined ? previous.feedback : "fenced",
      };
      if (!isDeepStrictEqual(saved, previous)) {
        await unit.egressSendReceipts.save(saved);
      }
      return saved;
    });
  }

  /** Independently classified rejection of an observed response, never generic failure. */
  async reject(
    authenticatedSender: EgressRef,
    value: unknown,
    selectedEvidence: unknown,
  ): Promise<"fenced"> {
    const input = attempt(value, authenticatedSender);
    const evidence = material(selectedEvidence);
    if (!isDeepStrictEqual(input.material, evidence)) {
      return invalid();
    }
    return this.state.transact(async (unit) => {
      const previous = receipt(await unit.egressSendReceipts.find(input), input);
      if (
        previous.observation === null &&
        (!previous.settled ||
          previous.outcome.kind === "refused" ||
          previous.outcome.kind === "uncertain")
      ) {
        return invalid();
      }
      if (previous.feedback !== "fenced") {
        await unit.credentialSources.rejectEgressMaterial(evidence);
        await unit.egressSendReceipts.save({ ...previous, feedback: "fenced" });
      }
      return "fenced" as const;
    });
  }
}
