import { isDeepStrictEqual } from "node:util";
import type { EgressRef, StaticMaterialEvidence } from "@openclaw-enterprise/contracts";
import { ResourceStateConflictError } from "../errors.ts";
import type { PostgresPlatformState } from "./postgres-state.ts";

export interface SendAttempt {
  readonly sender: EgressRef;
  readonly useId: string;
  readonly attemptId: string;
  readonly material: StaticMaterialEvidence | null;
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

export interface StoredSendReceipt extends SendAttempt {
  readonly outcome: SendOutcome;
  readonly settled: boolean;
  readonly feedback: "fenced" | null;
}

type TransactionOwner = Pick<PostgresPlatformState, "transact" | "queryInTransaction">;

function invalid(): never {
  throw new ResourceStateConflictError("The send receipt input or recorded state conflicts.");
}

function object(value: unknown): Record<string, unknown> {
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

function material(value: unknown): StaticMaterialEvidence {
  const item = exact(value, [
    "kind",
    "source",
    "binding",
    "grantHash",
    "isolationId",
    "adoption",
    "materialRefId",
    "secret",
    "secretDriver",
    "materialId",
    "materialVersion",
    "authoritativeObservedAt",
    "usableUntil",
    "retention",
  ]);
  const source = exact(item.source, [
    "installationId",
    "namespaceId",
    "source",
    "backend",
    "provider",
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

function attempt(value: unknown, authenticatedSender: EgressRef): SendAttempt {
  const item = exact(value, ["sender", "useId", "attemptId", "material", "deadlineAt"]);
  const sender = ref(item.sender);
  if (!isDeepStrictEqual(sender, ref(authenticatedSender))) {
    return invalid();
  }
  return {
    sender,
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

function outcome(value: unknown): SendOutcome {
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

function receipt(row: unknown, input: SendAttempt): StoredSendReceipt {
  const value = object(row);
  const recorded = attempt(value.binding, input.sender);
  if (
    !isDeepStrictEqual(recorded, input) ||
    typeof value.settled !== "boolean" ||
    (value.feedback !== null && value.feedback !== "fenced")
  ) {
    return invalid();
  }
  return {
    ...recorded,
    outcome: outcome(value.outcome),
    settled: value.settled,
    feedback: value.feedback,
  };
}

/**
 * Private trusted-sender persistence, never an Agent-facing authority API.
 * Authentication and classification belong to the caller. Nothing here sends,
 * authorizes, retries, or decides whether an operation may be dispatched.
 * TODO: compose at the static rejection caller with the canonical schema migration.
 */
export class EgressSendReceipts {
  private readonly state: TransactionOwner;

  constructor(state: TransactionOwner) {
    this.state = state;
  }

  /**
   * Persist possible dispatch before sending. Even created=true grants no authority;
   * the caller still needs its live checks. An existing attempt never permits resend.
   */
  async begin(
    authenticatedSender: EgressRef,
    value: unknown,
  ): Promise<{ created: boolean; receipt: StoredSendReceipt }> {
    const input = attempt(value, authenticatedSender);
    return this.state.transact(async (unit) => {
      const inserted = await this.state.queryInTransaction(
        unit,
        `INSERT INTO occ.egress_send_receipts (sender_id, sender_generation, use_id, attempt_id, binding, outcome)
         VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING RETURNING *`,
        [...this.key(input), input, { kind: "uncertain", dispatch: "possible" }],
      );
      const found =
        inserted.rows[0] ??
        (
          await this.state.queryInTransaction(
            unit,
            `SELECT * FROM occ.egress_send_receipts WHERE sender_id=$1 AND sender_generation=$2 AND use_id=$3 AND attempt_id=$4`,
            this.key(input),
          )
        ).rows[0];
      return { created: inserted.rows.length === 1, receipt: receipt(found, input) };
    });
  }

  /** Missing and possible records are recovery evidence only, never permission to retry. */
  async recover(
    authenticatedSender: EgressRef,
    value: unknown,
  ): Promise<StoredSendReceipt | undefined> {
    const input = attempt(value, authenticatedSender);
    return this.state.transact(async (unit) => {
      const found = await this.state.queryInTransaction(
        unit,
        `SELECT * FROM occ.egress_send_receipts WHERE sender_id=$1 AND sender_generation=$2 AND use_id=$3 AND attempt_id=$4`,
        this.key(input),
      );
      return found.rows[0] === undefined ? undefined : receipt(found.rows[0], input);
    });
  }

  /** Settle once. Unknown COMMIT propagates; reconcile using the unchanged attempt. */
  async record(
    authenticatedSender: EgressRef,
    value: unknown,
    result: unknown,
    rejection?: { readonly classification: "credential_rejected"; readonly evidence: unknown },
  ): Promise<StoredSendReceipt> {
    const input = attempt(value, authenticatedSender);
    const final = outcome(result);
    if (final.kind === "provider_rejected" && input.material === null) {
      return invalid();
    }
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
      const found = await this.state.queryInTransaction(
        unit,
        `SELECT * FROM occ.egress_send_receipts WHERE sender_id=$1 AND sender_generation=$2 AND use_id=$3 AND attempt_id=$4 FOR UPDATE`,
        this.key(input),
      );
      const previous = receipt(found.rows[0], input);
      if (previous.settled) {
        if (!isDeepStrictEqual(previous.outcome, final)) {
          return invalid();
        }
        if (evidence === undefined || previous.feedback === "fenced") {
          return previous;
        }
      }
      if (evidence !== undefined) {
        await unit.credentialSources.rejectEgressMaterial(evidence);
      }
      const saved = await this.state.queryInTransaction(
        unit,
        `UPDATE occ.egress_send_receipts SET outcome=$5, settled=true, feedback=COALESCE(feedback, $6) WHERE sender_id=$1 AND sender_generation=$2 AND use_id=$3 AND attempt_id=$4 RETURNING *`,
        [...this.key(input), final, evidence === undefined ? null : "fenced"],
      );
      return receipt(saved.rows[0], input);
    });
  }

  /** Independent trusted credential classification, including blocked responses. */
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
      const found = await this.state.queryInTransaction(
        unit,
        `SELECT * FROM occ.egress_send_receipts WHERE sender_id=$1 AND sender_generation=$2 AND use_id=$3 AND attempt_id=$4 FOR UPDATE`,
        this.key(input),
      );
      const recorded = receipt(found.rows[0], input);
      if (
        !recorded.settled ||
        recorded.outcome.kind === "refused" ||
        recorded.outcome.kind === "uncertain"
      ) {
        return invalid();
      }
      if (recorded.feedback === "fenced") {
        return recorded.feedback;
      }
      // The existing store-qualified static fence IS the durable obligation.
      // It neither rotates material nor follows a pointer to a newer version.
      await unit.credentialSources.rejectEgressMaterial(evidence);
      await this.state.queryInTransaction(
        unit,
        `UPDATE occ.egress_send_receipts SET feedback='fenced' WHERE sender_id=$1 AND sender_generation=$2 AND use_id=$3 AND attempt_id=$4`,
        this.key(input),
      );
      return "fenced";
    });
  }

  private key(input: SendAttempt): readonly unknown[] {
    return [input.sender.id, input.sender.generation, input.useId, input.attemptId];
  }
}
