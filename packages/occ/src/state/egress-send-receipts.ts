import { isDeepStrictEqual } from "node:util";
import type { EgressRef, StaticMaterialEvidence } from "@openclaw-enterprise/contracts";
import { ResourceStateConflictError } from "../errors.ts";
import { immutableCopy } from "@openclaw-enterprise/utils";
import type { PlatformStateStore } from "./platform-state.ts";

export interface SendAttempt {
  readonly sender: EgressRef;
  readonly instanceId: string;
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

export type SendObservation = Extract<SendOutcome, { dispatch: "confirmed" }>;

export interface StoredSendReceipt extends SendAttempt {
  /** Observed response/policy decision, never proof the sender applied that decision. */
  readonly observation: SendObservation | null;
  readonly outcome: SendOutcome;
  readonly settled: boolean;
  readonly feedback: "fenced" | null;
}

type TransactionOwner = Pick<PlatformStateStore, "transact">;

export interface EgressSendReceiptRepository {
  find(input: SendAttempt): Promise<StoredSendReceipt | undefined>;
  insert(input: SendAttempt): Promise<boolean>;
  save(receipt: StoredSendReceipt): Promise<void>;
}

function key(input: SendAttempt): readonly unknown[] {
  return [input.sender.id, input.sender.generation, input.instanceId, input.useId, input.attemptId];
}

function initial(input: SendAttempt): StoredSendReceipt {
  return {
    ...input,
    observation: null,
    outcome: { kind: "uncertain", dispatch: "possible" },
    settled: false,
    feedback: null,
  };
}

export function memoryEgressSendReceipts(
  rows: Map<string, StoredSendReceipt>,
): EgressSendReceiptRepository {
  const id = (input: SendAttempt) => JSON.stringify(key(input));
  return {
    find: async (input) => rows.get(id(input)),
    insert: async (input) => {
      if (rows.has(id(input))) {
        return false;
      }
      rows.set(id(input), immutableCopy(initial(attempt(input, input.sender))));
      return true;
    },
    save: async (value) => {
      const previous = rows.get(id(value));
      if (previous === undefined) {
        return;
      }
      const saved = {
        ...previous,
        outcome: outcome(value.outcome),
        observation: value.observation === null ? null : observation(value.observation),
        settled: value.settled,
        feedback: value.feedback,
      };
      // Mirror the SQL receipt constraints in the database substitute.
      if (
        (!saved.settled && saved.outcome.kind !== "uncertain") ||
        ((saved.outcome.kind === "provider_rejected" ||
          saved.observation?.kind === "provider_rejected") &&
          saved.feedback !== "fenced") ||
        (saved.observation !== null &&
          saved.settled &&
          saved.outcome.kind !== "uncertain" &&
          !isDeepStrictEqual(saved.observation, saved.outcome)) ||
        (saved.feedback !== null &&
          (saved.feedback !== "fenced" ||
            saved.material === null ||
            (saved.observation === null &&
              (!saved.settled ||
                saved.outcome.kind === "refused" ||
                saved.outcome.kind === "uncertain"))))
      ) {
        return invalid();
      }
      rows.set(id(value), immutableCopy(saved));
    },
  };
}

export function postgresEgressSendReceipts(client: {
  query(sql: string, values: unknown[]): Promise<{ rows: unknown[] }>;
}): EgressSendReceiptRepository {
  const where =
    "sender_id=$1 AND sender_generation=$2 AND instance_id=$3 AND use_id=$4 AND attempt_id=$5";
  return {
    find: async (input) => {
      const result = await client.query(
        "SELECT * FROM occ.egress_send_receipts WHERE " + where + " FOR UPDATE",
        [...key(input)],
      );
      const found = result.rows[0];
      if (found === undefined) {
        return undefined;
      }
      const row = object(found);
      return receipt(
        {
          ...object(row.binding),
          outcome: row.outcome,
          observation: row.observation,
          settled: row.settled,
          feedback: row.feedback,
        },
        input,
      );
    },
    insert: async (input) => {
      const result = await client.query(
        "INSERT INTO occ.egress_send_receipts (sender_id,sender_generation,instance_id,use_id,attempt_id,binding,outcome) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING RETURNING sender_id",
        [...key(input), input, initial(input).outcome],
      );
      return result.rows.length === 1;
    },
    save: async (value) => {
      await client.query(
        "UPDATE occ.egress_send_receipts SET outcome=$6, observation=$7, settled=$8, feedback=$9 WHERE " +
          where,
        [...key(value), value.outcome, value.observation, value.settled, value.feedback],
      );
    },
  };
}

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
  const {
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
    observation: value.observation === null ? null : observation(value.observation),
    outcome: outcome(value.outcome),
    settled: value.settled,
    feedback: value.feedback,
  };
}

function observation(value: unknown): SendObservation {
  const result = outcome(value);
  return result.kind === "refused" || result.kind === "uncertain" ? invalid() : result;
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
