import type {
  GitHubMetadataGrant,
  PreparedGitHubEgressLifecycle,
  PreparedGitHubEgressSource,
  PreparedGitHubMaterialEvidence,
} from "./prepared-github-egress.ts";
import type {
  AgentRevision,
  CredentialSource,
  CredentialSourceType,
  Driver,
  Namespace,
  Secret,
  SecretReference,
} from "./index.ts";

/** Configuration generations never advance merely because Secret material rotates. */
export interface EgressRef {
  readonly id: string;
  readonly generation: number;
}

export interface EgressSourceKey {
  readonly installationId: string;
  readonly namespaceId: string;
  readonly source: EgressRef;
  readonly backend: EgressRef;
  readonly provider: EgressRef;
}

/** Only live static inputs are admitted by the first protected implementation. */
export interface StaticEgressSource {
  readonly key: EgressSourceKey;
  readonly schemaVersion: 1;
  readonly adoption: "live";
  readonly materialRefId: string;
  readonly secret: SecretReference;
  readonly secretDriver: EgressRef;
  readonly sender: EgressRef;
  readonly resolver: EgressRef;
  /** Zero retention: every operation reads the authoritative selected store. */
  readonly retention: "none";
}

export type ProtectedEgressSource = StaticEgressSource | PreparedGitHubEgressSource;

export interface VersionedSecretValue {
  readonly value: string;
  readonly version: string;
  readonly authoritativeObservedAt: string;
  readonly expiresAt?: string;
}

/** Trusted Resolver-only input; values never become workload projections. */
export interface CredentialInputRead {
  readonly secret: Readonly<Secret>;
  readonly deadlineAt: string;
  readonly signal: AbortSignal;
  readonly retention: "none";
}

export interface EgressExecution {
  readonly installationId: string;
  readonly namespaceId: string;
  readonly agentId: string;
  readonly servicePrincipalId: string;
  readonly revisionId: string;
  readonly executionId: string;
}

export interface InferenceGrant {
  readonly kind: "inference";
  readonly models: readonly string[];
  readonly providerTools: "none";
}

export interface EgressBinding {
  readonly binding: EgressRef;
  readonly execution: EgressExecution;
  readonly source: EgressSourceKey;
  readonly grant: InferenceGrant | GitHubMetadataGrant;
  readonly grantHash: string;
  readonly isolationId: string;
}

export interface EgressRoute {
  readonly route: EgressRef;
  readonly binding: EgressBinding;
  readonly origin: string;
  readonly path: string;
  readonly method: "POST" | "GET";
  readonly operationPolicy: EgressRef;
  readonly responsePolicy: EgressRef;
  readonly deadlineMs: number;
}

export interface EgressPlan {
  readonly id: string;
  readonly generation: number;
  readonly execution: EgressExecution;
  readonly sandboxDriverId: string;
  readonly egressDriverId: string;
  readonly routes: readonly EgressRoute[];
}

/** Recorded only from authenticated adapter observation of the exact installed policy. */
export interface EgressInstallation {
  readonly plan: EgressPlan;
  readonly sandboxId: string;
  readonly sender: EgressRef;
  readonly installedAt: string;
  /** Adapter-verified installation fence. Historical evidence must be revalidated for each use. */
  readonly enforcement: {
    readonly instanceId: string;
    readonly configurationId: string;
    /** Public key bound by the adapter to this installation, never selected by a request. */
    readonly peerKeyId?: string;
  };
}

export interface EgressRequest {
  readonly id: string;
  readonly method: string;
  readonly url: string;
  readonly headers: readonly (readonly [string, string])[];
  readonly body: Uint8Array;
  readonly deadlineAt: string;
  readonly bindingId?: string;
}

export interface InferenceOperation {
  readonly kind: "inference";
  readonly action: "generate";
  readonly model: string;
}

export type EgressOperation =
  | InferenceOperation
  | {
      readonly kind: "github_repository_metadata";
      readonly repository: string;
      readonly repositoryId: string;
    };

export type EgressMaterialEvidence = StaticMaterialEvidence | PreparedGitHubMaterialEvidence;

export interface StaticMaterialEvidence {
  readonly kind: "static";
  readonly source: EgressSourceKey;
  readonly binding: EgressRef;
  readonly grantHash: string;
  readonly isolationId: string;
  readonly adoption: "live";
  readonly materialRefId: string;
  readonly secret: SecretReference;
  readonly secretDriver: EgressRef;
  readonly materialId: string;
  readonly materialVersion: string;
  readonly authoritativeObservedAt: string;
  readonly usableUntil: string;
  readonly retention: "none";
}

export type EgressRefusal =
  | {
      readonly kind: "denied";
      readonly code:
        | "identity"
        | "unauthorized"
        | "withdrawn"
        | "stale_configuration"
        | "scope_mismatch"
        | "ambiguous_route"
        | "invalid_handle"
        | "unsupported_operation";
    }
  | {
      readonly kind: "not_ready";
      readonly code: "material_missing" | "attachment_pending" | "expired";
    }
  | { readonly kind: "unavailable"; readonly code: "authority" | "secret_store" | "resolver" }
  | { readonly kind: "cancelled" | "deadline_exceeded" };

export interface EgressResponse {
  /** Present only when the trusted transport observed end-of-message, including actual last trailers. */
  readonly trailers?: readonly (readonly [string, string])[];
  readonly status: number;
  readonly headers: readonly (readonly [string, string])[];
  readonly body: Uint8Array;
}

/** Installed trusted provider semantics; callers never supply code or an injection callback. */
export interface CredentialProviderDefinition {
  readonly ref: EgressRef;
  readonly schemaVersion: 1;
  readonly sourceType: CredentialSourceType;
  normalizeConfig(config: Readonly<Record<string, string>>): Readonly<Record<string, string>>;
  normalizeGrant(
    models: readonly string[],
    config?: Readonly<Record<string, string>>,
  ): InferenceGrant | GitHubMetadataGrant;
  routes(source: Readonly<CredentialSource>, binding: EgressBinding): readonly EgressRoute[];
  classify(route: EgressRoute, request: EgressRequest): EgressOperation | undefined;
  inject(value: string): readonly (readonly [string, string])[];
  /** Positive provider evidence only; status alone never identifies rejected credentials. */
  credentialRejected(response: EgressResponse): boolean;
  protectResponse(
    response: EgressResponse,
    value: string,
    request: EgressRequest,
    operation: EgressOperation,
  ): EgressResponse | undefined;
}

export interface CredentialSourceControl {
  readonly preparedGitHub?: PreparedGitHubEgressLifecycle;
  readonly backend: EgressRef;
  readonly sender: EgressRef;
  readonly resolver: EgressRef;
  readonly providers: readonly CredentialProviderDefinition[];
  /** Capability evidence is obtained from the actual configured counterpart, never inferred. */
  assertAvailable(signal: AbortSignal): Promise<void>;
}

export interface EgressAttachment {
  readonly plan: EgressPlan;
  /** Nonsecret adapter-owned configuration; only the paired Sandbox interprets it. */
  readonly configuration: Readonly<Record<string, unknown>>;
}

export interface EgressRevisionContext {
  readonly namespace: Readonly<Namespace>;
  readonly revision: Readonly<AgentRevision>;
  readonly plan: EgressPlan;
  readonly signal: AbortSignal;
}

export interface EgressProxyDriver extends Driver {
  readonly capability: "egress_proxy";
  readonly sourceControl: CredentialSourceControl;
  configureRevision(context: EgressRevisionContext): Promise<EgressAttachment>;
  attachmentStatus(
    context: EgressRevisionContext,
    prepared: EgressAttachment,
  ): Promise<EgressInstallation | undefined>;
  /** Query the counterpart again; persisted installation records are not readiness leases. */
  verifyInstallation(
    context: EgressRevisionContext,
    installation: EgressInstallation,
  ): Promise<boolean>;
  withdrawBinding(context: EgressRevisionContext, binding: EgressRef): Promise<boolean>;
  removeRevision(context: EgressRevisionContext): Promise<boolean>;
}

/** Durable admission semantics, independent of credential bindings and route count. */
export interface ExecutionAdmission {
  readonly version: 2;
  readonly mode: "protected" | "unprotected";
}

/** Recognition only. A valid protected schema is not proof of deployability. */
export function assertExecutionAdmission(
  revision: Pick<AgentRevision, "executionAdmission" | "egressPlan">,
): void {
  const admission = revision.executionAdmission;
  if (
    !admission ||
    admission.version !== 2 ||
    (admission.mode !== "protected" && admission.mode !== "unprotected") ||
    Object.keys(admission).some((key) => key !== "version" && key !== "mode")
  ) {
    throw new Error("Missing or unsupported durable execution admission.");
  }
  if ((admission.mode === "protected") !== (revision.egressPlan !== undefined)) {
    throw new Error("Inconsistent durable execution admission and egress plan.");
  }
  if (admission.mode === "protected" && !Array.isArray(revision.egressPlan?.routes)) {
    throw new Error("Invalid protected execution plan.");
  }
}

/** Current shipped execution cutoff; ordinary Agent authentication cannot release it. */
export function assertExecutionReleaseAllowed(
  revision: Pick<AgentRevision, "executionAdmission" | "egressPlan">,
): void {
  assertExecutionAdmission(revision);
  if (revision.executionAdmission.mode === "protected") {
    // TODO(M1): enable only after Compute-owned release, installed deny-all for empty
    // plans, and an old-reader fence are proven together. No runtime flag bypass.
    throw new Error(
      "Protected execution is unavailable until Compute release and old-reader fencing are proven.",
    );
  }
}
