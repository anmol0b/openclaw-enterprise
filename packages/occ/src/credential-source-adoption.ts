import { isDeepStrictEqual } from "node:util";
import { immutableCopy } from "@openclaw-enterprise/utils";
import type {
  CredentialSource,
  EgressRef,
  EgressSourceKey,
  IAMDriver,
  SecretReference,
  VersionedSecretValue,
} from "@openclaw-enterprise/contracts";

/** Nonsecret identity of material already admitted by its immutable owner. */
export interface ImmutableSourceAuthority {
  readonly key: EgressSourceKey;
  readonly legacyDriverId: string;
  readonly origin: SecretReference;
  readonly originDriver: EgressRef;
  readonly originVersion: string;
  readonly target: {
    readonly kind: "snapshot" | "version";
    readonly owner: EgressRef;
    readonly id: string;
    readonly version: string;
  };
}

export type SourceAdoption =
  | { readonly mode: "explicit_update"; readonly authority: ImmutableSourceAuthority }
  | { readonly mode: "live"; readonly secret: SecretReference; readonly owner: EgressRef };

export interface AdoptedCredentialSource {
  readonly source: CredentialSource;
  readonly key: EgressSourceKey;
  readonly adoption: SourceAdoption;
}

export type AuthorityObservation =
  | { readonly state: "admitted"; readonly authority: ImmutableSourceAuthority }
  | { readonly state: "missing" | "revoked" | "unavailable" };

/** Trusted owner ports, not request-supplied attestations. No write or latest-value fallback. */
export interface SourceAdoptionAuthority {
  inspect(key: EgressSourceKey): Promise<AuthorityObservation>;
}

export interface SourceAdoptionMaterial {
  readImmutable(authority: ImmutableSourceAuthority): Promise<{
    readonly authority: ImmutableSourceAuthority;
    readonly material: VersionedSecretValue;
  }>;
  readLive(
    key: EgressSourceKey,
    secret: SecretReference,
    owner: EgressRef,
  ): Promise<{
    readonly secret: SecretReference;
    readonly owner: EgressRef;
    readonly material: VersionedSecretValue;
  }>;
}

export class SourceAdoptionError extends Error {
  readonly code: "denied" | "unavailable" | "missing_authority" | "mismatch";

  constructor(code: SourceAdoptionError["code"]) {
    super(`Credential source adoption: ${code}.`);
    this.name = "SourceAdoptionError";
    this.code = code;
  }
}

function requireMatch(condition: boolean): void {
  if (!condition) {
    throw new SourceAdoptionError("mismatch");
  }
}

function validRef(ref: EgressRef): boolean {
  return !!ref.id && Number.isSafeInteger(ref.generation) && ref.generation > 0;
}

function checkSource(source: CredentialSource, key: EgressSourceKey): SecretReference {
  // These are the two static inputs in the legacy catalog. In particular, an OAuth source
  // with one Secret is a lifecycle root, never an input for this serving-material migration.
  const fields = Object.keys(source.secrets);
  const [field] = fields;
  requireMatch(
    source.state === "ready" &&
      source.id === key.source.id &&
      source.namespaceId === key.namespaceId &&
      !!key.installationId &&
      validRef(key.source) &&
      validRef(key.backend) &&
      validRef(key.provider) &&
      fields.length === 1 &&
      ((source.type === "openai" && field === "api_key") ||
        (source.type === "bearer-token" && field === "token")),
  );
  const secret = source.secrets[field!]!;
  requireMatch(secret.kind === "secret" && !!secret.id && secret.namespaceId === key.namespaceId);
  return secret;
}

async function admitted(
  source: CredentialSource,
  key: EgressSourceKey,
  owner: SourceAdoptionAuthority,
): Promise<ImmutableSourceAuthority> {
  const origin = checkSource(source, key);
  const result = await owner.inspect(key);
  if (result.state !== "admitted") {
    if (result.state === "revoked") {
      throw new SourceAdoptionError("denied");
    }
    throw new SourceAdoptionError(result.state === "missing" ? "missing_authority" : "unavailable");
  }
  const authority = result.authority;
  requireMatch(
    isDeepStrictEqual(authority.key, key) &&
      authority.legacyDriverId === source.driverId &&
      isDeepStrictEqual(authority.origin, origin) &&
      validRef(authority.originDriver) &&
      validRef(authority.target.owner) &&
      !!authority.originVersion &&
      !!authority.target.id &&
      !!authority.target.version &&
      (authority.target.kind === "snapshot" || authority.target.kind === "version"),
  );
  if (authority.target.kind === "version") {
    requireMatch(
      isDeepStrictEqual(authority.target.owner, authority.originDriver) &&
        authority.target.id === origin.id &&
        authority.target.version === authority.originVersion,
    );
  }
  return immutableCopy(authority);
}

/** Reads admission only. A legacy SecretRef or Gateway copy cannot manufacture authority. */
export async function migrateCredentialSource(
  source: CredentialSource,
  key: EgressSourceKey,
  owner: SourceAdoptionAuthority,
): Promise<AdoptedCredentialSource> {
  source = immutableCopy(source);
  key = immutableCopy(key);
  requireMatch(source.egress === undefined);
  const authority = await admitted(source, key, owner);
  return immutableCopy({ source, key, adoption: { mode: "explicit_update", authority } });
}

/** Material access is separate from admission; snapshot reads never consult their origin. */
export async function readAdoptedCredentialSource(
  record: AdoptedCredentialSource,
  owner: SourceAdoptionAuthority,
  material: SourceAdoptionMaterial,
): Promise<VersionedSecretValue> {
  record = immutableCopy(record);
  const secret = checkSource(record.source, record.key);
  if (record.adoption.mode === "explicit_update") {
    const authority = await admitted(record.source, record.key, owner);
    requireMatch(isDeepStrictEqual(authority, record.adoption.authority));
    const result = await material.readImmutable(authority);
    requireMatch(isDeepStrictEqual(result.authority, authority));
    requireMatch(result.material.version === authority.target.version);
    return result.material;
  }
  requireMatch(
    record.adoption.mode === "live" &&
      isDeepStrictEqual(record.adoption.secret, secret) &&
      validRef(record.adoption.owner),
  );
  const result = await material.readLive(record.key, record.adoption.secret, record.adoption.owner);
  requireMatch(
    record.adoption.secret.namespaceId === record.key.namespaceId &&
      isDeepStrictEqual(result.secret, record.adoption.secret) &&
      isDeepStrictEqual(result.owner, record.adoption.owner) &&
      !!result.material.version,
  );
  return result.material;
}

async function authorize(
  iam: IAMDriver,
  principalId: string,
  action: "create" | "update" | "operate",
  resource: SecretReference | { kind: "credential_source"; id: string; namespaceId: string },
): Promise<void> {
  if (!(await iam.authorize({ principalId, action, resource })).allowed) {
    throw new SourceAdoptionError("denied");
  }
}

/** Validated candidate only: the integration owner must fence and durably activate it. */
export async function prepareLiveSource(
  input: {
    readonly source: CredentialSource;
    readonly key: EgressSourceKey;
    readonly secretOwner: EgressRef;
    readonly principalId: string;
    readonly current?: AdoptedCredentialSource;
  },
  ports: {
    readonly iam: IAMDriver;
    readonly authority: SourceAdoptionAuthority;
    readonly material: SourceAdoptionMaterial;
  },
): Promise<AdoptedCredentialSource> {
  // Capture before awaiting IAM; callers cannot swap a checked candidate during material I/O.
  const { source, key, secretOwner, principalId, current } = immutableCopy(input);
  await authorize(ports.iam, principalId, current ? "update" : "create", {
    kind: "credential_source",
    id: source.id,
    namespaceId: source.namespaceId,
  });
  const secret = checkSource(source, key);
  requireMatch(validRef(secretOwner));
  if (current) {
    requireMatch(isDeepStrictEqual(key, current.key));
    requireMatch(isDeepStrictEqual({ ...source, secrets: current.source.secrets }, current.source));
    if (current.adoption.mode === "explicit_update") {
      const authority = await admitted(current.source, current.key, ports.authority);
      requireMatch(isDeepStrictEqual(authority, current.adoption.authority));
    }
  }
  requireMatch(current !== undefined || key.source.generation === 1);
  await authorize(ports.iam, principalId, "operate", secret);
  const candidate: AdoptedCredentialSource = immutableCopy({
    source,
    key: { ...key, source: { ...key.source, generation: current ? key.source.generation + 1 : 1 } },
    adoption: { mode: "live", secret, owner: secretOwner },
  });
  await readAdoptedCredentialSource(candidate, ports.authority, ports.material);
  return candidate;
}

// TODO(egress source adoption): wire durable candidate CAS, replacement installation and both
// operation authorization checks into OCC before enabling this module in the Agent workflow.
