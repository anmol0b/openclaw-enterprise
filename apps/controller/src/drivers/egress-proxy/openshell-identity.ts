import { createPublicKey, verify, type KeyObject } from "node:crypto";
import type { EgressRef } from "@openclaw-enterprise/contracts";
import type { EgressPeer, EgressPeerVerifier } from "@openclaw-enterprise/occ";
import { asRecord } from "@openclaw-enterprise/utils";

export interface OpenShellEgressIdentityOptions {
  readonly issuer: string;
  readonly audience: string;
  readonly keyId: string;
  readonly publicKey: string | Buffer;
  readonly sender: EgressRef;
}

function instanceId(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)
  );
}

/** Verifies gateway-issued extension identities; sandbox names and request JSON grant nothing. */
export class OpenShellEgressIdentity implements EgressPeerVerifier {
  readonly audience: string;
  private readonly options: OpenShellEgressIdentityOptions;
  private readonly key: KeyObject;

  constructor(options: OpenShellEgressIdentityOptions) {
    this.options = options;
    this.audience = options.audience;
    this.key = createPublicKey(options.publicKey);
    if (
      this.key.asymmetricKeyType !== "ed25519" ||
      !options.issuer ||
      !options.audience ||
      !options.keyId ||
      !options.sender.id ||
      options.sender.generation < 1
    ) {
      throw new Error("Invalid OpenShell egress identity configuration.");
    }
  }

  private claims(authorization: string): Record<string, unknown> | undefined {
    if (!authorization.startsWith("Bearer ") || authorization.length > 8192) {
      return undefined;
    }
    const token = authorization.slice(7);
    const parts = token.split(".");
    if (parts.length !== 3 || parts.some((part) => !/^[A-Za-z0-9_-]+$/.test(part))) {
      return undefined;
    }
    try {
      const header = asRecord(JSON.parse(Buffer.from(parts[0]!, "base64url").toString("utf8")));
      if (
        !header ||
        header.alg !== "EdDSA" ||
        header.typ !== "openshell-ext+jwt" ||
        header.kid !== this.options.keyId ||
        header.crit !== undefined ||
        !verify(
          null,
          Buffer.from(`${parts[0]}.${parts[1]}`),
          this.key,
          Buffer.from(parts[2]!, "base64url"),
        )
      ) {
        return undefined;
      }
      const claims = asRecord(JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8")));
      const now = Math.floor(Date.now() / 1000);
      if (
        !claims ||
        claims.iss !== this.options.issuer ||
        claims.aud !== this.options.audience ||
        typeof claims.iat !== "number" ||
        !Number.isSafeInteger(claims.iat) ||
        typeof claims.exp !== "number" ||
        !Number.isSafeInteger(claims.exp) ||
        claims.iat > now + 5 ||
        claims.exp <= now ||
        claims.exp <= claims.iat ||
        claims.exp - claims.iat > 3600 ||
        typeof claims.jti !== "string" ||
        claims.jti.length === 0
      ) {
        return undefined;
      }
      return claims;
    } catch {
      return undefined;
    }
  }

  async verify(authorization: string): Promise<EgressPeer | undefined> {
    const claims = this.claims(authorization);
    if (
      !claims ||
      claims.caller_kind !== "supervisor" ||
      typeof claims.sandbox_id !== "string" ||
      !claims.sandbox_id ||
      !instanceId(claims.instance_id) ||
      claims.sub !== `spiffe://openshell/sandbox/${claims.sandbox_id}`
    ) {
      return undefined;
    }
    return {
      sender: this.options.sender,
      sandboxId: claims.sandbox_id,
      instanceId: claims.instance_id,
      expiresAt: new Date(Number(claims.exp) * 1000).toISOString(),
    };
  }

  verifyControl(authorization: string): boolean {
    const claims = this.claims(authorization);
    return (
      claims !== undefined &&
      ((claims.caller_kind === "gateway" &&
        claims.sub === this.options.issuer &&
        claims.sandbox_id === undefined) ||
        (claims.caller_kind === "supervisor" &&
          instanceId(claims.instance_id) &&
          typeof claims.sandbox_id === "string" &&
          claims.sub === `spiffe://openshell/sandbox/${claims.sandbox_id}`))
    );
  }
}
