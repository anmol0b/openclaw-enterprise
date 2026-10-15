import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import type { PreparedGitHubEgressSource, Secret } from "@openclaw-enterprise/contracts";
import type { PostgresClient, PostgresPool } from "@openclaw-enterprise/occ";
import type {
  GitHubPreparationAdmission as Admission,
  GitHubPreparationAttempt as Attempt,
  GitHubPreparationFamily as Family,
  GitHubPreparationStore,
} from "./prepared-contracts.ts";

const families = "occ.prepared_github_families";
const attempts = "occ.prepared_github_attempts";
type Source = PreparedGitHubEgressSource;
type FamilyRow = {
  source: Source;
  issuer: Secret;
  admission: Admission;
  enabled: boolean;
  live: boolean;
};
type AttemptRow = {
  id: string;
  admission: Admission;
  state: Attempt["state"];
  custody: string;
  material_version: string | null;
  provider_expires_at: Date;
  usable_until: Date;
  sealed: Buffer;
};

// Do not trust enrollment alone. A tombstone, an in-place change to the grant or a different
// issuer reference fences use even if management crashed before reaching this repository.
const live = (states: string) => `EXISTS (
 SELECT 1 FROM occ.credential_sources s JOIN occ.credential_source_secrets r
 ON r.namespace_id=s.namespace_id AND r.credential_source_id=s.id AND r.field='private_key'
 JOIN occ.secrets k ON k.namespace_id=r.namespace_id AND k.id=r.secret_id
 JOIN occ.installation i ON i.id=f.source #>> '{key,installationId}'
 WHERE s.id=f.source_id AND s.egress=f.source AND s.config->>'authority'='execution' AND s.state IN (${states})
 AND k.id=f.issuer->>'id' AND k.driver_id=f.issuer->>'driverId'
 AND k.backend_uid=f.issuer #>> '{backendRef,uid}' AND s.namespace_id=f.source #>> '{key,namespaceId}')`;
const active = live("'ready'");
const enrolling = live("'registering','ready'");
const matching = "f.source_id = $1 AND f.source = $2::jsonb";
const aad = (family: string, id: string) =>
  Buffer.from("occ:prepared-github:v1:" + family + ":" + id);

export class PreparedGitHubPostgres {
  private readonly pool: PostgresPool;
  private readonly custodyKey: Buffer;
  constructor(pool: PostgresPool, custodyKey: Buffer) {
    this.pool = pool;
    this.custodyKey = custodyKey;
  }

  private seal(bytes: Uint8Array, family: string, id: string) {
    const nonce = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.custodyKey, nonce);
    cipher.setAAD(aad(family, id));
    return Buffer.concat([nonce, cipher.update(bytes), cipher.final(), cipher.getAuthTag()]);
  }
  private open(b: Buffer, family: string, id: string) {
    const cipher = createDecipheriv("aes-256-gcm", this.custodyKey, b.subarray(0, 12));
    cipher.setAAD(aad(family, id));
    cipher.setAuthTag(b.subarray(-16));
    return Buffer.concat([cipher.update(b.subarray(12, -16)), cipher.final()]);
  }

  private async transaction<T>(work: (c: PostgresClient) => Promise<T>): Promise<T> {
    const c = await this.pool.connect();
    let discard = false;
    try {
      await c.query("BEGIN");
      await c.query("SET LOCAL statement_timeout = '4000ms'");
      await c.query("SET LOCAL lock_timeout = '1000ms'");
      const result = await work(c);
      try {
        await c.query("COMMIT");
      } catch (e) {
        discard = true;
        throw e;
      }
      return result;
    } catch (error) {
      if (!discard) {
        try {
          await c.query("ROLLBACK");
        } catch {
          discard = true;
        }
      }
      // Database diagnostics can contain failing row contents. No automatic transaction retries.
      const candidate = (error as { code?: string }).code;
      const code = candidate && /^[0-9A-Z]{5}$/.test(candidate) ? candidate : "guard";
      // eslint-disable-next-line preserve-caught-error -- original errors may contain the secret-bearing row
      throw new Error("Prepared GitHub custody transaction did not complete (" + code + ").");
    } finally {
      c.release(discard);
    }
  }

  async enroll(source: Source, issuer: Readonly<Secret>, admission: Admission) {
    const key = source.key.source.id;
    await this.transaction(async (c) => {
      await c.query(
        `INSERT INTO ${families} (source_id,source,issuer,admission) VALUES ($1,$2,$3,$4)
        ON CONFLICT (source_id) DO NOTHING`,
        [key, source, issuer, admission],
      );
      const { rows } = await c.query(
        `SELECT 1 FROM ${families} f WHERE ${matching}
        AND f.issuer=$3::jsonb AND enabled AND ${enrolling} FOR UPDATE OF f`,
        [key, source, issuer],
      );
      if (!rows.length) {
        throw new Error("Source or issuer changed during enrollment.");
      }
    });
  }

  async withdraw(source: Source) {
    const key = source.key.source.id;
    await this.transaction(async (c) => {
      await c.query(`UPDATE ${families} f SET enabled=false,worker_claim=NULL WHERE ${matching}`, [
        key,
        source,
      ]);
      await c.query(
        `UPDATE ${attempts} a SET custody='retire' FROM ${families} f WHERE ${matching}
        AND NOT enabled AND a.source_id=f.source_id AND custody='current'`,
        [key, source],
      );
    });
  }

  async withdrawalSettled(source: Source) {
    return this.transaction(async (c) => {
      const { rows } = await c.query(
        `SELECT 1 FROM ${attempts} a JOIN ${families} f USING (source_id)
        WHERE ${matching} AND NOT enabled AND custody <> 'revoked' LIMIT 1`,
        [source.key.source.id, source],
      );
      return !rows.length;
    });
  }

  async claim(claim: string) {
    return this.transaction(async (c) => {
      const { rows } = await c.query(
        `WITH due AS (SELECT source_id FROM ${families} f
        WHERE enabled AND next_check_at <= clock_timestamp() AND ${active}
        ORDER BY next_check_at LIMIT 1 FOR UPDATE SKIP LOCKED)
        UPDATE ${families} f SET next_check_at=clock_timestamp() + interval '60 seconds',worker_claim=$1
        FROM due WHERE f.source_id=due.source_id RETURNING f.source, f.issuer`,
        [claim],
      );
      return rows[0] as Pick<FamilyRow, "source" | "issuer"> | undefined;
    });
  }

  // The claim fences stale input observations, not unknown issuance. An unfinished attempt
  // stays unfinished across claims, input rotation, and restarts. No provider I/O under a SQL lock.
  async observeInput(source: Source, claim: string, version: string) {
    const key = source.key.source.id;
    return this.transaction(async (c) => {
      const { rows } = await c.query(
        `SELECT admission FROM ${families} f WHERE ${matching}
        AND enabled AND worker_claim=$3 AND ${active} FOR UPDATE OF f`,
        [key, source, claim],
      );
      const old = (rows[0] as { admission: Admission } | undefined)?.admission;
      if (!old || old.inputVersion === version) {
        return old;
      }
      const admission: Admission = {
        ...old,
        inputVersion: version,
        ownerEpoch: old.ownerEpoch + 1,
      };
      await c.query(`UPDATE ${families} SET admission=$2 WHERE source_id=$1`, [key, admission]);
      await c.query(
        `UPDATE ${attempts} SET custody='retire' WHERE source_id=$1 AND custody='current'`,
        [key],
      );
      return admission;
    });
  }

  async metadata(source: Source) {
    return this.transaction(async (c) => {
      // Exclude sealed bytes even from the projection, including when called for readiness.
      const { rows } = await c.query(
        `SELECT f.admission,id,material_version,provider_expires_at,usable_until
        FROM ${families} f JOIN ${attempts} a USING(source_id)
        WHERE ${matching} AND enabled AND ${active} AND custody='current' AND a.admission=f.admission
        AND usable_until > clock_timestamp()
        AND usable_until < clock_timestamp() + interval '61 minutes'`,
        [source.key.source.id, source],
      );
      return rows[0] as Omit<AttemptRow, "sealed"> | undefined;
    });
  }

  store(source: Source): GitHubPreparationStore {
    const key = source.key.source.id;
    const locked = <T>(
      familyId: string,
      change: boolean,
      update: (f: Family | undefined, allocate: () => string) => T,
    ) =>
      this.transaction(async (c) => {
        if (familyId !== key) {
          throw new Error("Family mismatch.");
        }
        const { rows } = await c.query(
          `SELECT admission, enabled, ${active} AS live
          FROM ${families} f WHERE ${matching} FOR ${change ? "UPDATE" : "SHARE"} OF f`,
          [key, source],
        );
        const f = rows[0] as FamilyRow | undefined;
        if (!f) {
          return update(undefined, randomUUID);
        }
        const list = (
          await c.query(
            `SELECT id,admission,state,custody,material_version,provider_expires_at,
          usable_until,CASE WHEN custody='current' THEN sealed END AS sealed FROM ${attempts}
          WHERE source_id=$1`,
            [key],
          )
        ).rows as AttemptRow[];
        const current = f.enabled && f.live ? list.find((a) => a.custody === "current") : undefined;
        const family: Family = {
          admission: f.admission,
          enabled: f.enabled && f.live,
          admittedGrantCount: 1,
          attempts: list.map((a) => ({
            id: a.id,
            admission: a.admission,
            state: a.state,
            ...(a.material_version ? { materialVersion: a.material_version } : {}),
          })),
        };
        if (current) {
          family.committed = {
            admission: current.admission,
            attemptId: current.id,
            materialVersion: current.material_version!,
            providerExpiresAt: current.provider_expires_at.getTime(),
            usableUntil: current.usable_until.getTime(),
            bytes: this.open(current.sealed, key, current.id),
          };
        }
        const previous = family.committed;
        try {
          const result = update(family, randomUUID);
          if (change) {
            const before = new Map(list.map((r) => [r.id, r]));
            for (const a of family.attempts) {
              const old = before.get(a.id);
              if (!old) {
                await c.query(
                  `INSERT INTO ${attempts} (id,source_id,admission,state) VALUES ($1,$2,$3,$4)`,
                  [a.id, key, a.admission, a.state],
                );
              } else if (old.state !== a.state) {
                const m = a.state === "committed" ? family.committed : undefined;
                if (
                  m &&
                  (m.attemptId !== a.id ||
                    !family.enabled ||
                    !isDeepStrictEqual(m.admission, f.admission))
                ) {
                  throw new Error("Publication fenced.");
                }
                const bytes = m?.bytes ?? a.candidate;
                if (m) {
                  await c.query(
                    `UPDATE ${attempts} SET custody='retire' WHERE source_id=$1 AND custody='current'`,
                    [key],
                  );
                }
                await c.query(
                  `UPDATE ${attempts} SET state=$2,custody=$3,sealed=$4,material_version=$5,
                  provider_expires_at=$6,usable_until=$7 WHERE id=$1 AND source_id=$8`,
                  [
                    a.id,
                    a.state,
                    m ? "current" : bytes ? "retire" : "intent",
                    bytes && this.seal(bytes, key, a.id),
                    m?.materialVersion,
                    m && new Date(m.providerExpiresAt),
                    m && new Date(m.usableUntil),
                    key,
                  ],
                );
                bytes?.fill(0);
              }
            }
          }
          return result;
        } finally {
          previous?.bytes.fill(0);
        }
      });
    return {
      readCurrent: (id, select) => locked(id, false, select),
      transact: (id, update) => locked(id, true, update),
    };
  }

  // Commit possible revocation before contacting GitHub. A missing response leaves 'revoking'
  // or 'unknown' and encrypted cleanup custody, never an automatic replay or a claim of revocation.
  async takeRetirement(key: string | null) {
    return this.transaction(async (c) => {
      const { rows } = await c.query(
        `WITH due AS (SELECT id FROM ${attempts} WHERE custody='retire'
        AND (source_id=$1 OR $1 IS NULL) LIMIT 1 FOR UPDATE SKIP LOCKED)
        UPDATE ${attempts} a SET custody='revoking' FROM due WHERE a.id=due.id
        RETURNING a.id, admission, sealed`,
        [key],
      );
      const a = rows[0] as AttemptRow | undefined;
      return (
        a && {
          id: a.id,
          admission: a.admission,
          bytes: this.open(a.sealed, a.admission.familyId, a.id),
        }
      );
    });
  }

  async finishRetirement(id: string, revoked: boolean) {
    await this.transaction(async (c) => {
      await c.query(
        `UPDATE ${attempts} SET custody=CASE WHEN $2 THEN 'revoked' ELSE 'unknown' END,
        sealed=CASE WHEN $2 THEN NULL ELSE sealed END WHERE id=$1 AND custody='revoking'`,
        [id, revoked],
      );
    });
  }
}
