import type {
  PreparedGitHubUseRequest,
  PreparedGitHubUseResponse,
  RepositoryRevisionState,
} from "@openclaw-enterprise/contracts";
import type { PostgresPool } from "@openclaw-enterprise/occ";
import { isDeepStrictEqual } from "node:util";
import { PreparedGitHubPostgres } from "./prepared-postgres.ts";
import type { GitHubPreparationAdmission } from "./prepared-contracts.ts";

const adoption = "prepared_repository_git";
const families = "occ.prepared_github_families";
const attempts = "occ.prepared_github_attempts";

export interface PreparedRepositorySession {
  readonly namespaceId: string;
  readonly revisionId: string;
  readonly admissionId: string;
  readonly sessionId: string;
  readonly driver: RepositoryRevisionState["driver"];
  readonly binding: RepositoryRevisionState["bindings"][number];
}

/** The session snapshot also binds Agent, installation and the broker's particular generation.
 * The deadline is checked live instead of extending or treating the snapshot as a lease. */
const sessions = `SELECT jsonb_build_object(
  'namespaceId',s.namespace_id, 'agentId',s.agent_id, 'revisionId',s.live_revision_id,
  'installationId',i.id, 'admissionId',s.admission_id, 'sessionId',b.session_id,
  'brokerGeneration',b.generation, 'driver',s.cleanup_context->'driver', 'binding',s.cleanup_context->'binding',
  'grant',s.cleanup_context #> '{binding,grant}') AS session,
  least(b.deadline_wall_ms, s.deadline_wall_ms) AS end_ms
  FROM occ.repository_session_attempts s
  JOIN occ.repository_broker_receipts b USING(admission_id)
  JOIN occ.agents g ON g.namespace_id=s.namespace_id AND g.id=s.agent_id AND g.active_revision_id=s.live_revision_id
  JOIN occ.agent_revisions rev ON rev.id=s.live_revision_id AND rev.namespace_id=s.namespace_id AND rev.agent_id=s.agent_id
  CROSS JOIN occ.installation i
  WHERE s.phase='open' AND s.broker_protocol=1 AND s.live_revision_id=s.revision_id
  AND b.state='active' AND b.generation IS NOT NULL AND b.session_id=s.session_id
  AND clock_timestamp() < to_timestamp(least(b.deadline_wall_ms, s.deadline_wall_ms) / 1000.0)
  AND g.status='active' AND g.desired_runtime_state='running' AND g.execution_mode='dedicated'
  AND s.cleanup_context #>> '{binding,profile}' = 'git-write'
  AND g.repository_bindings @> jsonb_build_array(jsonb_build_object('repositoryRef',s.repository_ref,'profile','git-write'))
  AND rev.admitted_spec #> '{repository_credentials,driver}'=s.cleanup_context->'driver'
  AND rev.admitted_spec #> '{repository_credentials,bindings}' @> jsonb_build_array(s.cleanup_context->'binding')`;
const live = `EXISTS (SELECT FROM (${sessions}) l WHERE l.session = f.source->'session')`;

export interface PreparedRepositoryGitSource {
  readonly adoption: typeof adoption;
  readonly key: { source: { id: string } };
  readonly session: PreparedRepositorySession;
  readonly grant: GitHubPreparationAdmission["grant"] & {
    profile: "git-ref-write";
    pushRef: string;
  };
}
type Policy = (session: PreparedRepositorySession) => PreparedRepositoryGitSource | undefined;

export class PreparedRepositoryGitStore extends PreparedGitHubPostgres {
  private readonly authority: string;
  private readonly policy: Policy;
  constructor(pool: PostgresPool, key: Buffer, authority: string, policy: Policy) {
    super(pool, key, authority, { active: live, adoption });
    this.authority = authority;
    this.policy = policy;
  }

  /** Background discovery only. Admission and key lookup are not reachable from use(). */
  async discover(): Promise<PreparedRepositoryGitSource[]> {
    return this.transaction(async (c) => {
      // Denial doesn't depend on this cleanup. Keep attempts, including unknown issuance, for recovery.
      await c.query(
        `WITH stopped AS (
        UPDATE ${families} f SET enabled=false
        WHERE enabled AND source->>'adoption'=$1 AND admission->>'issuerAuthority'=$2 AND NOT ${live}
        RETURNING source_id)
        UPDATE ${attempts} a SET custody='retire' FROM stopped s
        WHERE a.source_id=s.source_id AND custody='current'`,
        [adoption, this.authority],
      );
      const { rows } = await c.query(sessions);
      return (rows as { session: PreparedRepositorySession }[]).flatMap(
        ({ session }) => this.policy(session) ?? [],
      );
    });
  }

  async claimGit(
    source: PreparedRepositoryGitSource,
    version: string,
  ): Promise<GitHubPreparationAdmission | undefined> {
    const familyId = source.key.source.id;
    const admission: GitHubPreparationAdmission = {
      familyId,
      issuerAuthority: this.authority,
      generation: 1,
      ownerEpoch: 1,
      inputVersion: version,
      grant: source.grant,
    };
    return this.transaction(async (c) => {
      await c.query(
        `INSERT INTO ${families}(source_id,source,issuer,admission)
        SELECT $1, $2::jsonb, '{"kind":"worker-mounted-github-app-key"}', $3::jsonb
        FROM (${sessions}) l WHERE l.session=$2::jsonb->'session'
        ON CONFLICT (source_id) DO NOTHING`,
        [familyId, source, admission],
      );
      // A rotated App key fences the old material. It never clears an uncertain preparation attempt.
      await c.query(
        `WITH rotated AS (
        UPDATE ${families} f SET admission = f.admission || jsonb_build_object(
          'inputVersion', $3::text, 'ownerEpoch', (f.admission->>'ownerEpoch')::integer+1),
          next_check_at=clock_timestamp()
        WHERE source_id=$1 AND enabled AND f.source=$2::jsonb AND admission->>'issuerAuthority'=$4
          AND f.admission->>'inputVersion' <> $3 AND ${live} RETURNING source_id)
        UPDATE ${attempts} a SET custody='retire' FROM rotated r
        WHERE a.source_id=r.source_id AND custody='current'`,
        [familyId, source, version, this.authority],
      );
      const { rows } = await c.query(
        `UPDATE ${families} f SET next_check_at=clock_timestamp() + interval '60 seconds'
        WHERE source_id=$1 AND enabled AND source=$2::jsonb AND admission->>'inputVersion'=$3 AND admission->>'issuerAuthority'=$4
        AND next_check_at <= clock_timestamp() AND ${live} RETURNING admission`,
        [familyId, source, version, this.authority],
      );
      return (rows[0] as { admission: GitHubPreparationAdmission } | undefined)?.admission;
    });
  }

  /** Lock against admission withdrawal and material rotation. If commit is uncertain the copy is
   * discarded, but its non-secret use receipt may have committed. Never retry an exchange. */
  async use(q: PreparedGitHubUseRequest, signal: AbortSignal): Promise<PreparedGitHubUseResponse> {
    const deadline = Date.parse(q.deadlineAt);
    const valid = (until: number) => !signal.aborted && Date.now() < until;
    const fail = (): never => {
      throw new Error("PREPARED_REPOSITORY_GIT_UNAVAILABLE");
    };
    if (!valid(deadline) || deadline > Date.now() + 30_000) {
      return fail();
    }
    let bytes: Buffer | undefined;
    try {
      const result = await this.transaction(async (c) => {
        // Locks on the mutable session, receipt and Agent serialize withdrawal with this decision.
        // The admitted revision is immutable; the Agent row owns its current selection. The caller can never substitute its own Agent or repository policy.
        const { rows } = await c.query(
          `SELECT session,end_ms FROM
          (${sessions} AND b.session_id=$1 FOR SHARE OF s,b,g) l`,
          [q.sessionId],
        );
        const current = rows[0] as
          { session: PreparedRepositorySession; end_ms: string } | undefined;
        const source = current && this.policy(current.session);
        if (
          !source ||
          !current ||
          source.grant.pushRef !== q.pushRef ||
          !isDeepStrictEqual(current.session.binding.grant, {
            providerInstanceId: q.providerInstanceId,
            repositoryId: q.repositoryId,
            grantId: q.grantId,
          })
        ) {
          return fail();
        }
        const { rows: found } = await c.query(
          `SELECT a.id,a.admission,a.material_version, a.usable_until, a.sealed
          FROM ${families} f JOIN ${attempts} a USING(source_id)
          WHERE f.source_id=$1 AND f.source=$2::jsonb AND f.enabled AND f.admission->>'issuerAuthority'=$3
          AND a.custody='current' AND a.state='committed' AND a.admission=f.admission
          AND a.usable_until BETWEEN clock_timestamp() AND clock_timestamp() + interval '61 minutes'
          AND a.provider_expires_at >= a.usable_until FOR SHARE OF f,a`,
          [source.key.source.id, source, this.authority],
        );
        const m = found[0] as
          | {
              id: string;
              admission: GitHubPreparationAdmission;
              material_version: string;
              usable_until: Date;
              sealed: Buffer;
            }
          | undefined;
        if (!m || !isDeepStrictEqual(m.admission.grant, source.grant)) {
          return fail();
        }
        const until = Math.min(
          Date.now() + 5000,
          deadline,
          Number(current.end_ms),
          m.usable_until.getTime(),
        );
        if (!valid(until)) {
          return fail();
        }
        const sendStartBy = new Date(until).toISOString();
        await c.query(
          `INSERT INTO occ.prepared_repository_git_uses
          (exchange_id,admission_id,attempt_id,material_version,operation,request_digest_sha256,send_start_by)
          VALUES($1,$2,$3,$4,$5,$6,$7)`,
          [
            q.exchangeId,
            current.session.admissionId,
            m.id,
            m.material_version,
            q.operation,
            q.requestDigestSha256,
            sendStartBy,
          ],
        );
        if (!valid(until)) {
          return fail();
        }
        bytes = this.open(m.sealed, m.admission, m.id);
        return {
          sendStartBy,
          exchangeId: q.exchangeId,
          preparationAttemptId: m.id,
          materialVersion: m.material_version,
        };
      });
      if (!bytes || !valid(Date.parse(result.sendStartBy))) {
        return fail();
      }
      return { ...result, value: bytes.toString("utf8") };
    } finally {
      bytes?.fill(0);
    }
  }
}
