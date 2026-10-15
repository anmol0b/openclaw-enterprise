import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createOpenShellBackend } from "../../apps/controller/src/backends/openshell.ts";
import { OpenShellCredentialGatewayDriver } from "../../apps/controller/src/drivers/credential-gateway/openshell.ts";
import {
  migrateCredentialSource,
  readAdoptedCredentialSource,
  SourceAdoptionError,
} from "../../packages/occ/src/credential-source-adoption.ts";
import { createTestSecretDriver } from "../helpers/secret-driver.mjs";

export const fakeA = "rehearsal-material-A";
export const fakeB = "rehearsal-material-B";
const observedAt = "2026-10-14T12:00:00.000Z";

/** Passive task-owned custody only; this is not an implemented immutable Secret Driver. */
export function custody(state) {
  const reads = { admission: 0, immutable: 0, live: 0 };
  return {
    reads,
    authority: {
      async inspect(key) {
        reads.admission++;
        const entry = state.admissions.find(
          (entry) => JSON.stringify(entry.key) === JSON.stringify(key),
        );
        if (!entry) {
          return { state: "missing" };
        }
        if (state.revoked) {
          return { state: "revoked" };
        }
        return { state: "admitted", authority: structuredClone(entry) };
      },
    },
    material: {
      async readImmutable(authority) {
        reads.immutable++;
        const entry = state.snapshots.find(
          (entry) =>
            entry.id === authority.target.id &&
            entry.version === authority.target.version &&
            entry.owner.id === authority.target.owner.id &&
            entry.owner.generation === authority.target.owner.generation,
        );
        if (!entry) {
          throw new SourceAdoptionError("unavailable");
        }
        return {
          authority: structuredClone(authority),
          material: {
            value: entry.value,
            version: entry.version,
            authoritativeObservedAt: observedAt,
          },
        };
      },
      async readLive(_key, secret, owner) {
        reads.live++;
        if (
          !state.live ||
          state.live.secret.id !== secret.id ||
          state.live.secret.namespaceId !== secret.namespaceId ||
          state.live.owner.id !== owner.id ||
          state.live.owner.generation !== owner.generation
        ) {
          throw new SourceAdoptionError("unavailable");
        }
        return {
          secret,
          owner,
          material: {
            value: state.live.value,
            version: "B",
            authoritativeObservedAt: observedAt,
          },
        };
      },
    },
  };
}

export async function legacyFixture() {
  const namespace = { id: "ns_adoption", name: "adoption", status: "ready" };
  const source = {
    id: "cs_adoption",
    namespaceId: namespace.id,
    name: "adoption",
    type: "openai",
    config: {},
    secrets: { api_key: { kind: "secret", namespaceId: namespace.id, id: "sec_adoption" } },
    driverId: "gateway-adoption",
    state: "ready",
    createdAt: observedAt,
  };
  const key = {
    installationId: "installation-adoption",
    namespaceId: namespace.id,
    source: { id: source.id, generation: 1 },
    backend: { id: "backend-adoption", generation: 1 },
    provider: { id: "provider-adoption", generation: 1 },
  };
  const secretOwner = { id: "secret-adoption", generation: 1 };
  // This authority and immutable material predate migration. The legacy source row alone
  // cannot establish either. The rehearsal must not derive them from a later Secret read.
  const authority = {
    key,
    legacyDriverId: source.driverId,
    origin: source.secrets.api_key,
    originDriver: secretOwner,
    originVersion: "A",
    target: {
      kind: "snapshot",
      owner: { id: "snapshot-adoption", generation: 1 },
      id: "snapshot-A",
      version: "A",
    },
  };
  const state = {
    admissions: [authority],
    snapshots: [{ ...authority.target, value: fakeA }],
    live: { secret: source.secrets.api_key, owner: secretOwner, value: fakeA },
  };
  const providers = new Map();
  // The oracle can observe custody. The actual legacy client only returns provider metadata.
  const materialHeldByProvider = new Map();
  const profiles = new Map();
  const effects = { providers: 0, profiles: 0, detach: 0 };
  const client = {
    async getProviderProfile(_workspace, id) {
      return profiles.get(id);
    },
    async importProviderProfile(_workspace, profile) {
      effects.profiles++;
      profiles.set(profile.id, profile);
    },
    async getProvider(_workspace, id) {
      return providers.get(id);
    },
    async createProvider(input) {
      effects.providers++;
      const { name, labels, credentials } = input;
      const metadata = { name, type: input.type, labels, config: {}, resourceVersion: "1" };
      materialHeldByProvider.set(name, structuredClone(credentials));
      providers.set(name, metadata);
      return metadata;
    },
    async detachSandboxProvider() {
      effects.detach++;
      return { receiptId: "receipt-unfinished" };
    },
    async getSandboxProviderStatus() {
      return { state: "PROVIDER_READINESS_STATE_PENDING" };
    },
    close() {},
  };
  const backend = createOpenShellBackend(
    {
      id: key.backend.id,
      type: "openshell",
      configuration: { endpoint: "http://127.0.0.1:1" },
      drivers: { credential_gateway: source.driverId, sandbox: "sandbox-adoption" },
    },
    { gatewayClient: client },
  );
  const gateway = new OpenShellCredentialGatewayDriver(
    { binaries: ["/app/bin/codex"] },
    { id: source.driverId, backend },
  );
  const signal = new AbortController().signal;
  const secrets = createTestSecretDriver({ id: secretOwner.id });
  const secret = {
    id: source.secrets.api_key.id,
    namespaceId: namespace.id,
    driverId: secretOwner.id,
  };
  secret.backendRef = await secrets.create(secret, fakeA);
  await gateway.registerSource(
    { namespace, source, signal },
    {
      type: source.type,
      config: source.config,
      secrets: { api_key: await secrets.withValue(secret, async (value) => value) },
    },
  );
  const revision = {
    id: "revision-adoption",
    namespaceId: namespace.id,
    agentId: "agent-adoption",
    harness: { id: "codex", mode: "dedicated" },
    credentialSources: [
      { sourceId: source.id, credentialGatewayId: gateway.id, sourceType: source.type },
    ],
  };
  const attachments = await gateway.attachForRevision({
    namespace,
    revision,
    sources: [source],
    signal,
  });
  const withdrawalStatus = await gateway.withdraw({
    namespace,
    revision,
    signal,
    sourceId: source.id,
    sandbox: { resourceName: "sandbox-adoption" },
  });
  assert.equal(withdrawalStatus.state, "pending");
  const withdrawal = {
    namespaceId: namespace.id,
    agentId: revision.agentId,
    revisionId: revision.id,
    credentialSourceId: source.id,
    state: withdrawalStatus.state,
    requestedBy: "operator-adoption",
    requestedAt: observedAt,
    lastReason: "CREDENTIAL_WITHDRAWAL_PENDING",
    lastAttemptAt: observedAt,
  };
  await secrets.update(secret, fakeB);
  state.live.value = await secrets.withValue(secret, async (value) => value);
  async function inspectLegacyAttachment() {
    return gateway.attachmentStatus({
      namespace,
      revision,
      sources: [source],
      signal,
      sandbox: { resourceName: "sandbox-adoption" },
    });
  }
  return {
    source,
    key,
    secretOwner,
    state,
    effects,
    materialHeldByProvider,
    attachments,
    withdrawal,
    revision,
    inspectLegacyAttachment,
  };
}

/** Fresh process: no closures, gateway instances, material caches or pending work survive. */
export function restart(serialized) {
  return JSON.parse(
    execFileSync(process.execPath, [fileURLToPath(import.meta.url), "--resume"], {
      input: serialized,
      encoding: "utf8",
    }),
  );
}

export async function rehearse() {
  const fixture = await legacyFixture();
  const ports = custody(fixture.state);
  const before = structuredClone(fixture.effects);
  const record = await migrateCredentialSource(fixture.source, fixture.key, ports.authority);
  const saved = {
    record,
    state: fixture.state,
    attachments: fixture.attachments,
    withdrawal: fixture.withdrawal,
    revision: fixture.revision,
  };
  const resumed = restart(JSON.stringify(saved));
  assert.equal(resumed.material.value, fakeA);
  assert.deepEqual(resumed.attachments, fixture.attachments);
  assert.deepEqual(resumed.withdrawal, fixture.withdrawal);
  // Roll back before activation. The old reader still sees the attachment with revocation
  // pending; do not reattach it, replay the withdrawal, or infer it is safe to use.
  assert.deepEqual(await fixture.inspectLegacyAttachment(), [
    { sourceId: fixture.source.id, state: "pending" },
  ]);
  assert.deepEqual(fixture.effects, before);
  return { fixture, saved, resumed, ports };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (process.argv[2] === "--resume") {
    const saved = JSON.parse(readFileSync(0, "utf8"));
    const ports = custody(saved.state);
    const material = await readAdoptedCredentialSource(
      saved.record,
      ports.authority,
      ports.material,
    );
    process.stdout.write(
      JSON.stringify({
        material,
        attachments: saved.attachments,
        withdrawal: saved.withdrawal,
        revision: saved.revision,
        reads: ports.reads,
      }),
    );
  } else {
    const { resumed } = await rehearse();
    process.stdout.write(
      JSON.stringify({
        adoption: "explicit_update",
        version: resumed.material.version,
        attachments: resumed.attachments.length,
        withdrawal: resumed.withdrawal.state,
        reads: resumed.reads,
      }) + "\n",
    );
  }
}
