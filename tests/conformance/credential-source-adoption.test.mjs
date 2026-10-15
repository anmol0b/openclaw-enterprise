import assert from "node:assert/strict";
import test from "node:test";
import { NativeIAMDriver } from "../../packages/iam/src/index.ts";
import {
  migrateCredentialSource,
  prepareLiveSource,
  readAdoptedCredentialSource,
  SourceAdoptionError,
} from "../../packages/occ/src/credential-source-adoption.ts";
import {
  custody,
  fakeA,
  fakeB,
  legacyFixture,
  rehearse,
  restart,
} from "../fixtures/credential-source-adoption.mjs";
import { grantRole, principalIAMState } from "../helpers/iam-grants.mjs";

const failure = (code) => (error) => error instanceof SourceAdoptionError && error.code === code;

function policy(
  fixture,
  {
    action = "update",
    resourceKind = "credential_source",
    sourceId = fixture.source.id,
    namespaceId = fixture.source.namespaceId,
    secret = true,
  } = {},
) {
  const state = principalIAMState(["operator"], "adoption-rehearsal");
  grantRole(state, "operator", {
    id: "source-role",
    namespaceId,
    resource: { kind: resourceKind, id: sourceId },
    permissions: { [resourceKind]: [action] },
  });
  if (secret) {
    grantRole(state, "operator", {
      id: "secret-role",
      namespaceId,
      resource: { kind: "secret", id: fixture.source.secrets.api_key.id },
      permissions: { secret: ["operate"] },
    });
  }
  return new NativeIAMDriver({ loadNativeIAMState: async () => state });
}

async function migrated() {
  const fixture = await legacyFixture();
  const ports = custody(fixture.state);
  const record = await migrateCredentialSource(fixture.source, fixture.key, ports.authority);
  const input = {
    source: fixture.source,
    key: fixture.key,
    secretOwner: fixture.secretOwner,
    principalId: "operator",
    current: record,
  };
  return { fixture, ports, record, input };
}

test("serialized migration preserves approved A, real legacy attachments and unfinished withdrawal after fresh process restart", async () => {
  const { fixture, saved, resumed, ports } = await rehearse();
  assert.equal(saved.record.adoption.mode, "explicit_update");
  assert.equal(fixture.state.live.value, fakeB);
  const legacyProvider = resumed.attachments[0].ref;
  assert.equal(fixture.materialHeldByProvider.get(legacyProvider).OPENAI_API_KEY, fakeA);
  assert.deepEqual(resumed.attachments, fixture.attachments);
  assert.deepEqual(resumed.revision, fixture.revision);
  assert.deepEqual(resumed.withdrawal, fixture.withdrawal);
  assert.equal(resumed.withdrawal.state, "pending");
  assert.equal(resumed.withdrawal.requestedBy, "operator-adoption");
  assert.deepEqual(ports.reads, { admission: 1, immutable: 0, live: 0 });
  assert.deepEqual(resumed.reads, { admission: 1, immutable: 1, live: 0 });

  // Snapshot custody, not the provenance Secret, remains authoritative across restart.
  delete saved.state.live;
  assert.equal(restart(JSON.stringify(saved)).material.value, fakeA);
});

test("ordinary legacy rows lack immutable authority; migration never fabricates A or reads B", async () => {
  const { fixture, ports } = await migrated();
  fixture.state.admissions = [];
  await assert.rejects(
    migrateCredentialSource(fixture.source, fixture.key, ports.authority),
    failure("missing_authority"),
  );
  assert.equal(ports.reads.live, 0);
  assert.equal(ports.reads.immutable, 0);
});

test("a single OAuth refresh root cannot be adopted as static serving material", async () => {
  const { source, key, state } = await legacyFixture();
  const ports = custody(state);
  const origin = source.secrets.api_key;
  for (const [type, field] of [
    ["oauth2-client-credentials", "client_secret"],
    ["oauth2-refresh-token", "refresh_token"],
    ["openai", "refresh_token"],
  ]) {
    await assert.rejects(
      migrateCredentialSource(
        { ...source, type, secrets: { [field]: origin } },
        key,
        ports.authority,
      ),
      failure("mismatch"),
    );
  }
  assert.deepEqual(ports.reads, { admission: 0, immutable: 0, live: 0 });
});

test("immutable admission binds exact scope, source generation, origin and owner independently of material reads", async () => {
  const { fixture } = await migrated();
  const changes = [
    (entry) => {
      entry.key.installationId = "other-installation";
    },
    (entry) => {
      entry.key.namespaceId = "other-namespace";
    },
    (entry) => {
      entry.key.source.id = "other-source";
    },
    (entry) => {
      entry.key.source.generation++;
    },
    (entry) => {
      entry.legacyDriverId = "other-gateway";
    },
    (entry) => {
      entry.origin.id = "other-secret";
    },
    (entry) => {
      entry.origin.namespaceId = "other-namespace";
    },
    (entry) => {
      entry.originVersion = "";
    },
    (entry) => {
      entry.target.version = "";
    },
  ];
  for (const change of changes) {
    const authority = structuredClone(fixture.state.admissions[0]);
    change(authority);
    // Faulted authority responses deliberately ignore the requested key; the production
    // boundary must reject them instead of trusting the adapter's routing alone.
    await assert.rejects(
      migrateCredentialSource(fixture.source, fixture.key, {
        inspect: async () => ({ state: "admitted", authority }),
      }),
      failure("mismatch"),
    );
  }
  const { record, ports } = await migrated();
  const changed = structuredClone(record);
  changed.adoption.authority.target.owner.id = "foreign-owner";
  await assert.rejects(
    readAdoptedCredentialSource(changed, ports.authority, ports.material),
    failure("mismatch"),
  );
  assert.equal(ports.reads.immutable, 0);
});

test("exact-version targets must match origin store and version; read responses cannot substitute another owner or revision", async () => {
  const { fixture } = await migrated();
  const authority = fixture.state.admissions[0];
  authority.target = {
    kind: "version",
    owner: authority.originDriver,
    id: authority.origin.id,
    version: "A",
  };
  fixture.state.snapshots = [{ ...authority.target, value: fakeA }];
  const ports = custody(fixture.state);
  const record = await migrateCredentialSource(fixture.source, fixture.key, ports.authority);
  assert.equal(
    (await readAdoptedCredentialSource(record, ports.authority, ports.material)).value,
    fakeA,
  );
  for (const field of ["id", "version", "owner"]) {
    const invalid = structuredClone(authority);
    invalid.target[field] = field === "owner" ? { id: "other", generation: 1 } : "other";
    await assert.rejects(
      migrateCredentialSource(fixture.source, fixture.key, {
        inspect: async () => ({ state: "admitted", authority: invalid }),
      }),
      failure("mismatch"),
    );
  }
  for (const corrupt of [
    (result) => {
      result.material.version = "B";
    },
    (result) => {
      result.authority.target.owner.id = "foreign-owner";
    },
  ]) {
    await assert.rejects(
      readAdoptedCredentialSource(record, ports.authority, {
        ...ports.material,
        async readImmutable(request) {
          const result = await ports.material.readImmutable(request);
          corrupt(result);
          return result;
        },
      }),
      failure("mismatch"),
    );
  }
});

test("known revoke denies rereads and opt-in; unavailable admission or selected custody never falls back to B", async () => {
  const { fixture, record, input, ports } = await migrated();
  fixture.state.revoked = true;
  await assert.rejects(
    readAdoptedCredentialSource(record, ports.authority, ports.material),
    failure("denied"),
  );
  await assert.rejects(
    prepareLiveSource(input, { ...ports, iam: policy(fixture) }),
    failure("denied"),
  );
  fixture.state.revoked = false;
  await assert.rejects(
    readAdoptedCredentialSource(
      record,
      {
        inspect: async () => ({ state: "unavailable" }),
      },
      ports.material,
    ),
    failure("unavailable"),
  );
  fixture.state.snapshots = [];
  await assert.rejects(
    readAdoptedCredentialSource(record, ports.authority, ports.material),
    failure("unavailable"),
  );
  assert.equal(ports.reads.live, 0);
});

test("only exact source update plus Secret operate prepares live B; failed opt-in leaves A and old attachments intact", async () => {
  const { fixture, record, input, ports } = await migrated();
  const before = JSON.stringify({
    record,
    attachments: fixture.attachments,
    withdrawal: fixture.withdrawal,
  });
  for (const grants of [
    { action: "operate" },
    { action: "update", resourceKind: "agent" },
    { action: "update", sourceId: "other-source" },
    { namespaceId: "other-namespace" },
    { secret: false },
  ]) {
    await assert.rejects(
      prepareLiveSource(input, { ...ports, iam: policy(fixture, grants) }),
      failure("denied"),
    );
  }
  for (const change of [
    (value) => {
      value.key.source.generation++;
    },
    (value) => {
      value.key.installationId = "other-installation";
    },
    (value) => {
      value.secretOwner.generation++;
    },
  ]) {
    const stale = structuredClone(input);
    change(stale);
    await assert.rejects(
      prepareLiveSource(stale, { ...ports, iam: policy(fixture) }),
      (error) => error instanceof SourceAdoptionError,
    );
  }
  fixture.state.admissions = [];
  await assert.rejects(
    prepareLiveSource(input, { ...ports, iam: policy(fixture) }),
    failure("missing_authority"),
  );
  fixture.state.admissions = [record.adoption.authority];
  assert.equal(
    JSON.stringify({ record, attachments: fixture.attachments, withdrawal: fixture.withdrawal }),
    before,
  );
  assert.equal(
    (await readAdoptedCredentialSource(record, ports.authority, ports.material)).value,
    fakeA,
  );
  const candidate = await prepareLiveSource(input, { ...ports, iam: policy(fixture) });
  assert.equal(candidate.adoption.mode, "live");
  assert.equal(candidate.key.source.generation, 2);
  assert.equal(
    (await readAdoptedCredentialSource(candidate, ports.authority, ports.material)).value,
    fakeB,
  );
  assert.equal(
    JSON.stringify({ record, attachments: fixture.attachments, withdrawal: fixture.withdrawal }),
    before,
  );
});

test("new source admission defaults to live with exact create and Secret authority", async () => {
  const { fixture, ports, input } = await migrated();
  delete input.current;
  const candidate = await prepareLiveSource(input, {
    ...ports,
    iam: policy(fixture, { action: "create" }),
  });
  assert.equal(candidate.adoption.mode, "live");
  assert.equal(candidate.key.source.generation, 1);
  assert.equal(
    (await readAdoptedCredentialSource(candidate, ports.authority, ports.material)).value,
    fakeB,
  );
});

test("live records reject substituted Secret scope before material access", async () => {
  const { fixture, input, ports } = await migrated();
  const candidate = await prepareLiveSource(input, { ...ports, iam: policy(fixture) });
  const readsBefore = ports.reads.live;
  for (const change of [
    (record) => {
      record.adoption.secret.id = "other-secret";
    },
    (record) => {
      record.adoption.secret.namespaceId = "other-namespace";
    },
    (record) => {
      record.adoption.owner.generation = 0;
    },
  ]) {
    // Persisted references are independent JSON objects, not shared in-memory aliases.
    const forged = JSON.parse(JSON.stringify(candidate));
    change(forged);
    await assert.rejects(
      readAdoptedCredentialSource(forged, ports.authority, ports.material),
      failure("mismatch"),
    );
  }
  assert.equal(ports.reads.live, readsBefore);
});
