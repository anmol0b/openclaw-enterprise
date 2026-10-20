import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";

import { resolveApprovedHarness } from "../../apps/controller/src/composition/production-harness.ts";
import { createAuthPrincipalSeed } from "../../packages/iam/src/index.ts";
import { createPostgresAgentApp } from "../helpers/postgres-agent-app.mjs";
import { requiresPostgres } from "../helpers/postgres-database.mjs";

test(
  "Gateway managed mode is persisted at admission and requires Installation administration to change",
  requiresPostgres,
  async (t) => {
    const { controller, inject, pool, state, deployAgent } = await createPostgresAgentApp(t, {
      label: "gateway-managed-mode",
      authSecret: "gateway-managed-mode-postgres-auth-secret-minimum-32",
    });
    const { namespace, secretRef, agent, revision } = await deployAgent("Gateway managed mode");
    assert.equal(agent.gatewayManagedMode, true);
    assert.equal(revision.gatewayManagedMode, true);

    const member = createAuthPrincipalSeed(
      controller.installation.id,
      "https://identity.example.test",
      { id: randomUUID() },
      { grant: "none" },
    );
    await state.appendNativeIAMPrincipal(member);
    const iamPath = `/namespaces/${namespace.id}/iam`;
    const role = await inject("POST", `${iamPath}/roles`, {
      permissions: [
        { action: "administer", resourceKind: "agent" },
        { action: "update", resourceKind: "agent" },
        { action: "deploy", resourceKind: "agent" },
        { action: "read", resourceKind: "configuration" },
        { action: "operate", resourceKind: "secret" },
      ],
    });
    assert.equal(role.statusCode, 201, role.body);
    for (const [resourceKind, resourceId] of [
      ["agent", agent.id],
      ["configuration", agent.configurationId],
      ["secret", secretRef.id],
    ]) {
      const binding = await inject("POST", `${iamPath}/access-bindings`, {
        subjectKind: "identity",
        subjectId: member.principal.id,
        roleId: role.json().data.id,
        resourceKind,
        resourceId,
      });
      assert.equal(binding.statusCode, 201, binding.body);
    }

    const agentInput = {
      namespaceId: namespace.id,
      agentId: agent.id,
      configurationId: agent.configurationId,
    };
    const installationAdministrationDenied = {
      name: "AuthorizationDeniedError",
      authorization: {
        action: "administer",
        resource: { kind: "installation", id: controller.installation.id },
      },
    };
    await assert.rejects(
      controller.updateAgent(member.principal.id, { ...agentInput, gatewayManagedMode: false }),
      installationAdministrationDenied,
    );

    const agentPath = `/namespaces/${namespace.id}/agents/${agent.id}`;
    const saved = await inject("PATCH", agentPath, {
      configurationId: agent.configurationId,
      gatewayManagedMode: false,
    });
    assert.equal(saved.statusCode, 200, saved.body);
    assert.equal(saved.json().data.gatewayManagedMode, false);
    const ordinarySave = await controller.updateAgent(member.principal.id, agentInput);
    assert.equal(ordinarySave.gatewayManagedMode, false);
    await assert.rejects(
      controller.deployAgent(
        member.principal.id,
        { namespaceId: namespace.id, agentId: agent.id },
        resolveApprovedHarness,
      ),
      installationAdministrationDenied,
    );

    const admitted = await inject("POST", `${agentPath}/deploy`);
    assert.equal(admitted.statusCode, 202, admitted.body);
    assert.equal(admitted.json().data.gatewayManagedMode, false);
    const persisted = await pool.query(
      `SELECT id, gateway_managed_mode FROM occ.agent_revisions
       WHERE namespace_id = $1 AND agent_id = $2 ORDER BY revision_number`,
      [namespace.id, agent.id],
    );
    assert.deepEqual(persisted.rows, [
      { id: revision.id, gateway_managed_mode: true },
      { id: admitted.json().data.id, gateway_managed_mode: false },
    ]);
  },
);
