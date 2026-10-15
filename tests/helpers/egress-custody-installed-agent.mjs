import assert from "node:assert/strict";
import { observeInstalledProtection } from "./egress-installed-agent.mjs";
import { protectedConfigurationBody, sourceAccessBindingBody } from "./egress-connected-inputs.mjs";
import { repositoryPath } from "../fixtures/egress-custody-repository-origin.mjs";

export async function admitRepositoryAgent(setup, stack, evidence, owned) {
  const { create, provider } = owned;
  const name = "custody-" + evidence.runId;
  const configuration = await create(
    "configurations",
    protectedConfigurationBody(setup.controller.model),
  );
  // Bind an actual Agent ID into this newly consented, whole-execution source.
  // The Agent has no repository transport binding, executable pin, or model Secret.
  const agent = await create("agents", {
    name,
    configurationId: configuration.id,
    executionMode: "dedicated",
    harnessAuth: { method: "runtime" },
  });
  const issuer = await create("secrets", { name, value: provider.privateKey });
  const source = await create("credential-sources", {
    name,
    type: "github-app-metadata",
    config: { ...provider.identity, agent_id: agent.id, authority: "execution" },
    secrets: { private_key: issuer.ref },
  });
  assert.equal(source.egress?.adoption, "prepared", "must use protected warm-only GitHub source");
  const route = stack.namespacePath + "/agents/" + agent.id;
  const api = evidence.api;
  await api("PATCH", route, {
    configurationId: configuration.id,
    harnessAuth: { method: "runtime" },
    credentialSources: [{ sourceId: source.id }],
  });
  const role = await create("iam/roles", {
    name,
    permissions: [{ action: "operate", resourceKind: "credential_source" }],
  });
  const binding = await create("iam/access-bindings", sourceAccessBindingBody(agent, role, source));
  const bindings = await api("GET", stack.namespacePath + "/iam/access-bindings");
  assert.deepEqual(
    bindings.filter(({ subjectId }) => subjectId === agent.servicePrincipalId).map(({ id }) => id),
    [binding.id],
  );
  const transport = await api("POST", route + "/runtime-credentials", {});
  assert.equal(transport.transportConfigured, true);
  return { agent, source, role, binding, route };
}

export async function activateRepositoryAgent(setup, stack, evidence, owned, admitted) {
  const { agent, source, route } = admitted;
  await evidence.checkpoint("deploy-request", { agentId: agent.id });
  const revision = await evidence.api("POST", route + "/deploy", undefined, 202);
  await setup.f.waitFor(
    "actual worker-released protected repository Agent",
    async () => {
      const state = await evidence.api("GET", route + "/deployments/" + revision.id);
      assert.notEqual(state.status, "failed", "protected deployment failed; no runtime acceptance");
      return (await evidence.api("GET", route)).activeRevisionId === revision.id || undefined;
    },
    12 * 60_000,
  );
  const sandbox = await setup.f.waitForSandbox(stack.placement, revision);
  const sandboxId = await owned.recordSandbox(sandbox);
  const installed = await observeInstalledProtection(
    setup,
    stack,
    evidence,
    { agent, source, revision, sandbox, sandboxId },
    ({ grant }) =>
      grant.kind === "github_repository_metadata" &&
      grant.repository === owned.provider.identity.repository &&
      grant.isolationId === agent.id &&
      grant.profile === "metadata-read",
  );
  const [exactRoute, ...others] = installed.installation.plan.routes;
  assert.equal(others.length, 0);
  assert.equal(exactRoute.method, "GET");
  assert.equal(exactRoute.path, repositoryPath);
  assert.equal(
    exactRoute.origin,
    owned.provider.businessOrigin,
    "must address selected synthetic GitHub",
  );
  assert.equal(exactRoute.binding.execution.revisionId, revision.id);
  assert.ok(
    owned.provider.issues > 0,
    "provider must observe proactive scoped token issue before first workload read",
  );
  return { ...installed, revision };
}

// Only a freshly prepared, expressly disposable single API Pod may be restarted.
export async function restartDedicatedAuthority(setup) {
  const { kubectl, waitFor } = setup.f;
  const { controllerNamespace, controllerSelector } = setup.input;
  const api = async () =>
    JSON.parse(
      await kubectl(
        "get",
        "pods",
        "-n",
        controllerNamespace,
        "-l",
        controllerSelector,
        "-o",
        "json",
      ),
    ).items.filter(
      (p) =>
        p.metadata.labels["app.kubernetes.io/component"] === "api" && !p.metadata.deletionTimestamp,
    );
  const [old, ...others] = await api();
  assert.equal(others.length, 0);
  assert.equal(
    old.metadata.annotations["openclaw.dev/egress-custody-qualification-restart"],
    "permitted",
    "operator must dedicate this authority to the installed restart qualification",
  );
  assert.ok(old.spec.containers.some(({ image }) => image === setup.input.images.controller));
  await kubectl("delete", "pod", old.metadata.name, "-n", controllerNamespace, "--wait=false");
  const fresh = await waitFor(
    "fresh installed authority after lost dispatch acknowledgement",
    async () => {
      const [pod, ...other] = await api();
      if (!pod || other.length || pod.metadata.uid === old.metadata.uid) {
        return;
      }
      if (
        !pod.status.conditions?.some(({ type, status }) => type === "Ready" && status === "True")
      ) {
        return;
      }
      assert.ok(pod.spec.containers.some(({ image }) => image === setup.input.images.controller));
      return pod;
    },
    180_000,
  );
  return { retiredAuthorityUid: old.metadata.uid, replacementAuthorityUid: fresh.metadata.uid };
}
