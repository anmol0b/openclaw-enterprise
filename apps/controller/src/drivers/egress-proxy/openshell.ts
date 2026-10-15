import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import type {
  Backend,
  CredentialSourceControl,
  SandboxConduitWiring,
  EgressInstallation,
  ConduitPlan,
  ConduitDriver,
  EgressRef,
  ConduitRevisionContext,
  SandboxDriver,
} from "@openclaw-enterprise/contracts";
import { DependencyUnavailableError } from "@openclaw-enterprise/occ";
import { asRecord, immutableCopy, sha256Hex } from "@openclaw-enterprise/utils";
import { type OpenShellGateway, openShellWorkspaceName } from "../../backends/openshell.ts";
import { openAiStaticProvider } from "./openai-provider.ts";

export interface OpenShellConduitOptions {
  readonly middlewareName: string;
  readonly binaries: readonly string[];
}

// Proto3 omits default fields; compare their semantics while retaining every nondefault.
function wirePolicy(value: unknown, preserveDefaults = false, mapEntries = false): unknown {
  if (value instanceof Uint8Array) {
    return Buffer.from(value).toString("base64");
  }
  if (Array.isArray(value)) {
    return value.map((item) => wirePolicy(item, preserveDefaults));
  }
  const record = asRecord(value);
  return record
    ? Object.fromEntries(
        Object.entries(record)
          .sort(([left], [right]) => left.localeCompare(right, "en"))
          .map(([key, item]) => [
            key,
            wirePolicy(
              item,
              preserveDefaults || key === "config",
              ["network_policies", "network_middlewares", "graphql_persisted_queries"].includes(
                key,
              ),
            ),
          ])
          .filter(
            ([, item]) =>
              preserveDefaults ||
              mapEntries ||
              (item !== false &&
                item !== 0 &&
                item !== "" &&
                item !== undefined &&
                !(Array.isArray(item) && item.length === 0) &&
                !(asRecord(item) && Object.keys(item as object).length === 0)),
          ),
      )
    : value;
}

const capability = "openshell.supervisor-middleware.http-credential-access.v1";

// Retain uint64 revisions as decimal strings: Number would lose generation precision.
function revisionNumber(value: unknown): string | undefined {
  // Proto3 omits a scalar zero; the enclosing evidence message remains mandatory.
  if (value === undefined) {
    return "0";
  }
  return typeof value === "string" &&
    /^(0|[1-9][0-9]{0,19})$/.test(value) &&
    BigInt(value) <= 18446744073709551615n
    ? value
    : undefined;
}

function enforcementEvidence(
  status: Readonly<Record<string, unknown>>,
  sandboxId: string,
  policyVersion: number,
  revisionId: string,
): EgressInstallation["enforcement"] | undefined {
  const revision = asRecord(status.revision);
  const observation = asRecord(status.loaded_policy_observation);
  const source = asRecord(revision?.policy);
  const effective = asRecord(observation?.effective_policy);
  const evidence = asRecord(observation?.enforcement);
  if (
    !revision ||
    !observation ||
    !source ||
    !effective ||
    !evidence ||
    evidence.sandbox_id !== sandboxId ||
    typeof evidence.instance_id !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      evidence.instance_id,
    ) ||
    revision.version !== policyVersion ||
    status.active_version !== policyVersion ||
    ![2, "POLICY_STATUS_LOADED"].includes(revision.status as string | number) ||
    evidence.policy_version !== policyVersion ||
    typeof evidence.policy_hash !== "string" ||
    !/^[0-9a-f]{64}$/.test(evidence.policy_hash) ||
    typeof revision.policy_hash !== "string" ||
    !/^[0-9a-f]{64}$/.test(revision.policy_hash) ||
    observation.source_policy_hash !== revision.policy_hash ||
    revisionNumber(evidence.config_revision) === undefined ||
    revisionNumber(evidence.provider_env_revision) === undefined ||
    !isDeepStrictEqual(evidence.enforced_capabilities, [capability])
  ) {
    return undefined;
  }
  // This V1 observation trusts the registered supervisor and the producer's full
  // typed comparison, including fields outside our protobuf projection. It grants
  // no send authority. Unknown derivations must not produce an observation.
  const inertRule = observation.inert_provider_rule ?? "";
  if (inertRule === "") {
    if (
      evidence.policy_hash !== revision.policy_hash ||
      !isDeepStrictEqual(wirePolicy(source), wirePolicy(effective))
    ) {
      return undefined;
    }
  } else {
    const expectedName = `_provider_oce_runtime_${sha256Hex(revisionId, 16)}`;
    const sourceRules = asRecord(source.network_policies);
    const effectiveRules = asRecord(effective.network_policies);
    if (
      inertRule !== expectedName ||
      evidence.policy_hash === revision.policy_hash ||
      !sourceRules ||
      !effectiveRules ||
      Object.hasOwn(sourceRules, expectedName) ||
      !isDeepStrictEqual(wirePolicy(effectiveRules[expectedName]), { name: expectedName }) ||
      !isDeepStrictEqual(
        wirePolicy(source),
        wirePolicy({
          ...effective,
          network_policies: Object.fromEntries(
            Object.entries(effectiveRules).filter(([name]) => name !== expectedName),
          ),
        }),
      )
    ) {
      return undefined;
    }
  }
  return {
    instanceId: evidence.instance_id,
    // Local change fence, not the supplier's canonical policy hash. Both supplier
    // identities and complete decoded policies must remain stable on revalidation.
    configurationId: createHash("sha256")
      .update(
        JSON.stringify([
          sandboxId,
          evidence.instance_id,
          policyVersion,
          observation.source_policy_hash,
          evidence.policy_hash,
          revisionNumber(evidence.config_revision),
          revisionNumber(evidence.provider_env_revision),
          capability,
          wirePolicy(source),
          wirePolicy(effective),
          inertRule,
        ]),
      )
      .digest("hex"),
  };
}

/** Nonsecret, exact routing consumed and independently checked by the paired Sandbox. */
export function openShellEgressConfiguration(
  plan: ConduitPlan,
  options: OpenShellConduitOptions,
): Readonly<Record<string, unknown>> {
  if (
    new Set(plan.routes.map((route) => route.binding.binding.id)).size !== 1 ||
    plan.routes.length === 0
  ) {
    throw new Error("The protected inference slice requires exactly one binding.");
  }
  const hosts = [...new Set(plan.routes.map((route) => new URL(route.origin).hostname))];
  return immutableCopy({
    network_policies: Object.fromEntries(
      plan.routes.map((route, index) => {
        const origin = new URL(route.origin);
        return [
          `oce-egress-${index}`,
          {
            name: `oce-egress-${index}`,
            binaries: options.binaries.map((path) => ({ path })),
            endpoints: [
              {
                host: origin.hostname,
                ports: [Number(origin.port || 443)],
                protocol: "rest",
                enforcement: "NETWORK_ENFORCEMENT_MODE_ENFORCE",
                access: "NETWORK_ACCESS_PRESET_FULL",
                path: route.path,
              },
            ],
          },
        ];
      }),
    ),
    network_middlewares: {
      "oce-egress": {
        name: "oce-egress",
        middleware: options.middlewareName,
        on_error: "fail_closed",
        endpoints: { include: hosts },
        credential_authority: true,
      },
    },
  });
}

export class OpenShellConduitDriver implements ConduitDriver {
  readonly capability = "conduit" as const;
  readonly implementation = "openshell";
  readonly id: string;
  readonly sourceControl: CredentialSourceControl;
  private readonly backend: Backend<OpenShellGateway>;
  private readonly sandbox: SandboxDriver;
  private readonly options: OpenShellConduitOptions;

  static readonly configurationSchema = {
    type: "object",
    additionalProperties: false,
    required: ["middlewareName", "binaries"],
    properties: {
      middlewareName: { type: "string", minLength: 1 },
      binaries: { type: "array", minItems: 1, items: { type: "string", pattern: "^/" } },
    },
  };

  static validateConfiguration(configuration: unknown): void {
    const value = asRecord(configuration);
    if (
      !value ||
      Object.keys(value).some((key) => !["middlewareName", "binaries"].includes(key)) ||
      typeof value.middlewareName !== "string" ||
      !value.middlewareName.trim() ||
      !Array.isArray(value.binaries) ||
      value.binaries.length === 0 ||
      value.binaries.some(
        (path) => typeof path !== "string" || !path.startsWith("/") || path.includes(".."),
      )
    ) {
      throw new Error("Invalid protected OpenShell egress configuration.");
    }
  }

  constructor(
    options: OpenShellConduitOptions,
    selection: {
      readonly id: string;
      readonly backend: Backend<OpenShellGateway>;
      readonly sandbox: SandboxDriver;
    },
  ) {
    OpenShellConduitDriver.validateConfiguration(options);
    if (
      !options.middlewareName ||
      options.binaries.length === 0 ||
      options.binaries.some((binary) => !binary.startsWith("/") || binary.includes("..")) ||
      selection.sandbox.harnessResource === undefined
    ) {
      throw new Error("Invalid protected OpenShell egress configuration.");
    }
    this.id = selection.id;
    this.backend = selection.backend;
    this.sandbox = selection.sandbox;
    this.options = immutableCopy(options);
    this.sourceControl = Object.freeze({
      backend: { id: selection.backend.id, generation: 1 },
      sender: { id: `${selection.backend.id}/supervisor`, generation: 1 },
      resolver: { id: `${selection.id}/resolver`, generation: 1 },
      providers: [openAiStaticProvider],
      assertAvailable: async (signal: AbortSignal) => {
        const client = this.backend.client.clientForNamespace("");
        if (!client.getGatewayInfo) {
          throw new DependencyUnavailableError(
            "The selected OpenShell counterpart does not support protected egress.",
          );
        }
        const info = await client.getGatewayInfo(signal);
        const extensions = info.extensions;
        if (
          !Array.isArray(extensions) ||
          !extensions.some((value) => {
            const item = asRecord(value);
            return (
              item?.configured_name === options.middlewareName &&
              (item.kind === "EXTENSION_KIND_SUPERVISOR_MIDDLEWARE" || item.kind === 4) &&
              item.protocol_major === 1 &&
              Array.isArray(item.required_capabilities) &&
              item.required_capabilities.includes(capability) &&
              Array.isArray(item.supported_capabilities) &&
              item.supported_capabilities.includes(capability)
            );
          })
        ) {
          throw new DependencyUnavailableError(
            "The selected OpenShell counterpart has no negotiated protected egress authority.",
          );
        }
      },
    });
  }

  async configureRevision(context: ConduitRevisionContext): Promise<SandboxConduitWiring> {
    this.assertPlan(context);
    await this.sourceControl.assertAvailable(context.signal);
    return immutableCopy({
      plan: context.plan,
      configuration: openShellEgressConfiguration(context.plan, this.options),
    });
  }

  async wiringStatus(
    context: ConduitRevisionContext,
    prepared: SandboxConduitWiring,
  ): Promise<EgressInstallation | undefined> {
    this.assertPlan(context);
    if (!isDeepStrictEqual(prepared.plan, context.plan)) {
      throw new Error("The prepared Sandbox policy has a different admitted plan.");
    }
    await this.sourceControl.assertAvailable(context.signal);
    const ref = this.sandbox.harnessResource!(context);
    const client = this.backend.client.clientForNamespace(ref.namespaceName);
    const existing = await client.getSandbox(
      { workspace: openShellWorkspaceName(context.namespace), name: ref.resourceName },
      context.signal,
    );
    if (!existing) {
      return undefined;
    }
    this.assertOwned(existing.annotations, context);
    if (!existing.id || !client.getSandboxPolicyStatus) {
      return undefined;
    }
    const status = await client.getSandboxPolicyStatus(
      openShellWorkspaceName(context.namespace),
      ref.resourceName,
      context.signal,
    );
    const revision = asRecord(status.revision);
    const policy = asRecord(revision?.policy);
    const protectedConfiguration = openShellEgressConfiguration(context.plan, this.options);
    const expected = prepared.configuration;
    const expectedPolicies = asRecord(expected.network_policies);
    if (
      !expectedPolicies ||
      !isDeepStrictEqual(
        wirePolicy(expected.network_middlewares),
        wirePolicy(protectedConfiguration.network_middlewares),
      ) ||
      !isDeepStrictEqual(
        wirePolicy(
          Object.fromEntries(
            Object.entries(expectedPolicies).filter(([name]) => name.startsWith("oce-egress-")),
          ),
        ),
        wirePolicy(protectedConfiguration.network_policies),
      )
    ) {
      throw new Error("The prepared Sandbox policy changed protected egress routes.");
    }
    const policies = asRecord(policy?.network_policies);
    // The authenticated supervisor must report loading the exact policy. A desired spec,
    // provider name or running Pod alone is not installation evidence.
    if (
      !revision ||
      !policy ||
      !policies ||
      Number(status.active_version) !== context.plan.generation ||
      Number(revision.version) !== context.plan.generation ||
      ![2, "POLICY_STATUS_LOADED"].includes(revision.status as string | number) ||
      !isDeepStrictEqual(
        wirePolicy(policy.network_middlewares),
        wirePolicy(expected.network_middlewares),
      )
    ) {
      return undefined;
    }
    // The paired Sandbox supplies the entire admitted source, including filesystem,
    // process and auxiliary rules. Network-only equality cannot establish that source.
    if (!isDeepStrictEqual(wirePolicy(policy), wirePolicy(expected))) {
      throw new DependencyUnavailableError(
        "The installed egress source policy differs from its admitted policy.",
      );
    }
    const enforcement = enforcementEvidence(
      status,
      existing.id,
      context.plan.generation,
      context.revision.id,
    );
    return enforcement === undefined
      ? undefined
      : immutableCopy({
          plan: context.plan,
          sandboxId: existing.id,
          sender: this.sourceControl.sender,
          installedAt: new Date().toISOString(),
          enforcement,
        });
  }

  async verifyInstallation(
    context: ConduitRevisionContext,
    installation: EgressInstallation,
  ): Promise<boolean> {
    this.assertPlan(context);
    if (
      !installation.enforcement ||
      !isDeepStrictEqual(installation.plan, context.plan) ||
      !isDeepStrictEqual(installation.sender, this.sourceControl.sender)
    ) {
      return false;
    }
    await this.sourceControl.assertAvailable(context.signal);
    const ref = this.sandbox.harnessResource!(context);
    const client = this.backend.client.clientForNamespace(ref.namespaceName);
    const existing = await client.getSandbox(
      { workspace: openShellWorkspaceName(context.namespace), name: ref.resourceName },
      context.signal,
    );
    if (!existing || existing.id !== installation.sandboxId || !client.getSandboxPolicyStatus) {
      return false;
    }
    this.assertOwned(existing.annotations, context);
    const status = await client.getSandboxPolicyStatus(
      openShellWorkspaceName(context.namespace),
      ref.resourceName,
      context.signal,
    );
    // The supplier revalidates registration, effective config and installed registry under
    // its sandbox mutation lock. Exact equality also refuses replacements of our saved fence.
    return isDeepStrictEqual(
      enforcementEvidence(status, existing.id, context.plan.generation, context.revision.id),
      installation.enforcement,
    );
  }

  async withdrawBinding(context: ConduitRevisionContext, binding: EgressRef): Promise<boolean> {
    if (!context.plan.routes.some((route) => isDeepStrictEqual(route.binding.binding, binding))) {
      throw new Error("Unknown egress withdrawal binding.");
    }
    // TODO(egress multi-binding): install a reducing successor policy without stopping the
    // Harness. The first single-binding slice confirms Sandbox destruction instead.
    return this.removeRevision(context);
  }

  async removeRevision(context: ConduitRevisionContext): Promise<boolean> {
    this.assertPlan(context);
    const ref = this.sandbox.harnessResource!(context);
    const client = this.backend.client.clientForNamespace(ref.namespaceName);
    const selector = {
      workspace: openShellWorkspaceName(context.namespace),
      name: ref.resourceName,
    };
    const existing = await client.getSandbox(selector, context.signal);
    if (!existing) {
      return true;
    }
    this.assertOwned(existing.annotations, context);
    await client.deleteSandbox(selector, context.signal);
    return (await client.getSandbox(selector, context.signal)) === undefined;
  }

  private assertPlan(context: ConduitRevisionContext): void {
    if (
      !isDeepStrictEqual(context.plan, context.revision.egressPlan) ||
      context.plan.egressDriverId !== this.id ||
      context.plan.sandboxDriverId !== this.sandbox.id ||
      context.plan.execution.namespaceId !== context.namespace.id ||
      context.plan.execution.revisionId !== context.revision.id
    ) {
      throw new Error("Protected egress plan does not match its admitted owner.");
    }
  }

  private assertOwned(
    annotations: Readonly<Record<string, string>>,
    context: ConduitRevisionContext,
  ): void {
    if (
      annotations["openclaw.dev/namespace-id"] !== context.namespace.id ||
      annotations["openclaw.dev/agent-id"] !== context.revision.agentId ||
      annotations["openclaw.dev/revision-id"] !== context.revision.id
    ) {
      throw new Error("Protected Sandbox ownership differs from admission.");
    }
  }
}
