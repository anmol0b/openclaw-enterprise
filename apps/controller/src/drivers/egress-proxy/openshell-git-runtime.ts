import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname } from "node:path";
import { isDeepStrictEqual } from "node:util";
import type { AgentRevision } from "@openclaw-enterprise/contracts";
import {
  DependencyUnavailableError,
  SandboxGatewayUnavailableError,
  TransientDependencyError,
} from "@openclaw-enterprise/occ";
import type { startPreparedGitHubGitOwner } from "../../backends/repository-credentials/prepared-git-owner.ts";
import type { EgressAuthorityConfiguration } from "../../composition/egress-authority.ts";
import { REPOSITORY_CLIENT_BIN } from "../compute/kubernetes/repository-native-configuration.ts";
import {
  resolveGitHubRepositoryBinding,
  type GitHubRepositoryRegistry,
} from "../repo/github/credentials/registry.ts";
import type { OpenShellRepositoryMaterial } from "../repo/github/credentials/prepared-repository-git.ts";
import type {
  OpenShellGatewayClient,
  OpenShellSandboxResponse,
} from "../sandbox/openshell-gateway-client.ts";
import {
  OpenShellPreparedGitProvider,
  OpenShellPreparedGitProviderError,
  type OpenShellPreparedGitBinding,
  type OpenShellPreparedGitInstalled,
} from "./openshell-prepared-git-provider.ts";
import {
  createOpenShellOnlineGitAuthority,
  type OpenShellOnlineGitBinding,
  type OpenShellOnlineGitIdentity,
} from "./openshell-online-git-authority.ts";
import { bindOpenShellEgressAuthority } from "./openshell-authority.ts";

export interface OpenShellGitRuntimeConfiguration {
  readonly registrationName: string;
  readonly authority: EgressAuthorityConfiguration;
}
type Owner = Pick<
  Awaited<ReturnType<typeof startPreparedGitHubGitOwner>>,
  "readOpenShellMaterial" | "authorizeOpenShellRequest"
>;
type MaterialIdentity = Omit<OpenShellRepositoryMaterial, "value">;

/**
 * Why a revision's Git route is closed for good. The entry stays as a tombstone until a new
 * revision: the installation no longer verifies, a provider write's outcome is unknown, or the
 * worker withdrew it. Never a failed read (see OpenShellGitObservationFailure).
 */
export type OpenShellGitRouteBlockReason =
  | "withdrawn"
  | "bootstrap_failed"
  | "execution_replaced"
  | "supervisor_replaced"
  | "sandbox_mismatch"
  | "grant_changed"
  | "material_mismatch"
  | "provider_missing"
  | "provider_overlap"
  | "write_unknown"
  | "write_refused"
  | "gateway_unauthorized"
  | "unknown";

/**
 * Why the installation could not be observed this time: the gateway did not answer, another
 * gateway request failed, the read ran out of time, or the material store did not answer. The
 * route stays closed, nothing is written or replayed, and the worker observes again with a
 * bounded backoff (finding 2136).
 */
export type OpenShellGitObservationFailure =
  "gateway_unavailable" | "gateway_request_failed" | "timeout" | "read_failed";

/** The route's state for one revision, as Compute readiness and operators see it. */
export type OpenShellGitRouteState =
  | { readonly state: "none" }
  | { readonly state: "bootstrapping" }
  | {
      readonly state: "pending";
      readonly reason: "unverified" | "awaiting_material" | "material_unavailable" | "unobserved";
      readonly failure?: OpenShellGitObservationFailure;
    }
  | { readonly state: "installed" }
  | { readonly state: "blocked"; readonly reason: OpenShellGitRouteBlockReason };

/**
 * What a route state means for Compute readiness. Prepared material is discovered and read
 * only for the Agent's active revision (the `sessions` snapshot in prepared-repository-git.ts),
 * so a deploying revision whose Sandbox route has verified waits as `awaiting_material` (no
 * material was ever installed) until it activates: it is ready to activate, and its material
 * installs within seconds after. Holding it would never end (finding 2139). A revision that
 * lost the material it had (`material_unavailable`) and every other pending state waits; a
 * blocked route fails.
 */
export function openShellGitRouteReadiness(
  route: OpenShellGitRouteState,
): "ready" | "pending" | "blocked" {
  if (route.state === "blocked") {
    return "blocked";
  }
  if (
    route.state === "installed" ||
    (route.state === "pending" && route.reason === "awaiting_material")
  ) {
    return "ready";
  }
  return "pending";
}

export type OpenShellGitRuntimeEmit = (event: Readonly<Record<string, unknown>>) => void;

interface Entry {
  readonly revision: Readonly<AgentRevision>;
  readonly client: OpenShellGatewayClient;
  readonly provider: OpenShellPreparedGitProvider;
  readonly bindingId: string;
  readonly repository: string;
  readonly otherProviders: readonly string[];
  binding: OpenShellPreparedGitBinding;
  verify?: (sandbox: OpenShellSandboxResponse) => void;
  sandboxId?: string;
  /** The last observation that verified; the next one must read as the same installation. */
  supervisor?: OpenShellPreparedGitInstalled;
  /** A new supervisor session was adopted for the same process; reported once installed. */
  reconnected?: { readonly since: number } | undefined;
  /** The loss of material the route had was reported (on the first request it refused). */
  materialLost?: true | undefined;
  /** The route has been open at least once: a later install is a restoration. */
  opened?: true | undefined;
  material?: MaterialIdentity;
  installed?: OpenShellPreparedGitInstalled | undefined;
  blocked?: OpenShellGitRouteBlockReason;
  nextRefreshAt?: number;
  /** Why the route is closed while nothing blocks it. */
  pending?: "unverified" | "material_unavailable" | undefined;
  /** The last failed read, kept until a read succeeds; `failures` sizes the backoff. */
  unobserved?:
    | {
        readonly failure: OpenShellGitObservationFailure;
        readonly since: number;
        readonly failures: number;
      }
    | undefined;
  nextObserveAt?: number | undefined;
  /** When an installed route was last closed by a failed read; reported once it is restored. */
  closedAt?: number | undefined;
}
interface EntryState {
  entry?: Entry;
  failed?: true;
}
/** The runtime image's PATH, then the draft helper's directory. The image's own `gh` stays
 * first: the broker `gh` shim beside the helper has no repository manifest in this sandbox. */
const OPENSHELL_GIT_DRAFT_PATH = `/app/node_modules/.bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${REPOSITORY_CLIENT_BIN}`;
const binaries = [
  "/usr/bin/git",
  "/usr/lib/git-core/git-remote-https",
  "/usr/lib/git-core/git-remote-http",
  "/usr/libexec/git-core/git-remote-https",
  "/usr/libexec/git-core/git-remote-http",
  "/usr/bin/curl",
  "/usr/local/bin/node",
  "/usr/bin/node",
];
const OBSERVE_TIMEOUT_MS = 5000;
const REFRESH_INTERVAL_MS = 10_000;
// A failed read is observed again after 1 s, doubling to this cap. A replaced OpenShell
// Gateway Pod answers again within about 30 s; the route is back on the next read after that.
const OBSERVE_BACKOFF_CAP_MS = 10_000;

/** One of the runtime's own verifications failed: the installation no longer verifies. */
class OpenShellGitRouteError extends Error {
  readonly reason: OpenShellGitRouteBlockReason;

  constructor(reason: OpenShellGitRouteBlockReason, message: string, cause?: unknown) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "OpenShellGitRouteError";
    this.reason = reason;
  }
}

/** The revision's route is a tombstone: Compute fails the revision with that cause instead of
 * retrying a preparation that can never succeed (a new revision is required). */
export class OpenShellGitRouteBlockedError extends Error {
  readonly reason: OpenShellGitRouteBlockReason;

  constructor(reason: OpenShellGitRouteBlockReason) {
    super(`OpenShell Git revision binding is unavailable: ${reason}.`);
    this.name = "OpenShellGitRouteBlockedError";
    this.reason = reason;
  }
}

/** A read did not produce evidence. It says nothing about the installation. */
class OpenShellGitObservationError extends Error {
  readonly failure: OpenShellGitObservationFailure;

  constructor(failure: OpenShellGitObservationFailure, cause: unknown) {
    super(`OpenShell Git installation could not be observed: ${failure}.`, { cause });
    this.name = "OpenShellGitObservationError";
    this.failure = failure;
  }
}

function observationFailure(
  error: unknown,
  signal: AbortSignal,
): OpenShellGitObservationFailure | undefined {
  if (error instanceof OpenShellGitObservationError) {
    return error.failure;
  }
  if (error instanceof SandboxGatewayUnavailableError) {
    return "gateway_unavailable";
  }
  if (error instanceof DependencyUnavailableError || error instanceof TransientDependencyError) {
    return "gateway_request_failed";
  }
  if (
    signal.aborted ||
    (error instanceof Error && (error.name === "AbortError" || error.name === "TimeoutError"))
  ) {
    return "timeout";
  }
  return undefined;
}

// gRPC PERMISSION_DENIED and UNAUTHENTICATED: the gateway answered and refused this worker's
// identity. Never retried (owner rule: retry network and timeouts, never an auth failure).
const GRPC_PERMISSION_DENIED = 7;
const GRPC_UNAUTHENTICATED = 16;

function refusedIdentity(error: unknown): boolean {
  const code = (error as { readonly code?: unknown } | null)?.code;
  return code === GRPC_PERMISSION_DENIED || code === GRPC_UNAUTHENTICATED;
}

/** Runs a read. A failure that is not one of the runtime's own verifications is unavailable
 * evidence (the provider's observe() treats its reads the same way), never a verdict. */
async function read<T>(operation: () => Promise<T>, signal: AbortSignal): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof OpenShellGitRouteError || error instanceof OpenShellGitObservationError) {
      throw error;
    }
    if (refusedIdentity(error)) {
      throw new OpenShellGitRouteError(
        "gateway_unauthorized",
        "OpenShell Git gateway refused the worker's identity.",
      );
    }
    throw new OpenShellGitObservationError(
      observationFailure(error, signal) ?? "read_failed",
      error,
    );
  }
}

function revisionIdentity(revision: Readonly<AgentRevision>): Readonly<Record<string, string>> {
  const binding = revision.repositoryCredentials?.bindings[0];
  return {
    namespaceId: revision.namespaceId,
    agentId: revision.agentId,
    revisionId: revision.id,
    ...(binding === undefined ? {} : { repositoryRef: binding.repositoryRef }),
  };
}

/** Worker-local authority. A restart deliberately requires a new revision; persisted labels
 * alone cannot adopt an old supervisor or resume a provider write whose result was lost. */
export class OpenShellGitRuntime {
  private readonly entries = new Map<string, Promise<Entry>>();
  private readonly states = new Map<string, EntryState>();
  private owner: Owner | undefined;
  private emit: OpenShellGitRuntimeEmit | undefined;
  private stopped = new AbortController();
  private running: Promise<void> = Promise.resolve();
  private timer?: ReturnType<typeof setTimeout>;
  private server?: ReturnType<typeof createOpenShellOnlineGitAuthority>;
  readonly configuration: OpenShellGitRuntimeConfiguration;
  private readonly registry: GitHubRepositoryRegistry;
  constructor(configuration: OpenShellGitRuntimeConfiguration, registry: GitHubRepositoryRegistry) {
    this.configuration = configuration;
    this.registry = registry;
  }

  private scope(revision: Readonly<AgentRevision>) {
    const state = revision.repositoryCredentials;
    const binding = state?.bindings[0];
    if (
      !state ||
      state.bindings.length !== 1 ||
      !binding ||
      revision.harness.id !== "codex" ||
      revision.harness.mode !== "dedicated" ||
      revision.egressPlan ||
      state.deadlineWallMs <= Date.now() ||
      binding.profile !== "git-write"
    ) {
      throw new Error(
        "OpenShell prepared Git requires one live git-write binding and a dedicated Codex revision without another egress plan.",
      );
    }
    const resolved = resolveGitHubRepositoryBinding(this.registry, {
      namespaceId: revision.namespaceId,
      repositoryRef: binding.repositoryRef,
      profile: binding.profile,
    });
    const repository = this.registry.repositories.find(
      (r) => r.repositoryRef === binding.repositoryRef,
    )!;
    const policy = repository.namespaces.find((p) => p.namespaceId === revision.namespaceId)!;
    if (
      !isDeepStrictEqual(binding, resolved) ||
      policy.pushRefAllowlist?.length !== 1 ||
      !["git-only", "git-and-draft-pr"].includes(policy.transport ?? "")
    ) {
      throw new Error("OpenShell prepared Git requires the current exact registry grant.");
    }
    return { repository: repository.repository, binding, policy };
  }

  async prepare(
    revision: Readonly<AgentRevision>,
    client: OpenShellGatewayClient,
    workspace: string,
    sandbox: string,
    signal: AbortSignal,
    otherProviders: readonly string[] = [],
    otherHosts: readonly string[] = [],
  ) {
    const scope = this.scope(revision);
    if (otherHosts.some((host) => this.overlapsGit(host))) {
      throw new Error("OpenShell Git cannot share overlapping network policy.");
    }
    if (!this.owner || this.stopped.signal.aborted) {
      throw new Error("OpenShell Git worker is unavailable.");
    }
    let pending = this.entries.get(revision.id);
    if (!pending) {
      pending = (async (): Promise<Entry> => {
        await this.checkOtherProviders(client, workspace, otherProviders, signal);
        const current = await client.getSandbox({ workspace, name: sandbox }, signal);
        if (current) {
          // The rejected bootstrap is retained below, so this logs once per revision while
          // every later pass (maintenance included) rethrows the same failure.
          this.emit?.({
            event: "worker.error",
            code: "OPENSHELL_GIT_RECONCILIATION_REQUIRED",
            reason: "worker_restarted",
            ...revisionIdentity(revision),
          });
          throw new Error("OpenShell Git requires a new revision after worker restart.");
        }
        const info = await client.getGatewayInfo?.(signal);
        if (
          !Array.isArray(info?.extensions) ||
          !info.extensions.some((value) => {
            const extension = value as Record<string, unknown>;
            return (
              extension.configured_name === this.configuration.registrationName &&
              [4, "EXTENSION_KIND_SUPERVISOR_MIDDLEWARE"].includes(
                extension.kind as string | number,
              ) &&
              extension.protocol_major === 1
            );
          })
        ) {
          throw new Error("OpenShell Git middleware is not registered with the selected gateway.");
        }
        const ws = await client.getWorkspace(workspace, signal);
        if (!ws?.id) {
          throw new Error("OpenShell Git workspace identity is unavailable.");
        }
        const provider = new OpenShellPreparedGitProvider(client, {
          workspace,
          workspaceId: ws.id,
          sandbox,
          executionId: revision.id,
          repository: scope.repository,
          gitOrigin: "https://github.com",
          apiOrigin: "https://api.github.com",
          binaries,
        });
        const binding = await provider.bootstrap(signal);
        return {
          revision,
          client,
          provider,
          binding,
          repository: scope.repository,
          otherProviders: [...otherProviders],
          bindingId: randomBytes(24).toString("base64url"),
        };
      })();
      // Retain a rejected bootstrap as a stopped attempt, never silently replay its writes.
      this.entries.set(revision.id, pending);
      const state: EntryState = {};
      this.states.set(revision.id, state);
      void pending.then(
        (entry) => {
          state.entry = entry;
        },
        () => {
          state.failed = true;
        },
      );
    }
    const entry = await pending;
    if (entry.blocked) {
      throw new OpenShellGitRouteBlockedError(entry.blocked);
    }
    if (
      entry.client !== client ||
      entry.binding.workspace !== workspace ||
      entry.binding.sandbox !== sandbox ||
      !isDeepStrictEqual(entry.otherProviders, otherProviders) ||
      !isDeepStrictEqual(entry.revision, revision)
    ) {
      throw new Error("OpenShell Git revision binding is unavailable.");
    }
    // `oce-github pr-create --draft` runs from the image's repository client; Landlock and
    // PATH must admit it only where the grant allows a draft.
    const draft = scope.policy.transport === "git-and-draft-pr";
    return {
      provider: entry.binding.provider,
      readOnlyPaths: draft ? [dirname(REPOSITORY_CLIENT_BIN)] : [],
      environment: [
        ...(draft ? [{ name: "PATH", value: OPENSHELL_GIT_DRAFT_PATH }] : []),
        { name: "OCE_OPENSHELL_GIT_REPOSITORY", value: scope.repository },
        { name: "OCE_OPENSHELL_GIT_PUSH_REF", value: scope.policy.pushRefAllowlist![0]! },
        { name: "OCE_OPENSHELL_GIT_API_ORIGIN", value: "https://api.github.com" },
        ...(scope.policy.pullRequestBase
          ? [{ name: "OCE_OPENSHELL_GIT_BASE", value: scope.policy.pullRequestBase }]
          : []),
        { name: "GIT_TERMINAL_PROMPT", value: "0" },
        { name: "GIT_CONFIG_COUNT", value: "5" },
        { name: "GIT_CONFIG_KEY_0", value: "credential.helper" },
        { name: "GIT_CONFIG_VALUE_0", value: "" },
        {
          name: "GIT_CONFIG_KEY_1",
          value: `credential.https://github.com/${scope.repository}.git.helper`,
        },
        {
          name: "GIT_CONFIG_VALUE_1",
          value: "!f() { printf '%s\\n' 'username=x-access-token' \"password=$GITHUB_TOKEN\"; }; f",
        },
        { name: "GIT_CONFIG_KEY_2", value: "http.followRedirects" },
        { name: "GIT_CONFIG_VALUE_2", value: "false" },
        { name: "GIT_CONFIG_KEY_3", value: "http.sslVerify" },
        { name: "GIT_CONFIG_VALUE_3", value: "true" },
        { name: "GIT_CONFIG_KEY_4", value: "credential.useHttpPath" },
        { name: "GIT_CONFIG_VALUE_4", value: "true" },
      ],
      middlewares: {
        "oce-prepared-git": {
          name: "oce-prepared-git",
          middleware: this.configuration.registrationName,
          config: { fields: { binding_id: { stringValue: entry.bindingId } } },
          on_error: "fail_closed",
          order: 2147483647,
          endpoints: { include: ["github.com", "api.github.com"] },
        },
      },
    };
  }

  async bind(
    revisionId: string,
    verify: (sandbox: OpenShellSandboxResponse) => void,
  ): Promise<void> {
    const entry = await this.entries.get(revisionId);
    if (!entry || entry.blocked) {
      throw new Error("OpenShell Git has no admitted bootstrap.");
    }
    entry.verify = verify;
  }

  withdraw(revisionId: string): void {
    // Keep the tombstone to prevent adoption/recreation under the same execution identity.
    void this.entries.get(revisionId)?.then(
      (entry) => {
        entry.blocked ??= "withdrawn";
        entry.installed = undefined;
      },
      () => {},
    );
  }

  withdrawNamespace(namespaceId: string): void {
    for (const pending of this.entries.values()) {
      void pending.then(
        (entry) => {
          if (entry.revision.namespaceId === namespaceId) {
            entry.blocked ??= "withdrawn";
            entry.installed = undefined;
          }
        },
        () => {},
      );
    }
  }

  /**
   * The route's state for a revision this worker prepared. Compute readiness holds a
   * revision until the route is verified (installed, or awaiting its first material, which
   * is issued only once the revision is active) and fails it while the route is blocked, so
   * a deployment never reports success over a route that cannot open (findings 2136, 2139).
   */
  route(revisionId: string): OpenShellGitRouteState {
    const state = this.states.get(revisionId);
    if (state === undefined) {
      return { state: "none" };
    }
    if (state.failed) {
      return { state: "blocked", reason: "bootstrap_failed" };
    }
    const entry = state.entry;
    if (entry === undefined) {
      return { state: "bootstrapping" };
    }
    if (entry.blocked) {
      return { state: "blocked", reason: entry.blocked };
    }
    if (entry.installed) {
      return { state: "installed" };
    }
    if (entry.unobserved) {
      return { state: "pending", reason: "unobserved", failure: entry.unobserved.failure };
    }
    if (entry.pending === "material_unavailable" && entry.material === undefined) {
      return { state: "pending", reason: "awaiting_material" };
    }
    return { state: "pending", reason: entry.pending ?? "unverified" };
  }

  /** The first policy that also reaches the Git hosts, which only the middleware route may. */
  overlappingPolicy(
    policies: readonly {
      readonly name: string;
      readonly endpoints: readonly { readonly host: string }[];
    }[],
  ): string | undefined {
    return policies.find((policy) =>
      policy.endpoints.some((endpoint) => this.overlapsGit(endpoint.host)),
    )?.name;
  }

  private overlapsGit(host: string): boolean {
    const normalized = host.toLowerCase().replace(/\.$/, "");
    if (!/^(?:\*\.)?[a-z0-9.-]+$/.test(normalized)) {
      return true;
    }
    return ["github.com", "api.github.com"].some(
      (target) =>
        normalized === target ||
        (normalized.startsWith("*.") && target.endsWith(normalized.slice(1))),
    );
  }

  private async checkOtherProviders(
    client: OpenShellGatewayClient,
    workspace: string,
    providers: readonly string[],
    signal: AbortSignal,
  ): Promise<void> {
    for (const name of providers) {
      const provider = await client.getProvider(workspace, name, signal);
      if (!provider) {
        throw new OpenShellGitRouteError(
          "provider_missing",
          "OpenShell inference provider is unavailable.",
        );
      }
      const profile = await client.getProviderProfile(
        provider.profileWorkspace || workspace,
        provider.type,
        signal,
      );
      const definition = profile?.definition;
      const endpoints = definition?.endpoints;
      const credentials = definition?.credentials;
      if (
        !definition ||
        !Array.isArray(endpoints) ||
        !Array.isArray(credentials) ||
        endpoints.some((value) =>
          this.overlapsGit(String((value as Record<string, unknown>).host ?? "")),
        ) ||
        credentials.some((value) =>
          ((value as Record<string, unknown>).env_vars as string[] | undefined)?.includes(
            "GITHUB_TOKEN",
          ),
        )
      ) {
        throw new OpenShellGitRouteError(
          "provider_overlap",
          "OpenShell Git cannot share an unverified or overlapping credential provider.",
        );
      }
    }
  }

  /**
   * One verified read of the installation. Only the worker's own reconcile pass adopts a new
   * supervisor session (`adopt`); a request's lookup verifies against the reference and never
   * moves it, so late answers from concurrent reads cannot move it backwards.
   */
  private async observation(entry: Entry, signal: AbortSignal, adopt = false) {
    await read(
      () =>
        this.checkOtherProviders(
          entry.client,
          entry.binding.workspace,
          entry.otherProviders,
          signal,
        ),
      signal,
    );
    const sandbox = await read(
      () =>
        entry.client.getSandbox(
          { workspace: entry.binding.workspace, name: entry.binding.sandbox },
          signal,
        ),
      signal,
    );
    if (!sandbox?.id || !entry.verify) {
      return;
    }
    if (![2, "SANDBOX_PHASE_READY"].includes(sandbox.phase as string | number)) {
      return;
    }
    try {
      entry.verify(sandbox);
    } catch (error) {
      throw new OpenShellGitRouteError(
        "sandbox_mismatch",
        "OpenShell Git sandbox no longer matches its admitted content.",
        error,
      );
    }
    if (
      (sandbox.restartCount ?? 0) !== 0 ||
      ![1, "SANDBOX_RESTART_POLICY_NEVER"].includes(
        sandbox.spec?.restart_policy as string | number,
      ) ||
      (entry.sandboxId && entry.sandboxId !== sandbox.id)
    ) {
      throw new OpenShellGitRouteError(
        "execution_replaced",
        "OpenShell Git execution was replaced.",
      );
    }
    entry.sandboxId = sandbox.id;
    // observe() answers undefined, never throws, for a read it could not complete.
    const observed = await entry.provider.observe(entry.binding, sandbox.id, signal);
    if (!observed) {
      return;
    }
    const previous = entry.supervisor;
    if (previous === undefined) {
      if (adopt) {
        entry.supervisor = observed;
      }
      return observed;
    }
    if (
      observed.processInstanceId !== previous.processInstanceId ||
      observed.networkInstanceId !== previous.networkInstanceId
    ) {
      throw new OpenShellGitRouteError(
        "supervisor_replaced",
        "OpenShell Git supervisor was replaced.",
      );
    }
    if (observed.supervisorSessionId !== previous.supervisorSessionId) {
      // The supervisor holds a new control session. A replaced Gateway Pod does this to
      // every running Sandbox at once (the same supervisor process reconnects), so a
      // redeploy of the whole fleet is not required: the new session is adopted when the
      // verified observation is the same installation as before. Its identity must read
      // exactly as before: the Sandbox (id, name, workspace), the execution, the provider
      // (id, profile version, attachment epoch) and the supervisor's process and network
      // instance ids. Its generation (provider resource version and env revision, config
      // revision, policy hash, credential state) is verified by observe() against the
      // Gateway's own receipt and the provider version this worker last wrote, not against
      // the previous read: a credential rotation moves it, and its verifying read often lags
      // the write by seconds, so a stale snapshot would close healthy routes on every Gateway
      // restart that overlaps a rotation. Any other difference is a replaced supervisor
      // (finding 2136).
      //
      // Stated limit (owner decision 2026-10-20): in OpenShell 0.1.4 (`5a7728c3`) both
      // instance ids are asserted by the supervisor, not attested by the Gateway. The
      // network instance id is the supervisor's own SupervisorHello instance id
      // (crates/openshell-server/src/grpc/provider_readiness.rs; generated sandbox-side in
      // crates/openshell-supervisor-process/src/delegated.rs), the process instance id comes
      // from its readiness report and is only held constant within one session, and the
      // Gateway persists what a reconnecting supervisor claims as its main process instance
      // (crates/openshell-server/src/compute/mod.rs). ConnectSupervisor does authenticate a
      // sandbox principal scoped to this Sandbox id, so continuity rests on that principal
      // plus the supervisor's claims until OpenShell provides an attested reconnect identity
      // (a planned OpenShell change). No material is issued or replayed on adoption.
      if (
        (
          [
            "workspace",
            "sandbox",
            "sandboxId",
            "executionId",
            "provider",
            "providerId",
            "profileVersion",
            "attachmentEpoch",
          ] as const
        ).some((key) => observed[key] !== previous[key])
      ) {
        throw new OpenShellGitRouteError(
          "supervisor_replaced",
          "OpenShell Git supervisor was replaced.",
        );
      }
      if (adopt && entry.opened) {
        // Reported once the route is open again; a route that never opened has nothing to restore.
        entry.reconnected ??= { since: entry.closedAt ?? performance.now() };
      }
    }
    if (adopt) {
      entry.supervisor = observed;
    }
    return observed;
  }

  private identity(entry: Entry): Readonly<Record<string, string>> {
    return revisionIdentity(entry.revision);
  }

  private pending(entry: Entry, reason: "unverified" | "material_unavailable"): void {
    entry.installed = undefined;
    entry.pending = reason;
    entry.unobserved = undefined;
    entry.nextObserveAt = undefined;
  }

  private installedNow(entry: Entry, installed: OpenShellPreparedGitInstalled): void {
    entry.installed = installed;
    entry.nextRefreshAt = performance.now() + REFRESH_INTERVAL_MS;
    entry.pending = undefined;
    entry.unobserved = undefined;
    entry.nextObserveAt = undefined;
    entry.materialLost = undefined;
    entry.opened = true;
    const reconnected = entry.reconnected;
    if (entry.closedAt !== undefined || reconnected !== undefined) {
      this.emit?.({
        event: "worker.openshell-git-route",
        status: "restored",
        ...(reconnected === undefined ? {} : { reason: "supervisor_reconnected" }),
        durationMs: Math.round(performance.now() - (entry.closedAt ?? reconnected!.since)),
        ...this.identity(entry),
      });
      entry.closedAt = undefined;
      entry.reconnected = undefined;
    }
  }

  /** Closes the route for good and reports why; the entry is a tombstone from here on. */
  private block(entry: Entry, reason: OpenShellGitRouteBlockReason): void {
    entry.blocked = reason;
    entry.installed = undefined;
    entry.unobserved = undefined;
    entry.closedAt = undefined;
    entry.reconnected = undefined;
    this.emit?.({
      event: "worker.error",
      code: "OPENSHELL_GIT_RECONCILIATION_REQUIRED",
      reason,
      ...this.identity(entry),
    });
  }

  /**
   * Classifies a failed reconcile or lookup. The runtime's own verifications and an unknown
   * provider write block the route: no retry, replacement, or token replay. A failed read
   * only closes it until the next successful observation, with a bounded backoff.
   */
  private failed(entry: Entry, error: unknown, signal: AbortSignal): void {
    if (entry.blocked) {
      entry.installed = undefined;
      return;
    }
    let failure: OpenShellGitObservationFailure | undefined;
    if (error instanceof OpenShellGitRouteError) {
      this.block(entry, error.reason);
      return;
    }
    if (error instanceof OpenShellPreparedGitProviderError) {
      if (error.outcome === "unknown") {
        this.block(entry, "write_unknown");
        return;
      }
      // A refused write wrote nothing. Refused because the gateway did not answer, it is
      // observed again; refused for any other reason, the provider no longer verifies.
      failure = error.readFailure;
      if (failure === undefined) {
        this.block(entry, "write_refused");
        return;
      }
    } else {
      failure = observationFailure(error, signal);
      if (failure === undefined) {
        this.block(entry, "unknown");
        return;
      }
    }
    if (entry.installed) {
      entry.closedAt ??= performance.now();
    }
    entry.installed = undefined;
    const failures = (entry.unobserved?.failures ?? 0) + 1;
    entry.unobserved = {
      failure,
      since: entry.unobserved?.since ?? performance.now(),
      failures,
    };
    entry.nextObserveAt =
      performance.now() + Math.min(1000 * 2 ** (failures - 1), OBSERVE_BACKOFF_CAP_MS);
    if (failures === 1) {
      this.emit?.({
        event: "worker.openshell-git-route-warning",
        status: "unobserved",
        reason: failure,
        ...this.identity(entry),
      });
    }
  }

  private async reconcile(entry: Entry): Promise<void> {
    if (entry.blocked || !entry.verify || !this.owner) {
      return;
    }
    const now = performance.now();
    if (entry.installed ? now < (entry.nextRefreshAt ?? 0) : now < (entry.nextObserveAt ?? 0)) {
      return;
    }
    const signal = AbortSignal.any([this.stopped.signal, AbortSignal.timeout(OBSERVE_TIMEOUT_MS)]);
    try {
      // Observe the bootstrap supervisor before delivering the first usable credential.
      const observed = await this.observation(entry, signal, true);
      if (!observed) {
        this.pending(entry, "unverified");
        return;
      }
      const owner = this.owner;
      const material = await read(
        () => owner.readOpenShellMaterial(entry.revision.id, signal),
        signal,
      );
      if (!material) {
        if (entry.material) {
          // The route lost the material it had: the owner retired it (the App key was
          // rotated or rejected and preparation is quarantined, access was withdrawn, or a
          // newer version is active and this one is about to be withdrawn). The restoration
          // reports the outage's length; the first request refused meanwhile reports the
          // loss (finding 2135).
          entry.closedAt ??= performance.now();
        }
        this.pending(entry, "material_unavailable");
        return;
      }
      let scope: ReturnType<OpenShellGitRuntime["scope"]>;
      try {
        scope = this.scope(entry.revision);
      } catch (error) {
        throw new OpenShellGitRouteError(
          "grant_changed",
          "OpenShell Git admission no longer matches the registry grant.",
          error,
        );
      }
      const { binding, policy } = scope;
      if (
        material.repository !== entry.repository ||
        material.providerInstanceId !== binding.grant.providerInstanceId ||
        material.repositoryId !== binding.grant.repositoryId ||
        material.grantId !== binding.grant.grantId ||
        material.pushRef !== policy.pushRefAllowlist![0] ||
        material.apiOrigin !== "https://api.github.com"
      ) {
        throw new OpenShellGitRouteError(
          "material_mismatch",
          "OpenShell Git material does not match admission.",
        );
      }
      if (
        !entry.material ||
        entry.material.materialVersion !== material.materialVersion ||
        entry.material.preparationAttemptId !== material.preparationAttemptId
      ) {
        if (entry.blocked || this.stopped.signal.aborted || signal.aborted) {
          return;
        }
        this.pending(entry, "unverified");
        entry.binding = await entry.provider.rotate(
          entry.binding,
          { value: material.value, expiresAt: material.expiresAt },
          signal,
        );
        const { value: _value, ...identity } = material;
        entry.material = identity;
      }
      const installed = await this.observation(entry, signal, true);
      if (
        installed?.credentialState === "active" &&
        !entry.blocked &&
        !this.stopped.signal.aborted &&
        !signal.aborted
      ) {
        this.installedNow(entry, installed);
      } else {
        this.pending(entry, "unverified");
      }
    } catch (error) {
      this.failed(entry, error, signal);
    }
  }

  async lookup(
    identity: OpenShellOnlineGitIdentity,
    signal: AbortSignal,
  ): Promise<OpenShellOnlineGitBinding | undefined> {
    if (!this.owner || this.stopped.signal.aborted || signal.aborted) {
      return;
    }
    let reason = "no_binding";
    let denied: Entry | undefined;
    for (const pending of this.entries.values()) {
      const entry = await pending.catch(() => undefined);
      if (
        !entry ||
        entry.bindingId !== identity.bindingId ||
        entry.binding.workspace !== identity.workspace
      ) {
        continue;
      }
      // The binding is this entry's; from here the denial names the route's state.
      denied = entry;
      if (entry.blocked) {
        reason = "route_blocked";
        break;
      }
      if (entry.sandboxId !== identity.sandboxId) {
        reason = "execution_mismatch";
        break;
      }
      if (!entry.installed || !entry.material) {
        // A route that had material and lost it names that, so an operator can tell a
        // retired credential (recovery required) from a version still verifying.
        reason = entry.unobserved
          ? "route_unobserved"
          : entry.pending === "material_unavailable" && entry.material
            ? "material_unavailable"
            : "route_pending";
        if (reason === "material_unavailable" && !entry.materialLost) {
          // Said once per loss, and only for a Sandbox still asking: a version superseded
          // by a newer one loses its material a moment before it is withdrawn, and nothing
          // asks for it. A live version with a retired credential (recovery required) does.
          entry.materialLost = true;
          this.emit?.({
            event: "worker.openshell-git-route-warning",
            status: "pending",
            reason: "material_unavailable",
            ...this.identity(entry),
          });
        }
        break;
      }
      const material = entry.material;
      try {
        const observed = await this.observation(entry, signal);
        if (entry.blocked || this.stopped.signal.aborted || signal.aborted) {
          reason = entry.blocked ? "route_blocked" : "lookup_aborted";
          break;
        }
        if (entry.material !== material) {
          reason = "material_rotated";
          break;
        }
        if (!observed || !isDeepStrictEqual(observed, entry.installed)) {
          // The installation no longer reads as the one admitted: close the route until the
          // worker's own reconcile verifies it again.
          this.pending(entry, "unverified");
          reason = "installation_changed";
          break;
        }
        if (Date.parse(material.expiresAt) <= Date.now()) {
          reason = "material_expired";
          break;
        }
        return {
          sandboxId: identity.sandboxId,
          bindingId: identity.bindingId,
          workspace: identity.workspace,
          executionId: entry.revision.id,
          sessionId: material.sessionId,
          providerInstanceId: material.providerInstanceId,
          repositoryId: material.repositoryId,
          grantId: material.grantId,
          repository: material.repository,
          pushRef: material.pushRef,
          ...(material.pullRequestBase ? { pullRequestBase: material.pullRequestBase } : {}),
          apiOrigin: material.apiOrigin,
          installed: {
            preparationAttemptId: material.preparationAttemptId,
            materialVersion: material.materialVersion,
          },
        };
      } catch (error) {
        if (signal.aborted && !(error instanceof OpenShellGitRouteError)) {
          // The request's own budget ran out: this request is denied, and the route stays as
          // the worker's reconcile last left it.
          reason = "lookup_aborted";
          break;
        }
        this.failed(entry, error, signal);
        reason = entry.blocked ? "route_blocked" : "route_unobserved";
        break;
      }
    }
    // One line per denial the worker decides (finding 2133); the supervisor's own log only
    // says the middleware denied.
    this.emit?.({
      event: "worker.openshell-git-denied",
      reason,
      sandboxId: identity.sandboxId,
      requestId: identity.requestId,
      ...(denied === undefined ? {} : this.identity(denied)),
    });
    return undefined;
  }

  async start(owner: Owner, emit?: OpenShellGitRuntimeEmit): Promise<void> {
    if (this.owner || this.stopped.signal.aborted) {
      throw new Error("OpenShell Git worker already started or stopped.");
    }
    const config = this.configuration.authority;
    const [certificate, privateKey, publicKey] = await Promise.all([
      readFile(config.certificatePath),
      readFile(config.privateKeyPath),
      readFile(config.issuerPublicKeyPath),
    ]);
    this.owner = owner;
    this.emit = emit;
    this.server = createOpenShellOnlineGitAuthority({
      registrationName: this.configuration.registrationName,
      budgetMs: 3000,
      identity: {
        issuer: config.issuer,
        audience: config.audience,
        keyId: config.keyId,
        publicKey,
      },
      lookupBinding: (identity, signal) => this.lookup(identity, signal),
      approve: (request, installed, signal) =>
        owner.authorizeOpenShellRequest(request, installed, signal),
      onDeny: (denial) => {
        this.emit?.({ event: "worker.openshell-git-denied", ...denial });
      },
    });
    try {
      await bindOpenShellEgressAuthority(
        this.server,
        `${config.host.includes(":") ? `[${config.host}]` : config.host}:${config.port}`,
        certificate,
        privateKey,
      );
    } catch (error) {
      this.server.forceShutdown();
      this.owner = undefined;
      throw error;
    } finally {
      privateKey.fill(0);
    }
    const tick = () => {
      this.running = (async () => {
        for (const pending of this.entries.values()) {
          const entry = await pending.catch(() => undefined);
          if (entry) {
            await this.reconcile(entry);
          }
        }
      })().finally(() => {
        if (!this.stopped.signal.aborted) {
          this.timer = setTimeout(tick, 1000);
        }
      });
    };
    tick();
  }

  async close(): Promise<void> {
    this.stopped.abort();
    clearTimeout(this.timer);
    this.server?.forceShutdown();
    await this.running;
    this.owner = undefined;
    this.entries.clear();
    this.states.clear();
  }
}
