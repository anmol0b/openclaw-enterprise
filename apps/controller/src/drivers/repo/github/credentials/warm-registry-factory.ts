import type {
  PreparedRepositoryBackend,
  PreparedRepositoryBackendFactory,
} from "../../credentials/backend-contracts.ts";
import { sameBinding } from "../../credentials/sessions.ts";
import { githubProviderOrigin } from "./factory.ts";
import { createGatewayAuthentication } from "./gateway-authentication.ts";
import { resolveGitHubRepositoryBinding, validateGitHubRepositoryRegistry } from "./registry.ts";
import type { GitHubRepositoryRegistry } from "./registry.ts";
import { createRoutePolicy } from "./routes.ts";
import type { GitHubFactoryOptions } from "./types.ts";
import { authorizePreparedGitSend } from "./warm-use.ts";

type Options = Pick<GitHubFactoryOptions, "clock" | "limits" | "gatewayOrigin"> &
  Readonly<{ registry: GitHubRepositoryRegistry; socketPath: string; gitOrigin?: string }>;

/** A prepared Git broker can authorize one validated Git exchange. It has no App key or issuer. */
export function createPreparedGitHubRegistryFactory(
  options: Options,
): PreparedRepositoryBackendFactory & { trustedUpstreamOrigins: ReadonlySet<string> } {
  const registry = validateGitHubRepositoryRegistry(options.registry);
  const { socketPath, clock, limits } = options;
  const gitOrigin = githubProviderOrigin(options.gitOrigin ?? "https://github.com");
  const gatewayOrigin = githubProviderOrigin(options.gatewayOrigin);
  const entries = registry.repositories.flatMap(({ repository, repositoryRef, namespaces }) =>
    namespaces.map((policy) => {
      const [pushRef] = policy.pushRefAllowlist ?? [];
      if (
        policy.transport !== "git-only" ||
        policy.profiles[0] !== "git-write" ||
        !pushRef?.startsWith("refs/heads/") ||
        pushRef.includes("*") ||
        policy.pushRefAllowlist?.length !== 1
      ) {
        throw new Error("expected-exact-prepared-git-grant");
      }
      const profile = "git-write";
      const { namespaceId } = policy;
      const pushRefAllowlist = Object.freeze([pushRef]);
      const { grant } = resolveGitHubRepositoryBinding(registry, {
        namespaceId,
        repositoryRef,
        profile,
      });
      const route = createRoutePolicy({
        profile: "git-ref-write",
        pushRefAllowlist,
        repository,
        repositoryId: grant.repositoryId,
        gatewayOrigin,
        gitOrigin,
        apiOrigin: gitOrigin,
        limits,
      });
      const client = Object.freeze({
        repository,
        gatewayOrigin,
        gitRemote: gatewayOrigin + "/" + repository + ".git",
        gitUsername: "gateway-session",
        canonicalApiHost: "github.com",
        apiHost: new URL(gatewayOrigin).hostname,
        pushRefAllowlist,
      });
      return { grant, route, client, namespaceId, repositoryRef, pushRef, profile };
    }),
  );
  return Object.freeze<
    PreparedRepositoryBackendFactory & { trustedUpstreamOrigins: ReadonlySet<string> }
  >({
    trustedUpstreamOrigins: new Set([gitOrigin]),
    ...createGatewayAuthentication({
      isGitRoute: (head) => entries.some(({ route }) => !!route.route(head)),
    }),
    resolve() {
      throw new Error("BOUND_SESSION_REQUIRED");
    },
    resolveBound(input) {
      const entry = entries.find(
        ({ grant, namespaceId, repositoryRef, profile }) =>
          sameBinding(grant, input.expectedBinding) &&
          input.namespaceId === namespaceId &&
          input.repositoryRef === repositoryRef &&
          input.profile === profile,
      );
      if (!entry) {
        throw new Error("INVALID_BINDING");
      }
      if (input.durationSeconds > registry.maximumDurationSeconds) {
        throw new Error("INVALID_DURATION");
      }
      return { binding: entry.grant, client: entry.client };
    },
    createPrepared(authority) {
      const entry = entries.find(({ grant }) => sameBinding(grant, authority));
      if (!entry || !authority.sessionId) {
        throw new Error("INVALID_BINDING");
      }
      const { grant: binding, pushRef, route } = entry;
      return Object.freeze<PreparedRepositoryBackend>({
        binding,
        plan({ head }) {
          const plan = route.plan(head);
          if ("kind" in plan) {
            return plan;
          }
          if (plan.category === "api" || (plan.category === "git-push" && !plan.inputPolicy)) {
            return { kind: "denied", status: 400, code: "unsupported-request" };
          }
          // Unlike the ordinary streaming upload-pack path, authorize only after the
          // whole bounded body is available. Receive-pack's exact-ref policy runs there too.
          return Object.freeze({
            ...plan,
            bindRequestDigest: true,
            ...(plan.category === "git-fetch" ? { inputPolicy: () => true } : {}),
          });
        },
        authorize(plan, requestDigestSha256, bounds) {
          const operation =
            plan.category === "git-discovery"
              ? plan.effect === "write"
                ? "advertise-receive-pack"
                : "advertise-upload-pack"
              : plan.effect === "write"
                ? "receive-pack"
                : "upload-pack";
          return authorizePreparedGitSend(
            socketPath,
            clock,
            {
              ...authority,
              operation,
              pushRef,
              requestDigestSha256,
            },
            plan.requestHeaders,
            bounds,
          );
        },
      });
    },
  });
}
