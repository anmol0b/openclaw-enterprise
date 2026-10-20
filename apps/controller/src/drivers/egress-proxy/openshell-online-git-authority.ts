import { createHash, randomUUID } from "node:crypto";
import type { Server } from "@grpc/grpc-js";
import type {
  PreparedGitHubPullScope,
  PreparedGitHubUseRequest,
} from "@openclaw-enterprise/contracts";
import type { RequestHead } from "../repo/credentials/backend-contracts.ts";
import { decodePushedBranchRef } from "../repo/credentials/client-contracts.ts";
import { parseUnambiguousJson } from "../repo/credentials/json-members.ts";
import { planDraftPull } from "../repo/github/credentials/prepared-draft-pull.ts";
import { classifyRoute } from "../repo/github/credentials/routes/classification.ts";
import { allowsReceivePackInput } from "../repo/github/credentials/routes/receive-pack.ts";
import {
  createOpenShellOnlineHttpAuthority,
  type OpenShellOnlineHttpAuthorityOptions,
  type OpenShellOnlineHttpRequest,
} from "./openshell-online-authority.ts";

export interface OpenShellOnlineGitIdentity {
  readonly sandboxId: string;
  readonly bindingId: string;
  readonly requestId: string;
  /** Display metadata only; compare with the workspace in the trusted sandbox mapping. */
  readonly workspace: string;
}

export interface OpenShellOnlineGitBinding {
  readonly sandboxId: string;
  readonly bindingId: string;
  readonly workspace: string;
  /** A live, exclusively owned execution mapped by the runtime, absent from the stock JWT. */
  readonly executionId: string;
  readonly sessionId: string;
  readonly providerInstanceId: string;
  readonly repositoryId: string;
  readonly grantId: string;
  readonly repository: string;
  readonly pushRef: string;
  readonly pullRequestBase?: string;
  readonly gitOrigin?: string;
  readonly apiOrigin?: string;
  readonly installed: {
    readonly preparationAttemptId: string;
    readonly materialVersion: string;
  };
}

export interface OpenShellOnlineGitAuthorityOptions extends Omit<
  OpenShellOnlineHttpAuthorityOptions,
  "authorize"
> {
  /** Resolve exactly one live admitted workspace/execution from the authenticated sandbox and
   * binding. Require a never-reused sandbox identity dedicated to that execution. Recheck
   * replacement fencing, mandatory final middleware, TLS-only routing and the
   * installed provider generation. Neither RPC config nor workspace metadata is this proof. */
  readonly lookupBinding: (
    identity: OpenShellOnlineGitIdentity,
    signal: AbortSignal,
  ) => Promise<OpenShellOnlineGitBinding | undefined>;
  /** Check live session/grant/material in one transaction. For draft creates, durably consume
   * ONE submission per grant before returning true, including uncertain/expired permits, and
   * answer "draft_already_opened" once it is spent (unless the registry opts the grant out of
   * the limit). Never retry on a lost acknowledgement. This records possible use, not a
   * provider outcome. */
  readonly approve: (
    request: PreparedGitHubUseRequest,
    expectedInstalled: OpenShellOnlineGitBinding["installed"],
    signal: AbortSignal,
  ) => Promise<boolean | "draft_already_opened">;
  /** Told once per request the authority itself refuses, with the reason class (finding 2133).
   * A request with no live binding is the lookup's to report. Never the request's content. */
  readonly onDeny?: (denial: OpenShellOnlineGitDenial) => void;
}

/** Why the authority refused a request it could attribute to a live binding, or a request
 * whose shape it rejected before approval. */
export type OpenShellOnlineGitDenialReason =
  | "binding_mismatch"
  | "request_invalid"
  | "encoding_unsupported"
  | "draft_rejected"
  | "origin_mismatch"
  | "route_unsupported"
  | "discovery_body"
  | "body_empty"
  | "body_too_large"
  | "ref_not_allowed"
  | "approval_denied"
  | "approval_failed"
  | "draft_already_opened"
  | "aborted";

export interface OpenShellOnlineGitDenial {
  readonly reason: OpenShellOnlineGitDenialReason;
  readonly sandboxId: string;
  readonly requestId: string;
  readonly revisionId: string;
  readonly operation?: PreparedGitHubUseRequest["operation"];
}

function matchesOrigin(origin: string, request: OpenShellOnlineHttpRequest): boolean {
  const url = new URL(origin);
  return (
    url.origin === origin &&
    url.protocol === "https:" &&
    url.hostname === request.target.host &&
    Number(url.port || 443) === request.target.port
  );
}

function validBinding(
  binding: OpenShellOnlineGitBinding,
  request: OpenShellOnlineHttpRequest,
): boolean {
  return (
    binding.sandboxId === request.sandboxId &&
    binding.bindingId === request.bindingId &&
    binding.workspace === request.workspace &&
    [
      binding.executionId,
      binding.sessionId,
      binding.providerInstanceId,
      binding.repositoryId,
      binding.grantId,
      binding.installed?.preparationAttemptId,
      binding.installed?.materialVersion,
    ].every((id) => typeof id === "string" && /^[\x21-\x7e]{1,256}$/.test(id)) &&
    /^[A-Za-z0-9_-]+\/[A-Za-z0-9_.-]+$/.test(binding.repository) &&
    !/\/(?:\.|\.\.)$/.test(binding.repository) &&
    typeof binding.pushRef === "string" &&
    decodePushedBranchRef(Buffer.from(binding.pushRef)) === binding.pushRef &&
    (binding.pullRequestBase === undefined ||
      (decodePushedBranchRef(Buffer.from("refs/heads/" + binding.pullRequestBase)) ===
        "refs/heads/" + binding.pullRequestBase &&
        "refs/heads/" + binding.pullRequestBase !== binding.pushRef))
  );
}

function requestHead(request: OpenShellOnlineHttpRequest): RequestHead | undefined {
  const headers: Record<string, string> = Object.create(null);
  // Stock has already removed protected headers. Refuse unknown or repeated visible headers;
  // never interpret their absence as proof of original framing or authentication.
  const allowed = [
    "user-agent",
    "accept",
    "accept-encoding",
    "accept-language",
    "content-encoding",
    "content-type",
    "git-protocol",
    "pragma",
    "x-github-api-version",
  ];
  for (const [name, value] of request.headers) {
    if (
      !allowed.includes(name) ||
      Object.hasOwn(headers, name) ||
      (name === "accept-language" && value.length > 256) ||
      (name === "pragma" && value !== "no-cache") ||
      // Exactly one gzip layer; operation() admits it only where the body is never inspected.
      (name === "content-encoding" && value.toLowerCase() !== "gzip")
    ) {
      return undefined;
    }
    headers[name] = value;
  }
  return {
    method: request.target.method,
    rawTarget: request.target.path + (request.target.query ? "?" + request.target.query : ""),
    headers,
    receivedMonoMs: performance.now(),
    contentEncoding: headers["content-encoding"] === undefined ? "identity" : "gzip",
    // These lengths describe the complete buffered view, never the omitted original framing.
    framing: { kind: "length", bytes: request.body.byteLength },
  };
}

function draftScope(
  request: OpenShellOnlineHttpRequest,
  binding: OpenShellOnlineGitBinding,
  head: RequestHead,
): PreparedGitHubPullScope | undefined {
  const apiOrigin = binding.apiOrigin ?? "https://api.github.com";
  if (
    !binding.pullRequestBase ||
    !matchesOrigin(apiOrigin, request) ||
    request.body.byteLength > 64 * 1024 ||
    head.headers["git-protocol"] !== undefined ||
    (head.headers["x-github-api-version"] !== undefined &&
      head.headers["x-github-api-version"] !== "2026-03-10")
  ) {
    return undefined;
  }
  const json = parseUnambiguousJson(new TextDecoder("utf-8", { fatal: true }).decode(request.body));
  if (
    !json ||
    typeof json !== "object" ||
    Array.isArray(json) ||
    !("maintainer_can_modify" in json) ||
    json.maintainer_can_modify !== false
  ) {
    return undefined;
  }
  const { maintainer_can_modify: _, ...input } = json as Record<string, unknown>;
  // The ordinary broker canonicalizes. This authorizer cannot change bytes: require exactly
  // that canonical result, including the explicit restriction on maintainer modifications.
  const headers: Record<string, string> = { ...head.headers, "x-oce-operation-id": randomUUID() };
  delete headers["x-github-api-version"];
  let scope: PreparedGitHubPullScope | undefined;
  const plan = planDraftPull(
    { ...head, headers },
    {
      apiOrigin,
      repository: binding.repository,
      repositoryId: binding.repositoryId,
      head: binding.pushRef.slice("refs/heads/".length),
      base: binding.pullRequestBase,
    },
    (_plan, selected) => {
      scope = selected;
    },
  );
  if ("kind" in plan) {
    return undefined;
  }
  const verdict = plan.inputPolicy?.(Buffer.from(JSON.stringify(input)));
  return verdict &&
    typeof verdict === "object" &&
    "body" in verdict &&
    Buffer.from(verdict.body).equals(Buffer.from(request.body))
    ? scope
    : undefined;
}

type Selection =
  | { readonly selected: Pick<PreparedGitHubUseRequest, "operation" | "pull"> }
  | { readonly denied: OpenShellOnlineGitDenialReason };

function operation(
  request: OpenShellOnlineHttpRequest,
  binding: OpenShellOnlineGitBinding,
  head: RequestHead,
): Selection {
  if (request.target.path.startsWith("/repos/")) {
    if (head.contentEncoding !== "identity") {
      return { denied: "encoding_unsupported" };
    }
    const pull = draftScope(request, binding, head);
    return pull
      ? { selected: { operation: "create-draft-pull", pull } }
      : { denied: "draft_rejected" };
  }
  if (
    !matchesOrigin(binding.gitOrigin ?? "https://github.com", request) ||
    head.headers["x-github-api-version"] !== undefined
  ) {
    return { denied: "origin_mismatch" };
  }
  const route = classifyRoute(head, {
    repository: binding.repository,
    profile: "git-ref-write",
    targetBytes: 8192,
    graphql: "deny",
  });
  if (!route || route.kind === "api") {
    return { denied: "route_unsupported" };
  }
  // Git gzips upload-pack bodies over 1024 bytes. That body is opaque here (only its size is
  // bounded, and the digest binds the encoded bytes), so gzip is admitted there alone. Discovery
  // has no body; receive-pack and draft create bodies are inspected, so they stay identity.
  if (head.contentEncoding !== "identity" && route.kind !== "git-fetch") {
    return { denied: "encoding_unsupported" };
  }
  if (route.kind === "git-discovery") {
    if (request.body.byteLength !== 0 || head.headers["content-type"] !== undefined) {
      return { denied: "discovery_body" };
    }
    return {
      selected: {
        operation: route.effect === "write" ? "advertise-receive-pack" : "advertise-upload-pack",
      },
    };
  }
  if (!request.body.byteLength) {
    return { denied: "body_empty" };
  }
  if (route.kind === "git-fetch") {
    // Never parse or trust this body: it may be gzip, and the upstream decides what it means.
    return request.body.byteLength <= 1024 * 1024
      ? { selected: { operation: "upload-pack" } }
      : { denied: "body_too_large" };
  }
  return allowsReceivePackInput([binding.pushRef])(request.body) === true
    ? { selected: { operation: "receive-pack" } }
    : { denied: "ref_not_allowed" };
}

/** Authorize the stock sender's inspected request. The worker separately verifies installation
 * and delivers material; an allow here records possible use, never a successful send. */
export function createOpenShellOnlineGitAuthority(
  options: OpenShellOnlineGitAuthorityOptions,
): Server {
  if (typeof options.lookupBinding !== "function" || typeof options.approve !== "function") {
    throw new Error("OpenShell Git requires live binding and durable approval owners.");
  }
  return createOpenShellOnlineHttpAuthority({
    ...options,
    async authorize(request, signal) {
      const { sandboxId, bindingId, requestId, workspace } = request;
      const binding = await options.lookupBinding(
        { sandboxId, bindingId, requestId, workspace },
        signal,
      );
      if (!binding) {
        return "deny";
      }
      const deny = (
        reason: OpenShellOnlineGitDenialReason,
        selected?: PreparedGitHubUseRequest["operation"],
      ): "deny" => {
        options.onDeny?.({
          reason,
          sandboxId,
          requestId,
          revisionId: binding.executionId,
          ...(selected === undefined ? {} : { operation: selected }),
        });
        return "deny";
      };
      if (signal.aborted) {
        return deny("aborted");
      }
      if (!validBinding(binding, request)) {
        return deny("binding_mismatch");
      }
      const head = requestHead(request);
      if (!head) {
        return deny("request_invalid");
      }
      const selection = operation(request, binding, head);
      if ("denied" in selection) {
        return deny(selection.denied);
      }
      const { selected } = selection;
      if (signal.aborted) {
        return deny("aborted", selected.operation);
      }
      const { sessionId, providerInstanceId, repositoryId, grantId, pushRef, executionId } =
        binding;
      // Bind the authenticated mapping and the full inspected view. Do not accept a caller's
      // digest or confuse this normalized-view digest with an exact original-wire commitment.
      const requestDigestSha256 = createHash("sha256")
        .update(
          JSON.stringify([
            "openshell-git-v1",
            sandboxId,
            bindingId,
            requestId,
            workspace,
            executionId,
            sessionId,
            providerInstanceId,
            repositoryId,
            grantId,
            pushRef,
            request.target,
            request.headers,
          ]),
        )
        .update(Buffer.from([0]))
        .update(request.body)
        .digest("hex");
      let allowed: boolean | "draft_already_opened";
      try {
        allowed = await options.approve(
          {
            sessionId,
            providerInstanceId,
            repositoryId,
            grantId,
            pushRef,
            ...selected,
            exchangeId: randomUUID(),
            requestDigestSha256,
            deadlineAt: request.deadlineAt,
          },
          {
            preparationAttemptId: binding.installed.preparationAttemptId,
            materialVersion: binding.installed.materialVersion,
          },
          signal,
        );
      } catch {
        // The owner did not answer; nothing was recorded as possible use, so deny.
        return deny("approval_failed", selected.operation);
      }
      if (allowed === "draft_already_opened") {
        if (signal.aborted) {
          return deny("aborted", selected.operation);
        }
        // The grant's one draft create was already used (finding 2147). The helper says so
        // instead of the generic refusal; nothing about the earlier draft is disclosed.
        deny("draft_already_opened", selected.operation);
        return { reasonCode: "draft_already_opened" };
      }
      if (allowed !== true) {
        return deny("approval_denied", selected.operation);
      }
      return signal.aborted ? deny("aborted", selected.operation) : "allow";
    },
  });
}
