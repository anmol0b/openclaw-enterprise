import type {
  CredentialProviderDefinition,
  EgressRequest,
  EgressResponse,
  InferenceOperation,
} from "@openclaw-enterprise/contracts";
import { asRecord, immutableCopy } from "@openclaw-enterprise/utils";
import { normalizeOpenAiBaseUrl } from "../openai-endpoint.ts";
import { validResponsesRequest, validResponsesEvent } from "./openai-responses.ts";
import { parseUnambiguousJson } from "./openai-json.ts";

const maximumResponseBytes = 4 * 1024 * 1024;

function jsonRequest(request: EgressRequest): Record<string, unknown> | undefined {
  const headers = request.headers;
  if (headers.length > 64 || headers.some(([name, value]) => /[\r\n\0]/.test(name + value))) {
    return undefined;
  }
  const types = headers.filter(([name]) => name.toLowerCase() === "content-type");
  if (types.length !== 1 || !/^application\/json(?:;\s*charset=utf-8)?$/i.test(types[0]![1])) {
    return undefined;
  }
  if (
    headers.some(([name]) =>
      [
        "content-encoding",
        "transfer-encoding",
        "upgrade",
        "proxy-authorization",
        "x-oce-binding",
      ].includes(name.toLowerCase()),
    )
  ) {
    return undefined;
  }
  try {
    return asRecord(
      parseUnambiguousJson(new TextDecoder("utf-8", { fatal: true }).decode(request.body)),
    );
  } catch {
    return undefined;
  }
}

function protectedResponse(
  response: EgressResponse,
  credential: string,
  request: EgressRequest,
  operation: InferenceOperation,
): EgressResponse | undefined {
  if (
    response.status < 200 ||
    response.status >= 600 ||
    (response.status >= 300 && response.status < 400) ||
    response.body.byteLength > maximumResponseBytes
  ) {
    return undefined;
  }
  const types = response.headers.filter(([name]) => name.toLowerCase() === "content-type");
  const mediaType = types[0]?.[1];
  const streaming = jsonRequest(request)?.stream === true;
  const sse = streaming && /^text\/event-stream(?:;\s*charset=utf-8)?$/i.test(mediaType ?? "");
  if (
    types.length !== 1 ||
    !(
      sse ||
      (/^application\/json(?:;\s*charset=utf-8)?$/i.test(mediaType ?? "") &&
        (!streaming || response.status >= 400))
    ) ||
    response.headers.length > 64 ||
    response.headers.some(([name, value]) => /[\r\n\0]/.test(name + value)) ||
    response.headers.some(([name]) =>
      ["content-encoding", "trailer", "upgrade"].includes(name.toLowerCase()),
    )
  ) {
    return undefined;
  }
  try {
    const body = new TextDecoder("utf-8", { fatal: true }).decode(response.body);
    const encodings = [
      credential,
      encodeURIComponent(credential),
      Buffer.from(credential).toString("base64"),
      Buffer.from(credential).toString("base64url"),
    ];
    const leaked = (value: unknown): boolean =>
      typeof value === "string" && encodings.some((candidate) => value.includes(candidate));
    // Keep parsed-string scans bounded, including decoded data split across SSE deltas.
    const scan = (root: unknown): boolean => {
      const pending = [{ value: root, depth: 0 }];
      let nodes = 0;
      while (pending.length) {
        const { value, depth } = pending.pop()!;
        if (++nodes > 100_000 || depth > 64 || leaked(value)) {
          return false;
        }
        if (value !== null && typeof value === "object") {
          for (const [key, item] of Object.entries(value)) {
            if (leaked(key)) {
              return false;
            }
            pending.push({ value: item, depth: depth + 1 });
          }
        }
      }
      return true;
    };
    // Parse first so JSON escapes cannot hide credential bytes from the response policy.
    if (leaked(body) || response.headers.some(([name, value]) => leaked(name) || leaked(value))) {
      return undefined;
    }
    if (sse) {
      if (
        !protectedEvents(
          body,
          operation.model,
          scan,
          leaked,
          Math.max(...encodings.map((value) => value.length)),
        )
      ) {
        return undefined;
      }
    } else {
      const parsed: unknown = parseUnambiguousJson(body);
      if (!asRecord(parsed) || !scan(parsed) || !protectedResponseOutput(parsed, scan)) {
        return undefined;
      }
    }
    return {
      status: response.status,
      headers: [["content-type", sse ? "text/event-stream" : "application/json"]],
      body: new Uint8Array(response.body),
    };
  } catch {
    return undefined;
  }
}

// Decode exactly the JSON layer defined for function arguments. Strings inside
// that object remain strings; this is not a general-purpose encoding decoder.
function protectedArguments(value: unknown, scan: (value: unknown) => boolean): boolean {
  if (typeof value !== "string" || Buffer.byteLength(value) > 1024 * 1024) {
    return false;
  }
  const parsed = parseUnambiguousJson(value);
  return asRecord(parsed) !== undefined && scan(parsed);
}

function protectedResponseOutput(value: unknown, scan: (value: unknown) => boolean): boolean {
  const output = asRecord(value)?.output;
  return (
    !Array.isArray(output) ||
    output.every(
      (item) =>
        asRecord(item)?.type !== "function_call" || protectedArguments(item.arguments, scan),
    )
  );
}

interface ResponseItemState {
  readonly id: string;
  readonly type: string;
  done: boolean;
  readonly arguments: string[];
  argumentBytes: number;
  argumentsDone: boolean;
}

function protectedEvents(
  body: string,
  model: string,
  scan: (value: unknown) => boolean,
  leaked: (value: unknown) => boolean,
  maximumEncodingLength: number,
): boolean {
  const normalized = body.replaceAll("\r\n", "\n");
  if (normalized.includes("\r") || !normalized.endsWith("\n\n")) {
    return false;
  }
  let terminal = false;
  let responseId: string | undefined;
  let sequence = -1;
  let count = 0;
  const fragments = new Map<string, string>();
  const items = new Map<number, ResponseItemState>();
  const itemIds = new Set<string>();
  for (const block of normalized.split("\n\n")) {
    if (!block) {
      continue;
    }
    let eventName: string | undefined;
    const data: string[] = [];
    for (const line of block.split("\n")) {
      if (line.startsWith(":")) {
        continue;
      }
      if (line.startsWith("event:") && eventName === undefined) {
        eventName = line.slice(6).replace(/^ /, "");
      } else if (line.startsWith("data:")) {
        data.push(line.slice(5).replace(/^ /, ""));
      } else {
        return false;
      }
    }
    if (data.length === 0) {
      if (eventName !== undefined) {
        return false;
      }
      continue;
    }
    // Responses completion is explicit JSON. An opaque terminator is never evidence.
    if (terminal || ++count > 16_384) {
      return false;
    }
    const event = asRecord(parseUnambiguousJson(data.join("\n")));
    if (
      !event ||
      !validResponsesEvent(event, model) ||
      !scan(event) ||
      (eventName !== undefined && eventName !== event.type)
    ) {
      return false;
    }
    if (event.sequence_number !== undefined) {
      if (Number(event.sequence_number) <= sequence) {
        return false;
      }
      sequence = Number(event.sequence_number);
    }
    const response = asRecord(event.response);
    if (response) {
      if (responseId !== undefined && response.id !== responseId) {
        return false;
      }
      responseId = String(response.id);
      if (!protectedResponseOutput(response, scan)) {
        return false;
      }
    }
    const item = asRecord(event.item);
    const outputIndex = Number(event.output_index);
    if (event.type === "response.output_item.added") {
      if (
        typeof item?.id !== "string" ||
        items.has(outputIndex) ||
        itemIds.has(item.id) ||
        items.size >= 4096
      ) {
        return false;
      }
      itemIds.add(item.id);
      items.set(outputIndex, {
        id: item.id,
        type: String(item.type),
        done: false,
        arguments: [],
        argumentBytes: 0,
        argumentsDone: false,
      });
      if (
        item.type === "function_call" &&
        item.arguments !== "" &&
        !protectedArguments(item.arguments, scan)
      ) {
        return false;
      }
    } else if (event.output_index !== undefined) {
      const state = items.get(outputIndex);
      if (!state || state.done || (item?.id ?? event.item_id) !== state.id) {
        return false;
      }
      if (event.type === "response.output_item.done") {
        if (
          item?.type !== state.type ||
          (state.type === "function_call" &&
            (!protectedArguments(item.arguments, scan) ||
              (state.arguments.length > 0 && state.arguments.join("") !== item.arguments)))
        ) {
          return false;
        }
        state.done = true;
      } else if (String(event.type).startsWith("response.function_call_arguments.")) {
        if (state.type !== "function_call" || state.argumentsDone) {
          return false;
        }
        if (typeof event.delta === "string") {
          state.argumentBytes += Buffer.byteLength(event.delta);
          if (state.argumentBytes > 1024 * 1024) {
            return false;
          }
          state.arguments.push(event.delta);
        } else {
          const accumulated = state.arguments.join("");
          if (
            !protectedArguments(event.arguments, scan) ||
            (state.arguments.length > 0 &&
              (!protectedArguments(accumulated, scan) || accumulated !== event.arguments))
          ) {
            return false;
          }
          state.argumentsDone = true;
        }
      } else {
        let expectedType = "message";
        if (String(event.type).startsWith("response.reasoning_")) {
          expectedType = "reasoning";
        } else if (String(event.type).startsWith("response.custom_tool_call_input.")) {
          expectedType = "custom_tool_call";
        }
        if (state.type !== expectedType) {
          return false;
        }
      }
    }
    if (typeof event.delta === "string") {
      // The selected Codex consumer emits OutputTextDelta(delta), dropping item
      // IDs. Scan that observable concatenation even across valid item lifecycles.
      const key = String(event.type);
      const joined = (fragments.get(key) ?? "") + event.delta;
      if (leaked(joined)) {
        return false;
      }
      // Retain only a possible cross-event prefix, avoiding quadratic growth on long streams.
      fragments.set(key, joined.slice(-Math.max(1, maximumEncodingLength - 1)));
    }
    terminal = ["response.completed", "response.failed", "response.incomplete"].includes(
      String(event.type),
    );
  }
  // Complete accumulated arguments must be decoded even if a provider omitted
  // their .done event or supplied a different terminal snapshot.
  return (
    terminal &&
    [...items.values()].every(
      (item) =>
        item.done &&
        (item.arguments.length === 0 || protectedArguments(item.arguments.join(""), scan)),
    )
  );
}

/** Bounded inference with Harness-local tools and complete finite Responses SSE custody. */
export const openAiStaticProvider: CredentialProviderDefinition =
  Object.freeze<CredentialProviderDefinition>({
    ref: { id: "openai-static-https", generation: 1 },
    schemaVersion: 1,
    sourceType: {
      type: "openai",
      config: [{ name: "base_url", required: false }],
      secrets: [{ name: "api_key", required: true }],
      rotation: "external",
      harnessAuth: { modelProvider: "openai", loginMode: "api_key" },
    },
    normalizeConfig(config) {
      if (Object.keys(config).some((field) => field !== "base_url")) {
        throw new Error("Unsupported inference source configuration.");
      }
      const baseUrl = normalizeOpenAiBaseUrl(config.base_url ?? "https://api.openai.com/v1");
      if (!baseUrl) {
        throw new Error("Unsupported inference source endpoint.");
      }
      return { base_url: baseUrl };
    },
    normalizeGrant(models) {
      if (models.length !== 1 || !models[0] || models[0].length > 256) {
        throw new Error("Protected inference requires one explicit model.");
      }
      return immutableCopy({ kind: "inference", models, providerTools: "none" });
    },
    routes(source, binding) {
      const base = new URL(this.normalizeConfig(source.config).base_url!);
      return ["responses", "chat/completions"].map((operation) =>
        immutableCopy({
          route: {
            id: `${binding.binding.id}/${operation}`,
            generation: binding.binding.generation,
          },
          binding,
          origin: base.origin,
          path: `${base.pathname}/${operation}`,
          method: "POST" as const,
          operationPolicy: { id: "openai-bounded-inference", generation: 1 },
          responsePolicy: { id: "openai-bounded-response", generation: 1 },
          deadlineMs: 30_000,
        }),
      );
    },
    classify(route, request) {
      let url: URL;
      try {
        url = new URL(request.url);
      } catch {
        return undefined;
      }
      if (
        url.href !== request.url ||
        url.protocol !== "https:" ||
        url.username ||
        url.password ||
        url.search ||
        url.hash ||
        request.method !== route.method ||
        url.origin !== route.origin ||
        url.pathname !== route.path
      ) {
        return undefined;
      }
      const body = jsonRequest(request);
      if (
        !body ||
        typeof body.model !== "string" ||
        route.binding.grant.providerTools !== "none" ||
        !route.binding.grant.models.includes(body.model) ||
        (body.store !== undefined && body.store !== false)
      ) {
        return undefined;
      }
      const responseApi = route.path.endsWith("/responses");
      if (responseApi) {
        return validResponsesRequest(body)
          ? { kind: "inference", action: "generate", model: body.model }
          : undefined;
      }
      if (body.stream !== undefined && body.stream !== false) {
        return undefined;
      }
      const allowed = new Set([
        "model",
        "stream",
        "store",
        "temperature",
        "top_p",
        "messages",
        "max_completion_tokens",
      ]);
      if (Object.keys(body).some((key) => !allowed.has(key))) {
        return undefined;
      }
      for (const key of ["temperature", "top_p", "max_completion_tokens"]) {
        if (
          body[key] !== undefined &&
          (typeof body[key] !== "number" || !Number.isFinite(body[key]) || body[key] < 0)
        ) {
          return undefined;
        }
      }
      if (
        !Array.isArray(body.messages) ||
        body.messages.length === 0 ||
        body.messages.length > 128 ||
        body.messages.some((message) => {
          const item = asRecord(message);
          return (
            !item ||
            Object.keys(item).some((key) => key !== "role" && key !== "content") ||
            !["system", "user", "assistant"].includes(String(item.role)) ||
            typeof item.content !== "string"
          );
        })
      ) {
        return undefined;
      }
      return { kind: "inference", action: "generate", model: body.model };
    },
    inject(value) {
      if (value.length < 8 || value.length > 8192 || /[^\x21-\x7e]/.test(value)) {
        throw new Error("Static inference credential format is unsupported.");
      }
      return [["authorization", `Bearer ${value}`]];
    },
    credentialRejected(response) {
      if (
        response.status !== 401 ||
        response.body.byteLength > maximumResponseBytes ||
        response.headers.filter(([name]) => name.toLowerCase() === "content-type").length !== 1 ||
        !response.headers.some(
          ([name, value]) =>
            name.toLowerCase() === "content-type" &&
            /^application\/json(?:;\s*charset=utf-8)?$/i.test(value),
        ) ||
        response.headers.some(([name]) => name.toLowerCase() === "content-encoding")
      ) {
        return false;
      }
      try {
        const body = asRecord(
          parseUnambiguousJson(new TextDecoder("utf-8", { fatal: true }).decode(response.body)),
        );
        const error = asRecord(body?.error);
        return error?.code === "invalid_api_key" && error.type === "invalid_request_error";
      } catch {
        return false;
      }
    },
    protectResponse: protectedResponse,
  });
