import { asRecord } from "@openclaw-enterprise/utils";
import { parseUnambiguousJson } from "../repo/credentials/json-members.ts";

// Closed provider-owned schemas. Local tool schemas describe data for the Harness;
// provider-executed tools and remote references require a different admitted grant.
type Validator = (value: unknown) => boolean;
const text: Validator = (value) => typeof value === "string" && value.length <= 1024 * 1024;
const name: Validator = (value) =>
  typeof value === "string" && /^[a-zA-Z0-9_.:-]{1,256}$/.test(value);
const bool: Validator = (value) => typeof value === "boolean";
const number: Validator = (value) => typeof value === "number" && Number.isFinite(value);
const integer: Validator = (value) =>
  number(value) && Number.isSafeInteger(value) && Number(value) >= 0;
const oneOf =
  (...values: readonly unknown[]): Validator =>
  (value) =>
    values.includes(value);
const nullable =
  (check: Validator): Validator =>
  (value) =>
    value === null || check(value);
const array =
  (check: Validator, maximum = 4096): Validator =>
  (value) =>
    Array.isArray(value) && value.length <= maximum && value.every(check);
const object =
  (fields: Readonly<Record<string, Validator>>, required: readonly string[] = []): Validator =>
  (value) => {
    const record = asRecord(value);
    return (
      record !== undefined &&
      required.every((key) => Object.hasOwn(record, key)) &&
      Object.entries(record).every(
        ([key, item]) => Object.hasOwn(fields, key) && fields[key]!(item),
      )
    );
  };

function jsonValue(value: unknown, depth = 0): boolean {
  if (depth > 32) {
    return false;
  }
  if (value === null || typeof value === "boolean" || text(value) || number(value)) {
    return true;
  }
  if (Array.isArray(value)) {
    return value.length <= 1024 && value.every((item) => jsonValue(item, depth + 1));
  }
  const record = asRecord(value);
  return (
    record !== undefined &&
    Object.keys(record).length <= 256 &&
    Object.values(record).every((item) => jsonValue(item, depth + 1))
  );
}

function jsonSchema(value: unknown, depth = 0): boolean {
  if (depth > 16) {
    return false;
  }
  const nested = (item: unknown) => jsonSchema(item, depth + 1);
  const definitions: Validator = (item) => {
    const record = asRecord(item);
    return (
      record !== undefined &&
      Object.keys(record).length <= 256 &&
      Object.entries(record).every(([key, schema]) => text(key) && nested(schema))
    );
  };
  const type = oneOf("object", "array", "string", "number", "integer", "boolean", "null");
  return object({
    type: (item) => type(item) || array(type, 7)(item),
    properties: definitions,
    required: array(text, 256),
    additionalProperties: (item) => bool(item) || nested(item),
    items: nested,
    anyOf: array(nested, 64),
    oneOf: array(nested, 64),
    allOf: array(nested, 64),
    enum: array((item) => jsonValue(item), 1024),
    const: (item) => jsonValue(item),
    description: text,
    title: text,
    default: (item) => jsonValue(item),
    minimum: number,
    maximum: number,
    exclusiveMinimum: number,
    exclusiveMaximum: number,
    multipleOf: (item) => number(item) && Number(item) > 0,
    minLength: integer,
    maxLength: integer,
    minItems: integer,
    maxItems: integer,
    minProperties: integer,
    maxProperties: integer,
    uniqueItems: bool,
    pattern: text,
    format: text,
    $defs: definitions,
    $ref: (item) => typeof item === "string" && /^#\/\$defs\/[a-zA-Z0-9_.-]+$/.test(item),
    $schema: oneOf(
      "https://json-schema.org/draft/2020-12/schema",
      "http://json-schema.org/draft-07/schema#",
    ),
  })(value);
}

const functionTool = object(
  {
    type: oneOf("function"),
    name,
    description: text,
    parameters: jsonSchema,
    strict: bool,
    defer_loading: bool,
  },
  ["type", "name", "parameters"],
);
const customTool = object(
  {
    type: oneOf("custom"),
    name,
    description: text,
    defer_loading: bool,
    format: (value) =>
      object({ type: oneOf("text") }, ["type"])(value) ||
      object(
        {
          type: oneOf("grammar"),
          syntax: oneOf("lark", "regex"),
          definition: text,
        },
        ["type", "syntax", "definition"],
      )(value),
  },
  ["type", "name"],
);
const localTool: Validator = (value) => functionTool(value) || customTool(value);
const tool: Validator = (value) =>
  localTool(value) ||
  object(
    {
      type: oneOf("namespace"),
      name,
      description: text,
      tools: array(localTool, 128),
    },
    ["type", "name", "tools"],
  )(value);
const content: Validator = (value) =>
  object({ type: oneOf("input_text", "output_text"), text }, ["type", "text"])(value);
const status = oneOf("in_progress", "completed", "incomplete");
const summary = object({ type: oneOf("summary_text"), text }, ["type", "text"]);
const inputItem: Validator = (value) => {
  const item = asRecord(value);
  if (!item) {
    return false;
  }
  if (item.type === undefined || item.type === "message") {
    return object(
      {
        type: oneOf("message"),
        id: text,
        role: oneOf("system", "developer", "user", "assistant"),
        content: (part) => text(part) || array(content)(part),
        phase: oneOf("commentary", "partial_answer", "final_answer"),
        status,
      },
      ["role", "content"],
    )(item);
  }
  if (item.type === "reasoning") {
    return object(
      {
        type: oneOf("reasoning"),
        id: text,
        summary: array(summary),
        content: array(object({ type: oneOf("reasoning_text"), text }, ["type", "text"])),
        encrypted_content: nullable(text),
        status,
      },
      ["type", "summary"],
    )(item);
  }
  if (item.type === "function_call" || item.type === "custom_tool_call") {
    return object(
      {
        type: oneOf(item.type),
        id: text,
        call_id: text,
        name,
        namespace: name,
        ...(item.type === "function_call" ? { arguments: text } : { input: text }),
        status,
      },
      ["type", "call_id", "name", item.type === "function_call" ? "arguments" : "input"],
    )(item);
  }
  return object(
    {
      type: oneOf("function_call_output", "custom_tool_call_output"),
      id: text,
      call_id: text,
      name,
      namespace: name,
      output: (part) => text(part) || array(content)(part),
    },
    ["type", "call_id", "output"],
  )(item);
};

const reasoning = object({
  effort: oneOf("none", "minimal", "low", "medium", "high", "xhigh"),
  summary: oneOf("auto", "concise", "detailed"),
  context: oneOf("auto", "current_turn", "all_turns"),
});

const metadataText: Validator = (value) => typeof value === "string" && value.length <= 8192;
// These are telemetry fields emitted by the selected client, never OCC identities or grants.
const clientMetadata = object({
  session_id: metadataText,
  thread_id: metadataText,
  turn_id: metadataText,
  parent_turn_id: metadataText,
  root_turn_id: metadataText,
  "x-codex-installation-id": metadataText,
  "x-codex-window-id": metadataText,
  "x-codex-parent-thread-id": metadataText,
  "x-openai-subagent": metadataText,
  "x-codex-turn-metadata": (value) => {
    if (!metadataText(value)) {
      return false;
    }
    try {
      return object({
        installation_id: metadataText,
        session_id: metadataText,
        thread_id: metadataText,
        agent_name: metadataText,
        turn_id: metadataText,
        window_id: metadataText,
        window_number: integer,
        context_window_id: metadataText,
        request_kind: oneOf("turn", "prewarm", "compaction", "memory"),
        history_initialization: metadataText,
        root_turn_id: metadataText,
        parent_turn_id: metadataText,
        parent_thread_id: metadataText,
        forked_from_thread_id: metadataText,
        forked_from_ordinal_exclusive: integer,
        thread_source: metadataText,
        turn_trigger: metadataText,
        subagent_kind: metadataText,
        sandbox: metadataText,
        sandbox_mode: metadataText,
        auto_review_enabled: bool,
        node_repl_auto_review_required: bool,
        node_repl_disabled: bool,
        turn_started_at_unix_ms: integer,
        analytics_enabled: bool,
        history_ingest_requested: bool,
        model: metadataText,
      })(parseUnambiguousJson(String(value)));
    } catch {
      return false;
    }
  },
});
const textFormat: Validator = (value) =>
  object({ type: oneOf("text") }, ["type"])(value) ||
  object(
    { type: oneOf("json_schema"), name, description: text, strict: bool, schema: jsonSchema },
    ["type", "name", "schema"],
  )(value);

export function validResponsesRequest(body: Record<string, unknown>): boolean {
  return object(
    {
      model: text,
      instructions: text,
      input: (value) => text(value) || array(inputItem)(value),
      tools: array(tool, 128),
      tool_choice: oneOf("auto", "none", "required"),
      parallel_tool_calls: bool,
      reasoning: nullable(reasoning),
      store: oneOf(false),
      stream: bool,
      stream_options: object({
        include_usage: bool,
        include_obfuscation: bool,
        reasoning_summary_delivery: oneOf("sequential_cutoff"),
      }),
      include: array(oneOf("reasoning.encrypted_content"), 1),
      service_tier: oneOf("auto", "default", "flex", "priority"),
      prompt_cache_key: text,
      client_metadata: clientMetadata,
      text: object({ verbosity: oneOf("low", "medium", "high"), format: textFormat }),
      temperature: (value) => number(value) && Number(value) >= 0 && Number(value) <= 2,
      top_p: (value) => number(value) && Number(value) >= 0 && Number(value) <= 1,
      max_output_tokens: (value) => integer(value) && Number(value) > 0,
    },
    ["model", "input", "store"],
  )(body);
}

const outputContent = object(
  {
    type: oneOf("output_text"),
    text,
    annotations: array(() => false, 0),
    logprobs: array(() => false, 0),
  },
  ["type", "text"],
);
const outputItem: Validator = (value) =>
  object(
    {
      type: oneOf("message"),
      id: text,
      role: oneOf("assistant"),
      status,
      content: array(outputContent),
      phase: oneOf("commentary", "partial_answer", "final_answer"),
    },
    ["type", "id", "role", "content"],
  )(value) ||
  (asRecord(value)?.type !== "message" &&
    inputItem(value) &&
    ["reasoning", "function_call", "custom_tool_call"].includes(String(asRecord(value)?.type)));
const usage = object(
  {
    input_tokens: integer,
    output_tokens: integer,
    total_tokens: integer,
    input_tokens_details: object({ cached_tokens: integer }),
    output_tokens_details: object({ reasoning_tokens: integer }),
  },
  ["input_tokens", "output_tokens", "total_tokens"],
);
const error = object({ code: nullable(text), message: text, type: text, param: nullable(text) }, [
  "message",
]);
const response = object(
  {
    id: text,
    object: oneOf("response"),
    created_at: number,
    completed_at: nullable(number),
    status: oneOf("in_progress", "completed", "failed", "incomplete", "cancelled", "queued"),
    model: text,
    output: array(outputItem),
    usage: nullable(usage),
    error: nullable(error),
    incomplete_details: nullable(
      object({ reason: oneOf("max_output_tokens", "content_filter") }, ["reason"]),
    ),
    instructions: nullable(text),
    tools: array(tool, 128),
    tool_choice: oneOf("auto", "none", "required"),
    parallel_tool_calls: bool,
    reasoning: object({ effort: nullable(text), summary: nullable(text) }),
    store: bool,
    background: oneOf(false),
    service_tier: text,
    temperature: nullable(number),
    top_p: nullable(number),
    max_output_tokens: nullable(integer),
    max_tool_calls: nullable(integer),
    text: object({ verbosity: oneOf("low", "medium", "high"), format: textFormat }),
    previous_response_id: oneOf(null),
    prompt_cache_key: nullable(text),
    prompt_cache_retention: nullable(text),
    safety_identifier: nullable(text),
    user: nullable(text),
    truncation: oneOf("disabled", "auto"),
    metadata: object({}),
  },
  ["id", "status", "output"],
);

// The stream needs only this projection of the closed wire shapes checked below.
type ResponseOutputItem =
  | { type: "message"; content: { type: "output_text"; text: string }[] }
  | { type: "reasoning" | "custom_tool_call" }
  | { type: "function_call"; arguments: string };
export type ItemEvent = {
  type: "response.output_item.added" | "response.output_item.done";
  output_index: number;
  item: ResponseOutputItem & { id: string };
};
export type ItemContentEvent = {
  type: string;
  output_index: number;
  item_id: string;
  delta?: string;
  arguments?: string;
  content_index?: number;
  part?: { type: "output_text"; text: string };
};
export type ResponsesEvent = { type: string; sequence_number?: number } & (
  | { response: { id: string; status: string; output: ResponseOutputItem[] } }
  | ItemEvent
  | ItemContentEvent
);

/** Check an individual wire event. Order and completion belong to the stream. */
export function isResponsesEvent(value: unknown, model: string): value is ResponsesEvent {
  const event = asRecord(value);
  if (!event || typeof event.type !== "string") {
    return false;
  }
  const base = { type: oneOf(event.type), sequence_number: integer };
  if (
    [
      "response.created",
      "response.in_progress",
      "response.completed",
      "response.failed",
      "response.incomplete",
    ].includes(event.type)
  ) {
    const envelope = asRecord(event.response);
    return (
      object({ ...base, response }, ["type", "response"])(event) &&
      (envelope?.model === undefined || envelope.model === model) &&
      envelope?.status === event.type.slice("response.".length).replace("created", "in_progress")
    );
  }
  if (["response.output_item.added", "response.output_item.done"].includes(event.type)) {
    return (
      typeof asRecord(event.item)?.id === "string" &&
      object({ ...base, output_index: integer, item: outputItem }, [
        "type",
        "output_index",
        "item",
      ])(event)
    );
  }
  const indexed = { ...base, item_id: text, output_index: integer };
  if (["response.content_part.added", "response.content_part.done"].includes(event.type)) {
    return object({ ...indexed, content_index: integer, part: outputContent }, [
      "type",
      "item_id",
      "output_index",
      "content_index",
      "part",
    ])(event);
  }
  if (
    ["response.reasoning_summary_part.added", "response.reasoning_summary_part.done"].includes(
      event.type,
    )
  ) {
    return object({ ...indexed, summary_index: integer, part: summary }, [
      "type",
      "item_id",
      "output_index",
      "summary_index",
      "part",
    ])(event);
  }
  for (const [prefix, index, field] of [
    ["response.output_text", "content_index", "text"],
    ["response.reasoning_text", "content_index", "text"],
    ["response.reasoning_summary_text", "summary_index", "text"],
    ["response.function_call_arguments", undefined, "arguments"],
    ["response.custom_tool_call_input", undefined, "input"],
  ] as const) {
    const isDelta = event.type === `${prefix}.delta`;
    if (isDelta || event.type === `${prefix}.done`) {
      const dataField = isDelta ? "delta" : field;
      return object(
        {
          ...indexed,
          ...(index === undefined ? {} : { [index]: integer }),
          [dataField]: text,
          ...(prefix === "response.output_text" ? { logprobs: array(() => false, 0) } : {}),
          ...(isDelta ? { obfuscation: text } : {}),
        },
        ["type", "item_id", "output_index", dataField, ...(index === undefined ? [] : [index])],
      )(event);
    }
  }
  return false;
}
