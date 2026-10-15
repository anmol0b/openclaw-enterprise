import { asRecord } from "@openclaw-enterprise/utils";
import { parseUnambiguousJson } from "./openai-json.ts";
import {
  isResponsesEvent,
  type ItemContentEvent,
  type ItemEvent,
  type ResponsesEvent,
} from "./openai-responses.ts";

type Scan = (value: unknown) => boolean;

interface ResponseProtection {
  scan: Scan;
  leaked: (text: string) => boolean;
  fragmentOverlap: number;
}

// Decode exactly the JSON layer defined for function arguments. Strings inside
// that object remain strings; this is not a general-purpose encoding decoder.
const maximumArgumentBytes = 1024 * 1024;
function protectedArguments(text: string, scan: Scan): boolean {
  if (Buffer.byteLength(text) > maximumArgumentBytes) {
    return false;
  }
  const argumentsObject = asRecord(parseUnambiguousJson(text));
  return argumentsObject !== undefined && scan(argumentsObject);
}

export function protectedResponseOutput(value: unknown, scan: Scan): boolean {
  const output = asRecord(value)?.output;
  return (
    !Array.isArray(output) ||
    output.every((entry: unknown) => {
      const item = asRecord(entry);
      return (
        item?.type !== "function_call" ||
        (typeof item.arguments === "string" && protectedArguments(item.arguments, scan))
      );
    })
  );
}

/** Inspect the entire bounded response before the provider releases its original bytes. */
export function protectedResponsesStream(
  body: string,
  model: string,
  policy: ResponseProtection,
): boolean {
  const stream = new ResponsesStream(policy);
  let eventCount = 0;
  for (const { name, data } of eventFrames(body)) {
    if (++eventCount > 16_384) {
      return false;
    }
    const event = parseUnambiguousJson(data);
    if (
      !isResponsesEvent(event, model) ||
      (name !== undefined && name !== event.type) ||
      !policy.scan(event) ||
      !stream.accept(event)
    ) {
      return false;
    }
  }
  return stream.complete;
}

// Only comments, event and data fields are admitted. Unlike a browser EventSource,
// never discard an unknown field or unfinished frame, or accept a bare carriage return.
function* eventFrames(body: string): Generator<{ name: string | undefined; data: string }> {
  if (!body.endsWith("\n\n") && !body.endsWith("\n\r\n")) {
    throw new Error("Expected a complete Responses event frame.");
  }
  let name: string | undefined;
  const data: string[] = [];
  let start = 0;
  let hasField = false;
  while (start < body.length) {
    const end = body.indexOf("\n", start);
    const line = body.slice(start, end).replace(/\r$/, "");
    start = end + 1;
    if (line.includes("\r")) {
      throw new Error("Unexpected carriage return in Responses event.");
    }
    if (line === "") {
      if (!hasField) {
        throw new Error("Unexpected empty Responses event frame.");
      }
      if (data.length > 0) {
        yield { name, data: data.join("\n") };
      } else if (name !== undefined) {
        throw new Error("Responses event has a name but no data.");
      }
      name = undefined;
      data.length = 0;
    } else if (line.startsWith("data:")) {
      data.push(line.slice(5).replace(/^ /, ""));
    } else if (line.startsWith("event:") && name === undefined) {
      name = line.slice(6).replace(/^ /, "");
    } else if (!line.startsWith(":")) {
      throw new Error("Unsupported Responses event field.");
    }
    hasField = line !== "";
  }
}

interface TrackedItem {
  id: string;
  type: ItemEvent["item"]["type"];
  done: boolean;
  argumentDeltas: string[];
  argumentBytes: number;
  completedArguments?: string;
}

class ResponsesStream {
  private readonly policy: ResponseProtection;
  private readonly items = new Map<number, TrackedItem>();
  private readonly itemIds = new Set<string>();
  private readonly fragments = new Map<string, string>();
  private responseId?: string;
  private sequence = -1;
  private terminal = false;

  constructor(policy: ResponseProtection) {
    this.policy = policy;
  }

  get complete(): boolean {
    return this.terminal && [...this.items.values()].every((item) => item.done);
  }

  accept(event: ResponsesEvent): boolean {
    if (
      this.terminal ||
      (event.sequence_number !== undefined && event.sequence_number <= this.sequence)
    ) {
      return false;
    }
    this.sequence = event.sequence_number ?? this.sequence;
    if ("response" in event) {
      const { id, status } = event.response;
      if (this.responseId !== undefined && id !== this.responseId) {
        return false;
      }
      this.responseId = id;
      // The closed event schema binds the event name to this exact response status.
      this.terminal = status === "completed" || status === "failed" || status === "incomplete";
      return protectedResponseOutput(event.response, this.policy.scan);
    }
    return "item" in event ? this.outputItem(event) : this.itemContent(event);
  }

  private outputItem({ type, output_index, item }: ItemEvent): boolean {
    const tracked = this.items.get(output_index);
    if (type === "response.output_item.added") {
      if (tracked || this.itemIds.has(item.id) || this.items.size >= 4096) {
        return false;
      }
      this.itemIds.add(item.id);
      this.items.set(output_index, {
        id: item.id,
        type: item.type,
        done: false,
        argumentDeltas: [],
        argumentBytes: 0,
      });
      return (
        item.type !== "function_call" ||
        item.arguments === "" ||
        protectedArguments(item.arguments, this.policy.scan)
      );
    }
    if (!tracked || tracked.done || tracked.id !== item.id || tracked.type !== item.type) {
      return false;
    }
    tracked.done = true;
    return (
      item.type !== "function_call" || argumentsMatch(tracked, item.arguments, this.policy.scan)
    );
  }

  private itemContent(event: ItemContentEvent): boolean {
    const item = this.items.get(event.output_index);
    if (!item || item.done || item.id !== event.item_id) {
      return false;
    }
    if (event.delta !== undefined) {
      // Codex exposes output deltas without item IDs. Protect the concatenation the
      // consumer sees, including across two distinct, otherwise valid output items.
      const text = (this.fragments.get(event.type) ?? "") + event.delta;
      if (this.policy.leaked(text)) {
        return false;
      }
      this.fragments.set(event.type, text.slice(-this.policy.fragmentOverlap));
    }
    if (event.type.startsWith("response.function_call_arguments.")) {
      return item.type === "function_call" && acceptArguments(item, event, this.policy.scan);
    }
    if (event.type.startsWith("response.reasoning_")) {
      return item.type === "reasoning";
    }
    if (event.type.startsWith("response.custom_tool_call_input.")) {
      return item.type === "custom_tool_call";
    }
    return item.type === "message";
  }
}

function acceptArguments(item: TrackedItem, event: ItemContentEvent, scan: Scan): boolean {
  if (item.completedArguments !== undefined) {
    return false;
  }
  if (event.delta !== undefined) {
    item.argumentBytes += Buffer.byteLength(event.delta);
    if (item.argumentBytes > maximumArgumentBytes) {
      return false;
    }
    item.argumentDeltas.push(event.delta);
    return true;
  }
  if (event.arguments === undefined || !argumentsMatch(item, event.arguments, scan)) {
    return false;
  }
  item.completedArguments = event.arguments;
  return true;
}

// A snapshot may arrive with no deltas, or the argument .done event may be omitted.
// Decode the exact arguments assembled by the consumer and require snapshots to agree.
function argumentsMatch(item: TrackedItem, text: string, scan: Scan): boolean {
  if (item.completedArguments !== undefined) {
    return text === item.completedArguments;
  }
  return (
    (item.argumentDeltas.length === 0 || text === item.argumentDeltas.join("")) &&
    protectedArguments(text, scan)
  );
}
