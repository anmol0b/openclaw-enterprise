/** JSON.parse discards duplicate members. Refuse them before selecting a model or
 * releasing original response bytes, since peers may disagree about the winning value. */
export function parseUnambiguousJson(text: string): unknown {
  const parsed: unknown = JSON.parse(text);
  const stack: { keys: Set<string> | undefined; expectingKey: boolean }[] = [];
  for (const [token] of text.matchAll(/"(?:\\.|[^"\\])*"|[{}[\],:]/gs)) {
    if (token === "{" || token === "[") {
      stack.push({ keys: token === "{" ? new Set() : undefined, expectingKey: token === "{" });
    } else if (token === "}" || token === "]") {
      stack.pop();
    } else {
      const frame = stack.at(-1);
      if (frame?.keys && token === ",") {
        frame.expectingKey = true;
      } else if (frame?.keys && frame.expectingKey && token.startsWith('"')) {
        const key: string = JSON.parse(token);
        if (frame.keys.has(key)) {
          throw new Error("Ambiguous JSON members are unsupported.");
        }
        frame.keys.add(key);
        frame.expectingKey = false;
      }
    }
  }
  return parsed;
}
