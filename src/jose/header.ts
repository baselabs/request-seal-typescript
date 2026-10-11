import { byteString, decodeBase64Url, encodeBase64Url } from "../bytes.ts";
import { decodeUtf8, encodeUtf8 } from "../runtime.ts";
import {
  decodeJson,
  encodeJson,
  type JsonNode,
  type JsonObject,
} from "../json.ts";
import { deepFreeze } from "../brand.ts";
import { JOSE_MAX_COMPACT_BYTES, JSON_LIMITS } from "../constants.ts";
import {
  joseError,
  isRequestSealError,
  type JoseError,
} from "../errors/types.ts";
import { err, ok, type Result } from "../result.ts";
/** An ordered JOSE protected-header sequence of JSON members. */
export type Header = readonly (readonly [string, JsonNode])[];
export function fail(
  reason: JoseError["reason"],
  layer: JoseError["layer"] = "input",
): never {
  throw joseError(reason, layer);
}
export function need(
  value: unknown,
  reason: JoseError["reason"],
  layer: JoseError["layer"] = "input",
): asserts value {
  if (!value) fail(reason, layer);
}
export function take<T>(r: Result<T>): T {
  if (!r.ok) throw r.error;
  return r.value;
}
export function safe<T>(fn: () => T): Result<T> {
  try {
    return ok(fn());
  } catch (e) {
    return err(
      isRequestSealError(e) && e.kind === "jose"
        ? e
        : joseError("invalid_header", "input"),
    );
  }
}
export function headerValue(h: Header, key: string): JsonNode | undefined {
  return h.find((p) => p[0] === key)?.[1];
}
// Small reference maps enumerate binary keys in UTF-8 order. Larger maps use
// a runtime-specific hash order; our deterministic order is declared separately.
function compareNames(a: string, b: string): number {
  const x = encodeUtf8(a), y = encodeUtf8(b);
  for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i]! - y[i]!;
  return x.length - y.length;
}
function mapOrder(pairs: Header): Header {
  return [...pairs].sort((a, b) => compareNames(a[0], b[0]));
}
function depthScan(b: Uint8Array): void {
  let depth = 0, quoted = false, escaped = false;
  for (const c of b) {
    if (quoted && escaped) escaped = false;
    else if (quoted && c === 92) escaped = true;
    else if (c === 34) quoted = !quoted;
    else if (!quoted && (c === 123 || c === 91)) {need(depth < 4, "limit"); depth++;}
    else if (!quoted && (c === 125 || c === 93)) {need(depth > 0, "invalid_header"); depth--;}
  }
  need(depth === 0 && !quoted, "invalid_header");
}
function tree(node: JsonNode): void {
  if (node !== null && typeof node === "object") {
    if (node.kind === "number") {
      need(/^-?(?:0|[1-9][0-9]*)$/.test(node.lexeme), "invalid_header");
      const n = BigInt(node.lexeme);
      need(n >= -999999999999999n && n <= 999999999999999n, "limit");
    } else if (node.kind === "array") for (const v of node.items) tree(v);
    else for (const [, v] of mapOrder(node.pairs)) tree(v);
  }
}
function reject(h: Header): void {
  const has = (k: string) => h.some((p) => p[0] === k);
  need(!has("zip"), "compression_unsupported");
  need(!has("crit"), "unsupported_critical_header");
  need(!["jku", "x5u", "jwk", "b64"].some(has), "unsupported_header");
  need(typeof headerValue(h, "alg") === "string", "invalid_header");
}
export function json(input: unknown): Result<Header> {
  return safe(() => {
    const b = bytes(input);
    need(b.length <= JSON_LIMITS.maxBytes, "limit");
    depthScan(b);
    const decoded = take(decodeJson(b, {rejectDuplicates: true, acceptNoncharacters: true}));
    need(decoded.duplicates.length === 0, "duplicate_member");
    const node = decoded.node;
    need(
      node !== null && typeof node === "object" && node.kind === "object",
      "invalid_header",
    );
    tree(node);
    reject(node.pairs);
    return take(deepFreeze(node.pairs));
  });
}
export function parse(segment: unknown): Result<Header> {
  return safe(() => {
    need(typeof segment === "string", "invalid_base64");
    need(segment.length <= 21846, "limit");
    // Octet strings already measure bytes; Unicode strings use their UTF-8 width
    // for the limit before the base64url decoder rejects their alphabet.
    if (/[^\u0000-\u00ff]/u.test(segment))
      need(encodeUtf8(segment).length <= 21846, "limit");
    return take(json(take(decodeBase64Url(segment))));
  });
}
// Snapshot structure independently of value validation so depth takes precedence.
// Invalid descriptors and exotic objects remain invalid values for the next pass.
function structure(value: unknown, depth: number): unknown {
  if (value === null || typeof value !== "object") return value;
  need(depth < 4, "limit");
  if (Array.isArray(value))
    return Array.from(value, (v) => structure(v, depth + 1));
  if (![Object.prototype, null].includes(Object.getPrototypeOf(value))) return value;
  const copy = Object.create(null) as Record<PropertyKey, unknown>;
  for (const key of Reflect.ownKeys(value)) {
    const d = Object.getOwnPropertyDescriptor(value, key)!;
    copy[key] = Object.hasOwn(d, "value")
      ? structure(d.value, depth + 1)
      : undefined;
  }
  return copy;
}
/** Caller pairs use the owned ordered JSON tree; plain nested objects are snapshotted. */
function node(value: unknown, depth: number): JsonNode {
  if (value === null || typeof value === "boolean" || typeof value === "string")
    return value;
  if (typeof value === "number" || typeof value === "bigint") {
    need(typeof value !== "number" || Number.isInteger(value), "invalid_header");
    need(
      typeof value === "bigint" || Number.isSafeInteger(value),
      "limit",
    );
    need(value >= -999999999999999n && value <= 999999999999999n, "limit");
    return { kind: "number", lexeme: String(value) };
  }
  need(value !== null && typeof value === "object", "invalid_header");
  need(depth < 4, "limit");
  if (Array.isArray(value)) {
    need(value.length <= 64, "limit");
    return {
      kind: "array",
      items: Array.from(value, (v) => node(v, depth + 1)),
    };
  }
  need(
    [Object.prototype, null].includes(Object.getPrototypeOf(value)),
    "invalid_header",
  );
  const keys = Reflect.ownKeys(value);
  need(keys.length <= 64, "limit");
  const pairs: [string, JsonNode][] = [];
  for (const key of keys.sort((a, b) => typeof a === "string" && typeof b === "string" ? compareNames(a, b) : 0)) {
    need(typeof key === "string", "invalid_header");
    const d = Object.getOwnPropertyDescriptor(value, key)!;
    need(Object.hasOwn(d, "value"), "invalid_header");
    pairs.push([key, node(d.value, depth + 1)]);
  }
  return { kind: "object", pairs: mapOrder(pairs) };
}
export function serialize(
  input: unknown,
): Result<Readonly<{ protected: string; header: Header }>> {
  return safe(() => {
    need(Array.isArray(input), "limit");
    need(input.length <= 64, "limit");
    const supplied: [string, unknown][] = [],
      names = new Set<string>();
    for (const p of input) {
      need(Array.isArray(p) && p.length === 2, "invalid_header");
      const name: unknown = p[0], value: unknown = p[1];
      need(
        typeof name === "string",
        "invalid_header",
      );
      need(!names.has(name), "duplicate_member");
      names.add(name);
      supplied.push([name, value]);
    }
    const shaped = supplied.map(([name, value]) => [name, structure(value, 1)] as const);
    const validated = new Map<string, JsonNode>();
    for (const [name, value] of [...shaped].sort((a, b) => compareNames(a[0], b[0]))) {
      const owned = node(value, 1);
      tree(owned);
      validated.set(name, owned);
    }
    const pairs: [string, JsonNode][] = supplied.map(([name]) => [name, validated.get(name)!]);
    const raw = take(
      encodeJson({ kind: "object", pairs } satisfies JsonObject, {acceptNoncharacters: true}),
    );
    const header = take(json(raw));
    return Object.freeze({ protected: encodeBase64Url(raw), header });
  });
}
export function bytes(input: unknown): Uint8Array<ArrayBuffer> {
  need(
    input instanceof Uint8Array || typeof input === "string",
    "invalid_serialization",
  );
  need(input.length <= JOSE_MAX_COMPACT_BYTES, "limit");
  const r = byteString(input);
  need(r.ok, "invalid_serialization");
  return r.value;
}
export function compact(
  input: unknown,
  count: 3 | 5,
  checkPrefix = true,
): Result<readonly string[]> {
  return safe(() => {
    need(input instanceof Uint8Array || typeof input === "string", "invalid_serialization");
    need(input.length <= JOSE_MAX_COMPACT_BYTES, "limit");
    const unicode = typeof input === "string" && /[^\u0000-\u00ff]/u.test(input);
    const b = unicode ? undefined : bytes(input);
    let text = "";
    if (typeof input === "string") text = input;
    else {
      for (let i = 0; i < b!.length; i += 4096)
        text += String.fromCharCode(...b!.subarray(i, i + 4096));
    }
    // Unicode White_Space matches String.trim_leading, including NEL but not BOM.
    // Non-octet strings reach segment validation, including the header byte
    // limit, before rejection as invalid base64url.
    const prefix = unicode ? "" : decodeUtf8(b);
    if (checkPrefix) need(!/^[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]*[\[{]/u.test(prefix), "unsupported_serialization");
    const parts: string[] = [];
    let start = 0;
    for (let i = 0; i < count; i++) {
      const end = text.indexOf(".", start);
      if (i === count - 1) {
        need(end === -1, "invalid_serialization");
        parts.push(text.slice(start));
      } else {
        need(end !== -1, "invalid_serialization");
        parts.push(text.slice(start, end));
        start = end + 1;
      }
    }
    return Object.freeze(parts);
  });
}
export const JoseHeader = Object.freeze({ json, parse, serialize, compact });
