import { deepFreeze, snapshotOptions } from "../brand.ts";
import { type Context, isContext, withDeadline } from "../context.ts";
import {
  type AdapterError,
  adapterError,
  isRequestSealError,
} from "../errors/types.ts";
import type { Reason } from "../errors/parity.ts";
import { err, ok, type Result } from "../result.ts";
import { BODY_MAX_BYTES } from "../constants.ts";
import { inner } from "../signature-fields.ts";
import type { InnerList } from "../structured-fields/index.ts";
export type Adapter = "node-http" | "fetch";
export function failure(
  adapter: Adapter,
  stage: AdapterError["stage"],
  reason: Reason<"adapter">,
  source: unknown = null,
  attempt = 0,
): AdapterError {
  return adapterError(
    reason,
    adapter,
    stage,
    attempt,
    isRequestSealError(source) &&
      ["core", "custody", "message"].includes(source.kind)
      ? (source as AdapterError["source"])
      : null,
  );
}
export function take(
  input: unknown,
  keys: readonly string[],
  adapter: Adapter,
  stage: AdapterError["stage"],
): Readonly<Record<string, unknown>> {
  const r = snapshotOptions(input, keys);
  if (!r.ok) throw failure(adapter, stage, "invalid_options");
  return r.value;
}
export function need(
  value: unknown,
  adapter: Adapter,
  stage: AdapterError["stage"],
  reason: Reason<"adapter">,
  attempt = 0,
): asserts value {
  if (!value) throw failure(adapter, stage, reason, null, attempt);
}
export function unwrap<T>(
  result: Result<T>,
  adapter: Adapter,
  stage: AdapterError["stage"],
  reason: Reason<"adapter">,
  attempt?: number,
): T {
  if (!result.ok) {
    if (result.error.kind === "adapter") {
      throw attempt === undefined ? result.error : failure(
        adapter,
        result.error.stage,
        result.error.reason,
        result.error.source,
        attempt,
      );
    }
    if (
      result.error.kind === "custody" &&
      result.error.reason === "deadline_exceeded"
    ) throw result.error;
    throw failure(
      adapter,
      stage,
      reason === "signing_failed" && result.error.reason === "digest_mismatch"
        ? "digest_conflict"
        : reason,
      result.error,
      attempt ?? 0,
    );
  }
  return result.value;
}
export function caught<T>(
  e: unknown,
  adapter: Adapter,
  stage: AdapterError["stage"],
  reason: Reason<"adapter">,
  attempt?: number,
): Result<T> {
  if (isRequestSealError(e)) {
    if (e.kind === "adapter") {
      return err(
        attempt === undefined
          ? e
          : failure(adapter, e.stage, e.reason, e.source, attempt),
      );
    }
    if (e.kind === "custody" && e.reason === "deadline_exceeded") return err(e);
  }
  return err(failure(adapter, stage, reason, null, attempt ?? 0));
}
export function context(
  a: Readonly<Record<string, unknown>>,
  adapter: Adapter,
  stage: AdapterError["stage"],
): Context {
  if (Object.hasOwn(a, "context")) {
    need(isContext(a.context), adapter, stage, "invalid_options");
    return a.context;
  }
  return unwrap(withDeadline(), adapter, stage, "invalid_options");
}
export function maximum(
  a: Readonly<Record<string, unknown>>,
  adapter: Adapter,
  stage: AdapterError["stage"],
): number {
  const max = Object.hasOwn(a, "maxBytes") ? a.maxBytes : BODY_MAX_BYTES;
  need(
    typeof max === "number" &&
      Number.isSafeInteger(max) &&
      max >= 0 &&
      max <= BODY_MAX_BYTES,
    adapter,
    stage,
    "invalid_options",
  );
  return max;
}
export function spec(
  input: unknown,
  adapter: Adapter,
): Readonly<Record<string, unknown>> {
  const s = take(
    input,
    [
      "label",
      "signatureInput",
      "algorithm",
      "components",
      "parameters",
      "created",
      "expiresIn",
      "nonce",
      "alg",
      "keyid",
      "tag",
      "digest",
      "fieldSchemas",
    ],
    adapter,
    "sign",
  );
  if (!Object.hasOwn(s, "parameters")) {
    return unwrap(deepFreeze(s), adapter, "sign", "invalid_options");
  }
  return unwrap(
    deepFreeze(
      Object.assign(Object.create(null), s, {
        parameters: take(
          s.parameters,
          ["created", "expiresIn", "nonce", "alg", "keyid", "tag"],
          adapter,
          "sign",
        ),
      }),
    ),
    adapter,
    "sign",
    "invalid_options",
  );
}
export function components(
  s: Readonly<Record<string, unknown>>,
  adapter: Adapter,
): InnerList {
  return unwrap(
    inner(Object.hasOwn(s, "components") ? s.components : s.signatureInput),
    adapter,
    "sign",
    "invalid_options",
  );
}
export function signingOptions(
  a: Readonly<Record<string, unknown>>,
  c: Context,
): Readonly<Record<string, unknown>> {
  const out = Object.assign(Object.create(null), { context: c });
  for (const k of ["clock", "nonce", "signingTimeout"]) {
    if (Object.hasOwn(a, k)) out[k] = a[k];
  }
  return Object.freeze(out);
}
export function latin(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return s;
}
export function redirectOptions(
  a: Readonly<Record<string, unknown>>,
  adapter: Adapter,
): Readonly<Record<string, unknown>> {
  const out = Object.assign(Object.create(null), a);
  for (const name of ["allowedOrigins", "credentialHeaders"] as const) {
    if (!Object.hasOwn(a, name)) continue;
    const owned = unwrap(
      deepFreeze(a[name]),
      adapter,
      "attach",
      "invalid_options",
    );
    need(
      Array.isArray(owned) && owned.length <= 64,
      adapter,
      "attach",
      "invalid_options",
    );
    need(
      owned.every((v) => {
        if (typeof v !== "string") return false;
        if (name === "credentialHeaders") {
          return v.length <= 256 && /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(v);
        }
        try {
          const u = new URL(v);
          return ["http:", "https:"].includes(u.protocol) && u.origin === v;
        } catch {
          return false;
        }
      }),
      adapter,
      "attach",
      "invalid_options",
    );
    out[name] = owned;
  }
  return Object.freeze(out);
}
export function redirectLocation(
  value: string,
  base: URL | string,
  adapter: Adapter,
  attempt: number,
): URL {
  try {
    const next = new URL(value, base);
    next.hash = "";
    return next;
  } catch {
    throw failure(adapter, "sign", "invalid_request", null, attempt);
  }
}
export function allowedOrigin(
  url: URL,
  source: URL,
  list: unknown,
  adapter: Adapter,
  attempt: number,
): void {
  need(
    ["http:", "https:"].includes(url.protocol) && !url.username &&
      !url.password,
    adapter,
    "sign",
    "invalid_request",
    attempt,
  );
  if (url.origin === source.origin) return;
  need(
    Array.isArray(list) && list.includes(url.origin),
    adapter,
    "sign",
    "cross_origin_redirect",
    attempt,
  );
}
export const REDIRECT_BODY_FIELDS: readonly string[] = Object.freeze([
  "content-type",
  "content-length",
  "content-encoding",
  "content-language",
  "content-location",
  "content-digest",
]);
export const RUNTIME_MANAGED_FIELDS: readonly string[] = Object.freeze([
  "host",
  "content-length",
  "accept-encoding",
  "connection",
  "transfer-encoding",
  "trailer",
  "keep-alive",
  "proxy-connection",
  "te",
  "upgrade",
]);
export const RESPONSE_HOP_FIELDS: readonly string[] = Object.freeze([
  "transfer-encoding",
  "connection",
  "trailer",
  "keep-alive",
  "proxy-connection",
  "te",
  "upgrade",
]);
export function responseRefused(
  part: InnerList["value"][number],
  fields: readonly string[],
): boolean {
  return !part.parameters.some(([k]) => k === "req") &&
    (fields.includes(String(part.value.value)) ||
      part.parameters.some(([k]) => k === "tr"));
}
export function redirectGet(status: number, method: string): boolean {
  return (status === 303 && method !== "GET" && method !== "HEAD") ||
    ((status === 301 || status === 302) && method === "POST");
}
export function limitNumber(
  value: unknown,
  max: number,
  adapter: Adapter,
): number {
  need(
    typeof value === "number" &&
      Number.isSafeInteger(value) &&
      value >= 0 &&
      value <= max,
    adapter,
    "attach",
    "invalid_options",
  );
  return value;
}
export function result<T>(v: T): Result<T> {
  return ok(v);
}
