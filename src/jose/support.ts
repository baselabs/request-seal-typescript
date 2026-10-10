import { snapshotOptions } from "../brand.ts";
import {
  withDeadline,
  isContext,
  remainingMs,
  run,
  type Context,
} from "../context.ts";
import { joseError, isRequestSealError } from "../errors/types.ts";
import { err, ok, type Result } from "../result.ts";
import { take, need, fail, type Header } from "./header.ts";
export const JWS_ALGORITHMS = Object.freeze([
  "RS256",
  "PS256",
  "PS384",
  "PS512",
  "HS256",
  "ES256",
  "ES384",
  "EdDSA",
]);
export const JWE_ALGORITHMS = Object.freeze([
  "RSA-OAEP-256",
  "RSA-OAEP",
  "A128GCMKW",
  "A256GCMKW",
  "dir",
]);
export const ENCRYPTION = Object.freeze(["A128GCM", "A256GCM"]);
export type Resolution = Readonly<Record<string, unknown>>;
export type Policy = Readonly<{
  algorithms: readonly string[];
  timeout: number;
  key_resolver: (
    request: Readonly<{
      algorithm: string;
      encryption?: string;
      header: Header;
    }>,
    context: Context,
  ) => unknown;
  encryption?: readonly string[];
  max_plaintext?: number;
}>;
function list(input: unknown, allowed: readonly string[]): readonly string[] {
  need(
    Array.isArray(input) && input.length > 0 && input.length <= 8,
    "invalid_policy",
  );
  const copied = Array.from(input);
  need(
    new Set(copied).size === copied.length &&
      copied.every((x) => typeof x === "string" && allowed.includes(x)),
    "invalid_policy",
  );
  return Object.freeze(copied);
}
export function policy(input: unknown, kind: "jws" | "jwe"): Policy {
  const keys =
    kind === "jws"
      ? ["algorithms", "timeout", "key_resolver"]
      : [
          "algorithms",
          "encryption",
          "max_plaintext",
          "timeout",
          "key_resolver",
        ];
  const r = snapshotOptions(input, keys);
  need(r.ok && Object.keys(r.value).length === keys.length, "invalid_policy");
  const p = r.value;
  need(
    Number.isInteger(p.timeout) &&
      (p.timeout as number) >= 1 &&
      (p.timeout as number) <= 300000 &&
      typeof p.key_resolver === "function",
    "invalid_policy",
  );
  const algorithms = list(
    p.algorithms,
    kind === "jws" ? JWS_ALGORITHMS : JWE_ALGORITHMS,
  );
  const out = Object.assign(Object.create(null), {
    algorithms,
    timeout: p.timeout,
    key_resolver: p.key_resolver,
  }) as Policy;
  if (kind === "jwe") {
    const encryption = list(p.encryption, ENCRYPTION);
    need(
      Number.isInteger(p.max_plaintext) &&
        (p.max_plaintext as number) > 0 &&
        (p.max_plaintext as number) <= 1048576,
      "invalid_policy",
    );
    Object.assign(out, { encryption, max_plaintext: p.max_plaintext });
  }
  return Object.freeze(out);
}
export function context(
  options: unknown,
  timeout = 5000,
  signing = false,
): Context {
  const r = snapshotOptions(
    options,
    signing ? ["timeout", "context"] : ["context"],
  );
  need(r.ok, "invalid_options");
  const p = r.value;
  if (Object.hasOwn(p, "timeout")) {
    need(
      Number.isInteger(p.timeout) &&
        (p.timeout as number) >= 1 &&
        (p.timeout as number) <= 300000,
      "invalid_options",
    );
    timeout = p.timeout as number;
  }
  if (Object.hasOwn(p, "context"))
    need(isContext(p.context), "invalid_options");
  const c = withDeadline(
    Object.hasOwn(p, "context")
      ? { timeoutMs: timeout, parent: p.context }
      : { timeoutMs: timeout },
  );
  need(c.ok, "invalid_options");
  return c.value;
}
export async function bounded<T>(
  c: Context,
  work: () => Promise<Result<T>>,
  fallback: "signer_failed" | "invalid_signature" | "decryption_failed",
): Promise<Result<T>> {
  const r = await run(c, async () => {
    try {
      return await work();
    } catch (e) {
      return err(
        isRequestSealError(e) && e.kind === "jose"
          ? e
          : joseError(fallback, "crypto"),
      );
    }
  });
  if (!r.ok && r.error.kind !== "jose")
    return err(
      joseError(
        r.error.reason === "deadline_exceeded" ? "deadline_exceeded" : fallback,
        "crypto",
      ),
    );
  return r;
}
export function alive(c: Context): void {
  need(remainingMs(c) > 0, "deadline_exceeded", "crypto");
}
export async function resolve(
  p: Policy,
  request: Parameters<Policy["key_resolver"]>[0],
  c: Context,
): Promise<Resolution> {
  let result: unknown;
  try {
    result = await p.key_resolver(Object.freeze(request), c);
  } catch {
    fail("key_resolver_failed", "key");
  }
  alive(c);
  need(result && typeof result === "object", "key_resolver_failed", "key");
  const r = snapshotOptions(result, ["ok", "value", "error"]);
  need(r.ok, "key_resolver_failed", "key");
  if (r.value.ok === false) fail("unknown_key", "key");
  need(
    r.value.ok === true && Object.hasOwn(r.value, "value"),
    "key_resolver_failed",
    "key",
  );
  const entry = snapshotOptions(r.value.value, [
    "algorithm",
    "key",
    "verify",
    "unwrap",
  ]);
  need(entry.ok, "key_resolver_failed", "key");
  need(
    entry.value.algorithm === request.algorithm,
    "algorithm_mismatch",
    "key",
  );
  return entry.value;
}
export async function publicSafe<T>(
  work: () => Promise<Result<T>>,
): Promise<Result<T>> {
  try {
    return await work();
  } catch (e) {
    return err(
      isRequestSealError(e) && e.kind === "jose"
        ? e
        : joseError("invalid_options", "input"),
    );
  }
}
export function selected(
  h: Header,
  algorithms: readonly string[],
  encryption?: readonly string[],
): string {
  const alg = h.find((p) => p[0] === "alg")?.[1];
  need(
    typeof alg === "string" && algorithms.includes(alg),
    "algorithm_not_permitted",
  );
  if (encryption) {
    const enc = h.find((p) => p[0] === "enc")?.[1];
    need(
      typeof enc === "string" && encryption.includes(enc),
      "algorithm_not_permitted",
    );
  }
  return alg;
}
export { take, ok, err };
