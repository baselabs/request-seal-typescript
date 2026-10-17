import { snapshotOptions } from "../brand.ts";
import { encodeUtf8 } from "../runtime.ts";
import {err, type Result } from "../result.ts";
import { JWE, type JweResult } from "./jwe.ts";
import { JWS, type JwsResult } from "./jws.ts";
import { compact, headerValue, need, take } from "./header.ts";
import {joseError} from "../errors/types.ts";
import { publicSafe, ok } from "./support.ts";
const branded = new WeakSet<object>();
/** A branded pair of authenticated outer JWE and verified inner JWS results. */
export type NestedResult = Readonly<{ jwe: JweResult; jws: JwsResult }>;
/** Check the private brand of a nested JOSE result. */
export function isNestedResult(value: unknown): value is NestedResult {
  return typeof value === "object" && value !== null && branded.has(value);
}
export function innerCompact(input: Uint8Array): Result<readonly string[]> {
  const framed = compact(input, 3, false);
  return !framed.ok && framed.error.reason === 'invalid_serialization' ? err(joseError('nesting_depth', 'nesting')) : framed;
}
// RFC 7515 Section 4.1.10: a cty value with no "/" is read with "application/"
// prepended. The recursion-implying set is the registered JOSE media types
// (Section 9.2.1: application/jose and application/jose+json), their
// per-structure spellings application/jws and application/jwe, and RFC 7519's
// application/jwt (abbreviated "JWT"): each declares the payload is another
// JOSE envelope, which this one-level module refuses. Any other cty names
// ordinary typed payload content and is the application's business.
function nestingCty(cty: unknown): boolean {
  if (typeof cty !== "string") return false;
  // Media-type parameters do not change the type/subtype classification, so
  // strip them before the abbreviation rule.
  const base = cty.split(";", 1)[0]!.trim();
  const expanded = base.includes("/") ? base : `application/${base}`;
  return [
    "application/jose",
    "application/jose+json",
    "application/jws",
    "application/jwe",
    "application/jwt",
  ].includes(expanded.toLowerCase());
}
/** Authenticate an outer JWE and verify its inner compact JWS. */
export async function decrypt(
  input: unknown,
  policy: unknown,
  options: unknown,
): Promise<Result<NestedResult>> {
  return publicSafe(async () => {
    const opts = snapshotOptions(options, ["content_types", "context"]);
    need(opts.ok, "invalid_options");
    const o = opts.value;
    const types = o.content_types;
    need(
      Array.isArray(types) && types.length > 0 && types.length <= 64,
      "invalid_options",
    );
    const copied = Array.from(types);
    need(
      new Set(copied).size === copied.length &&
        copied.every(
          (t) =>
            typeof t === "string" &&
            encodeUtf8(t).length > 0 &&
            encodeUtf8(t).length <= 256,
        ),
      "invalid_options",
    );
    const snapshot = snapshotOptions(policy, ["jwe", "jws"]);
    need(snapshot.ok && Object.keys(snapshot.value).length === 2, "invalid_policy");
    const p = snapshot.value;
    const stageOptions = Object.hasOwn(o, "context")
      ? { context: o.context }
      : {};
    const outer = await JWE.decrypt(input, p.jwe, stageOptions);
    if (!outer.ok) return outer;
    const plaintext = outer.value.plaintext;
    try {
      need(
        copied.includes(headerValue(outer.value.header, "cty")),
        "content_type_mismatch",
        "nesting",
      );
      take(innerCompact(plaintext));
      const inner = await JWS.verify(plaintext, p.jws, stageOptions);
      if (!inner.ok) return inner;
      need(
        !nestingCty(headerValue(inner.value.header, "cty")),
        "nesting_depth",
        "nesting",
      );
      const result = Object.freeze({ jwe: outer.value, jws: inner.value });
      branded.add(result);
      return ok(result);
    } finally {
      plaintext.fill(0);
    }
  });
}
/** One-level nested JWE decryption and JWS verification operations. */
export const Nested = Object.freeze({
  /** Authenticate an outer JWE and verify its inner compact JWS. */
  decrypt,
  /** Check the private brand of the operation result. */
  isResult: isNestedResult });
