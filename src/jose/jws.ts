import {denoInspection} from "../brand.ts";
import { encodeBase64Url, decodeBase64Url } from "../bytes.ts";
import { encodeUtf8 } from "../runtime.ts";
import type { Context } from "../context.ts";
import { isKeyHandle } from "../key_handle.ts";
import { validSigner } from "../signer.ts";
import { isPublicKey, verifyPublicKey } from "../public_key.ts";
import { resolveAlgorithm } from "../crypto/algorithm.ts";
import { snapshotOptions } from "../brand.ts";
import { CUSTODY_SIGNATURE_MAX_BYTES } from "../constants.ts";
import { joseError, isRequestSealError } from "../errors/types.ts";
import type { Result } from "../result.ts";
import {
  bytes,
  json,
  serialize,
  parse,
  compact,
  need,
  type Header,
} from "./header.ts";
import {
  JWS_ALGORITHMS,
  context,
  policy,
  resolve,
  selected,
  bounded,
  publicSafe,
  alive,
  take,
  ok,
  err,
} from "./support.ts";
const branded = new WeakSet<object>(),
  token = Object.freeze({});
/** Check the private brand of a verified JWS result. */
export function isJwsResult(value: unknown): value is JwsResult {
  return typeof value === "object" && value !== null && branded.has(value);
}
/** A branded verified JWS result that confines payload bytes. */
export class JwsResult {
  readonly algorithm: string;
  readonly header: Header;
  readonly protected: string;
  readonly crypto = "valid";
  readonly principal = "unattributed";
  readonly authorization = "not_evaluated";
  #payload: Uint8Array<ArrayBuffer>;
  constructor(
    t: object,
    algorithm: string,
    header: Header,
    protectedPart: string,
    payload: Uint8Array,
  ) {
    if (t !== token) throw new TypeError("Invalid JWS result construction");
    this.algorithm = algorithm;
    this.header = header;
    this.protected = protectedPart;
    this.#payload = new Uint8Array(payload);
    branded.add(this);
    Object.freeze(this);
  }
  get payload(): Uint8Array<ArrayBuffer> {
    return new Uint8Array(this.#payload);
  }
  /** Return a bounded public inspection view without retained cryptographic bytes. */
  toJSON(): unknown {
    return Object.freeze({
      algorithm: this.algorithm,
      crypto: this.crypto,
      principal: this.principal,
      authorization: this.authorization,
    });
  }
  [Symbol.for("nodejs.util.inspect.custom")](): unknown {
    return this.toJSON();
  }
  [Symbol.for("Deno.customInspect")](render?: unknown): unknown {
    return denoInspection(render, this.toJSON());
  }
}
Object.freeze(JwsResult.prototype);
Object.freeze(JwsResult);
async function signing(
  protectedPart: string,
  h: Header,
  payload: unknown,
  handle: unknown,
  c: Context,
): Promise<Result<string>> {
  const data = bytes(payload);
  try {
    need(data.length !== 0, "detached_payload");
    const alg = selected(h, JWS_ALGORITHMS);
    const base = protectedPart + "." + encodeBase64Url(data);
    bytes(base);
    need(validSigner(handle), "invalid_options");
    if (isKeyHandle(handle)) {
      const spec = resolveAlgorithm(handle.algorithm);
      need(spec.ok && spec.value.id === "jws:" + alg, "algorithm_mismatch", "key");
    }
    return await bounded(
      c,
      async () => {
        const input = encodeUtf8(base);
        let signature: Uint8Array<ArrayBuffer>;
        try {
          let result: unknown;
          try {
            result = isKeyHandle(handle)
              ? await handle.sign({ jws: alg }, input, c)
              : await (handle as (selector: unknown, input: Uint8Array) => unknown)({ jws: alg }, input);
          } catch {
            alive(c);
            need(false, "signer_failed", "crypto");
          }
          alive(c);
          const r = snapshotOptions(result, ["ok", "value", "error"]);
          need(r.ok, "signer_failed", "crypto");
          if (r.value.ok !== true) {
            const e = r.value.error;
            return err(joseError(isRequestSealError(e) && e.reason === "deadline_exceeded" ? "deadline_exceeded" : "signer_failed", "crypto"));
          }
          need(r.value.value instanceof Uint8Array, "signer_failed", "crypto");
          need(r.value.value.length > 0 && r.value.value.length <= CUSTODY_SIGNATURE_MAX_BYTES, "signer_failed", "crypto");
          // A trusted signer can return a view into its operation input.
          signature = new Uint8Array(r.value.value);
        } finally {input.fill(0);}
        try {
          const output = base + "." + encodeBase64Url(signature);
          bytes(output);
          return ok(output);
        } finally {signature.fill(0);}
      },
      "signer_failed",
    );
  } finally {
    data.fill(0);
  }
}
/** Sign a compact JWS with an explicit algorithm and caller-owned signer. */
export async function sign(
  protectedPairs: unknown,
  payload: unknown,
  handle: unknown,
  options: unknown = {},
): Promise<Result<string>> {
  return publicSafe(async () => {
    const c = context(options, 5000, true);
    const data = bytes(payload);
    try {
      need(data.length !== 0, "detached_payload");
      const h = take(serialize(protectedPairs));
      return await signing(h.protected, h.header, data, handle, c);
    } finally {data.fill(0);}
  });
}
/** Sign a compact JWS while preserving the supplied protected-header bytes. */
export async function signProtected(
  protectedBytes: unknown,
  payload: unknown,
  handle: unknown,
  options: unknown = {},
): Promise<Result<string>> {
  return publicSafe(async () => {
    const c = context(options, 5000, true);
    const data = bytes(payload);
    try {
      need(data.length !== 0, "detached_payload");
      const raw = bytes(protectedBytes), h = take(json(raw));
      return await signing(encodeBase64Url(raw), h, data, handle, c);
    } finally {data.fill(0);}
  });
}
/** Verify a compact JWS under an explicit algorithm and key policy. */
export async function verify(
  input: unknown,
  inputPolicy: unknown,
  options: unknown = {},
): Promise<Result<JwsResult>> {
  return publicSafe(async () => {
    const p = policy(inputPolicy, "jws"),
      c = context(options, p.timeout);
    return bounded(
      c,
      async () => {
        const parts = take(compact(input, 3)),
          protectedPart = parts[0]!,
          payloadWire = parts[1]!,
          signatureWire = parts[2]!;
        const h = take(parse(protectedPart)),
          alg = selected(h, p.algorithms);
        need(payloadWire !== "", "detached_payload");
        const payload = take(decodeBase64Url(payloadWire)),
          signature = take(decodeBase64Url(signatureWire));
        try {
          need(
            signature.length > 0,
            "invalid_signature",
            "crypto",
          );
          const entry = await resolve(p, { algorithm: alg, header: h }, c);
          need(
            Object.keys(entry).length === 2 &&
              (Object.hasOwn(entry, "key") ||
                typeof entry.verify === "function"),
            "key_resolver_failed",
            "key",
          );
          const base = encodeUtf8(
            protectedPart + "." + payloadWire,
          );
          let valid = false;
          if (isKeyHandle(entry.key))
            valid = (await entry.key.verify({ jws: alg }, signature, base, c))
              .ok;
          else if (isPublicKey(entry.key))
            valid = (
              await verifyPublicKey(entry.key, { jws: alg }, signature, base)
            ).ok;
          else if (typeof entry.verify === "function") {
            try {
              const r: unknown = await entry.verify(
                { jws: alg },
                base,
                signature,
                c,
              );
              valid =
                !!r &&
                typeof r === "object" &&
                Object.hasOwn(r, "ok") &&
                (r as Result<true>).ok === true &&
                Object.hasOwn(r, "value") &&
                (r as { value: unknown }).value === true;
            } catch {
              valid = false;
            }
          } else need(false, "key_resolver_failed", "key");
          alive(c);
          need(valid, "invalid_signature", "crypto");
          return ok(new JwsResult(token, alg, h, protectedPart, payload));
        } finally {
          payload.fill(0);
          signature.fill(0);
        }
      },
      "invalid_signature",
    );
  });
}
/** Compact JWS signing and verification operations. */
export const JWS = Object.freeze({
  /** Sign a compact JWS with an explicit algorithm and caller-owned signer. */
  sign,
  /** Sign a compact JWS while preserving the supplied protected-header bytes. */
  signProtected,
  /** Verify a compact JWS under an explicit algorithm and key policy. */
  verify,
  /** Check the private brand of the operation result. */
  isResult: isJwsResult,
});
