import {denoInspection} from "../brand.ts";
import { now } from "../runtime.ts";
import { isContext, withDeadline, type Context } from "../context.ts";
import { Custody } from "../custody/index.ts";
import {
  confineContentKey,
  type UnwrappedKey,
} from "../custody/content_key.ts";
import { decodeKey } from "../custody/der.ts";
import { snapshotJwk, publicMembers, permitted } from "../custody/jwk.ts";
import { isPublicKey, bindPublicKey, type PublicKey } from "../public_key.ts";
import { isKeyHandle, type KeyHandle } from "../key_handle.ts";
import { decodeBase64Url, encodeBase64Url } from "../bytes.ts";
import { joseError } from "../errors/types.ts";
import { type Result, ok } from "../result.ts";
import * as primitive from "../crypto/jose.ts";
import { resolveAlgorithm, importParameters } from "../crypto/algorithm.ts";
import { bytes, headerValue, need, take, type Header } from "./header.ts";
import { bounded, publicSafe, alive, JWE_ALGORITHMS } from "./support.ts";
const branded = new WeakSet<object>(),
  token = Object.freeze({});
/** Owned encrypted-key and content-encryption-key bytes from key wrapping. */
export type WrapResult = Readonly<{
  encrypted_key: Uint8Array<ArrayBuffer>;
  header: Header;
}>;
/** Check the private brand of a JOSE key-management handle. */
export function isKeyManagementHandle(
  value: unknown,
): value is KeyManagementHandle {
  return typeof value === "object" && value !== null && branded.has(value);
}
/** Caller-owned custodian primitives. RSA private and AES keys never escape as
 * CryptoKey references. Primitive decrypt releases bytes only after authentication. */
export class KeyManagementHandle {
  readonly algorithm: string;
  #key: CryptoKey | undefined;
  #width: number;
  private constructor(
    t: object,
    algorithm: string,
    key: CryptoKey,
    width: number,
  ) {
    if (t !== token) throw new TypeError("Invalid key-management construction");
    this.algorithm = algorithm;
    this.#key = key;
    this.#width = width;
    branded.add(this);
    Object.freeze(this);
  }
  /** Import caller-owned local key material into a confined capability. */
  static async local(
    algorithm: unknown,
    material: unknown,
  ): Promise<Result<KeyManagementHandle>> {
    return publicSafe(async () => {
      need(
        typeof algorithm === "string" && JWE_ALGORITHMS.includes(algorithm),
        "algorithm_not_permitted",
      );
      if (!algorithm.startsWith("RSA")) {
        need(material instanceof Uint8Array, "algorithm_mismatch", "key");
        const width =
          algorithm === "A128GCMKW"
            ? 16
            : algorithm === "A256GCMKW"
              ? 32
              : material.length;
        need(
          material.length === width && [16, 32].includes(width),
          "algorithm_mismatch",
          "key",
        );
        const copy = new Uint8Array(material);
        try {
          const key = await primitive.aesImport(
            copy,
            false,
            algorithm === "dir"
              ? ["decrypt"]
              : ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
          );
          return ok(new KeyManagementHandle(token, algorithm, key, width));
        } finally {
          copy.fill(0);
        }
      }
      // Reuse the existing validated custody import, including its real public /
      // private agreement probe, before constructing this custodian-side primitive.
      const selected = take(resolveAlgorithm({ jwe: algorithm }, true));
      const captured =
        typeof material === "string"
          ? material
          : material instanceof Uint8Array
            ? new Uint8Array(material)
            : take(snapshotJwk(material, true, selected));
      const owner = await Custody.local({ jwe: algorithm }, captured);
      if (!owner.ok) {
        if (captured instanceof Uint8Array) captured.fill(0);
      }
      need(owner.ok, "algorithm_mismatch", "key");
      let der: Uint8Array<ArrayBuffer> | undefined;
      try {
        const spec = selected;
        let key: CryptoKey;
        if (typeof captured === "string" || captured instanceof Uint8Array) {
          const decoded = take(
            decodeKey(captured, typeof captured === "string" ? "pem" : "pkcs8"),
          );
          der = decoded.der;
          key = await primitive.importKey(
            "pkcs8",
            der,
            importParameters(spec),
            false,
            ["decrypt", "unwrapKey"],
          );
        } else {
          const j = take(snapshotJwk(captured, true, spec));
          need(permitted(j, spec, "decrypt"), "algorithm_mismatch", "key");
          const clean = Object.assign(Object.create(null), publicMembers(j));
          for (const k of ["d", "p", "q", "dp", "dq", "qi"]) clean[k] = j[k];
          key = await primitive.importKey(
            "jwk",
            clean,
            importParameters(spec),
            false,
            ["decrypt", "unwrapKey"],
          );
        }
        return ok(
          new KeyManagementHandle(
            token,
            algorithm,
            key,
            Math.ceil(
              (key.algorithm as { name: string; modulusLength: number })
                .modulusLength / 8,
            ),
          ),
        );
      } finally {
        der?.fill(0);
        if (captured instanceof Uint8Array) captured.fill(0);
        await owner.value.release();
      }
    });
  }
  /** Wrap a generated content-encryption key with the bound key-management algorithm. */
  async wrap(
    algorithm: unknown,
    content: unknown,
    context?: Context,
  ): Promise<Result<WrapResult>> {
    return publicSafe(async () => {
      need(
        algorithm === this.algorithm && this.algorithm.endsWith("GCMKW"),
        "algorithm_mismatch",
        "key",
      );
      const c = context === undefined ? take(withDeadline()) : context;
      need(isContext(c), "invalid_options");
      const input = bytes(content);
      need([16, 32].includes(input.length), "algorithm_mismatch", "key");
      return bounded(
        c,
        async () => {
          const key = this.#key;
          need(key, "signer_failed", "crypto");
          const iv = random(12);
          try {
            const sealed = await primitive.gcmWrap(key, input, iv);
            alive(c);
            need(this.#key, "signer_failed", "crypto");
            return ok(
              Object.freeze({
                encrypted_key: sealed.slice(0, -16),
                header: Object.freeze([
                  Object.freeze(["iv", encodeBase64Url(iv)] as const),
                  Object.freeze([
                    "tag",
                    encodeBase64Url(sealed.subarray(-16)),
                  ] as const),
                ]),
              }),
            );
          } finally {
            input.fill(0);
          }
        },
        "signer_failed",
      );
    });
  }
  /** Authenticate and decrypt content using the bound direct-encryption key. */
  async decrypt(
    encryptedKey: unknown,
    header: Header,
    context?: Context,
  ): Promise<Result<Uint8Array<ArrayBuffer>>> {
    return publicSafe(async () => {
      const c = context === undefined ? take(withDeadline()) : context;
      need(isContext(c), "invalid_options");
      need(headerValue(header, "alg") === this.algorithm, "decryption_failed", "crypto");
      const data = bytes(encryptedKey);
      return bounded(
        c,
        async () => {
          const key = this.#key;
          need(key, "decryption_failed", "crypto");
          let output: Uint8Array<ArrayBuffer>;
          try {
            if (this.algorithm.startsWith("RSA")) {
              need(data.length === this.#width, "decryption_failed", "crypto");
              output = await primitive.oaepDecrypt(key, data);
            } else if (this.algorithm.endsWith("GCMKW")) {
              const iv = take(decodeBase64Url(headerValue(header, "iv"))),
                tag = take(decodeBase64Url(headerValue(header, "tag")));
              need(iv.length === 12, "invalid_iv");
              need(tag.length === 16, "invalid_tag");
              const sealed = new Uint8Array(data.length + 16);
              sealed.set(data);
              sealed.set(tag, data.length);
              output = await primitive.aesDecrypt(key, sealed, iv);
            } else {
              need(false, "decryption_failed", "crypto");
            }
            if (
              !this.#key ||
              c.signal.aborted ||
              now() >= c.deadline
            ) {
              output.fill(0);
              alive(c);
              need(false, "decryption_failed", "crypto");
            }
            return ok(output);
          } finally {
            data.fill(0);
          }
        },
        "decryption_failed",
      );
    });
  }
  /** Confine an unwrapped content-encryption key in a decryption capability. */
  async unwrap(
    encryptedKey: unknown,
    header: Header,
    context?: Context,
  ): Promise<Result<UnwrappedKey>> {
    return publicSafe(async () => {
      const c = context === undefined ? take(withDeadline()) : context;
      need(isContext(c), "invalid_options");
      need(headerValue(header, "alg") === this.algorithm, "decryption_failed", "crypto");
      const data = bytes(encryptedKey);
      if (this.algorithm === "dir") {
        need(this.#key, "decryption_failed", "crypto");
        need(data.length === 0, "decryption_failed", "crypto");
        alive(c);
        return ok(confineContentKey(this.#key));
      }
      return bounded(c, async () => {
        const key = this.#key;
        need(key, "decryption_failed", "crypto");
        const enc = headerValue(header, "enc");
        need(enc === "A128GCM" || enc === "A256GCM", "decryption_failed", "crypto");
        const length = enc === "A128GCM" ? 128 : 256;
        try {
          let recovered: CryptoKey;
          if (this.algorithm.startsWith("RSA")) {
            need(data.length === this.#width, "decryption_failed", "crypto");
            recovered = await primitive.unwrapContentKey(key, data, "RSA-OAEP", length);
          } else {
            need(this.algorithm.endsWith("GCMKW"), "decryption_failed", "crypto");
            const iv = take(decodeBase64Url(headerValue(header, "iv"))), tag = take(decodeBase64Url(headerValue(header, "tag")));
            need(iv.length === 12, "invalid_iv"); need(tag.length === 16, "invalid_tag");
            const sealed = new Uint8Array(data.length + tag.length);
            sealed.set(data); sealed.set(tag, data.length);
            recovered = await primitive.unwrapContentKey(key, sealed, "AES-GCM", length, iv);
          }
          alive(c);
          need(this.#key, "decryption_failed", "crypto");
          return ok(confineContentKey(recovered));
        } finally {data.fill(0);}
      }, "decryption_failed");
    });
  }
  /** Release retained key-management custody and invalidate the capability. */
  async release(): Promise<Result<true>> {
    this.#key = undefined;
    return ok(true);
  }
  /** Return a bounded public inspection view without retained cryptographic bytes. */
  toJSON(): unknown {
    return Object.freeze({
      kind: "KeyManagementHandle",
      algorithm: this.algorithm,
    });
  }
  [Symbol.for("nodejs.util.inspect.custom")](): unknown {
    return this.toJSON();
  }
  [Symbol.for("Deno.customInspect")](render?: unknown): unknown {
    return denoInspection(render, this.toJSON());
  }
}
Object.freeze(KeyManagementHandle.prototype);
Object.freeze(KeyManagementHandle);
export function random(length: number): Uint8Array<ArrayBuffer> {
  try {
    // Enforce the WebCrypto quota even when a runtime accepts larger requests.
    if (!Number.isInteger(length) || length < 0 || length > 65536)
      throw joseError("entropy_failure", "crypto");
    return primitive.random(new Uint8Array(length));
  } catch {
    throw joseError("entropy_failure", "crypto");
  }
}
export async function wrapPublic(
  key: PublicKey | KeyHandle,
  algorithm: string,
  content: Uint8Array,
  context: Context,
): Promise<Result<WrapResult>> {
  return bounded(
    context,
    async () => {
      const publicKey = isKeyHandle(key)
        ? take(await key.publicKey(context))
        : key;
      need(
        isPublicKey(publicKey) &&
          bindPublicKey(publicKey, { jwe: algorithm }).ok,
        "algorithm_mismatch",
        "key",
      );
      const spec = take(resolveAlgorithm({ jwe: algorithm }, true));
      const j = take(publicKey.jwk());
      const operation = await primitive.importKey(
        "jwk",
        publicMembers(j),
        importParameters(spec),
        false,
        ["encrypt"],
      );
      const encrypted = await primitive.oaepEncrypt(operation, content);
      alive(context);
      return ok(
        Object.freeze({ encrypted_key: encrypted, header: Object.freeze([]) }),
      );
    },
    "signer_failed",
  );
}
/** Constructors and branding checks for JOSE key-management capabilities. */
export const KeyManagement = Object.freeze({
  /** Import caller-owned local key material into a confined capability. */
  local: KeyManagementHandle.local,
  /** Check the private brand of a key-management capability. */
  isHandle: isKeyManagementHandle,
});
