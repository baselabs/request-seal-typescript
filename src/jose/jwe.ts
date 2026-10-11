import {denoInspection} from "../brand.ts";
import { encodeJson } from "../json.ts";
import { encodeUtf8 } from "../runtime.ts";
import { encodeBase64Url, decodeBase64Url } from "../bytes.ts";
import { isKeyHandle } from "../key_handle.ts";
import { isPublicKey } from "../public_key.ts";
import {
  confineContentKey,
  isUnwrappedKey,
  type UnwrappedKey,
} from "../custody/content_key.ts";
import { snapshotOptions } from "../brand.ts";
import { joseError, isRequestSealError } from "../errors/types.ts";
import type { Result } from "../result.ts";
import * as primitive from "../crypto/jose.ts";
import {
  bytes,
  serialize,
  parse,
  compact,
  headerValue,
  need,
  type Header,
} from "./header.ts";
import {
  JWE_ALGORITHMS,
  ENCRYPTION,
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
import { random, wrapPublic } from "./key-management.ts";
const branded = new WeakSet<object>(),
  token = Object.freeze({});
/** Check the private brand of an authenticated JWE result. */
export function isJweResult(value: unknown): value is JweResult {
  return typeof value === "object" && value !== null && branded.has(value);
}
/** A branded authenticated JWE result that confines plaintext bytes. */
export class JweResult {
  readonly algorithm: string;
  readonly encryption: string;
  readonly header: Header;
  readonly protected: string;
  readonly recipient_integrity = "valid";
  readonly origin = "unbound";
  readonly principal = "unattributed";
  readonly authorization = "not_evaluated";
  #plaintext: Uint8Array<ArrayBuffer>;
  constructor(
    t: object,
    algorithm: string,
    encryption: string,
    header: Header,
    protectedPart: string,
    plaintext: Uint8Array,
  ) {
    if (t !== token) throw new TypeError("Invalid JWE result construction");
    this.algorithm = algorithm;
    this.encryption = encryption;
    this.header = header;
    this.protected = protectedPart;
    this.#plaintext = new Uint8Array(plaintext);
    branded.add(this);
    Object.freeze(this);
  }
  get plaintext(): Uint8Array<ArrayBuffer> {
    return new Uint8Array(this.#plaintext);
  }
  /** Return a bounded public inspection view without retained cryptographic bytes. */
  toJSON(): unknown {
    return Object.freeze({
      algorithm: this.algorithm,
      encryption: this.encryption,
      recipient_integrity: this.recipient_integrity,
      origin: this.origin,
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
Object.freeze(JweResult.prototype);
Object.freeze(JweResult);
function width(enc: string): number {
  return enc === "A128GCM" ? 16 : 32;
}
function encryptedKey(alg: string, ek: Uint8Array, h: Header): void {
  if (alg === "dir") need(ek.length === 0, "decryption_failed", "crypto");
  else if (alg.endsWith("GCMKW")) {
    need(
      ek.length === width(headerValue(h, "enc") as string),
      "decryption_failed",
      "crypto",
    );
    need(
      take(decodeBase64Url(headerValue(h, "iv"))).length === 12,
      "invalid_iv",
    );
    need(
      take(decodeBase64Url(headerValue(h, "tag"))).length === 16,
      "invalid_tag",
    );
  } else
    need(ek.length >= 256 && ek.length <= 1024, "decryption_failed", "crypto");
}
/** Encrypt content into compact JWE using explicit key-management and content algorithms. */
export async function encrypt(
  protectedPairs: unknown,
  plaintext: unknown,
  recipient: unknown,
  options: unknown = {},
): Promise<Result<string>> {
  return publicSafe(async () => {
    const c = context(options, 5000, true),
      data = bytes(plaintext),
      initial = take(serialize(protectedPairs)),
      alg = selected(initial.header, JWE_ALGORITHMS, ENCRYPTION),
      enc = headerValue(initial.header, "enc") as string;
    return bounded(
      c,
      async () => {
        const cek = random(width(enc));
        try {
          const iv = random(12);
          let wrapped: unknown;
          if (isKeyHandle(recipient) || isPublicKey(recipient))
            wrapped = await wrapPublic(recipient, alg, cek, c);
          else if (typeof recipient === "function") {
            const provided = new Uint8Array(cek);
            try {
              wrapped = await recipient(alg, provided, c);
            } catch {
              alive(c);
              need(false, "signer_failed", "crypto");
            } finally {
              provided.fill(0);
            }
          } else need(false, "invalid_options");
          alive(c);
          const r = snapshotOptions(wrapped, ["ok", "value", "error"]);
          need(r.ok, "signer_failed", "crypto");
          if (r.value.ok === false) {
            const error = r.value.error;
            if (isRequestSealError(error) && error.kind === "jose" && error.reason === "entropy_failure")
              throw joseError("entropy_failure", "crypto");
          }
          need(r.value.ok === true, "signer_failed", "crypto");
          const w = snapshotOptions(r.value.value, ["encrypted_key", "header"]);
          need(
            w.ok &&
              Object.keys(w.value).length === 2 &&
              w.value.encrypted_key instanceof Uint8Array &&
              Array.isArray(w.value.header),
            "signer_failed",
            "crypto",
          );
          const extra = w.value.header;
          const ek = new Uint8Array(w.value.encrypted_key);
          const count = extra.length;
          need(Number.isSafeInteger(count) && count >= 0 && count <= 2, "unsupported_header");
          const additions: [string, string][] = [];
          for (let i = 0; i < count; i++) {
            const pair = extra[i];
            need(Array.isArray(pair) && pair.length === 2, "unsupported_header");
            const name: unknown = pair[0], value: unknown = pair[1];
            need(typeof name === "string" && ["iv", "tag"].includes(name) && typeof value === "string", "unsupported_header");
            additions.push([name, value]);
          }
          need(
            alg.endsWith("GCMKW") || additions.length === 0,
            "unsupported_header",
          );
          need(
            !additions.some((p) => initial.header.some((h) => h[0] === p[0])),
            "duplicate_member",
          );
          // Snapshot caller pairs before the wrapper can mutate them. Already parsed
          // nodes serialize directly, preserving the original top-level order.
          const combined: Header = Object.freeze([
            ...initial.header,
            ...[...additions].sort((a, b) =>
              a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0,
            ),
          ]);
          const raw = take(encodeJson({ kind: "object", pairs: combined }, {acceptNoncharacters: true})),
            protectedPart = encodeBase64Url(raw),
            h = take(parse(protectedPart));
          encryptedKey(alg, ek, h);
          const contentKey = await primitive.aesImport(cek, false, ["encrypt"]);
          const sealed = await primitive.aesEncrypt(
            contentKey,
            data,
            iv,
            encodeUtf8(protectedPart),
          );
          alive(c);
          const output = [
            protectedPart,
            encodeBase64Url(ek),
            encodeBase64Url(iv),
            encodeBase64Url(sealed.subarray(0, -16)),
            encodeBase64Url(sealed.subarray(-16)),
          ].join(".");
          bytes(output);
          return ok(output);
        } finally {
          cek.fill(0);
          data.fill(0);
        }
      },
      "signer_failed",
    );
  });
}
/** Authenticate and decrypt compact JWE under an explicit policy. */
export async function decrypt(
  input: unknown,
  inputPolicy: unknown,
  options: unknown = {},
): Promise<Result<JweResult>> {
  return publicSafe(async () => {
    const p = policy(inputPolicy, "jwe"),
      c = context(options, p.timeout);
    return bounded(
      c,
      async () => {
        const parts = take(compact(input, 5)),
          protectedPart = parts[0]!,
          h = take(parse(protectedPart)),
          alg = selected(h, p.algorithms, p.encryption),
          enc = headerValue(h, "enc") as string;
        const ek = take(decodeBase64Url(parts[1])),
          iv = take(decodeBase64Url(parts[2]));
        need(iv.length === 12, "invalid_iv");
        const tag = take(decodeBase64Url(parts[4]));
        need(tag.length === 16, "invalid_tag");
        const ciphertext = take(decodeBase64Url(parts[3]));
        need(ciphertext.length <= p.max_plaintext!, "limit");
        encryptedKey(alg, ek, h);
        const entry = await resolve(
          p,
          { algorithm: alg, encryption: enc, header: h },
          c,
        );
        need(
          Object.keys(entry).length === 2 &&
            (Object.hasOwn(entry, "key") || Object.hasOwn(entry, "unwrap")),
          "key_resolver_failed",
          "key",
        );
        need(
          isKeyHandle(entry.key) ||
            isKeyHandle(entry.unwrap) ||
            typeof entry.unwrap === "function",
          "key_resolver_failed",
          "key",
        );
        // Every path prepares a fresh native, non-extractable fallback key.
        let fallback: UnwrappedKey;
        try {
          fallback = confineContentKey(
            await primitive.generateKey({name: "AES-GCM", length: width(enc) * 8}, false, ["decrypt"]),
          );
        } catch {
          need(false, "entropy_failure", "crypto");
        }
        let opened: UnwrappedKey | undefined,
          validUnwrap = false, ownedOpened = false;
        try {
          try {
            const handle = isKeyHandle(entry.key)
              ? entry.key
              : isKeyHandle(entry.unwrap)
                ? entry.unwrap
                : undefined;
            const result: unknown = handle
              ? await handle.unwrap({ jwe: alg }, ek, c, {
                  length: width(enc) * 8,
                })
              : await (entry.unwrap as Function)(new Uint8Array(ek), h, c);
            if (
              result &&
              typeof result === "object" &&
              Object.hasOwn(result, "ok") &&
              (result as Result<unknown>).ok === true &&
              Object.hasOwn(result, "value")
            ) {
              const value = (result as { value: unknown }).value;
              if (isUnwrappedKey(value)) {
                opened = value;
                ownedOpened = handle !== undefined;
                validUnwrap = value.length === width(enc) * 8;
              } else if (
                value instanceof Uint8Array &&
                value.length === width(enc)
              ) {
                const copy = new Uint8Array(value);
                try {
                  opened = confineContentKey(
                    await primitive.aesImport(copy, false, ["decrypt"]),
                  );
                  ownedOpened = true;
                  validUnwrap = true;
                } finally {
                  copy.fill(0);
                }
              }
            }
            alive(c);
          } catch {
            alive(c);
          }
          if (opened && !validUnwrap) {
            if (ownedOpened) await opened.release();
            opened = undefined;
          }
          const sealed = new Uint8Array(ciphertext.length + 16);
          sealed.set(ciphertext);
          sealed.set(tag, ciphertext.length);
          const r = await (opened ?? fallback).decrypt(
            sealed,
            {
              iv,
              additionalData: encodeUtf8(protectedPart),
              tagLength: 128,
            },
            c,
          );
          try {
            alive(c);
            if (!r.ok || !validUnwrap)
              return err(joseError("decryption_failed", "crypto"));
            return ok(
              new JweResult(token, alg, enc, h, protectedPart, r.value),
            );
          } finally {
            if (r.ok) r.value.fill(0);
          }
        } finally {
          if (ownedOpened) await opened?.release();
          await fallback.release();
        }
      },
      "decryption_failed",
    );
  });
}
/** Compact JWE encryption and authenticated decryption operations. */
export const JWE = Object.freeze({
  /** Encrypt content into compact JWE using explicit key-management and content algorithms. */
  encrypt,
  /** Authenticate and decrypt compact JWE under an explicit policy. */
  decrypt,
  /** Check the private brand of the operation result. */
  isResult: isJweResult });
