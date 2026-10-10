// JOSE primitives share the captured runtime boundary with HTTP signing.
import * as subtle from "./subtle.ts";
export async function aesImport(
  bytes: Uint8Array,
  extractable = false,
  usages: ("encrypt" | "decrypt" | "wrapKey" | "unwrapKey")[] = [
    "encrypt",
    "decrypt",
  ],
): Promise<CryptoKey> {
  return subtle.importKey(
    "raw",
    new Uint8Array(bytes),
    { name: "AES-GCM" },
    extractable,
    usages,
  );
}
export async function aesEncrypt(
  key: CryptoKey,
  data: Uint8Array,
  iv: Uint8Array,
  aad = new Uint8Array(),
): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(
    await subtle.encrypt(
      {
        name: "AES-GCM",
        iv: new Uint8Array(iv),
        additionalData: new Uint8Array(aad),
        tagLength: 128,
      },
      key,
      new Uint8Array(data),
    ),
  );
}
export async function aesDecrypt(
  key: CryptoKey,
  data: Uint8Array,
  iv: Uint8Array,
  aad = new Uint8Array(),
): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(
    await subtle.decrypt(
      {
        name: "AES-GCM",
        iv: new Uint8Array(iv),
        additionalData: new Uint8Array(aad),
        tagLength: 128,
      },
      key,
      new Uint8Array(data),
    ),
  );
}
export async function oaepEncrypt(
  key: CryptoKey,
  data: Uint8Array,
): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(
    await subtle.encrypt({ name: "RSA-OAEP" }, key, new Uint8Array(data)),
  );
}
export async function oaepDecrypt(
  key: CryptoKey,
  data: Uint8Array,
): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(
    await subtle.decrypt({ name: "RSA-OAEP" }, key, new Uint8Array(data)),
  );
}
export async function gcmWrap(
  kek: CryptoKey,
  bytes: Uint8Array,
  iv: Uint8Array,
): Promise<Uint8Array<ArrayBuffer>> {
  // wrapKey must export the CEK. This temporary CEK is extractable; the content
  // operation and recovered key are independently imported non-extractably.
  const cek = await aesImport(bytes, true, ["encrypt"]);
  return new Uint8Array(
    await subtle.wrapKey("raw", cek, kek, {
      name: "AES-GCM",
      iv: new Uint8Array(iv),
      tagLength: 128,
    }),
  );
}
export { random, importKey, generateKey } from "./subtle.ts";

/** Native unwrap imports the recovered CEK without exposing raw bytes to JS. */
export function unwrapContentKey(
  kek: CryptoKey,
  wrapped: Uint8Array,
  algorithm: "RSA-OAEP" | "AES-GCM",
  length: 128 | 256,
  iv?: Uint8Array,
): Promise<CryptoKey> {
  return subtle.unwrapKey("raw", new Uint8Array(wrapped), kek,
    algorithm === "RSA-OAEP" ? {name: algorithm} : {name: algorithm, iv: new Uint8Array(iv!), tagLength: 128},
    {name: "AES-GCM", length}, false, ["decrypt"]);
}
