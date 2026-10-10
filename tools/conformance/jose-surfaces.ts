import {
  JWS,
  JWE,
  Nested,
  KeyManagement,
  Custody,
  PublicKey,
  decodeBase64Url,
  encodeBase64Url,
  ok,
  type KeyHandle,
  type KeyManagementHandle,
  type Context,
  type JoseProtectedHeader,
} from "../../src/index.ts";
import { publicMembers } from "../../src/custody/jwk.ts";
import { ruleId } from "../../src/errors/types.ts";
import { sourcePlain } from "./wire.ts";
import type { Surface, CorpusResources, SurfaceResult } from "./loader.ts";
import type { BatchItem, BatchCheck } from "./batch.ts";
function record(v: unknown): v is Record<string, any> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}
function material(v: unknown, r: CorpusResources): any {
  if (record(v) && Object.hasOwn(v, "ref")) {
    const x = r.reference(v);
    if (!x.ok) throw Error("Invalid reference");
    return sourcePlain(x.value);
  }
  if (record(v) && Object.keys(v).join(",") === "b64") {
    const x = decodeBase64Url(v.b64);
    if (!x.ok) throw Error("Invalid bytes");
    return x.value;
  }
  if (record(v) && Object.keys(v).join(",") === "pairs")
    return Object.fromEntries(v.pairs);
  return v;
}
function tagged(v: unknown): number {
  if (
    !record(v) ||
    Object.keys(v).join(",") !== "int" ||
    typeof v.int !== "string" ||
    !/^\d+$/.test(v.int) ||
    !Number.isSafeInteger(Number(v.int))
  )
    throw Error("Invalid integer");
  return Number(v.int);
}
const invalid = (): SurfaceResult => ({
  ok: false,
  loaderReason: "invalid_manifest",
});
export function joseSurface(name: string): Surface {
  return async (m, r) => {
    const owners: (KeyHandle | KeyManagementHandle)[] = [];
    try {
      if (!m.policy) return invalid();
      if (
        !Object.keys(m.inputs).every((k) =>
          [
            "compact",
            "key",
            "payload",
            "protected",
            "jwe_key",
            "jws_key",
          ].includes(k),
        )
      )
        return invalid();
      const key = material(m.inputs.key, r);
      const signaturePolicy = (p: Record<string, any>, rawKey: any) => ({
        ...p,
        timeout: p.timeout === undefined ? 5000 : tagged(p.timeout),
        key_resolver: async (request: { algorithm: string }) => {
          if (request.algorithm === "HS256") {
            const h = await Custody.local({ jws: request.algorithm }, rawKey);
            if (!h.ok) return h;
            owners.push(h.value);
            return ok({ algorithm: request.algorithm, key: h.value });
          }
          const pub = await PublicKey.import(publicMembers(rawKey));
          return pub.ok
            ? ok({ algorithm: request.algorithm, key: pub.value })
            : pub;
        },
      });
      const encryptionPolicy = (p: Record<string, any>, rawKey: any) => ({
        ...p,
        timeout: tagged(p.timeout),
        max_plaintext: tagged(p.max_plaintext),
        key_resolver: async (request: { algorithm: string }) => {
          if (request.algorithm.startsWith("RSA")) {
            const h = await Custody.local({ jwe: request.algorithm }, rawKey);
            if (!h.ok) return h;
            owners.push(h.value);
            return ok({ algorithm: request.algorithm, key: h.value });
          }
          const raw = decodeBase64Url(rawKey.k);
          if (!raw.ok) return raw;
          const h = await KeyManagement.local(request.algorithm, raw.value);
          raw.value.fill(0);
          if (!h.ok) return h;
          owners.push(h.value);
          return ok({
            algorithm: request.algorithm,
            unwrap: (ek: unknown, header: JoseProtectedHeader, c: Context) =>
              h.value.unwrap(ek, header, c),
          });
        },
      });
      if (name === "jws.sign") {
        if (
          !Array.isArray(m.policy.algorithms) ||
          m.policy.algorithms.length !== 1
        )
          return invalid();
        const algorithm = m.policy.algorithms[0];
        const h = await Custody.local({ jws: algorithm }, key);
        if (!h.ok) return h;
        owners.push(h.value);
        const signed = await JWS.signProtected(
          material(m.inputs.protected, r),
          material(m.inputs.payload, r),
          h.value,
        );
        if (!signed.ok) return signed;
        if (m.class === "byte_exact")
          return ok({ bytes: new TextEncoder().encode(signed.value) });
        const verified = await JWS.verify(
          signed.value,
          signaturePolicy(m.policy, key),
        );
        return verified.ok
          ? ok({
              valid: true,
              facts: {
                payload: { b64: encodeBase64Url(verified.value.payload) },
              },
            })
          : verified;
      }
      if (name === "jws.verify") {
        const verified = await JWS.verify(
          material(m.inputs.compact, r),
          signaturePolicy(m.policy, key),
        );
        return verified.ok
          ? ok({
              valid: true,
              facts: {
                payload: { b64: encodeBase64Url(verified.value.payload) },
              },
            })
          : verified;
      }
      if (name === "jwe.decrypt") {
        const opened = await JWE.decrypt(
          material(m.inputs.compact, r),
          encryptionPolicy(m.policy, key),
        );
        return opened.ok
          ? ok({
              valid: true,
              facts: {
                payload: { b64: encodeBase64Url(opened.value.plaintext) },
              },
            })
          : opened;
      }
      if (name === "nested.decrypt") {
        if (!record(m.policy.jwe) || !record(m.policy.jws)) return invalid();
        const opened = await Nested.decrypt(
          material(m.inputs.compact, r),
          {
            jwe: encryptionPolicy(m.policy.jwe, material(m.inputs.jwe_key, r)),
            jws: signaturePolicy(m.policy.jws, material(m.inputs.jws_key, r)),
          },
          { content_types: m.policy.content_types },
        );
        return opened.ok
          ? ok({
              valid: true,
              facts: {
                payload: { b64: encodeBase64Url(opened.value.jws.payload) },
              },
            })
          : opened;
      }
      return invalid();
    } catch {
      return invalid();
    } finally {
      for (const h of owners) await h.release();
    }
  };
}
function hex(v: unknown): Uint8Array<ArrayBuffer> {
  if (typeof v !== "string" || !/^(?:[a-fA-F0-9]{2})*$/.test(v))
    throw Error("Invalid hex");
  return new Uint8Array(v.match(/../g)?.map((b) => parseInt(b, 16)) ?? []);
}
export async function joseBatchItem(
  item: BatchItem,
  m: Record<string, any>,
): Promise<BatchCheck> {
  const override = m.overrides?.[item.id],
    expected =
      override?.outcome === "reject"
        ? { rule_id: override.rule_id }
        : item.value.result;
  let owner: KeyManagementHandle | undefined;
  try {
    const g = item.parent,
      t = item.value;
    if (!g) throw Error("Invalid group");
    let algorithm: string, raw: any, header: JoseProtectedHeader;
    if (m.batch.item_format === "wycheproof-aes-gcm/1") {
      if (g.type !== "AeadTest" || typeof t.aad !== 'string' || !/^(?:[a-fA-F0-9]{2})*$/.test(t.aad)) throw Error("Invalid group");
      if (t.aad !== '') return {ok: true, expected: 'not_applicable', actual: 'not_applicable', notApplicable: true};
      raw = hex(t.key);
      algorithm = raw.length === 16 ? "A128GCMKW" : "A256GCMKW";
      header = [
        ["iv", encodeBase64Url(hex(t.iv))],
        ["tag", encodeBase64Url(hex(t.tag))],
      ];
    } else {
      if (
        g.type !== "RsaesOaepDecrypt" ||
        g.sha !== "SHA-256" ||
        g.mgf !== "MGF1" ||
        g.mgfSha !== "SHA-256" ||
        t.label !== ""
      )
        throw Error("Invalid group");
      algorithm = "RSA-OAEP-256";
      raw = g.privateKeyJwk;
      header = [];
    }
    header = [["alg", algorithm], ...header];
    const imported = await KeyManagement.local(algorithm, raw);
    if (raw instanceof Uint8Array) raw.fill(0);
    if (imported.ok) owner = imported.value;
    const result = imported.ok
      ? await imported.value.decrypt(hex(t.ct), header)
      : imported;
    const actual = result.ok ? "valid" : { rule_id: ruleId(result.error) };
    let matches = false;
    if (override?.outcome === "reject")
      matches = !result.ok && ruleId(result.error) === override.rule_id;
    else if (t.result === "valid" && result.ok) {
      const expectedBytes = hex(t.msg);
      matches =
        result.value.length === expectedBytes.length &&
        result.value.every((b, i) => b === expectedBytes[i]);
      result.value.fill(0);
    } else
      matches =
        t.result === "invalid" && !result.ok && result.error.kind === "jose";
    return { ok: matches, expected, actual };
  } catch {
    return { ok: false, expected, actual: "unexpected_item_shape" };
  } finally {
    await owner?.release();
  }
}
