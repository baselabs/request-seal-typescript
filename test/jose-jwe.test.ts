import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { inspect } from "node:util";
import fc from "fast-check";
import * as API from "../src/index.ts";
import { Custody, ok, type Result } from "../src/index.ts";
const value = <T>(r: Result<T>): T => {
  assert.equal(r.ok, true, r.ok ? "" : JSON.stringify(r.error));
  if (!r.ok) throw Error("Rejected");
  return r.value;
};
const source = async (f: string) =>
  JSON.parse(await readFile("conformance/sources/" + f, "utf8"));
test("published OAEP and direct GCM envelopes authenticate exact protected bytes", async () => {
  assert.ok("JWE" in API, "JWE decrypt API is available");
  const { JWE, isJweResult } = await import("../src/jose/jwe.ts");
  const { KeyManagement } = await import("../src/jose/key-management.ts");
  for (const f of [
    "rfc7516/rfc7516.json",
    "rfc7520/5_2.key_encryption_using_rsa-oaep_with_aes-gcm.json",
    "rfc7520/5_6.direct_encryption_using_aes-gcm.json",
  ]) {
    const v = await source(f),
      wire = v.compact ?? v.output.compact,
      key = v.key ?? v.input.key;
    const h = JSON.parse(
      Buffer.from(wire.split(".")[0], "base64url").toString(),
    );
    const owner =
      h.alg === "dir"
        ? value(
            await KeyManagement.local("dir", value(API.decodeBase64Url(key.k))),
          )
        : value(await Custody.local({ jwe: h.alg }, key));
    const policy = {
      algorithms: [h.alg],
      encryption: [h.enc],
      timeout: 5000,
      max_plaintext: 1048576,
      key_resolver: () =>
        ok(
          h.alg === "dir"
            ? {
                algorithm: h.alg,
                unwrap: (
                  ek: unknown,
                  header: API.JoseProtectedHeader,
                  c: API.Context,
                ) => ("unwrap" in owner ? owner.unwrap(ek, header, c) : null),
              }
            : { algorithm: h.alg, key: owner },
        ),
    };
    try {
      const r = value(await JWE.decrypt(wire, policy));
      assert.deepEqual(
        r.plaintext,
        new TextEncoder().encode(v.plaintext ?? v.input.plaintext),
      );
      assert.ok(isJweResult(r));
      assert.ok(Object.isFrozen(r));
      assert.ok(!isJweResult({ ...r }));
      assert.ok(!inspect(r).includes(wire.split(".")[0]));
      const original = r.plaintext;
      r.plaintext.fill(0);
      assert.deepEqual(r.plaintext, original);
      const parts = wire.split("."),
        tag = value(API.decodeBase64Url(parts[4]));
      tag[0]! ^= 1;
      parts[4] = API.encodeBase64Url(tag);
      const bad = await JWE.decrypt(parts.join("."), policy);
      assert.equal(bad.ok, false);
      if (!bad.ok)
        assert.deepEqual(bad.error, {
          kind: "jose",
          reason: "decryption_failed",
          layer: "crypto",
          correlation: null,
          retryable: false,
        });
    } finally {
      await owner.release();
    }
  }
});
test("fresh encryption round trips random plaintext through every wrapping algorithm and both content ciphers", async () => {
  assert.ok("JWE" in API, "JWE encrypt API is available");
  const { JWE } = await import("../src/jose/jwe.ts");
  const { KeyManagement } = await import("../src/jose/key-management.ts");
  const rsa = (await source("rfc7516/rfc7516.json")).key;
  for (const alg of [
    "RSA-OAEP",
    "RSA-OAEP-256",
    "A128GCMKW",
    "A256GCMKW",
    "dir",
  ])
    for (const enc of ["A128GCM", "A256GCM"]) {
      const owner = alg.startsWith("RSA")
        ? value(await Custody.local({ jwe: alg }, rsa))
        : alg === "dir"
          ? undefined
          : value(
              await KeyManagement.local(
                alg,
                crypto.getRandomValues(
                  new Uint8Array(alg === "A128GCMKW" ? 16 : 32),
                ),
              ),
            );
      try {
        await fc.assert(
          fc.asyncProperty(
            fc.uint8Array({ maxLength: 256 }),
            async (plaintext) => {
              let direct:
                | Awaited<ReturnType<typeof KeyManagement.local>>
                | undefined;
              const recipient = alg.startsWith("RSA")
                ? owner
                : async (a: string, cek: Uint8Array) => {
                    if (a === "dir") {
                      direct = await KeyManagement.local(a, cek);
                      return ok({
                        encrypted_key: new Uint8Array(),
                        header: [],
                      });
                    }
                    return (owner as API.KeyManagementHandle).wrap(a, cek);
                  };
              const token = value(
                await JWE.encrypt(
                  [
                    ["alg", alg],
                    ["enc", enc],
                  ],
                  plaintext,
                  recipient,
                ),
              );
              const policy = {
                algorithms: [alg],
                encryption: [enc],
                timeout: 5000,
                max_plaintext: 1048576,
                key_resolver: () =>
                  ok(
                    alg.startsWith("RSA")
                      ? { algorithm: alg, key: owner }
                      : {
                          algorithm: alg,
                          unwrap: (
                            ek: unknown,
                            h: API.JoseProtectedHeader,
                            c: API.Context,
                          ) =>
                            (alg === "dir"
                              ? value(direct!)
                              : (owner as API.KeyManagementHandle)
                            ).unwrap(ek, h, c),
                        },
                  ),
              };
              assert.deepEqual(
                value(await JWE.decrypt(token, policy)).plaintext,
                plaintext,
              );
              if (direct) await value(direct).release();
            },
          ),
          { seed: 7516, numRuns: 12 },
        );
      } finally {
        await owner?.release();
      }
    }
});
