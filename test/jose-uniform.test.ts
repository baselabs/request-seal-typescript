import test from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import {
  JWE,
  KeyManagement,
  ok,
  type Context,
  type JoseProtectedHeader,
  decodeBase64Url,
  encodeBase64Url,
  isRequestSealError,
} from "../src/index.ts";
import { oaepCases, value } from "./support/jose-oaep.ts";
test("OAEP leading zero, masked seed, masked data block and tag corruption yield identical complete errors", async (t) => {
  for (const algorithm of ["RSA-OAEP", "RSA-OAEP-256"] as const) {
    const v = await oaepCases(algorithm, (s) => t.diagnostic(s));
    try {
      assert.equal((await JWE.decrypt(v.cases.valid, v.policy)).ok, true);
      for (const name of [
        "leading_zero",
        "masked_seed",
        "masked_data_block",
        "tag",
      ]) {
        const r = await JWE.decrypt(v.cases[name], v.policy);
        assert.equal(r.ok, false);
        if (r.ok) throw Error("Released plaintext");
        assert.ok(Object.isFrozen(r));
        assert.ok(Object.isFrozen(r.error));
        assert.ok(isRequestSealError(r.error));
        assert.equal(JSON.stringify(r.error), JSON.stringify({
          kind: "jose",
          reason: "decryption_failed",
          layer: "crypto",
          correlation: null,
          retryable: false,
        }));
        t.diagnostic(algorithm + " " + name + " " + JSON.stringify(r.error));
      }
      await fc.assert(
        fc.asyncProperty(
          fc.integer({ min: 0, max: 4 }),
          fc.nat(),
          fc.integer({ min: 0, max: 7 }),
          async (index, offset, bit) => {
            const parts = v.cases.valid!.split("."),
              bytes = value(decodeBase64Url(parts[index]));
            bytes[offset % bytes.length]! ^= 1 << bit;
            parts[index] = encodeBase64Url(bytes);
            const r = await JWE.decrypt(parts.join("."), v.policy);
            assert.equal(r.ok, false);
            if (!r.ok) {
              assert.equal(r.error.kind, "jose");
              assert.ok(Object.isFrozen(r));
              assert.ok(Object.isFrozen(r.error));
              assert.ok(isRequestSealError(r.error));
              assert.equal(JSON.stringify(r.error), JSON.stringify({
                kind: "jose", reason: index === 0 ? r.error.reason : "decryption_failed",
                layer: index === 0 ? r.error.layer : "crypto", correlation: null, retryable: false,
              }));
            }
          },
        ),
        { seed: 7518, numRuns: 48 },
      );
    } finally {
      await v.release();
    }
  }
});

test("wrong content keys and callback failures share the complete frozen error", async () => {
  const source = await import('node:fs/promises');
  const v = JSON.parse(await source.readFile('conformance/sources/rfc7520/5_6.direct_encryption_using_aes-gcm.json', 'utf8'));
  const real = value(await KeyManagement.local('dir', value(decodeBase64Url(v.input.key.k))));
  const wrong = value(await KeyManagement.local('dir', crypto.getRandomValues(new Uint8Array(16))));
  const makePolicy = (unwrap: Function) => ({algorithms: ['dir'], encryption: ['A128GCM'], max_plaintext: 1048576, timeout: 5000, key_resolver: () => ok({algorithm: 'dir', unwrap})});
  const expected = '{"kind":"jose","reason":"decryption_failed","layer":"crypto","correlation":null,"retryable":false}';
  const check = (r: Awaited<ReturnType<typeof JWE.decrypt>>) => {
    assert.equal(r.ok, false);
    if (r.ok) throw Error('Released plaintext');
    assert.ok(Object.isFrozen(r)); assert.ok(Object.isFrozen(r.error)); assert.ok(isRequestSealError(r.error));
    assert.equal(JSON.stringify(r.error), expected);
  };
  try {
    const open = (ek: unknown, h: JoseProtectedHeader, c: Context) => real.unwrap(ek, h, c);
    assert.equal((await JWE.decrypt(v.output.compact, makePolicy(open))).ok, true);
    check(await JWE.decrypt(v.output.compact, makePolicy((ek: unknown, h: JoseProtectedHeader, c: Context) => wrong.unwrap(ek, h, c))));
    check(await JWE.decrypt(v.output.compact, makePolicy(() => {throw Error('private-canary');})));
    await wrong.release();
    check(await JWE.decrypt(v.output.compact, makePolicy((ek: unknown, h: JoseProtectedHeader, c: Context) => wrong.unwrap(ek, h, c))));
    for (const segment of [0, 1, 2, 3, 4]) await fc.assert(fc.asyncProperty(fc.constant(segment), fc.nat(), fc.integer({min: 0, max: 7}), async (index, offset, bit) => {
      const parts = v.output.compact.split('.');
      const expected = ['algorithm_not_permitted', 'decryption_failed', 'decryption_failed', 'decryption_failed', 'decryption_failed'][index];
      if (index === 0) {
        const data = value(decodeBase64Url(parts[0]));
        const at = new TextDecoder().decode(data).indexOf('dir'); assert.ok(at >= 0);
        data[at + offset % 3]! ^= 1 << (bit % 5); parts[0] = encodeBase64Url(data);
      } else if (index === 1) parts[1] = encodeBase64Url(new Uint8Array([1 << bit]));
      else {const data = value(decodeBase64Url(parts[index])); data[offset % data.length]! ^= 1 << bit; parts[index] = encodeBase64Url(data);}
      const result = await JWE.decrypt(parts.join('.'), makePolicy(open));
      assert.equal(!result.ok && result.error.reason, expected, 'segment ' + index);
      if (index !== 0) check(result);
    }), {seed: 7516, numRuns: 48});
  } finally {await real.release(); await wrong.release();}
});
