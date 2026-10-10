import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { inspect } from "node:util";
import fc from "fast-check";
import * as API from "../src/index.ts";
import { Custody, PublicKey, ok, type Result } from "../src/index.ts";
import { publicMembers } from "../src/custody/jwk.ts";
const value = <T>(r: Result<T>): T => {
  assert.equal(r.ok, true, r.ok ? "" : JSON.stringify(r.error));
  if (!r.ok) throw Error("Rejected");
  return r.value;
};
const source = async (f: string) =>
  JSON.parse(await readFile("conformance/sources/" + f, "utf8"));
test("published HMAC and RSA protected bytes sign exactly and verify before releasing payload", async () => {
  assert.ok("JWS" in API, "JWS sign and verify API is available");
  const { JWS, isJwsResult } = await import("../src/jose/jws.ts");
  const v = await source("rfc7515/rfc7515.json");
  for (const [section, alg] of [
    ["A.1", "HS256"],
    ["A.2", "RS256"],
  ] as const) {
    const vector = v[section],
      parts = vector.compact.split(".");
    const h = value(await Custody.local({ jws: alg }, vector.key));
    try {
      const payload = value(API.decodeBase64Url(parts[1]));
      const token = value(
        await JWS.signProtected(
          value(API.decodeBase64Url(parts[0])),
          payload,
          h,
        ),
      );
      assert.equal(token, vector.compact);
      const policy = {
        algorithms: [alg],
        timeout: 5000,
        key_resolver: () => ok({ algorithm: alg, key: h }),
      };
      const r = value(await JWS.verify(token, policy));
      assert.deepEqual(r.payload, payload);
      assert.equal(r.protected, parts[0]);
      assert.ok(isJwsResult(r));
      assert.ok(!isJwsResult({ ...r }));
      assert.ok(Object.isFrozen(r));
      r.payload.fill(0);
      assert.deepEqual(r.payload, payload);
      assert.ok(!inspect(r).includes(parts[0]));
      assert.ok(!JSON.stringify(r).includes(parts[0]));
      const bad = value(API.decodeBase64Url(parts[2]));
      bad[0]! ^= 1;
      assert.equal(
        (
          await JWS.verify(
            parts.slice(0, 2).concat(API.encodeBase64Url(bad)).join("."),
            policy,
          )
        ).ok,
        false,
      );
    } finally {
      await h.release();
    }
  }
});
test("every supported JWS algorithm obeys random payload round trips", async () => {
  assert.ok("JWS" in API, "all eight JWS algorithms are available");
  const { JWS } = await import("../src/jose/jws.ts");
  const rsa = (await source("rfc7515/rfc7515.json"))["A.2"].key;
  const ec = (await source("rfc7515/rfc7515.json"))["A.3"].key;
  const ed = await source("rfc8037/rfc8037.json");
  const p384 = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-384" },
    true,
    ["sign", "verify"],
  );
  for (const alg of [
    "RS256",
    "PS256",
    "PS384",
    "PS512",
    "HS256",
    "ES256",
    "ES384",
    "EdDSA",
  ] as const) {
    const material =
      alg === "HS256"
        ? { hmac: crypto.getRandomValues(new Uint8Array(32)) }
        : alg === "ES256"
          ? ec
          : alg === "ES384"
            ? await crypto.subtle.exportKey("jwk", p384.privateKey)
            : alg === "EdDSA"
              ? ed
              : rsa;
    const h = value(await Custody.local({ jws: alg }, material));
    try {
      const key =
        alg === "HS256"
          ? h
          : value(await PublicKey.import(publicMembers(material)));
      const policy = {
        algorithms: [alg],
        timeout: 5000,
        key_resolver: () => ok({ algorithm: alg, key }),
      };
      await fc.assert(
        fc.asyncProperty(
          fc.uint8Array({ minLength: 1, maxLength: 128 }),
          async (payload) => {
            const token = value(await JWS.sign([["alg", alg]], payload, h));
            assert.deepEqual(
              value(await JWS.verify(token, policy)).payload,
              payload,
            );
          },
        ),
        { seed: 7515, numRuns: 16 },
      );
    } finally {
      await h.release();
    }
  }
});
