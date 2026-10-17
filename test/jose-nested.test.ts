import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import * as API from "../src/index.ts";
import { Custody, PublicKey, ok, type Result } from "../src/index.ts";
import { publicMembers } from "../src/custody/jwk.ts";
const value = <T>(r: Result<T>): T => {
  assert.equal(r.ok, true, r.ok ? "" : JSON.stringify(r.error));
  if (!r.ok) throw Error("Rejected");
  return r.value;
};
test("published nesting authenticates the outer envelope and verifies one inner signature", async () => {
  assert.ok("Nested" in API, "one-level nested decrypt API is available");
  const { Nested, isNestedResult } = await import("../src/jose/nested.ts");
  const v = JSON.parse(
    await readFile(
      "conformance/sources/rfc7520/6.nesting_signatures_and_encryption.json",
      "utf8",
    ),
  );
  const owner = value(
    await Custody.local({ jwe: "RSA-OAEP" }, v.encrypt.input.key),
  );
  const publicKey = value(
    await PublicKey.import(publicMembers(v.sign.input.key)),
  );
  const jwe = {
    algorithms: ["RSA-OAEP"],
    encryption: ["A128GCM"],
    max_plaintext: 1048576,
    timeout: 5000,
    key_resolver: () => ok({ algorithm: "RSA-OAEP", key: owner }),
  };
  const jws = {
    algorithms: ["PS256"],
    timeout: 5000,
    key_resolver: () => ok({ algorithm: "PS256", key: publicKey }),
  };
  try {
    const r = value(
      await Nested.decrypt(
        v.encrypt.output.compact,
        { jwe, jws },
        { content_types: ["JWT"] },
      ),
    );
    assert.ok(isNestedResult(r));
    assert.ok(Object.isFrozen(r));
    assert.ok(!isNestedResult({ ...r }));
    assert.deepEqual(
      r.jws.payload,
      new TextEncoder().encode(v.sign.input.payload),
    );
    const mismatch = await Nested.decrypt(
      v.encrypt.output.compact,
      { jwe, jws },
      { content_types: ["JWS"] },
    );
    assert.equal(mismatch.ok, false);
    if (!mismatch.ok)
      assert.equal(mismatch.error.reason, "content_type_mismatch");
    const deeper = value(
      await API.JWE.encrypt(
        [
          ["alg", "RSA-OAEP"],
          ["enc", "A128GCM"],
          ["cty", "JWT"],
        ],
        v.encrypt.output.compact,
        owner,
      ),
    );
    const depth = await Nested.decrypt(
      deeper,
      { jwe, jws },
      { content_types: ["JWT"] },
    );
    assert.equal(depth.ok, false);
    if (!depth.ok) assert.equal(depth.error.reason, "nesting_depth");
  } finally {
    await owner.release();
  }
});

test('inner compact size failures preserve limit while segment failures report nesting depth', async () => {
  const {innerCompact} = await import('../src/jose/nested.ts');
  const {JOSE_MAX_COMPACT_BYTES} = await import('../src/constants.ts');
  const huge = innerCompact(new Uint8Array(JOSE_MAX_COMPACT_BYTES + 1));
  assert.equal(!huge.ok && huge.error.reason, 'limit');
  const segments = innerCompact(new TextEncoder().encode('a.b.c.d'));
  assert.equal(!segments.ok && segments.error.reason, 'nesting_depth');
});

test('an inner cty naming ordinary typed payload content verifies while JOSE media types still reject', async () => {
  const { Nested } = await import("../src/jose/nested.ts");
  const v = JSON.parse(
    await readFile(
      "conformance/sources/rfc7520/6.nesting_signatures_and_encryption.json",
      "utf8",
    ),
  );
  const owner = value(await Custody.local({ jwe: "RSA-OAEP" }, v.encrypt.input.key));
  const signer = value(await Custody.local({ jws: "PS256" }, v.sign.input.key));
  const publicKey = value(await PublicKey.import(publicMembers(v.sign.input.key)));
  const jwePolicy = {
    algorithms: ["RSA-OAEP"],
    encryption: ["A128GCM"],
    max_plaintext: 1048576,
    timeout: 5000,
    key_resolver: () => ok({ algorithm: "RSA-OAEP", key: owner }),
  };
  const jwsPolicy = {
    algorithms: ["PS256"],
    timeout: 5000,
    key_resolver: () => ok({ algorithm: "PS256", key: publicKey }),
  };
  const payload = new TextEncoder().encode(v.sign.input.payload);
  const wrap = async (cty: string) => {
    const jws = value(await API.JWS.sign([["alg", "PS256"], ["cty", cty]], payload, signer));
    return value(
      await API.JWE.encrypt(
        [["alg", "RSA-OAEP"], ["enc", "A128GCM"], ["cty", "JWT"]],
        jws,
        owner,
      ),
    );
  };
  try {
    // Any other inner cty names ordinary typed payload content and is the
    // application's business, with or without the abbreviation rule.
    for (const cty of ["application/json", "json", "text/plain", "application/example+jws"]) {
      const token = await wrap(cty);
      const r = value(await Nested.decrypt(token, { jwe: jwePolicy, jws: jwsPolicy }, { content_types: ["JWT"] }));
      assert.deepEqual(r.jws.payload, payload, cty);
    }
    // A JOSE media type declares the payload is another JOSE envelope, which
    // this one-level module refuses: registered and per-structure spellings,
    // abbreviated forms, parameters stripped before the abbreviation rule,
    // and case differences all classify (RFC 7515 Sections 4.1.10, 9.2.1).
    for (const cty of [
      "application/jose",
      "application/jose+json",
      "application/jws",
      "application/jwe",
      "application/jwt",
      "JWT",
      "jose",
      "JWS",
      "Jwt",
      'JWT;x="a/b"',
      "application/JWT",
    ]) {
      const token = await wrap(cty);
      const r = await Nested.decrypt(token, { jwe: jwePolicy, jws: jwsPolicy }, { content_types: ["JWT"] });
      assert.equal(r.ok, false, cty);
      if (!r.ok) assert.equal(r.error.reason, "nesting_depth", cty);
    }
  } finally {
    await owner.release();
    await signer.release();
  }
});
