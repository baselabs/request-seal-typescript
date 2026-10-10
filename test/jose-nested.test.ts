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
