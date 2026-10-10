import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  JWS,
  JWE,
  Nested,
  KeyManagement,
  Custody,
  ok,
  err,
  withDeadline,
  decodeBase64Url,
  encodeBase64Url,
  type Context,
  type JoseProtectedHeader,
  type Result,
} from "../src/index.ts";
import { joseError } from "../src/errors/types.ts";
import { random } from "../src/jose/key-management.ts";
import { value } from "./support/jose-oaep.ts";
const bytes = (s: string) => new TextEncoder().encode(s);
const fault = (r: Result<unknown>, reason: string) => {
  assert.equal(r.ok, false);
  if (!r.ok) {
    assert.equal(r.error.kind, "jose");
    assert.equal(r.error.reason, reason);
    assert.ok(!JSON.stringify(r.error).includes("private-canary"));
  }
};
test("JWS policies, resolver contracts and byte mutations return the exact bounded reasons", async () => {
  const v = JSON.parse(
    await readFile("conformance/sources/rfc7515/rfc7515.json", "utf8"),
  )["A.2"];
  const owner = value(await Custody.local({ jws: "RS256" }, v.key));
  const p = {
    algorithms: ["RS256"],
    timeout: 5000,
    key_resolver: () => ok({ algorithm: "RS256", key: owner }),
  };
  try {
    for (const policy of [
      { ...p, extra: true },
      { ...p, algorithms: [] },
      { ...p, algorithms: ["ES512"] },
      { ...p, algorithms: ["RS256", "RS256"] },
      { ...p, timeout: 0 },
    ])
      fault(await JWS.verify(v.compact, policy), "invalid_policy");
    fault(
      await JWS.verify(v.compact, { ...p, algorithms: ["PS256"] }),
      "algorithm_not_permitted",
    );
    fault(
      await JWS.verify(v.compact, {
        ...p,
        key_resolver: () => err(joseError("unknown_key", "key")),
      }),
      "unknown_key",
    );
    fault(
      await JWS.verify(v.compact, {
        ...p,
        key_resolver: () => ok({ algorithm: "PS256", key: owner }),
      }),
      "algorithm_mismatch",
    );
    fault(
      await JWS.verify(v.compact, {
        ...p,
        key_resolver: () => {
          throw Error("private-canary");
        },
      }),
      "key_resolver_failed",
    );
    fault(
      await JWS.verify(v.compact, {
        ...p,
        key_resolver: () => ok({ algorithm: "RS256", key: owner, extra: true }),
      }),
      "key_resolver_failed",
    );
    fault(
      await JWS.verify(v.compact, {
        ...p,
        key_resolver: () =>
          ok({
            algorithm: "RS256",
            verify: async (
              a: unknown,
              base: Uint8Array,
              sig: Uint8Array,
              c: Context,
            ) => {
              await owner.verify(a, sig, base, c);
              throw Error("private-canary");
            },
          }),
      }),
      "invalid_signature",
    );
    const parts = v.compact.split(".");
    parts[0] = encodeBase64Url(bytes('{ "alg":"RS256" }'));
    fault(await JWS.verify(parts.join("."), p), "invalid_signature");
    parts[1] = "";
    fault(await JWS.verify(parts.join("."), p), "detached_payload");
    fault(await JWS.verify("{}.x.y", p), "unsupported_serialization");
    fault(await JWS.verify(null, p), "invalid_serialization");
    fault(await JWS.verify(v.compact + ".", p), "invalid_serialization");
    fault(
      await JWS.sign([["alg", "RS256"]], bytes("x"), owner, { timeout: 0 }),
      "invalid_options",
    );
    fault(
      await JWS.sign([["alg", "PS256"]], bytes("x"), owner),
      "algorithm_mismatch",
    );
    let reads = 0;
    const opts = {
      get timeout() {
        reads++;
        return 5000;
      },
    };
    assert.equal(
      (await JWS.sign([["alg", "RS256"]], bytes("x"), owner, opts)).ok,
      true,
    );
    assert.equal(reads, 1);
    const parent = value(withDeadline({ timeoutMs: 1 }));
    await new Promise((r) => setTimeout(r, 5));
    fault(
      await JWS.sign([["alg", "RS256"]], bytes("x"), owner, {
        context: parent,
      }),
      "deadline_exceeded",
    );
    const slow = {
      ...p,
      timeout: 2,
      key_resolver: async () => {
        await new Promise((r) => setTimeout(r, 30));
        return p.key_resolver();
      },
    };
    fault(await JWS.verify(v.compact, slow), "deadline_exceeded");
    await owner.release();
    fault(
      await JWS.sign([["alg", "RS256"]], bytes("x"), owner),
      "signer_failed",
    );
  } finally {
    await owner.release();
  }
});
test("JWE policies, IV/tag bounds, custody failures and callback deadlines stay closed", async () => {
  const v = JSON.parse(
    await readFile(
      "conformance/sources/rfc7520/5_6.direct_encryption_using_aes-gcm.json",
      "utf8",
    ),
  );
  const owner = value(
    await KeyManagement.local("dir", value(decodeBase64Url(v.input.key.k))),
  );
  const unwrap = (ek: unknown, h: JoseProtectedHeader, c: Context) =>
    owner.unwrap(ek, h, c);
  const p = {
    algorithms: ["dir"],
    encryption: ["A128GCM"],
    timeout: 5000,
    max_plaintext: 1048576,
    key_resolver: () => ok({ algorithm: "dir", unwrap }),
  };
  try {
    assert.equal((await JWE.decrypt(v.output.compact, p)).ok, true);
    for (const [index, width, reason] of [
      [2, 11, "invalid_iv"],
      [4, 15, "invalid_tag"],
    ] as const) {
      const parts = v.output.compact.split(".");
      parts[index] = encodeBase64Url(new Uint8Array(width));
      fault(await JWE.decrypt(parts.join("."), p), reason);
    }
    fault(
      await JWE.decrypt(v.output.compact, { ...p, max_plaintext: 1 }),
      "limit",
    );
    fault(
      await JWE.decrypt(v.output.compact, { ...p, encryption: ["A256GCM"] }),
      "algorithm_not_permitted",
    );
    fault(
      await JWE.decrypt(v.output.compact, { ...p, max_plaintext: 0 }),
      "invalid_policy",
    );
    fault(
      await JWE.decrypt(v.output.compact, {
        ...p,
        key_resolver: () =>
          ok({
            algorithm: "dir",
            unwrap: () => {
              throw Error("private-canary");
            },
          }),
      }),
      "decryption_failed",
    );
    const late = {
      ...p,
      timeout: 2,
      key_resolver: () =>
        ok({
          algorithm: "dir",
          unwrap: async (ek: unknown, h: JoseProtectedHeader, c: Context) => {
            await new Promise((r) => setTimeout(r, 30));
            return unwrap(ek, h, c);
          },
        }),
    };
    fault(await JWE.decrypt(v.output.compact, late), "deadline_exceeded");
    const opaque = value(
      await owner.unwrap(new Uint8Array(), [["alg", "dir"]], value(withDeadline())),
    );
    assert.equal(JSON.stringify(opaque), '{"kind":"UnwrappedKey"}');
    await opaque.release();
    await owner.release();
    fault(await JWE.decrypt(v.output.compact, p), "decryption_failed");
  } finally {
    await owner.release();
  }
});
test("entropy requests beyond the WebCrypto quota return the exact bounded error", () => {
  assert.equal(random(32).length, 32);
  assert.throws(
    () => random(65537),
    (e) =>
      !!e &&
      typeof e === "object" &&
      JSON.stringify(e) ===
        '{"kind":"jose","reason":"entropy_failure","layer":"crypto","correlation":null,"retryable":false}',
  );
});
test("an AES capability cannot authenticate under a different declared content-key width", async () => {
  const cek = crypto.getRandomValues(new Uint8Array(32)),
    iv = crypto.getRandomValues(new Uint8Array(12));
  const header = encodeBase64Url(bytes('{"alg":"dir","enc":"A128GCM"}'));
  const key = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, [
    "encrypt",
  ]);
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: bytes(header), tagLength: 128 },
      key,
      bytes("payload"),
    ),
  );
  const wire = [
    header,
    "",
    encodeBase64Url(iv),
    encodeBase64Url(sealed.slice(0, -16)),
    encodeBase64Url(sealed.slice(-16)),
  ].join(".");
  const owner = value(await KeyManagement.local("dir", cek));
  try {
    const p = {
      algorithms: ["dir"],
      encryption: ["A128GCM"],
      max_plaintext: 1024,
      timeout: 5000,
      key_resolver: () =>
        ok({
          algorithm: "dir",
          unwrap: (ek: unknown, h: JoseProtectedHeader, c: Context) =>
            owner.unwrap(ek, h, c),
        }),
    };
    fault(await JWE.decrypt(wire, p), "decryption_failed");
  } finally {
    await owner.release();
  }
});
