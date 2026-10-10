import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fc from "fast-check";
import * as api from "../src/index.ts";
const A = api as any,
  text = new TextEncoder();
const hasher = {
  create(algorithm: string) {
    const h = createHash(algorithm === "sha-256" ? "sha256" : "sha512");
    return {
      update(bytes: Uint8Array) {
        h.update(bytes);
      },
      finish() {
        return new Uint8Array(h.digest());
      },
    };
  },
};
test("content digests match RFC 9530 published checksums", async () => {
  assert.equal(typeof A.digest, "function");
  const r = await A.digest(text.encode('{"hello": "world"}\n'), [
    "sha-256",
    "sha-512",
  ]);
  assert.equal(r.ok, true);
  assert.equal(
    new TextDecoder().decode(r.value),
    "sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:, sha-512=:YMAam51Jz/jOATT6/zvHrLVgOYTGFy1d6GJiOHTohq4yP+pgk4vf2aCsyRZOtw8MjkM7iw7yZ/WkppmM44T3qg==:",
  );
  assert.equal(
    (await A.digest(new Uint8Array(), ["md5"])).error.reason,
    "unsupported_algorithm",
  );
  assert.equal(
    (await A.digest(new Uint8Array(api.DIGEST_MAX_BYTES + 1), ["sha-256"]))
      .error.reason,
    "limit",
  );
  assert.equal(
    (await A.digest(new Uint8Array(api.DIGEST_MAX_BYTES), ["sha-256"])).ok,
    true,
  );
});
test("incremental digests agree with one-shot hashes over random chunking", async () => {
  assert.equal(typeof A.DigestState?.create, "function");
  await fc.assert(
    fc.asyncProperty(
      fc.uint8Array({ maxLength: 2000 }),
      fc.integer({ min: 1, max: 100 }),
      async (bytes, size) => {
        const r = await A.DigestState.create(
          "content",
          ["sha-256", "sha-512"],
          hasher,
        );
        assert.equal(r.ok, true);
        const state = r.value;
        for (let i = 0; i < bytes.length; i += size)
          assert.equal(
            (await state.update(bytes.subarray(i, i + size))).ok,
            true,
          );
        const result = await state.finish();
        assert.equal(result.ok, true);
        assert.deepEqual(
          result.value,
          (await A.digest(bytes, ["sha-256", "sha-512"])).value,
        );
        assert.equal(A.isDigestState({ ...state }), false);
        assert.equal((await state.update(bytes)).error.reason, "invalid_state");
      },
    ),
    { numRuns: 30 },
  );
});
test("incremental limits reject excess bytes and permit explicit larger budgets", async () => {
  assert.equal(typeof A.DigestState?.create, "function");
  const r = await A.DigestState.create("content", ["sha-256"], hasher, {
    maxBytes: 3,
  });
  assert.equal(r.ok, true);
  assert.equal((await r.value.update(text.encode("abc"))).ok, true);
  assert.equal((await r.value.update(text.encode("d"))).error.reason, "limit");
  assert.equal(
    (
      await A.DigestState.create("content", ["sha-256"], hasher, {
        maxBytes: api.DIGEST_MAX_BYTES + 1,
      })
    ).ok,
    true,
  );
});
test("received digests reject duplicate supported algorithms weak-only fields and mismatches", async () => {
  assert.equal(typeof A.checkDigest, "function");
  const msg = async (field: string, bytes = "") => {
    const r = await api.Message.request(
      "GET",
      "https://example.com/",
      [["content-digest", field]],
      bytes,
    );
    assert.equal(r.ok, true);
    return (r as any).value;
  };
  const empty = "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:";
  for (const [field, bytes, reason] of [
    [empty + ", " + empty, "", "conflicting_digest"],
    ["md5=:AA==:", "", "unsupported_algorithm"],
    [empty, "abc", "mismatch"],
    ["sha-256=:AA==:", "", "invalid_digest_length"],
  ] as const) {
    const r = await A.checkDigest(await msg(field, bytes), "content");
    assert.equal(r.error.reason, reason);
  }
  const r = await A.checkDigest(
    await msg(empty + ", unknown=:AA==:"),
    "content",
  );
  assert.equal(r.ok, true);
  assert.deepEqual(r.value.unsupported, ["unknown"]);
});
test("hasher construction detects mislabeled real SHA-2 implementations", async () => {
  assert.equal(typeof A.DigestState?.create, "function");
  const wrong = {
    create() {
      const h = createHash("sha512");
      return {
        update(bytes: Uint8Array) {
          h.update(bytes);
        },
        finish() {
          return new Uint8Array(h.digest());
        },
      };
    },
  };
  const r = await A.DigestState.create("content", ["sha-256"], wrong);
  assert.equal(r.ok, false);
  assert.equal(r.error.reason, "invalid_state");
});

for (const operation of ["update", "finish"] as const)
  for (const mode of ["return", "throw"] as const)
    for (const name of ["mismatch", "limit"] as const)
      test("caller hasher " + operation + " " + mode + " " + name + " becomes invalid_state", async () => {
        const {digestError} = await import("../src/errors/types.ts");
        let armed = false;
        const port = {create(algorithm: string) {
          const h = createHash(algorithm === "sha-256" ? "sha256" : "sha512");
          const fault = () => {const e = digestError(name); if (mode === "throw") throw e; return e;};
          return {
            update(chunk: Uint8Array) {if (armed && operation === "update") return fault(); h.update(chunk);},
            finish() {if (armed && operation === "finish") return fault(); return new Uint8Array(h.digest());},
          };
        }};
        const state = (await A.DigestState.create("content", ["sha-256"], port)).value;
        assert.ok(state);
        if (operation === "finish") assert.equal((await state.update(text.encode("abc"))).ok, true);
        armed = true;
        const r = operation === "update" ? await state.update(text.encode("abc")) : await state.finish();
        assert.equal(r.ok, false);
        assert.equal(r.error.kind, "digest"); assert.equal(r.error.reason, "invalid_state");
        assert.equal((await state.finish()).error.reason, "invalid_state");
      });
