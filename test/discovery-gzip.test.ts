import { snapshotWithMedia } from "./support/discovery-snapshot.ts";
import test from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import { gzipSync, constants } from "node:zlib";
import { Discovery, type Result } from "../src/index.ts";
const jwk = {
  kty: "OKP",
  crv: "Ed25519",
  x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
};
const kid = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";
const source = {
  type: "jwks_uri",
  location: "https://agent.example",
  maxBytes: 262144,
  maxDecodedBytes: 262144,
};
function value<T>(r: Result<T>): T {
  assert.equal(r.ok, true, JSON.stringify(r));
  return (r as { ok: true; value: T }).value;
}
test("gzip snapshots reject concatenation and unused compressed bytes on every runtime", async () => {
  const body = Buffer.from(JSON.stringify({ keys: [jwk] }));
  const zipped = gzipSync(body),
    empty = gzipSync("");
  value(
    await snapshotWithMedia(source, zipped, 100, [
      ["content-encoding", "gzip"],
    ]),
  );
  for (const bytes of [
    Buffer.concat([zipped, zipped]),
    Buffer.concat([empty, zipped]),
    Buffer.concat([zipped, empty]),
    Buffer.concat([
      zipped.subarray(0, -8),
      Buffer.from([0, 0]),
      zipped.subarray(-8),
    ]),
  ]) {
    const r = await snapshotWithMedia(source, bytes, 100, [
      ["content-encoding", "gzip"],
    ]);
    assert.equal(
      r.ok,
      false,
      "one gzip member must consume all compressed bytes",
    );
    if (!r.ok) assert.equal(r.error.reason, "invalid_response");
  }
});
test("stored, fixed and dynamic DEFLATE blocks retain independently compressed bytes", async () => {
  const body = Buffer.from(
    JSON.stringify({
      keys: [jwk],
      padding: "abcdefghijklmnopqrstuvwxyz0123456789".repeat(2000),
    }),
  );
  for (const [settings, kind] of [
    [{ level: 0 }, 0],
    [{ strategy: constants.Z_FIXED }, 1],
    [{ level: 9 }, 2],
  ] as const) {
    const zipped = gzipSync(body, settings);
    assert.equal((zipped[10]! >> 1) & 3, kind);
    const set = value(
      await snapshotWithMedia(source, zipped, 100, [
        ["content-encoding", "gzip"],
      ]),
    );
    assert.deepEqual(Object.keys(set.keys), [kid]);
  }
});
test("generated gzip payloads preserve key sets and refuse inserted stream suffixes", async () => {
  await fc.assert(
    fc.asyncProperty(fc.string({ maxLength: 4096 }), async (padding) => {
      const zipped = gzipSync(JSON.stringify({ keys: [jwk], padding }));
      assert.deepEqual(
        Object.keys(
          value(
            await snapshotWithMedia(source, zipped, 100, [
              ["content-encoding", "gzip"],
            ]),
          ).keys,
        ),
        [kid],
      );
      const suffix = Buffer.concat([
        zipped.subarray(0, -8),
        Buffer.from([0]),
        zipped.subarray(-8),
      ]);
      assert.equal(
        (
          await snapshotWithMedia(source, suffix, 100, [
            ["content-encoding", "gzip"],
          ])
        ).ok,
        false,
      );
    }),
    { seed: 1951, numRuns: 30 },
  );
});

test('dynamic DEFLATE distance tables reject reserved HDIST values like zlib', async () => {
  const {deflateSize} = await import('../src/discovery/deflate.ts');
  const {inflateRawSync} = await import('node:zlib');
  function block(distances: number): Uint8Array {
    const bits: number[] = [];
    const write = (value: number, width: number) => {for (let i = 0; i < width; i++) bits.push((value >> i) & 1);};
    write(1, 1); write(2, 2); write(0, 5); write(distances - 1, 5); write(14, 4);
    const order = [16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1];
    for (const n of order) write(n === 0 || n === 1 ? 1 : 0, 3);
    for (let i = 0; i < 257; i++) write(i === 256 ? 1 : 0, 1);
    for (let i = 0; i < distances; i++) write(i === 0 ? 1 : 0, 1);
    write(0, 1);
    const out = new Uint8Array(Math.ceil(bits.length / 8)); for (let i = 0; i < bits.length; i++) out[i >> 3]! |= bits[i]! << (i & 7);
    return out;
  }
  const valid = block(30); assert.equal(inflateRawSync(valid).length, 0); assert.equal(deflateSize(valid, 0, valid.length, 16), 0);
  for (const count of [31, 32]) {const bad = block(count); assert.throws(() => inflateRawSync(bad)); assert.throws(() => deflateSize(bad, 0, bad.length, 16));}
});
