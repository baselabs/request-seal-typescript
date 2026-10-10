import { snapshotWithMedia } from "./support/discovery-snapshot.ts";
import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createPrivateKey, createHash, sign } from "node:crypto";
import { gzipSync } from "node:zlib";
import { Discovery, type Result } from "../src/index.ts";
const kid = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";
function value<T>(r: Result<T>): T {
  assert.equal(r.ok, true, JSON.stringify(r));
  return (r as { ok: true; value: T }).value;
}
test("snapshot possession proofs reject mutations and bound signed key lifetime", async () => {
  const jwk = JSON.parse(
    await readFile("test/fixtures/upstream/custody/rfc8037.json", "utf8"),
  );
  const key = createPrivateKey({ key: jwk, format: "jwk" });
  delete jwk.d;
  const body = Buffer.from(JSON.stringify({ keys: [jwk] }));
  const now = Math.floor(Date.now() / 1000);
  for (const encoded of [body, gzipSync(body)]) {
    const digest =
      "sha-256=:" + createHash("sha256").update(encoded).digest("base64") + ":";
    const params = `("@authority";req "content-digest");created=${now};expires=${now + 40};keyid="${kid}";tag="http-message-signatures-directory"`;
    const base = `"@authority";req: agent.example\n"content-digest": ${digest}\n"@signature-params": ${params}`;
    const headers = [
      ["content-digest", digest],
      ["signature-input", `directory=${params}`],
      [
        "signature",
        `directory=:${sign(null, Buffer.from(base), key).toString("base64")}:`,
      ],
      ["cache-control", "max-age=300"],
      ...(encoded === body ? [] : [["content-encoding", "gzip"]]),
    ];
    const source = { type: "directory", location: "https://agent.example" };
    const set = value(
      await snapshotWithMedia(source, encoded, now, headers),
    );
    assert.equal(set.proof, "signed");
    assert.equal(set.expiresAt, now + 40);
    assert.equal(set.keys[kid]!.expiresAt, now + 40);
    for (const index of [0, 1, 2]) {
      const changed = headers.map((p) => [...p]);
      changed[index]![1] =
        index === 0
          ? "sha-256=:AAAA:"
          : index === 1
            ? `directory=${params.replace("http-message-signatures-directory", "other")}`
            : "directory=:AAAA:";
      const rejected = await snapshotWithMedia(
        source,
        encoded,
        now,
        changed,
      );
      assert.equal(rejected.ok, false);
      if (!rejected.ok)
        assert.equal(rejected.error.reason, "directory_signature_invalid");
    }
    const tampered = new Uint8Array(encoded);
    tampered[30] = tampered[30]! ^ 1;
    assert.equal(
      (await snapshotWithMedia(source, tampered, now, headers))
        .ok,
      false,
    );
  }
});
