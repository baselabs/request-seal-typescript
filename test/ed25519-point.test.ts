import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { PublicKey, Custody, type Result } from "../src/index.ts";
import { publicSpki, writePem } from "../src/custody/der.ts";
import { encodeBase64Url } from "../src/bytes.ts";
const value = <T>(r: Result<T>): T => { assert.ok(r.ok, JSON.stringify(r)); return r.value; };
// Defensive inputs independently confirmed by Elixir 56b8f0c's Euler-criterion test.
for (const y of [2, 7, 8]) for (const sign of [0, 1])
test(`Ed25519 non-point y=${y}, sign=${sign} rejects across all public formats`, async () => {
  const bytes = new Uint8Array(32); bytes[0] = y; bytes[31] = sign << 7;
  const jwk = { kty: "OKP", crv: "Ed25519", x: encodeBase64Url(bytes) };
  const spki = value(publicSpki(jwk));
  for (const [format, material] of [["jwk", jwk], ["spki", spki], ["der", spki], ["pem", value(writePem("PUBLIC KEY", spki))]] as const) {
    const result = await PublicKey.import(material, format);
    assert.equal(!result.ok && result.error.reason, "invalid_key", format);
  }
  const seed = JSON.parse(readFileSync("test/fixtures/upstream/custody/rfc8037.json", "utf8"));
  const privateImport = await Custody.local("ed25519", { ...seed, x: jwk.x });
  if (privateImport.ok) await privateImport.value.release();
  assert.equal(!privateImport.ok && privateImport.error.reason, "invalid_key");
});

test("published RFC 8037 public key and RFC 8032 points import in every supported format", async () => {
  for (const hex of [
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
    "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
  ]) {
    const jwk = { kty: "OKP", crv: "Ed25519", x: encodeBase64Url(new Uint8Array(Buffer.from(hex, "hex"))) };
    const spki = value(publicSpki(jwk));
    for (const [format, material] of [["jwk", jwk], ["spki", spki], ["der", spki], ["pem", value(writePem("PUBLIC KEY", spki))]] as const)
      assert.equal(value((await PublicKey.import(material, format))).jwk().ok, true);
  }
});
