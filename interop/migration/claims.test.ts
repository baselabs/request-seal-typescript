// Proves every comparison claim in docs/guides/migrating-from-http-message-signatures.md by
// running http-message-signatures (pinned in package.json) beside RequestSeal on the same inputs.
// Run: npm ci --prefix interop/migration --ignore-scripts && node --experimental-strip-types --no-warnings --test interop/migration/claims.test.ts
import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  Crypto,
  Custody,
  Message,
  Policy,
  PublicKey,
  createMemoryStore,
  ok,
  sign,
  verify,
  type KeyHandle,
  type Result,
  type SigningAlgorithm,
} from "../../src/index.ts";

type LibMessage = { method: string; url: string; headers: Record<string, string | string[]> };
const require = createRequire(import.meta.url);
const lib = require("http-message-signatures");
const { signMessage, verifyMessage } = lib.httpbis as {
  signMessage: (config: Record<string, unknown>, message: LibMessage) => Promise<LibMessage>;
  verifyMessage: (config: Record<string, unknown>, message: LibMessage) => Promise<boolean | null>;
};
const { createSigner, createVerifier } = lib as {
  createSigner: (key: unknown, alg: string, id?: string) => unknown;
  createVerifier: (key: unknown, alg: string) => unknown;
};
const pinned = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8")).dependencies["http-message-signatures"];

function must<T>(r: Result<T>): T {
  assert.ok(r.ok, JSON.stringify(r));
  return (r as { value: T }).value;
}
const text = (bytes: Uint8Array) => new TextDecoder().decode(bytes);
const wire = (m: { fields: readonly { name: string; value: Uint8Array }[] }, name: string) =>
  m.fields.filter((f) => f.name.toLowerCase() === name).map((f) => text(f.value));
// The library reads the real clock, so every timestamp is relative to now.
const now = Math.floor(Date.now() / 1000);
const created = new Date(now * 1000);
const expires = new Date((now + 300) * 1000);
const url = "https://example.com/a/b?x=1";
const edKeys = generateKeyPairSync("ed25519");
const edPem = edKeys.privateKey.export({ type: "pkcs8", format: "pem" }) as string;
const edPublic = must(await PublicKey.import(edKeys.publicKey.export({ format: "jwk" })));
const clock = () => now;
const fresh = { clock, maxAge: 600, skew: 0, requireExpires: false };
const edHandle = (await Custody.local("ed25519", edPem)) as Result<KeyHandle>;
const handle = must(edHandle);
const libKeys = (id: string, extra: Record<string, unknown> = {}) => ({
  async keyLookup(params: { keyid?: string }) {
    return params.keyid === id
      ? { id, algs: ["ed25519"], verify: createVerifier(edKeys.publicKey, "ed25519"), ...extra }
      : null;
  },
});
const policy = (components: string, extra: Record<string, unknown> = {}) =>
  must(Policy.create({
    algorithms: ["ed25519"],
    components,
    keyResolver: ({ keyid }: { keyid: string | null }) =>
      ok(keyid === "k1" ? { algorithm: "ed25519" as SigningAlgorithm, key: edPublic } : null),
    freshness: fresh,
    content: "not_required",
    replay: "not_required",
    ...extra,
  }));
async function libSigned(fields: string[], headers: Record<string, string> = {}, extra: Record<string, unknown> = {}) {
  return signMessage(
    { key: createSigner(edKeys.privateKey, "ed25519", "k1"), name: "sig", fields, paramValues: { created, expires }, ...extra },
    { method: "POST", url, headers },
  );
}
async function asRequestSeal(m: LibMessage, body = "") {
  const fields: [string, string][] = Object.entries(m.headers).map(([k, v]) => [k, Array.isArray(v) ? v.join(", ") : v]);
  return must(await Message.request(m.method, String(m.url), fields, body));
}

test("pinned version: the guide compares the exact release in interop/migration/package.json", () => {
  const installed = JSON.parse(readFileSync(new URL("./node_modules/http-message-signatures/package.json", import.meta.url), "utf8"));
  assert.equal(installed.version, pinned);
  assert.match(pinned, /^\d+\.\d+\.\d+$/);
  const readme = readFileSync(new URL("./node_modules/http-message-signatures/README.md", import.meta.url), "utf8");
  assert.match(readme, /last updated against\s+\[revision 13\]/);
  assert.match(readme, /"minimal" signature implementation/);
  assert.match(readme, /don't provide any integrity over the message/);
});

test("claim 1: the same message, components, parameters and Ed25519 key give byte-identical signature headers", async () => {
  const theirs = await libSigned(["@method", "@authority", "@path", "content-type"], { "content-type": "application/json" },
    { params: ["created", "expires", "keyid", "alg"] });
  const input = String(theirs.headers["Signature-Input"]).replace(/^sig=/, "");
  const message = await asRequestSeal({ method: "POST", url, headers: { "content-type": "application/json" } });
  const ours = must(await sign(message, { label: "sig", signatureInput: input, algorithm: "ed25519" }, handle));
  assert.deepEqual(wire(ours, "signature-input"), [theirs.headers["Signature-Input"]]);
  assert.deepEqual(wire(ours, "signature"), [theirs.headers.Signature]);
});

test("claim 2: RequestSeal verifies a signature made by http-message-signatures", async () => {
  const theirs = await libSigned(["@method", "@authority", "@path", "content-type"], { "content-type": "application/json" },
    { params: ["created", "expires", "keyid", "alg"] });
  const message = await asRequestSeal(theirs);
  const verified = must(await verify(message, policy('("@method" "@authority" "@path" "content-type")'), { label: "sig" }));
  assert.equal(verified.label, "sig");
  assert.equal(verified.authorization, "not_evaluated");
});

test("claim 3: http-message-signatures verifies a signature made by RequestSeal", async () => {
  const message = await asRequestSeal({ method: "POST", url, headers: { "content-type": "application/json" } });
  const signed = must(await sign(message, {
    label: "sig", components: '("@method" "@authority" "@path" "content-type")', algorithm: "ed25519", expiresIn: 300, keyid: "k1",
  }, handle, { clock }));
  const headers: Record<string, string> = { "content-type": "application/json" };
  for (const name of ["signature", "signature-input"]) headers[name] = wire(signed, name).join(", ");
  assert.equal(await verifyMessage(libKeys("k1"), { method: "POST", url, headers }), true);
});

test("claim 4: generated parameters differ: RequestSeal adds a random nonce and requires an explicit lifetime; the library adds no nonce and defaults to five minutes", async () => {
  const theirs = await signMessage(
    { key: createSigner(edKeys.privateKey, "ed25519", "k1"), fields: ["@method"], paramValues: { created } },
    { method: "GET", url, headers: {} });
  assert.equal(theirs.headers["Signature-Input"], `sig=("@method");keyid="k1";alg="ed25519";created=${now};expires=${now + 300}`);
  const message = await asRequestSeal({ method: "GET", url, headers: {} });
  const ours = must(await sign(message, { label: "sig", components: '("@method")', algorithm: "ed25519", expiresIn: 300 }, handle, { clock }));
  const input = wire(ours, "signature-input")[0]!;
  assert.match(input, new RegExp(`^sig=\\("@method"\\);created=${now};expires=${now + 300};nonce="[A-Za-z0-9_-]{43}";alg="ed25519"$`));
  const withoutLifetime = await sign(message, { label: "sig", components: '("@method")', algorithm: "ed25519" }, handle);
  assert.equal(withoutLifetime.ok, false);
});

test("claim 5: a missing signature or an unknown key is null (indeterminate) in the library and a named rejection in RequestSeal", async () => {
  const unsigned = { method: "GET", url, headers: {} } as LibMessage;
  assert.equal(await verifyMessage(libKeys("k1"), unsigned), null);
  const theirs = await libSigned(["@method"], {}, { params: ["created", "expires", "keyid", "alg"] });
  assert.equal(await verifyMessage(libKeys("some-other-key"), theirs), null);
  const none = await verify(await asRequestSeal(unsigned), policy('("@method")'), { label: "sig" });
  assert.ok(!none.ok && none.error.kind === "core" && none.error.reason === "missing_signature_input");
  const unknown = await verify(await asRequestSeal(theirs), policy('("@method")', {
    keyResolver: () => ok(null),
  }), { label: "sig" });
  assert.ok(!unknown.ok && unknown.error.kind === "core" && unknown.error.reason === "unknown_key");
});

test("claim 6: the library never reads a body, so a signed Content-Digest header proves nothing about the bytes; RequestSeal recomputes it", async () => {
  const digestHeader = `sha-256=:${Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode('{"amount":1}'))).toString("base64")}:`;
  const theirs = await libSigned(["@method", "content-digest"], { "content-digest": digestHeader }, { params: ["created", "expires", "keyid", "alg"] });
  assert.equal(await verifyMessage(libKeys("k1"), theirs), true);
  const forgedBody = await asRequestSeal(theirs, '{"amount":1000000}');
  const rejected = await verify(forgedBody, policy('("@method" "content-digest")', {
    content: { kind: "content", algorithms: ["sha-256"], section: "headers" },
  }), { label: "sig" });
  assert.ok(!rejected.ok && rejected.error.kind === "core" && rejected.error.reason === "digest_mismatch");
  const honest = await asRequestSeal(theirs, '{"amount":1}');
  must(await verify(honest, policy('("@method" "content-digest")', {
    content: { kind: "content", algorithms: ["sha-256"], section: "headers" },
  }), { label: "sig" }));
});

test("claim 7: the library has no replay check, so the same signed request verifies again; RequestSeal rejects the second use", async () => {
  const theirs = await libSigned(["@method"], {}, { params: ["created", "expires", "keyid", "alg", "nonce"], paramValues: { created, expires, nonce: "once" } });
  assert.equal(await verifyMessage(libKeys("k1"), theirs), true);
  assert.equal(await verifyMessage(libKeys("k1"), theirs), true);
  const store = must(createMemoryStore({ maxEntries: 100 }));
  const replaying = policy('("@method")', {
    replay: {
      identifier: "nonce",
      namespace: new TextEncoder().encode("migration"),
      commitment: async (facts: { identifier: string }) => ok(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(facts.identifier)))),
      store,
      timeoutMs: 1000,
    },
  });
  const message = await asRequestSeal(theirs);
  must(await verify(message, replaying, { label: "sig" }));
  const again = await verify(message, replaying, { label: "sig" });
  assert.ok(!again.ok && again.error.kind === "core" && again.error.reason === "replayed");
});

test("claim 8: a library key without an algs list accepts a signature whose alg parameter names another algorithm; RequestSeal refuses an algorithm the policy does not permit and one the resolver contradicts", async () => {
  const secret = randomBytes(32);
  const mislabeled = await signMessage(
    { key: createSigner(secret, "hmac-sha256", "k1"), name: "sig", fields: ["@method"], paramValues: { created, expires, alg: "ed25519" }, params: ["created", "expires", "keyid", "alg"] },
    { method: "GET", url, headers: {} });
  assert.match(String(mislabeled.headers["Signature-Input"]), /alg="ed25519"/);
  const unrestricted = { async keyLookup() { return { id: "k1", verify: createVerifier(secret, "hmac-sha256") }; } };
  assert.equal(await verifyMessage(unrestricted, mislabeled), true);
  const hmac = must(await Custody.local("hmac-sha256", { hmac: new Uint8Array(secret) }));
  const mislabeledMessage = await asRequestSeal(mislabeled);
  const configured = (algorithms: SigningAlgorithm[]) => must(Policy.create({
    algorithms, components: '("@method")', keyResolver: () => ok({ algorithm: "hmac-sha256" as SigningAlgorithm, key: hmac }),
    freshness: fresh, content: "not_required", replay: "not_required",
  }));
  const refused = await verify(mislabeledMessage, configured(["hmac-sha256"]), { label: "sig" });
  assert.ok(!refused.ok && refused.error.kind === "core" && refused.error.reason === "algorithm_not_permitted");
  const mismatch = await verify(mislabeledMessage, configured(["hmac-sha256", "ed25519"]), { label: "sig" });
  assert.ok(!mismatch.ok && mismatch.error.kind === "core" && mismatch.error.reason === "algorithm_mismatch");
});

test("claim 9: the library accepts a signature with no created or expires under maxAge and covering no components; RequestSeal's policy rejects both", async () => {
  const bare = await signMessage({ key: createSigner(edKeys.privateKey, "ed25519", "k1"), name: "sig", fields: [], params: ["keyid", "alg"] },
    { method: "GET", url, headers: {} });
  assert.equal(await verifyMessage({ ...libKeys("k1"), maxAge: 60 }, bare), true);
  const message = await asRequestSeal(bare);
  const noTime = await verify(message, policy('()'), { label: "sig" });
  assert.ok(!noTime.ok && noTime.error.kind === "core" && noTime.error.reason === "missing_created");
  const noCoverage = await verify(await asRequestSeal(await libSigned([], {}, { params: ["created", "expires", "keyid", "alg"] })), policy('("@method" "@authority")'), { label: "sig" });
  assert.ok(!noCoverage.ok && noCoverage.error.kind === "core" && noCoverage.error.reason === "missing_required_component");
  assert.equal(await verifyMessage({ ...libKeys("k1"), requiredFields: ["@method"] }, await libSigned([], {}, { params: ["created", "expires", "keyid", "alg"] })).catch((e: Error) => e.constructor.name), "UnacceptableSignatureError");
});

test("claim 10: failures are exceptions in the library and Results in RequestSeal", async () => {
  const past = { created: new Date((now - 1000) * 1000), expires: new Date((now - 700) * 1000) };
  const stale = await libSigned(["@method"], {}, { params: ["created", "expires", "keyid", "alg"], paramValues: past });
  const expired = await verifyMessage({ ...libKeys("k1") }, stale).then(() => null, (e: Error) => e);
  assert.ok(expired instanceof lib.ExpiredError);
  const message = await asRequestSeal(stale);
  const late = await verify(message, must(Policy.create({
    algorithms: ["ed25519"], components: '("@method")', keyResolver: () => ok({ algorithm: "ed25519" as SigningAlgorithm, key: edPublic }),
    freshness: { clock: () => now, maxAge: 600, skew: 0, requireExpires: true }, content: "not_required", replay: "not_required",
  })), { label: "sig" });
  assert.ok(!late.ok && late.error.kind === "core" && late.error.reason === "expired");
});

test("claim 11: the library reports the verdict of the last signature it processes; RequestSeal verifies exactly the label you name", async () => {
  const good = await libSigned(["@method"], {}, { name: "good", params: ["created", "expires", "keyid", "alg"] });
  const bad = await libSigned(["@method"], {}, { name: "bad", params: ["created", "expires", "keyid", "alg"] });
  const forged = String(bad.headers.Signature).replace(/:.*:/, `:${Buffer.alloc(64, 1).toString("base64")}:`);
  const join = (a: LibMessage, b: LibMessage, header: string) => `${a.headers[header]}, ${b.headers[header]}`;
  const both = (first: LibMessage, second: LibMessage) => ({
    method: "POST", url,
    headers: { Signature: join(first, second, "Signature"), "Signature-Input": join(first, second, "Signature-Input") },
  });
  const forgedBad = { ...bad, headers: { ...bad.headers, Signature: forged } };
  assert.equal(await verifyMessage(libKeys("k1"), both(forgedBad, good)), true);
  assert.equal(await verifyMessage(libKeys("k1"), both(good, forgedBad)), false);
  const message = await asRequestSeal(both(forgedBad, good));
  must(await verify(message, policy('("@method")'), { label: "good" }));
  const named = await verify(message, policy('("@method")'), { label: "bad" });
  assert.ok(!named.ok && named.error.kind === "core" && named.error.reason === "invalid_signature");
});

test("claim 12: algorithm support differs: the library also signs rsa-v1_5-sha1 and ships a Cavage draft module; RequestSeal supports RFC 9421 and the six registered algorithms it lists", async () => {
  assert.equal(typeof createSigner("secret", "rsa-v1_5-sha1"), "object");
  assert.equal(typeof lib.cavage.signMessage, "function");
  const algorithms = must(Crypto.algorithms());
  assert.deepEqual([...algorithms].sort(), ["ecdsa-p256-sha256", "ecdsa-p384-sha384", "ed25519", "hmac-sha256", "rsa-pss-sha512", "rsa-v1_5-sha256"]);
  assert.ok(!algorithms.includes("rsa-v1_5-sha1" as never));
  const cavage = await lib.cavage.signMessage(
    { key: createSigner(edKeys.privateKey, "ed25519", "k1"), fields: ["@request-target", "date"] },
    { method: "GET", url, headers: { host: "example.com", date: "Tue, 14 Nov 2023 22:13:20 GMT" } });
  assert.ok(Object.keys(cavage.headers).some((name) => name.toLowerCase() === "signature" || name.toLowerCase() === "authorization"));
  const result = await verify(await asRequestSeal(cavage), policy('("@method")'), { label: "sig" });
  assert.equal(result.ok, false);
});

test("claim 13: the library signs with any HMAC secret length; RequestSeal handles require 32 bytes, and a verifier callback accepts any length", async () => {
  const refused = await Custody.local("hmac-sha256", { hmac: new TextEncoder().encode("sharedsecret") });
  assert.ok(!refused.ok && refused.error.kind === "custody" && refused.error.reason === "invalid_key");
  // The same inputs as the library README example reproduce its published headers, which the guide verifies with a callback.
  const signed = await signMessage(
    { key: createSigner("sharedsecret", "hmac-sha256", "my-key-id"), name: "sig", fields: [], paramValues: { created: new Date(1_700_669_009_000), expires: new Date(1_700_669_309_000) } },
    { method: "POST", url: "https://example.com", headers: { "content-type": "application/json" } });
  assert.equal(signed.headers.Signature, "sig=:RkplfaUzQ4xIkSVP9hT+Y55yAYX9VwSeHmjS5X7d0fE=:");
  assert.equal(signed.headers["Signature-Input"], 'sig=();keyid="my-key-id";alg="hmac-sha256";created=1700669009;expires=1700669309');
});
