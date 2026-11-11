import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createPrivateKey, createPublicKey, createHash, sign, verify } from "node:crypto";
import { createServer } from "node:http";
import { once } from "node:events";
import * as Seal from "../src/index.ts";
import * as N from "../src/adapters/node-http/index.ts";
import * as F from "../src/adapters/fetch/index.ts";
import { rawRequest } from "./support/wire-server.ts";
import { nodeAdapterTest } from "./support/node-adapter-test.ts";
const networkTest = nodeAdapterTest(import.meta.url);
const value = <T>(r: Seal.Result<T>): T => { assert.ok(r.ok, JSON.stringify(r)); return r.value; };
const text = (b: Uint8Array) => new TextDecoder().decode(b);
const privatePem = readFileSync("conformance/sources/rfc9421/keys/ed25519_private.pem", "utf8");
const privateKey = createPrivateKey(privatePem), publicKey = createPublicKey(privateKey);
const components = '("@target-uri" "@authority" "@scheme")';
const spec = { label: "sig", algorithm: "ed25519", signatureInput: components };
function policy(key: Seal.PublicKey) {
  return value(Seal.Policy.create({ algorithms: ["ed25519"], components,
    keyResolver: () => Seal.ok({ algorithm: "ed25519", key }),
    freshness: "not_evaluated", content: "not_required", replay: "not_required" }));
}
// Exact values from Elixir f27282a and RFC 9421 Sections 2.2.2–2.2.4.
for (const [url, authority, scheme] of [
  ["https://EXAMPLE.COM:443/", "example.com", "https"],
  ["http://Example.Org:80/x?y=1", "example.org", "http"],
  ["https://Example.COM:08443/a%2Fb?y=%2f", "example.com:08443", "https"],
  ["https://[2001:DB8::A]:443/", "[2001:db8::a]", "https"],
  ["HTTPS://EXAMPLE.COM:443/a%2Fb?x=%2f", "example.com", "https"],
] as const) test(`target URI bytes survive construction and reciprocal signatures: ${url}`, async () => {
  const h = value(await Seal.Custody.local("ed25519", privatePem));
  try {
    const key = value(await h.publicKey());
    const m = value(await Seal.Message.request("GET", url, [], ""));
    const expected = `"@target-uri": ${url}\n"@authority": ${authority}\n"@scheme": ${scheme}\n"@signature-params": ${components}`;
    assert.equal(text(value(Seal.SignatureBase.build(m, components))), expected);
    const signed = value(await Seal.sign(m, spec, h));
    const signature = text(signed.fields.find(f => f.name.toLowerCase() === "signature")!.value);
    assert.ok(verify(null, Buffer.from(expected), publicKey, Buffer.from(signature.slice(5, -1), "base64")));
    const reciprocal = value(Seal.Message.create({ ...signed, fields: signed.fields.map(f =>
      f.name.toLowerCase() === "signature" ? value(Seal.FieldOccurrence.create({ name: f.name,
        section: "headers", value: `sig=:${sign(null, Buffer.from(expected), privateKey).toString("base64")}:` })) : f) }));
    value(await Seal.verify(reciprocal, policy(key), { label: "sig" }));
    const tampered = value(Seal.Message.create({ ...reciprocal, authority: reciprocal.authority!.toLowerCase() === reciprocal.authority
      ? reciprocal.authority!.toUpperCase() : reciprocal.authority!.toLowerCase() }));
    const rejected = await Seal.verify(tampered, policy(key), { label: "sig" });
    assert.equal(!rejected.ok && rejected.error.reason, "invalid_signature");
    const response = value(await Seal.Message.response(200, [], "", { request: m }));
    const related = '("@target-uri";req "@authority";req)';
    assert.equal(text(value(Seal.SignatureBase.build(response, related))),
      `"@target-uri";req: ${url}\n"@authority";req: ${authority}\n"@signature-params": ${related}`);
  } finally { await h.release(); }
});

for (const field of ["forwarded", "x-forwarded"] as const)
networkTest(`${field} reconstruction preserves the trusted external URI spelling`, async () => {
  const h = value(await Seal.Custody.local("ed25519", privatePem));
  const key = value(await h.publicKey());
  const server = createServer((req, res) => {
    void (async () => {
      const captured = value(await N.captureRequest(req, { trustedProxies: { peers: ["127.0.0.1"], field } }));
      const verified = await Seal.verify(captured.message, policy(key), { label: "sig" });
      res.statusCode = verified.ok ? 204 : 401;
      res.end();
    })().catch(() => { res.statusCode = 500; res.end(); });
  });
  server.listen(0, "127.0.0.1"); await once(server, "listening");
  const address = server.address(); assert.ok(address && typeof address === "object");
  try {
    const target = "HTTPS://EXAMPLE.COM:443/a%2Fb?x=%2f";
    const base = `"@target-uri": ${target}\n"@authority": example.com\n"@scheme": https\n"@signature-params": ${components}`;
    const forwarded = field === "forwarded" ? 'Forwarded: proto=HTTPS;host="EXAMPLE.COM:443"'
      : 'X-Forwarded-Proto: HTTPS\r\nX-Forwarded-Host: EXAMPLE.COM:443';
    const wire = `GET /a%2Fb?x=%2f HTTP/1.1\r\nHost: internal.example\r\n${forwarded}\r\nSignature-Input: sig=${components}\r\nSignature: sig=:${sign(null, Buffer.from(base), privateKey).toString("base64")}:\r\nConnection: close\r\n\r\n`;
    assert.match((await rawRequest(address.port, wire)).toString(), /^HTTP\/1\.1 204/);
  } finally {
    server.closeAllConnections();
    await new Promise<void>(resolve => server.close(() => resolve()));
    await h.release();
  }
});

test("preserved authorities are validated before component normalization", async () => {
  for (const url of ["https://EXAMPLE.COM:000443/", "http://Example.Org:000080/", "https://EXAMPLE.COM:65536/", "https://user@EXAMPLE.COM/"])
    assert.equal((await Seal.Message.request("GET", url, [], "")).ok, false, url);
});

for (const existing of [false, true])
test(`adding a label preserves covered digest bytes (existing=${existing})`, async () => {
  const h = value(await Seal.Custody.local("ed25519", privatePem));
  try {
    const key = value(await h.publicKey()), body = "exact POST content\n";
    const digest = ` sha-512=:${createHash("sha512").update(body).digest("base64")}:,  sha-256=:${createHash("sha256").update(body).digest("base64")}: `;
    const m = value(await Seal.Message.request("POST", "https://EXAMPLE.COM:443/submit",
      existing ? [["Content-Digest", digest]] : [], body));
    const components = '("@method" "@target-uri" "@authority" "content-digest")';
    const spec = { label: "first", algorithm: "ed25519", components, expiresIn: 60, digest: ["sha-256", "sha-512"] };
    const first = value(await Seal.sign(m, spec, h));
    const before = first.fields.filter(f => f.name.toLowerCase() === "content-digest");
    if (existing) assert.equal(text(before[0]!.value), digest);
    const second = value(await Seal.sign(first, { ...spec, label: "second" }, h));
    assert.deepEqual(second.fields.filter(f => f.name.toLowerCase() === "content-digest"), before);
    const p = value(Seal.Policy.create({ algorithms: ["ed25519"], components,
      keyResolver: () => Seal.ok({ algorithm: "ed25519", key }), freshness: "not_evaluated",
      content: { kind: "content", algorithms: ["sha-256", "sha-512"], section: "headers" }, replay: "not_required" }));
    for (const label of ["first", "second"]) value(await Seal.verify(second, p, { label }));
    const changed = value(Seal.Message.create({ ...second, body: { state: "retained", bytes: "tampered" } }));
    const rejected = await Seal.verify(changed, p, { label: "second" });
    assert.equal(!rejected.ok && rejected.error.reason, "digest_mismatch");
  } finally { await h.release(); }
});

for (const transport of ["wire", "node", "fetch"] as const)
networkTest(`${transport} signatures bind the authority actually sent`, async () => {
  const h = value(await Seal.Custody.local("ed25519", privatePem));
  const key = value(await h.publicKey());
  const seen: string[] = [];
  const server = createServer((req, res) => {
    void (async () => {
      const captured = value(await N.captureRequest(req));
      seen.push(captured.message.authority!);
      const verified = await Seal.verify(captured.message, policy(key), { label: "sig" });
      res.statusCode = verified.ok ? 204 : 401;
      res.end();
    })().catch(() => { res.statusCode = 500; res.end(); });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address(); assert.ok(address && typeof address === "object");
  const url = `http://LOCALHOST:${address.port}/a%2Fb?x=%2f`;
  try {
    if (transport === "wire") {
      const m = value(await Seal.Message.request("GET", url, [], ""));
      // Sign an independently specified wire base, rather than the constructor's result.
      const base = `"@target-uri": ${url}\n"@authority": localhost:${address.port}\n"@scheme": http\n"@signature-params": ${components}`;
      const wire = `GET /a%2Fb?x=%2f HTTP/1.1\r\nHost: LOCALHOST:${address.port}\r\nSignature-Input: sig=${components}\r\nSignature: sig=:${sign(null, Buffer.from(base), privateKey).toString("base64")}:\r\nConnection: close\r\n\r\n`;
      assert.ok(m);
      assert.match((await rawRequest(address.port, wire)).toString(), /^HTTP\/1\.1 204/);
      assert.deepEqual(seen, [`LOCALHOST:${address.port}`]);
    } else if (transport === "node") {
      const result = value(await N.signedRequest({ url }, { label: "sig", algorithm: "ed25519", components, expiresIn: 60 }, h));
      assert.equal(result.message.status, 204);
      assert.deepEqual(seen, [`localhost:${address.port}`]);
    } else {
      const result = value(await F.signRequest(new Request(url), { label: "sig", algorithm: "ed25519", components, expiresIn: 60 }, h));
      assert.equal((await fetch(result.request)).status, 204);
      assert.deepEqual(seen, [`localhost:${address.port}`]);
    }
  } finally {
    server.closeAllConnections();
    await new Promise<void>(resolve => server.close(() => resolve()));
    await h.release();
  }
});
