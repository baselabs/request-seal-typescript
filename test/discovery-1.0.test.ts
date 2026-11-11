import nodeTest from "node:test";
import { nodeAdapterTest } from "./support/node-adapter-test.ts";
const test = nodeTest, networkTest = nodeAdapterTest(import.meta.url);
import assert from "node:assert/strict";
import { DiscoverySource, Discovery, type Result } from "../src/index.ts";
import { Discovery as NodeDiscovery } from "../src/discovery/node.ts";
import { fields, header, values, expiry, mediaType } from "../src/discovery/headers.ts";
import { decodeBody } from "../src/discovery/gzip.ts";
import { peer, jwks, kid } from "./support/discovery-peer.ts";
const value = <T>(r: Result<T>): T => { assert.ok(r.ok, JSON.stringify(r)); return r.value; };
const bytes = (s: string) => new TextEncoder().encode(s);
const epoch = 1735689600;
const date = (now: number) => new Date(now * 1000).toUTCString();

for (const mode of ["ordinary", "conditional", "nested", "outer-clamp", "max-ttl", "key-expiry"] as const)
networkTest(`RFC 9111 corrected age includes real TLS response delay: ${mode}`, async () => {
  let now = epoch;
  const p = await peer((req, res) => {
    now += req.url === "/keys" ? 40 : 30;
    const outer = mode === "nested" || mode === "outer-clamp";
    res.writeHead(mode === "conditional" ? 304 : 200, {
      "content-type": "application/json", "cache-control": `max-age=${req.url === "/client.json" ? mode === "outer-clamp" ? 110 : 600 : 300}`,
      date: date(epoch), age: "100", etag: '"v1"',
    });
    res.end(outer && req.url === "/client.json"
      ? JSON.stringify({ client_id: `https://127.0.0.1:${p.port}/client.json`, jwks_uri: `https://127.0.0.1:${p.port}/keys` })
      : mode === "key-expiry" ? JSON.stringify({ keys: [{ ...JSON.parse(jwks()).keys[0], exp: epoch + 90 }] }) : jwks());
  });
  try {
    const nested = mode === "nested" || mode === "outer-clamp";
    const source = value(DiscoverySource.create({ type: nested ? "cimd" : "jwks_uri",
      location: `https://127.0.0.1:${p.port}/${nested ? "client.json" : "keys"}`,
      permittedAddresses: ["127.0.0.1"], cacerts: [p.ca], ...(mode === "max-ttl" ? { minTtl: 0, maxTtl: 150 } : {}) }));
    let samples = 0;
    const options = { clock: () => {
      const sampled = now;
      // Account for document processing separately from the nested fetch.
      if (nested && ++samples === 2) now += 10;
      return sampled;
    } };
    const set = value(mode === "conditional"
      ? await NodeDiscovery.fetchWithValidators(source, '"v1"', 300, options)
      : await NodeDiscovery.fetch(source, options));
    if ("keys" in set) assert.ok(set.keys[kid]);
    // max(Age + response_delay, response_time - Date); both requests have their own delay.
    assert.equal(set.expiresAt, epoch + (mode === "nested" ? 240 : mode === "outer-clamp" ? 30 : mode === "max-ttl" ? 50 : mode === "key-expiry" ? 90 : 200));
    if (mode === "ordinary") assert.equal(set.fetchedAt, epoch + 40);
  } finally { await p.close(); }
});

test("snapshots have zero response delay and retain max-TTL and no-cache clamps", async () => {
  const source = value(DiscoverySource.create({ type: "jwks_uri", location: "https://agent.example/keys", minTtl: 0, maxTtl: 150 }));
  for (const [control, ttl] of [["max-age=300", 50], ["no-cache, max-age=300", 0]] as const) {
    const set = value(await Discovery.resolver.fromSnapshot(source, bytes(jwks()), epoch,
      [["content-type", "application/json"], ["cache-control", control], ["age", "100"], ["date", date(epoch)]]));
    assert.equal(set.expiresAt, epoch + ttl);
  }
});

test("discovery field boundaries trim SP and HTAB without deleting obs-text whitespace", async () => {
  const source = value(DiscoverySource.create({ type: "jwks_uri", location: "https://agent.example/keys", minTtl: 7 }));
  for (const space of [new Uint8Array([0xa0]), bytes("\u2003"), bytes("\u202f"), bytes("\u3000")]) {
    const raw = new Uint8Array([32, 9, ...space, ...bytes("application/json"), ...space, 9, 32]);
    const fs = fields([["content-type", raw]]);
    const retained = String.fromCharCode(...raw.subarray(2, -2));
    assert.equal(header(fs, "content-type"), retained);
    assert.deepEqual(values(fs, "content-type"), [retained]);
    assert.throws(() => mediaType(fs, "jwks_uri"), (e: unknown) => !!e && typeof e === "object" && "reason" in e && e.reason === "unexpected_media_type");
  }
  const fs = fields([["cache-control", "\xa0max-age=300\xa0"]]);
  assert.equal(expiry(fs, source, epoch), epoch + 7);
  await assert.rejects(() => decodeBody(bytes(jwks()), "\xa0identity\xa0", 65536));
  assert.doesNotThrow(() => mediaType(fields([["content-type", " \tapplication/json\t ;charset=utf-8"]]), "jwks_uri"));
  assert.deepEqual(await decodeBody(bytes(jwks()), " \tidentity\t ", 65536), bytes(jwks()));
});

networkTest("real TLS framing and media fields reject non-OWS boundaries", async () => {
  for (const [name, token, expected] of [["Content-Length", "2", "invalid_response"], ["Transfer-Encoding", "chunked", "invalid_response"], ["Content-Encoding", "identity", "invalid_response"], ["Content-Type", "application/json", "unexpected_media_type"]] as const) {
    const p = await peer((_req, res) => res.end());
    p.server.removeAllListeners("request");
    p.server.on("secureConnection", socket => {
      socket.on("error", () => {});
      socket.once("data", () => socket.end(Buffer.from(`HTTP/1.1 200 OK\r\n${name === "Content-Type" ? "" : "Content-Type: application/json\r\n"}${name}: \xa0${token}\xa0\r\nConnection: close\r\n\r\n{}`, "latin1")));
    });
    try {
      const source = value(DiscoverySource.create({ type: "jwks_uri", location: `https://127.0.0.1:${p.port}/keys`, permittedAddresses: ["127.0.0.1"], cacerts: [p.ca] }));
      const r = await NodeDiscovery.fetch(source);
      assert.equal(!r.ok && r.error.reason, expected, name);
    } finally { await p.close(); }
  }
});

test("CIMD requires a non-root document path at construction and snapshot validation", async () => {
  for (const suffix of ["", "/", "?client=1", "/?client=1"]) {
    const source = { type: "cimd", location: `https://agent.example${suffix}` };
    const r = DiscoverySource.create(source);
    assert.equal(!r.ok && r.error.reason, "invalid_source");
    const snapshot = await Discovery.resolver.fromSnapshot(source, bytes(JSON.stringify({ client_id: source.location, jwks: JSON.parse(jwks()) })), epoch, [["content-type", "application/json"]]);
    assert.equal(!snapshot.ok && snapshot.error.reason, "invalid_source");
  }
  for (const path of ["/client.json", "/clients/app/"]) value(DiscoverySource.create({ type: "cimd", location: `https://agent.example${path}` }));
  for (const type of ["directory", "jwks_uri"]) value(DiscoverySource.create({ type, location: "https://agent.example/" }));
});

networkTest("discovery stops retained response collection at the shared chunk bound", async () => {
  const p = await peer((_req, res) => res.end());
  p.server.removeAllListeners("request");
  p.server.on("secureConnection", socket => {
    socket.on("error", () => {});
    socket.once("data", () => socket.end(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n${"1\r\n \r\n".repeat(16384)}${jwks().length.toString(16)}\r\n${jwks()}\r\n0\r\n\r\n`));
  });
  try {
    const source = value(DiscoverySource.create({ type: "jwks_uri", location: `https://127.0.0.1:${p.port}/keys`, permittedAddresses: ["127.0.0.1"], cacerts: [p.ca] }));
    const r = await NodeDiscovery.fetch(source);
    assert.equal(!r.ok && r.error.reason, "limit");
  } finally { await p.close(); }
});
