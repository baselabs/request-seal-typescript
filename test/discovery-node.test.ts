import * as nodeTls from "node:tls";
import { snapshotWithMedia } from "./support/discovery-snapshot.ts";
import nodeTest from "node:test";
import {runtimeTest} from "./support/discovery-runtime.ts";
const test = runtimeTest(nodeTest, "discovery-node.test.ts");
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { peer, jwk, jwks, kid, type Peer } from "./support/discovery-peer.ts";
import {
  DiscoverySource,
  Discovery,
  createCache,
  PublicKey,
  encodeBase64,
  withDeadline,
  type Result,
} from "../src/index.ts";
import { createServer } from "node:net";
import { spawn } from "node:child_process";
import { dnsPublisher } from "./support/discovery-dns.ts";
import { readFile } from "node:fs/promises";
import { createPrivateKey, createHash, sign as nodeSign, X509Certificate } from "node:crypto";
import { readDer, sequence, tlv } from "../src/custody/der.ts";
const nodePath = "../src/discovery/node.ts";
async function api() {
  assert.ok(
    existsSync(new URL(nodePath, import.meta.url)),
    "bounded Node discovery transport exists",
  );
  return import(nodePath) as Promise<typeof import("../src/discovery/node.ts")>;
}
function value<T>(r: Result<T>): T {
  assert.equal(r.ok, true, JSON.stringify(r));
  return (r as { ok: true; value: T }).value;
}
function refused(r: Result<unknown>, reason: string) {
  assert.equal(r.ok, false);
  if (!r.ok) {
    assert.equal(r.error.kind, "discovery");
    assert.equal(r.error.reason, reason);
    assert.doesNotMatch(
      JSON.stringify(r.error),
      /localhost|canary|stack|certificate|127\./,
    );
  }
}
const config = (p: Peer, more: Record<string, unknown> = {}) =>
  value(
    DiscoverySource.create({
      type: "jwks_uri",
      location: `https://localhost:${p.port}/keys`,
      cacerts: [p.ca],
      permittedAddresses: ["127.0.0.1", "::1"],
      ...more,
    }),
  );
test(
  "invalid DNS server endpoints reject before contacting the TLS publisher",
  { timeout: 15000 },
  async () => {
    const { Discovery: NodeDiscovery } = await api();
    const p = await peer((_q, r) => r.end(jwks()));
    try {
      for (const endpoint of [
        ".",
        "999.0.0.1",
        "127.0.0.1:0",
        "127.0.0.1:65536",
        "[::1]:0",
        "[::::]:53",
      ])
        refused(
          await NodeDiscovery.fetch(config(p), { dnsServers: [endpoint] }),
          "invalid_options",
        );
      let calls = 0;
      const servers = ["127.0.0.1:53"];
      Object.defineProperty(servers, Symbol.iterator, {
        value: function* () {
          calls++;
          for (let i = 0; i < 17; i++) yield servers[0];
        },
      });
      refused(
        await NodeDiscovery.fetch(config(p), { dnsServers: servers }),
        "invalid_options",
      );
      const roots = [p.ca];
      Object.defineProperty(roots, Symbol.iterator, {
        value: function* () {
          calls++;
          for (let i = 0; i < 257; i++) yield roots[0];
        },
      });
      refused(
        DiscoverySource.create({
          type: "jwks_uri",
          location: "https://localhost/keys",
          cacerts: roots,
        }),
        "invalid_source",
      );
      assert.equal(calls, 0);
      assert.equal(p.connections, 0);
    } finally {
      await p.close();
    }
  },
);
test(
  "source trust roots reject malformed certificate fields before connecting",
  { timeout: 15000 },
  async () => {
    const p = await peer((_q, r) => r.end(jwks()));
    try {
      const cert = value(readDer(p.ca));
      const tbs = cert.children[0]!;
      // Change tags in actual OpenSSL-issued certificate fields, preserving DER framing.
      for (const index of [1, 2, 3, 4, 5, 6]) {
        const damaged = sequence(
          ...tbs.children.map((node, i) =>
            tlv(i === index ? 4 : node.tag, node.bytes),
          ),
        );
        const der = sequence(
          damaged,
          ...cert.children.slice(1).map((node) => tlv(node.tag, node.bytes)),
        );
        refused(
          DiscoverySource.create({
            type: "jwks_uri",
            location: "https://localhost/keys",
            cacerts: [der],
          }),
          "invalid_source",
        );
      }
      assert.equal(p.connections, 0);
    } finally {
      await p.close();
    }
  },
);
test(
  "real HTTPS JWKS imports keys and verifies configured trust roots",
  { timeout: 15000 },
  async (t) => {
    const { Discovery: NodeDiscovery } = await api();
    let sent = 0;
    const p = await peer((_req, res) => {
      const date = new Date();
      sent = Math.floor(date.getTime() / 1000);
      res.writeHead(200, {
        "content-type": "application/jwk-set+json",
        "cache-control": "max-age=30",
        date: date.toUTCString(),
      });
      res.end(jwks());
    });
    try {
      const s = config(p),
        original = new Uint8Array(p.ca);
      p.ca.fill(0);
      const set = value(await NodeDiscovery.fetch(s));
      assert.deepEqual(Object.keys(set.keys), [kid]);
      assert.equal(set.proof, "not_applicable");
      // RFC 9111 Section 4.2.3: the lifetime is max-age less the apparent age,
      // which is one second when the Date and the clock read straddle a second.
      assert.equal(set.expiresAt - set.fetchedAt, 30 - Math.max(set.fetchedAt - sent, 0));
      assert.equal(p.requests, 1);
      p.ca.set(original);
      assert.equal(value(await set.keys[kid]!.key.thumbprint()), kid);
      const osResult = await NodeDiscovery.fetch(value(DiscoverySource.create({
        type: "jwks_uri", location: s.location, permittedAddresses: ["127.0.0.1", "::1"],
      })));
      const systemStore = typeof nodeTls.getCACertificates === "function" && nodeTls.getCACertificates("system").length > 0;
      if (systemStore) refused(osResult, "tls_failed");
      else {
        assert.equal(osResult.ok, false);
        if (!osResult.ok) {
          assert.equal(osResult.error.kind, "discovery");
          assert.equal(osResult.error.reason, "transport_unavailable");
        }
      }
      refused(
        await NodeDiscovery.fetch(config(p, { permittedAddresses: [] })),
        "address_denied",
      );
      t.diagnostic(
        `TLS JWKS: success; OS roots: ${systemStore ? "tls_failed" : "transport_unavailable"}; private DNS: address_denied`,
      );
    } finally {
      await p.close();
    }
  },
);
test(
  "qualified no-cache and no-store directives still zero snapshot freshness",
  { timeout: 15000 },
  async () => {
    const { Discovery: NodeDiscovery } = await api();
    const now = Math.floor(Date.now() / 1000);
    const date = (t: number) => new Date(t * 1000).toUTCString();
    // RFC 9111 Sections 5.2.2.3 and 5.2.2.4: no-store and no-cache also arrive
    // qualified, as in no-cache="content-type" (and the RFC 7234 quoted form whose
    // member can itself contain commas), and with unquoted values (no-cache=nope).
    // Every spelling forces revalidation; max-age without them still caches.
    for (const [controls, others, ttl] of [
      [["no-cache"], [["expires", date(now + 120)]], 0],
      [["no-store"], [["expires", date(now + 120)]], 0],
      [['no-cache="content-type"'], [["expires", date(now + 120)]], 0],
      [['no-cache="content-type"', "max-age=604800"], [], 0],
      [['no-cache="Set-Cookie, Foo"'], [["expires", date(now + 120)]], 0],
      [["no-cache=nope"], [["expires", date(now + 120)]], 0],
      [['no-store="content-type"'], [["expires", date(now + 120)]], 0],
      [["max-age=0"], [["expires", date(now + 120)]], 0],
      [["max-age=10"], [["expires", date(now + 120)]], 10],
    ] as const) {
      const p = await peer((_q, r) => {
        // Two controls travel as two header fields, matching the multi-field
        // join the same header name produces on a real publisher.
        r.writeHead(200, [
          ["content-type", "application/jwk-set+json"],
          ...controls.map((control) => ["cache-control", control] as [string, string]),
          ["date", date(now)],
          ...others.map(([name, value]) => [name, value] as [string, string]),
        ]);
        r.end(jwks());
      });
      try {
        const set = value(
          await NodeDiscovery.fetch(config(p), { clock: () => now }),
        );
        assert.equal(p.requests, 1);
        assert.equal(set.expiresAt, now + ttl, JSON.stringify(controls));
      } finally {
        await p.close();
      }
    }
  },
);
test(
  "out-of-registry alg and unusable keys skip while leaked members reject the set",
  { timeout: 15000 },
  async () => {
    const { Discovery: NodeDiscovery } = await api();
    // RFC 7517 Appendix A.1 public members (vendored at
    // test/fixtures/upstream/custody/rfc7517.json) beside an ES512-asserted
    // Ed25519 key and an X25519 OKP key: none can satisfy a signature policy,
    // so all three skip and the usable key still resolves (RFC 7517 Section 5).
    const encryption = {
      kty: "RSA",
      n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
      e: "AQAB",
      alg: "RSA-OAEP",
      use: "enc",
    };
    const publisher = (keys: unknown[]) =>
      peer((_q, r) => {
        r.writeHead(200, [["content-type", "application/jwk-set+json"]]);
        r.end(JSON.stringify({ keys }));
      });
    const mixed = await publisher([
      encryption,
      { ...jwk, alg: "ES512" },
      { kty: "OKP", crv: "X25519", x: jwk.x },
      jwk,
    ]);
    try {
      const set = value(await NodeDiscovery.fetch(config(mixed)));
      assert.deepEqual(Object.keys(set.keys), [kid]);
      assert.equal(set.keys[kid]!.assertedAlgorithm, null);
      value(await set.lookup(kid, ["ed25519"]));
    } finally {
      await mixed.close();
    }
    // A leaked private member rejects the whole set loudly even when the
    // leaked key's own out-of-registry alg would otherwise skip it away.
    const leaky = await publisher([
      { ...jwk, alg: "ES512", d: "private-canary" },
      jwk,
    ]);
    try {
      refused(await NodeDiscovery.fetch(config(leaky)), "invalid_key_set");
    } finally {
      await leaky.close();
    }
    // A set where every key is skipped resolves empty and lookups fail closed.
    const none = await publisher([encryption, { ...jwk, alg: "ES512" }]);
    try {
      const empty = value(await NodeDiscovery.fetch(config(none)));
      assert.deepEqual(Object.keys(empty.keys), []);
      refused(await empty.lookup(kid, ["ed25519"]), "unknown_key");
    } finally {
      await none.close();
    }
  },
);
for (const host of ["127.0.0.1", "[::1]", "2130706433", "[::ffff:127.0.0.1]"])
  test(
    `literal location ${host} is denied before connection`,
    { timeout: 15000 },
    async (t) => {
      const { Discovery: NodeDiscovery } = await api();
      const p = await peer(
        (_q, r) => r.end(jwks()),
        host === "[::1]" ? "::1" : "127.0.0.1",
      );
      try {
        const s = value(
          DiscoverySource.create({
            type: "jwks_uri",
            location: `https://${host}:${p.port}/keys`,
            cacerts: [p.ca],
          }),
        );
        refused(await NodeDiscovery.fetch(s), "address_denied");
        assert.equal(p.connections, 0);
        t.diagnostic(`literal ${host}: address_denied; accepts=0`);
      } finally {
        await p.close();
      }
    },
  );
for (const host of ["127.0.0.2", "[::1]", "2130706434", "[::ffff:127.0.0.2]"])
  test(
    `redirect target ${host} is revalidated before connection`,
    { timeout: 15000 },
    async (t) => {
      const { Discovery: NodeDiscovery } = await api();
      const p = await peer((_q, r) => {
        r.writeHead(302, { location: `https://${host}/keys` });
        r.end();
      });
      try {
        refused(
          await NodeDiscovery.fetch(
            config(p, {
              location: `https://127.0.0.1:${p.port}/keys`,
              maxRedirects: 1,
              redirectScope: "any_https",
              permittedAddresses: ["127.0.0.1"],
            }),
          ),
          "address_denied",
        );
        assert.equal(p.requests, 1);
        t.diagnostic(`redirect ${host}: address_denied`);
      } finally {
        await p.close();
      }
    },
  );
test(
  "exact permitted addresses reach IPv4 and IPv6 TLS listeners and deny neighboring addresses",
  { timeout: 15000 },
  async (t) => {
    const { Discovery: NodeDiscovery } = await api();
    for (const address of ["127.0.0.1", "::1"]) {
      const p = await peer((_q, r) => {
        r.setHeader("content-type", "application/json");
        r.end(jwks());
      }, address);
      try {
        const host = address.includes(":") ? `[${address}]` : address;
        const s = config(p, {
          location: `https://${host}:${p.port}/keys`,
          permittedAddresses: [address],
        });
        assert.ok((await NodeDiscovery.fetch(s)).ok);
        refused(
          await NodeDiscovery.fetch(
            config(p, {
              location: s.location,
              permittedAddresses: [address === "::1" ? "::2" : "127.0.0.2"],
            }),
          ),
          "address_denied",
        );
        t.diagnostic(
          `permit ${address}: success; different permit: address_denied`,
        );
      } finally {
        await p.close();
      }
    }
  },
);
test(
  "redirects require explicit scope and obey the hop ceiling",
  { timeout: 15000 },
  async (t) => {
    const { Discovery: NodeDiscovery } = await api();
    let target = "/keys";
    const p = await peer((q, r) => {
      if (q.url === "/keys") {
        r.setHeader("content-type", "application/json");
        r.end(jwks());
      } else {
        r.writeHead(302, { location: target });
        r.end();
      }
    });
    try {
      refused(
        await NodeDiscovery.fetch(
          config(p, { location: `https://localhost:${p.port}/start` }),
        ),
        "redirect_denied",
      );
      assert.ok(
        (
          await NodeDiscovery.fetch(
            config(p, {
              location: `https://localhost:${p.port}/start`,
              maxRedirects: 1,
            }),
          )
        ).ok,
      );
      target = "/loop";
      refused(
        await NodeDiscovery.fetch(
          config(p, {
            location: `https://localhost:${p.port}/loop`,
            maxRedirects: 1,
          }),
        ),
        "redirect_limit",
      );
      target = "http://localhost/keys";
      refused(
        await NodeDiscovery.fetch(
          config(p, {
            location: `https://localhost:${p.port}/start`,
            maxRedirects: 1,
          }),
        ),
        "redirect_denied",
      );
      target = "/malformed%escape";
      refused(
        await NodeDiscovery.fetch(
          config(p, {
            location: `https://localhost:${p.port}/start`,
            maxRedirects: 1,
          }),
        ),
        "redirect_denied",
      );
      t.diagnostic(
        "redirect default: redirect_denied; permitted hop: success; ceiling: redirect_limit; HTTP: redirect_denied",
      );
    } finally {
      await p.close();
    }
  },
);
for (const [name, status, body, headers, reason] of [
  ["oversized body", 200, " ".repeat(65537), {}, "limit"],
  [
    "gzip bomb",
    200,
    gzipSync(new Uint8Array(65537)),
    { "content-encoding": "gzip" },
    "limit",
  ],
  [
    "unsupported coding",
    200,
    jwks(),
    { "content-encoding": "br" },
    "invalid_response",
  ],
  [
    "too many keys",
    200,
    JSON.stringify({ keys: Array.from({ length: 33 }, () => jwk) }),
    {},
    "limit",
  ],
  [
    "too deep JSON",
    200,
    '{"keys":[],"x":' + "[".repeat(33) + "0" + "]".repeat(33) + "}",
    {},
    "limit",
  ],
  ["4xx", 404, "", {}, "unexpected_status"],
  ["5xx", 503, "", {}, "unexpected_status"],
] as const)
  test(
    `real HTTPS ${name} returns a bounded refusal`,
    { timeout: 15000 },
    async (t) => {
      const { Discovery: NodeDiscovery } = await api();
      const p = await peer((_q, r) => {
        r.writeHead(status, { "content-type": "application/json", ...headers });
        r.end(body);
      });
      try {
        const result = await NodeDiscovery.fetch(config(p));
        refused(result, reason);
        if (!result.ok && result.error.kind === "discovery")
          assert.equal(result.error.retryable, name === "5xx");
        t.diagnostic(`${name}: ${reason}; retryable=${name === "5xx"}`);
      } finally {
        await p.close();
      }
    },
  );
test(
  "deadline and caller abort destroy the real TLS socket",
  { timeout: 15000 },
  async (t) => {
    const { Discovery: NodeDiscovery } = await api();
    let sawClose: Promise<void> | undefined;
    let connected: () => void = () => {};
    const ready = new Promise<void>((r) => (connected = r));
    const p = await peer((q, _r) => {
      sawClose = new Promise<void>((done) =>
        q.socket.once("close", () => done()),
      );
      connected();
    });
    try {
      const controller = new AbortController(),
        context = value(
          withDeadline({ signal: controller.signal, timeoutMs: 2000 }),
        );
      const pending = NodeDiscovery.fetch(config(p), { context });
      await ready;
      controller.abort();
      refused(await pending, "deadline_exceeded");
      await sawClose;
      refused(
        await NodeDiscovery.fetch(config(p), { timeoutMs: 100 }),
        "deadline_exceeded",
      );
      await sawClose;
      t.diagnostic(
        "caller abort and deadline: deadline_exceeded; both server sockets closed",
      );
    } finally {
      await p.close();
    }
  },
);
test(
  "CIMD fetches exact documents and same-origin JWKS under one deadline",
  { timeout: 15000 },
  async (t) => {
    const { Discovery: NodeDiscovery } = await api();
    let mode = "inline", keysSent = 0;
    const p = await peer((q, r) => {
      const date = new Date();
      if (q.url === "/keys") keysSent = Math.floor(date.getTime() / 1000);
      r.setHeader("date", date.toUTCString());
      r.setHeader("content-type", "application/json");
      r.setHeader(
        "cache-control",
        q.url === "/keys" ? "max-age=10" : "max-age=60",
      );
      const client_id = `https://localhost:${p.port}/client`;
      if (q.url === "/keys") r.end(jwks());
      else
        r.end(
          JSON.stringify({
            client_id: mode === "mismatch" ? client_id + "x" : client_id,
            ...(mode === "inline"
              ? { jwks: { keys: [jwk] } }
              : {
                  jwks_uri:
                    mode === "cross"
                      ? "https://other.example/keys"
                      : `https://localhost:${p.port}/keys`,
                }),
            ...(mode === "ambiguous" ? { jwks: { keys: [] } } : {}),
          }),
        );
    });
    try {
      const s = config(p, {
        type: "cimd",
        location: `https://localhost:${p.port}/client`,
      });
      assert.ok((await NodeDiscovery.fetch(s)).ok);
      mode = "nested";
      const set = value(await NodeDiscovery.fetch(s));
      // The shorter JWKS lifetime governs, less its RFC 9111 apparent age.
      assert.equal(set.expiresAt - set.fetchedAt, 10 - Math.max(set.fetchedAt - keysSent, 0));
      assert.equal(set.keys[kid]!.sourceType, "cimd");
      assert.equal(set.keys[kid]!.location, `https://localhost:${p.port}/keys`);
      mode = "mismatch";
      refused(await NodeDiscovery.fetch(s), "client_id_mismatch");
      mode = "cross";
      refused(await NodeDiscovery.fetch(s), "redirect_denied");
      mode = "ambiguous";
      refused(await NodeDiscovery.fetch(s), "ambiguous_key_source");
      t.diagnostic(
        "CIMD inline/nested: success; mismatch: client_id_mismatch; cross origin: redirect_denied; both key sources: ambiguous_key_source",
      );
    } finally {
      await p.close();
    }
  },
);
test(
  "real DNS changes are revalidated and TLS connects only to the vetted numeric address",
  { timeout: 15000 },
  async (t) => {
    const { Discovery: NodeDiscovery } = await api(),
      dns = await dnsPublisher();
    const p = await peer((_q, r) => {
      r.setHeader("content-type", "application/json");
      r.end(jwks());
    });
    try {
      const s = config(p, {
        location: `https://directory.test:${p.port}/keys`,
      });
      dns.rebind();
      assert.ok(
        (await NodeDiscovery.fetch(s, { dnsServers: [dns.server] })).ok,
      );
      assert.equal(p.requests, 1);
      assert.deepEqual(dns.queries, [1, 28]);
      refused(
        await NodeDiscovery.fetch(s, { dnsServers: [dns.server] }),
        "address_denied",
      );
      assert.equal(p.requests, 1);
      assert.deepEqual(dns.queries, [1, 28, 1, 28]);
      dns.set("127.0.0.1", "::1");
      assert.ok(
        (await NodeDiscovery.fetch(s, { dnsServers: [dns.server] })).ok,
      );
      assert.equal(p.requests, 2);
      dns.set("127.0.0.1");
      refused(
        await NodeDiscovery.fetch(
          config(p, { location: `https://unlisted.test:${p.port}/keys` }),
          { dnsServers: [dns.server] },
        ),
        "tls_failed",
      );
      assert.equal(p.requests, 2);
      dns.set("169.254.169.254");
      refused(
        await NodeDiscovery.fetch(s, { dnsServers: [dns.server] }),
        "address_denied",
      );
      assert.equal(p.requests, 2);
      // The reference removes duplicate answers before applying the 64-address bound.
      dns.set("127.0.0.1");
      dns.repeat(65);
      assert.ok(
        (await NodeDiscovery.fetch(s, { dnsServers: [dns.server] })).ok,
      );
      assert.equal(p.requests, 3);
      dns.repeat(1);
      t.diagnostic(
        `DNS A/AAAA: vetted; permitted rebind pinned without second query; subsequent metadata answer: address_denied; loopback accepts unchanged`,
      );
    } finally {
      await dns.close();
      await p.close();
    }
  },
);
test(
  "authoritative NXDOMAIN is a nonretryable config error distinct from resolver failures",
  { timeout: 15000 },
  async () => {
    const { Discovery: NodeDiscovery } = await api(),
      dns = await dnsPublisher();
    const p = await peer((_q, r) => {
      r.setHeader("content-type", "application/json");
      r.end(jwks());
    });
    try {
      const s = config(p, {
        location: `https://directory.test:${p.port}/keys`,
      });
      // SERVFAIL on both families is resolver trouble: retryable.
      dns.fail(2);
      const failed = await NodeDiscovery.fetch(s, { dnsServers: [dns.server] });
      refused(failed, "resolution_failed");
      assert.equal(
        !failed.ok && failed.error.kind === "discovery"
          ? failed.error.retryable
          : undefined,
        true,
      );
      // An authoritative NXDOMAIN on every query names a domain that does
      // not exist: a configuration error, never retried.
      dns.fail(3);
      refused(
        await NodeDiscovery.fetch(s, { dnsServers: [dns.server] }),
        "domain_not_found",
      );
      const nxdomain = await NodeDiscovery.fetch(s, { dnsServers: [dns.server] });
      assert.equal(
        !nxdomain.ok && nxdomain.error.kind === "discovery"
          ? nxdomain.error.retryable
          : undefined,
        false,
      );
      // The OS resolver path splits the same way: RFC 2606 reserves the
      // .invalid TLD, so the real resolver answers NXDOMAIN.
      const system = await NodeDiscovery.fetch(
        config(p, { location: "https://request-seal-nxdomain.invalid/keys" }),
      );
      refused(system, "domain_not_found");
      assert.equal(
        !system.ok && system.error.kind === "discovery"
          ? system.error.retryable
          : undefined,
        false,
      );
    } finally {
      await dns.close();
      await p.close();
    }
  },
);
test(
  "interim 1xx responses are skipped and never become the final status",
  { timeout: 15000 },
  async () => {
    const { Discovery: NodeDiscovery } = await api();
    // RFC 9110 Section 15.2: interim responses are provisional and a client
    // must be able to parse those preceding a final one. Five are skipped,
    // the reference bound; a sixth names a misbehaving publisher.
    for (const hints of [1, 5]) {
      const p = await peer((_q, r) => {
        for (let i = 0; i < hints; i++)
          r.writeEarlyHints({ link: "</keys>; rel=preload" });
        r.writeHead(200, [["content-type", "application/jwk-set+json"]]);
        r.end(jwks());
      });
      try {
        const set = value(await NodeDiscovery.fetch(config(p)));
        assert.deepEqual(Object.keys(set.keys), [kid]);
      } finally {
        await p.close();
      }
    }
    const many = await peer((_q, r) => {
      for (let i = 0; i < 6; i++)
        r.writeEarlyHints({ link: "</keys>; rel=preload" });
      r.writeHead(200, [["content-type", "application/jwk-set+json"]]);
      r.end(jwks());
    });
    try {
      refused(await NodeDiscovery.fetch(config(many)), "invalid_response");
    } finally {
      await many.close();
    }
    // Interims with no final response never yield a snapshot; the platform's
    // socket teardown surfaces as a bounded discovery failure.
    const p = await peer((_q, r) => {
      r.writeEarlyHints({});
      r.destroy();
    });
    try {
      const result = await NodeDiscovery.fetch(config(p), { timeoutMs: 2000 });
      assert.equal(result.ok, false);
    } finally {
      await p.close();
    }
  },
);
test(
  "a CIMD document's nested jwks_uri is checked against the serving origin",
  { timeout: 15000 },
  async () => {
    const { Discovery: NodeDiscovery } = await api();
    // Under a permissive redirect scope the CIMD document can arrive from a
    // different origin than the configured one; its jwks_uri legitimately
    // names that serving origin (the mirror the redirect selected).
    let document = "";
    const b = await peer((q, r) => {
      r.setHeader("content-type", "application/json");
      r.setHeader(
        "cache-control",
        q.url === "/keys" ? "max-age=30" : "max-age=60",
      );
      if (q.url === "/keys") {
        r.end(jwks());
        return;
      }
      r.end(document);
    });
    const a = await peer((_q, r) => {
      r.writeHead(302, { location: `https://localhost:${b.port}/client` });
      r.end();
    });
    try {
      // The client_id stays the configured location: it identifies the
      // caller's own registration, not the mirror that served the document.
      document = JSON.stringify({
        client_id: `https://localhost:${a.port}/client`,
        jwks_uri: `https://localhost:${b.port}/keys`,
      });
      const s = value(
        DiscoverySource.create({
          type: "cimd",
          location: `https://localhost:${a.port}/client`,
          redirectScope: "any_https",
          maxRedirects: 1,
          cacerts: [a.ca, b.ca],
          permittedAddresses: ["127.0.0.1", "::1"],
        }),
      );
      const set = value(await NodeDiscovery.fetch(s));
      assert.equal(set.keys[kid]!.sourceType, "cimd");
      // Provenance names the origin that actually served the nested JWKS.
      assert.equal(set.keys[kid]!.origin, `https://localhost:${b.port}`);
    } finally {
      await a.close();
      await b.close();
    }
  },
);
test(
  "environment proxy settings never contact the real proxy listener",
  { timeout: 15000 },
  async (t) => {
    await api();
    let contacts = 0;
    const proxy = createServer((socket) => {
      contacts++;
      socket.destroy();
    });
    await new Promise<void>((done) => proxy.listen(0, "127.0.0.1", done));
    const address = proxy.address();
    assert.ok(address && typeof address === "object");
    const p = await peer((_q, r) => {
      r.setHeader("content-type", "application/json");
      r.end(jwks());
    });
    try {
      const code = `import {DiscoverySource} from './src/index.ts';import {Discovery} from './src/discovery/node.ts';async function main(){const config=JSON.parse(process.env.DISCOVERY_SOURCE);config.cacerts=config.cacerts.map(root=>new Uint8Array(root));const s=DiscoverySource.create(config);if(!s.ok)throw Error('source');const result=await Discovery.fetch(s.value);console.log(JSON.stringify({ok:result.ok,reason:result.ok?null:result.error.reason}));if(!result.ok)process.exitCode=1;}main().catch(()=>process.exitCode=1);`;
      const child = spawn(
        process.execPath,
        process.versions.deno
          ? ["eval", code]
          : process.versions.bun
            ? ["--eval", code]
            : [
                "--experimental-strip-types",
                "--no-warnings",
                "--input-type=module",
                "-e",
                code,
              ],
        {
          env: {
            ...process.env,
            NODE_USE_ENV_PROXY: "1",
            HTTPS_PROXY: `http://127.0.0.1:${address.port}`,
            https_proxy: `http://127.0.0.1:${address.port}`,
            NO_PROXY: "",
            no_proxy: "",
            DISCOVERY_SOURCE: JSON.stringify({
              type: "jwks_uri",
              location: `https://127.0.0.1:${p.port}/keys`,
              cacerts: [Array.from(p.ca)],
              permittedAddresses: ["127.0.0.1"],
            }),
          },
          stdio: ["ignore", "pipe", "pipe"],
        },
      );
      // JSON carries only public CA bytes. Convert their transport representation in the child.
      let output = "",
        errors = "";
      child.stdout.on("data", (b) => (output += b));
      child.stderr.on("data", (b) => (errors += b));
      const status = await new Promise<number | null>((done) =>
        child.once("close", done),
      );
      assert.equal(status, 0, output + errors);
      assert.equal(contacts, 0);
      assert.equal(p.requests, 1);
      t.diagnostic(
        "NODE_USE_ENV_PROXY=1; real proxy contacts=0; vetted TLS peer reached",
      );
    } finally {
      await p.close();
      await new Promise<void>((done) => proxy.close(() => done()));
    }
  },
);
async function proofHeaders(
  body: Uint8Array,
  authority: string,
  now: number,
  changes: Record<string, unknown> = {},
) {
  const privateJwk = JSON.parse(
    await readFile("test/fixtures/upstream/custody/rfc8037.json", "utf8"),
  );
  const key = createPrivateKey({ key: privateJwk, format: "jwk" });
  const contentDigest =
    "sha-256=:" + createHash("sha256").update(body).digest("base64") + ":";
  const params = `("@authority";req "content-digest");created=${changes.created ?? now};expires=${changes.expires ?? now + 120};keyid="${kid}";tag="${changes.tag ?? "http-message-signatures-directory"}"`;
  // Independent RFC 9421 base construction by the actual TLS publisher.
  const base = `"@authority";req: ${changes.authority ?? authority}\n"content-digest": ${contentDigest}\n"@signature-params": ${params}`;
  const signature = nodeSign(null, Buffer.from(base), key).toString("base64");
  return {
    "content-digest": contentDigest,
    "signature-input": `${changes.label ?? "directory"}=${params}`,
    signature: `${changes.label ?? "directory"}=:${signature}:`,
  };
}
test(
  "real signed directories bind possession, authority, digest, key, tag and expiry",
  { timeout: 15000 },
  async (t) => {
    const { Discovery: NodeDiscovery } = await api();
    const now = Math.floor(Date.now() / 1000);
    let changes: Record<string, unknown> = {},
      coding = "identity",
      mode = "signed";
    const p = await peer((req, res) => {
      void (async () => {
        const body =
          coding === "identity" ? Buffer.from(jwks()) : gzipSync(jwks());
        const headers = await proofHeaders(
          body,
          req.headers.host!,
          now,
          changes,
        );
        res.writeHead(200, {
          "content-type": "application/http-message-signatures-directory+json",
          "cache-control": "max-age=300",
          ...(coding === "identity" ? {} : { "content-encoding": coding }),
          ...(mode === "signed" ? headers : {}),
        });
        res.end(body);
      })().catch((error) => res.destroy(error));
    });
    try {
      const s = config(p, {
        type: "directory",
        location: `https://localhost:${p.port}`,
      });
      const set = value(await NodeDiscovery.fetch(s, { clock: () => now }));
      assert.equal(set.proof, "signed");
      assert.equal(set.expiresAt, now + 120);
      const snapshotBody = new TextEncoder().encode(jwks());
      const headers = await proofHeaders(
        snapshotBody,
        `localhost:${p.port}`,
        now,
      );
      const snapshot = value(
        await snapshotWithMedia(
          s,
          snapshotBody,
          now,
          Object.entries(headers),
        ),
      );
      assert.equal(snapshot.proof, "signed");
      for (const mutation of [
        { authority: "other.example" },
        { created: now + 1 },
        { expires: now - 1 },
        { tag: "wrong" },
        { label: "other", tag: "unrelated" },
      ]) {
        changes = mutation;
        refused(
          await NodeDiscovery.fetch(s, { clock: () => now }),
          "directory_signature_invalid",
        );
      }
      changes = { label: "possession" };
      assert.ok((await NodeDiscovery.fetch(s, { clock: () => now })).ok);
      changes = {};
      coding = "GZIP";
      assert.ok((await NodeDiscovery.fetch(s, { clock: () => now })).ok);
      coding = "x-gzip";
      assert.ok((await NodeDiscovery.fetch(s, { clock: () => now })).ok);
      coding = "identity";
      mode = "unsigned";
      refused(
        await NodeDiscovery.fetch(s, { clock: () => now }),
        "directory_unsigned",
      );
      assert.equal(
        value(
          await NodeDiscovery.fetch(
            config(p, {
              type: "directory",
              location: s.location,
              requireSignedDirectory: false,
            }),
            { clock: () => now },
          ),
        ).proof,
        "unsigned",
      );
      t.diagnostic(
        "TLS directory + snapshot: signed; authority/created/expires/tag/selection mutations: directory_signature_invalid; gzip/x-gzip signed: success; unsigned: directory_unsigned; explicit relaxation: unsigned",
      );
    } finally {
      await p.close();
    }
  },
);
for (const address of [
  "0.0.0.1",
  "10.0.0.1",
  "100.64.0.1",
  "127.0.0.1",
  "169.254.0.1",
  "172.16.0.1",
  "192.0.0.1",
  "192.0.2.1",
  "192.31.196.1",
  "192.52.193.1",
  "192.88.99.1",
  "192.168.0.1",
  "192.175.48.1",
  "198.18.0.1",
  "198.51.100.1",
  "203.0.113.1",
  "224.0.0.1",
  "240.0.0.1",
  "2001::1",
  "2001:db8::1",
  "2620:4f:8000::1",
  "3fff::1",
  "::",
  "::1",
  "fe80::1",
  "fc00::1",
  "ff00::1",
  "::ffff:10.0.0.1",
  "64:ff9b::a00:1",
  "2002:a00:1::1",
])
  test(`special-purpose denial table rejects ${address}`, async (t) => {
    const { Discovery: NodeDiscovery } = await api();
    const host = address.includes(":") ? `[${address}]` : address;
    refused(
      await NodeDiscovery.fetch(
        value(
          DiscoverySource.create({
            type: "jwks_uri",
            location: `https://${host}/keys`,
            cacerts: [new Uint8Array(new X509Certificate(nodeTls.rootCertificates[0]!).raw)],
          }),
        ),
        { timeoutMs: 5000 },
      ),
      "address_denied",
    );
    t.diagnostic(`${address}: address_denied`);
  });
test(
  "cache freshness, rotation, removals and failure policy use the real TLS publisher",
  { timeout: 15000 },
  async (t) => {
    const { Discovery: NodeDiscovery } = await api();
    let now = Math.floor(Date.now() / 1000),
      keys: Record<string, unknown>[] = [jwk],
      status = 200,
      control = "max-age=1";
    const p = await peer((q, r) => {
      r.writeHead(status, {
        "content-type": "application/json",
        "cache-control": control,
        date: new Date(now * 1000).toUTCString(),
      });
      r.end(
        JSON.stringify(
          q.url === "/client"
            ? {
                client_id: `https://localhost:${p.port}/client`,
                jwks: { keys },
              }
            : { keys },
        ),
      );
    });
    try {
      const s = config(p),
        cache = value(
          createCache({ clock: () => now, fetch: NodeDiscovery.fetch }),
        );
      value(await cache.resolve(s, kid));
      value(await cache.resolve(s, kid));
      assert.equal(p.requests, 1);
      now++;
      status = 503;
      refused(await cache.resolve(s, kid), "unexpected_status");
      refused(await cache.resolve(s, kid), "source_unavailable");
      assert.equal(p.requests, 2);
      status = 200;
      value(await cache.refresh(s));
      value(await cache.resolve(s, kid));
      assert.equal(p.requests, 3);
      keys = [];
      const rotated = value(await cache.refresh(s));
      assert.equal(Object.keys(rotated.keys).length, 0);
      refused(await cache.resolve(s, kid), "unknown_key");
      assert.equal(p.requests, 4);
      keys = [jwk];
      const restored = value(await cache.refresh(s));
      assert.notEqual(restored.revision, rotated.revision);
      value(cache.remove(s, kid));
      refused(await cache.resolve(s, kid), "revoked_key");
      assert.equal(Object.keys(value(await cache.refresh(s)).keys).length, 0);
      value(cache.invalidate(s));
      refused(await cache.resolve(s, kid), "revoked_key");
      value(cache.close());
      control = "no-store, max-age=60";
      const transient = value(
        createCache({ clock: () => now, fetch: NodeDiscovery.fetch }),
      );
      const before = p.requests;
      value(await transient.resolve(s, kid));
      value(await transient.resolve(s, kid));
      assert.equal(p.requests, before + 2);
      value(transient.close());
      const cimd = config(p, {
          type: "cimd",
          location: `https://localhost:${p.port}/client`,
        }),
        cimdCache = value(
          createCache({ clock: () => now, fetch: NodeDiscovery.fetch }),
        );
      status = 503;
      const prior = p.requests;
      refused(await cimdCache.resolve(cimd, kid), "unexpected_status");
      refused(await cimdCache.resolve(cimd, kid), "unexpected_status");
      assert.equal(p.requests, prior + 2);
      status = 200;
      value(await cimdCache.resolve(cimd, kid));
      value(cimdCache.close());
      t.diagnostic(
        "real cache: fresh reuse; stale+503 refused; negative entry stopped refetch; explicit recovery; rotation/removal changed revision; tombstone retained; no-store fetched twice; CIMD failures fetched twice",
      );
    } finally {
      await p.close();
    }
  },
);
test(
  "concurrent cache waiters share one TLS fetch and invalidation closes pending sockets",
  { timeout: 15000 },
  async (t) => {
    const { Discovery: NodeDiscovery } = await api();
    let release: () => void = () => {},
      accepted: () => void = () => {};
    let ready = new Promise<void>((done) => (accepted = done)),
      closed: Promise<void> | undefined;
    const p = await peer((req, res) => {
      closed = new Promise<void>((done) =>
        req.socket.once("close", () => done()),
      );
      release = () => {
        res.setHeader("content-type", "application/json");
        res.setHeader("cache-control", "max-age=60");
        res.end(jwks());
      };
      accepted();
    });
    try {
      const s = config(p),
        cache = value(
          createCache({ fetch: NodeDiscovery.fetch, maxInFlight: 1 }),
        );
      const work = Array.from({ length: 12 }, () => cache.resolve(s, kid));
      await ready;
      const other = config(p, { negativeTtl: 29 });
      refused(await cache.resolve(other, kid), "cache_overloaded");
      release();
      for (const result of await Promise.all(work)) value(result);
      assert.equal(p.requests, 1);
      value(cache.invalidate(s));
      ready = new Promise<void>((done) => (accepted = done));
      const pending = cache.resolve(s, kid);
      await ready;
      value(cache.invalidate(s));
      refused(await pending, "source_unavailable");
      await closed;
      value(cache.close());
      t.diagnostic(
        "12 waiters: one real TLS fetch; second source: cache_overloaded; invalidation: source_unavailable; server socket closed",
      );
    } finally {
      await p.close();
    }
  },
);
test(
  "single gzip member, framing and header ceilings are enforced against TLS responses",
  { timeout: 15000 },
  async (t) => {
    const { Discovery: NodeDiscovery } = await api();
    let body: Buffer = gzipSync(jwks()),
      mode = "gzip";
    const p = await peer((_q, res) => {
      if (mode === "gzip") {
        res.writeHead(200, {
          "content-type": "application/json",
          "content-encoding": "gzip",
        });
        res.end(body);
      } else {
        res.socket!.end(
          "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" +
            mode +
            "Connection: close\r\n\r\n" +
            jwks(),
        );
      }
    });
    try {
      value(await NodeDiscovery.fetch(config(p)));
      for (const b of [
        Buffer.concat([gzipSync(jwks()), gzipSync(jwks())]),
        Buffer.concat([gzipSync(jwks()), gzipSync("extra")]),
        gzipSync(jwks()).subarray(0, -4),
        Buffer.concat([gzipSync(jwks()), Buffer.from("canary")]),
      ]) {
        body = b;
        refused(await NodeDiscovery.fetch(config(p)), "invalid_response");
      }
      for (const raw of [
        "Transfer-Encoding: chunked\r\nContent-Length: 1\r\n",
        "Content-Length: 1\r\nContent-Length: 1\r\n",
        "Content-Length: -1\r\n",
      ]) {
        mode = raw;
        refused(await NodeDiscovery.fetch(config(p)), "invalid_response");
      }
      mode = "X-Large: " + "x".repeat(16384) + "\r\n";
      refused(await NodeDiscovery.fetch(config(p)), "limit");
      t.diagnostic(
        "gzip concatenation/truncation/trailing bytes: invalid_response; ambiguous lengths/framing: invalid_response; oversized header: limit",
      );
    } finally {
      await p.close();
    }
  },
);

test("default lookup fetches localhost and rejects an empty address allowlist", async () => {
  const {Discovery: NodeDiscovery} = await api();
  const p = await peer((_q, r) => {r.setHeader("content-type", "application/json"); r.end(jwks());});
  try {
    const s = config(p);
    value(await NodeDiscovery.fetch(s));
    refused(await NodeDiscovery.fetch(config(p, {permittedAddresses: []})), "address_denied");
    assert.equal(p.requests, 1);
  } finally {await p.close();}
});


test("denies a literal before a contended deadline dispatch", async (t) => {
  const {Discovery: NodeDiscovery} = await api();
  const p = await peer((_q, r) => r.end(jwks()));
  try {
    const s = value(DiscoverySource.create({type: 'jwks_uri', location: `https://127.0.0.1:${p.port}/keys`, cacerts: [p.ca]}));
    const pending = NodeDiscovery.fetch(s, {timeoutMs: 10});
    const start = performance.now();
    while (performance.now() - start < 40) { /* Real event-loop contention before dispatch. */ }
    const result = await pending;
    t.diagnostic(`blocked event loop ${Math.floor(performance.now()-start)} ms; result=${result.ok?'accepted':result.error.reason}; connections=${p.connections}`);
    refused(result, 'address_denied'); assert.equal(p.connections, 0);
  } finally {await p.close();}
});
test('raw response head ceiling includes the terminating CRLFCRLF', async () => {
  const {Discovery: NodeDiscovery} = await api();
  let size = 16384;
  const p = await peer((_q, r) => {
    const body = jwks();
    const prefix = `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\nX-Pad: `;
    const head = prefix + 'x'.repeat(size - Buffer.byteLength(prefix) - 4) + '\r\n\r\n';
    assert.equal(Buffer.byteLength(head), size);
    r.socket!.end(head + body);
  });
  try {
    value(await NodeDiscovery.fetch(config(p)));
    size++; refused(await NodeDiscovery.fetch(config(p)), 'limit');
  } finally {await p.close();}
});
test('unterminated response head at the ceiling rejects before the deadline', async () => {
  const {Discovery: NodeDiscovery} = await api();
  const p = await peer((_q, r) => {
    const prefix = 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Pad: ';
    const head = prefix + 'x'.repeat(16384 - Buffer.byteLength(prefix));
    assert.equal(Buffer.byteLength(head), 16384);
    assert.equal(head.includes('\r\n\r\n'), false);
    r.socket!.write(head);
  });
  try {
    const context = value(withDeadline({timeoutMs: 2000}));
    refused(await NodeDiscovery.fetch(config(p), {context}), 'limit');
    assert.equal(context.signal.aborted, false, 'limit is returned while the deadline remains active');
    assert.equal(p.requests, 1);
  } finally {await p.close();}
});
test('SPKI BIT STRING requires zero unused bits inside a certificate', async () => {
  const {certificate} = await import('../src/discovery/certificate.ts');
  const {encodeDer} = await import('../src/custody/der.ts');
  const p = await peer((_q, r) => r.end());
  try {
    assert.deepEqual(certificate(p.ca), p.ca);
    const root = value(readDer(p.ca)), tbs = root.children[0]!;
    const index = tbs.children.findIndex(n => n.tag === 48 && n.children.length === 2 && n.children[1]?.tag === 3);
    assert.ok(index >= 0); const spki = tbs.children[index]!;
    const bits = new Uint8Array(spki.children[1]!.bytes); bits[0] = 1; bits[bits.length - 1]! &= 254;
    const alteredSpki = sequence(value(encodeDer(spki.children[0]!)), tlv(3, bits));
    const alteredTbs = sequence(...tbs.children.map((n, i) => i === index ? alteredSpki : value(encodeDer(n))));
    const altered = sequence(alteredTbs, ...root.children.slice(1).map(n => value(encodeDer(n))));
    assert.throws(() => certificate(altered), e => !!e && typeof e === 'object' && 'reason' in e && e.reason === 'invalid_source');
  } finally {await p.close();}
});
test('a silent TLS handshake reaches the deadline and a closed port is a connect failure', async () => {
  const {Discovery: NodeDiscovery} = await api();
  const sockets = new Set<import('node:net').Socket>();
  const listener = createServer(socket => {sockets.add(socket); socket.once('close', () => sockets.delete(socket));});
  await new Promise<void>(resolve => listener.listen(0, '127.0.0.1', resolve));
  const port = (listener.address() as import('node:net').AddressInfo).port;
  const ca = new Uint8Array(new X509Certificate(nodeTls.rootCertificates[0]!).raw);
  const s = value(DiscoverySource.create({type: 'jwks_uri', location: `https://127.0.0.1:${port}/`, permittedAddresses: ['127.0.0.1'], cacerts: [ca], timeoutMs: 50}));
  try {refused(await NodeDiscovery.fetch(s), 'deadline_exceeded');} finally {for (const socket of sockets) socket.destroy(); await new Promise<void>(resolve => listener.close(() => resolve()));}
  const closed = value(DiscoverySource.create({...s, timeoutMs: 5000}));
  const pending = NodeDiscovery.fetch(closed);
  // Exercise actual event-loop contention before the closed-port connect dispatch.
  const until = performance.now() + 80; while (performance.now() < until) {}
  refused(await pending, 'connect_failed');
});

test(
  "conditional revalidation carries If-None-Match and a 304 keeps the stored set",
  { timeout: 15000 },
  async () => {
    const { Discovery: NodeDiscovery } = await api();
    const etag = '"keys-v1"';
    let requests = 0;
    const conditional: string[] = [];
    const p = await peer((q, r) => {
      requests++;
      const sent = q.headers["if-none-match"];
      if (sent !== undefined) conditional.push(String(sent));
      if (sent === etag) {
        // RFC 9111 Section 15.4.5: the 304 answers the conditional request.
        r.writeHead(304, [["cache-control", "max-age=30"]]);
        r.end();
        return;
      }
      r.writeHead(200, [
        ["content-type", "application/jwk-set+json"],
        ["etag", etag],
        ["cache-control", "max-age=1"],
      ]);
      r.end(jwks());
    });
    const fetcher = (s: unknown, o: { clock: () => number; validators?: { etag: string; lifetime: number } }) =>
      o.validators
        ? NodeDiscovery.fetchWithValidators(
            s,
            o.validators.etag,
            o.validators.lifetime,
            o,
          )
        : NodeDiscovery.fetch(s, o);
    try {
      const s = config(p);
      // The first fetch stores the validator with the set.
      const first = value(await NodeDiscovery.fetch(s));
      assert.equal(first.etag, etag);
      assert.deepEqual(Object.keys(first.keys), [kid]);
      // A direct conditional fetch answers 304: no keys, stored lifetime
      // renewed by the 304's own max-age.
      const now = Math.floor(Date.now() / 1000);
      const revalidated = value(
        await NodeDiscovery.fetchWithValidators(s, etag, 99, {
          clock: () => now,
        }),
      );
      assert.ok("notModified" in revalidated && revalidated.notModified === true);
      assert.equal("notModified" in revalidated ? revalidated.etag : undefined, etag);
      assert.equal("notModified" in revalidated ? revalidated.expiresAt : undefined, now + 30);
      // Without the 304's directives, the stored lifetime persists.
      const bare = await peer((_q, r) => {
        r.writeHead(304);
        r.end();
      });
      try {
        const persisted = value(
          await NodeDiscovery.fetchWithValidators(
            config(bare),
            etag,
            120,
            { clock: () => now },
          ),
        );
        assert.ok("notModified" in persisted && persisted.notModified === true);
        assert.equal("notModified" in persisted ? persisted.expiresAt : undefined, now + 120);
      } finally {
        await bare.close();
      }
      // A 304 naming a different validator identifies a different
      // representation and rejects.
      const swapped = await peer((q, r) => {
        if (q.headers["if-none-match"] !== undefined) {
          r.writeHead(304, [["etag", '"keys-v2"']]);
          r.end();
          return;
        }
        r.writeHead(200, [["content-type", "application/jwk-set+json"], ["etag", '"keys-v1"']]);
        r.end(jwks());
      });
      try {
        refused(
          await NodeDiscovery.fetchWithValidators(config(swapped), etag, 60),
          "invalid_response",
        );
      } finally {
        await swapped.close();
      }
      // An unsolicited 304 stays an unexpected status.
      const unsolicited = await peer((_q, r) => {
        r.writeHead(304);
        r.end();
      });
      try {
        refused(await NodeDiscovery.fetch(config(unsolicited)), "unexpected_status");
      } finally {
        await unsolicited.close();
      }
      // A validator never crosses a redirect: the target resource is fetched
      // unconditionally, so its 200 answers with a full key set.
      let targetSawConditional = false;
      const target = await peer((q, r) => {
        if (q.headers["if-none-match"] !== undefined)
          targetSawConditional = true;
        r.writeHead(200, [["content-type", "application/jwk-set+json"], ["etag", '"target-v1"']]);
        r.end(jwks());
      });
      const redirecting = await peer((_q, r) => {
        r.writeHead(302, { location: `https://localhost:${target.port}/keys` });
        r.end();
      });
      try {
        const full = value(
          await NodeDiscovery.fetchWithValidators(
            value(
              DiscoverySource.create({
                type: "jwks_uri",
                location: `https://localhost:${redirecting.port}/keys`,
                cacerts: [redirecting.ca, target.ca],
                permittedAddresses: ["127.0.0.1", "::1"],
                maxRedirects: 1,
                redirectScope: "any_https",
              }),
            ),
            etag,
            60,
          ),
        );
        assert.ok(!("notModified" in full));
        assert.deepEqual(Object.keys(full.keys), [kid]);
        assert.equal(full.etag, '"target-v1"');
        assert.equal(targetSawConditional, false);
      } finally {
        await redirecting.close();
        await target.close();
      }
      // Through a revalidating cache: the second resolve reuses the stored
      // keys and sends the validator, and the merged set carries the 304's
      // own freshness. The cache clock is the real clock, so the 304's Date
      // header lines up with it and apparent age does not eat the max-age.
      const c = value(
        createCache({
          clock: () => Math.floor(Date.now() / 1000),
          fetch: fetcher as never,
        }),
      );
      const before = requests;
      conditional.length = 0;
      try {
        const stored = value(await c.refresh(s));
        assert.equal(stored.etag, etag);
        await new Promise((done) => setTimeout(done, 1100));
        const resolved = value(await c.resolve(s, kid, { algorithms: ["ed25519"] }));
        assert.equal(resolved.thumbprint, kid);
        assert.equal(requests - before, 2);
        assert.deepEqual(conditional, [etag]);
        // The stored set was kept (not refetched); the 304's max-age=30
        // renewed its freshness, so the immediate next resolve serves from
        // the merged entry without another request.
        const after = value(await c.resolve(s, kid, { algorithms: ["ed25519"] }));
        assert.equal(after.thumbprint, kid);
        assert.equal(requests - before, 2);
      } finally {
        c.close();
      }
      // A dead key forces a full fetch: a source whose keys all expired
      // revalidates unconditionally, so the next request carries no
      // If-None-Match.
      const deadBefore = requests;
      conditional.length = 0;
      const dead = value(
        createCache({
          clock: () => Math.floor(Date.now() / 1000),
          fetch: fetcher as never,
        }),
      );
      try {
        const expiring = config(p, { maxTtl: 1, minTtl: 0 });
        value(await dead.refresh(expiring));
        await new Promise((done) => setTimeout(done, 1100));
        const resolved = value(
          await dead.resolve(expiring, kid, { algorithms: ["ed25519"] }),
        );
        assert.equal(resolved.thumbprint, kid);
        assert.equal(requests - deadBefore, 2);
        assert.deepEqual(conditional, []);
      } finally {
        dead.close();
      }
    } finally {
      await p.close();
    }
  },
);
