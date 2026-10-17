import { snapshotWithMedia } from "./support/discovery-snapshot.ts";
import { parseBody } from "../src/discovery/body.ts";
import test from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import * as library from "../src/index.ts";
import type { Result } from "../src/result.ts";
const bytes = (s: string) => new TextEncoder().encode(s);
// RFC 8037 Appendix A.3, unchanged public components and expected thumbprint.
const jwk = {
  kty: "OKP",
  crv: "Ed25519",
  x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
};
const kid = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";
function value<T>(r: Result<T>): T {
  assert.equal(r.ok, true, JSON.stringify(r));
  return (r as { ok: true; value: T }).value;
}
function api() {
  assert.ok("Discovery" in library, "Discovery core API is exported");
  return library as typeof import("../src/index.ts");
}
function reject(r: Result<unknown>, reason: string) {
  assert.equal(r.ok, false);
  if (!r.ok) {
    assert.equal(r.error.kind, "discovery");
    assert.equal(r.error.reason, reason);
    assert.deepEqual(Object.keys(r.error).sort(), [
      "kind",
      "reason",
      "retryable",
    ]);
  }
}
test("discovery sources are owned, branded and validated without networking", () => {
  const { DiscoverySource, isDiscoverySource, directoryId } = api();
  const s = value(
    DiscoverySource.create({
      type: "directory",
      location: "https://agent.example",
    }),
  );
  assert.equal(
    s.location,
    "https://agent.example/.well-known/http-message-signatures-directory",
  );
  assert.equal(s.keyId, "thumbprint");
  assert.ok(Object.isFrozen(s));
  assert.ok(isDiscoverySource(s));
  assert.equal(isDiscoverySource({ ...s }), false);
  assert.equal(value(directoryId("Case Sensitive ID")), true);
  assert.equal(value(directoryId("bad\n")), false);
  for (const location of [
    "http://agent.example",
    "https://a.example/#",
    "https://u@a.example",
    "https://a.example/a/../b",
    "https://a.example/%2e%2e/b",
    "https://a.example/%0a",
    "https://a.example/\\bad",
    "https://a.example/%zz",
  ])
    reject(
      DiscoverySource.create({ type: "jwks_uri", location }),
      "invalid_source",
    );
  reject(
    DiscoverySource.create({ type: "cimd", location: "https://agent.example" }),
    "invalid_source",
  );
  reject(
    DiscoverySource.create({
      type: "directory",
      location: "https://agent.example/wrong",
    }),
    "invalid_source",
  );
  reject(
    DiscoverySource.create({
      type: "directory",
      location: "https://agent.example",
      keyId: "directory",
    }),
    "invalid_source",
  );
  reject(
    DiscoverySource.create({
      type: "jwks_uri",
      location: "https://agent.example",
      negativeTtl: 301,
    }),
    "invalid_options",
  );
  reject(
    DiscoverySource.create({
      type: "jwks_uri",
      location: "https://agent.example",
      unknown: true,
    }),
    "invalid_source",
  );
  let reads = 0;
  const permittedAddresses = ["127.0.0.1"];
  const owned = value(
    DiscoverySource.create({
      type: "jwks_uri",
      get location() {
        reads++;
        return "https://agent.example";
      },
      permittedAddresses,
    }),
  );
  permittedAddresses[0] = "127.0.0.2";
  assert.equal(reads, 1);
  assert.deepEqual(owned.permittedAddresses, ["127.0.0.1"]);
});
test("caller array iterators cannot bypass option ceilings or execute callbacks", async () => {
  const { Discovery, DiscoverySource } = api();
  let calls = 0;
  function hostile(values: string[], count: number) {
    Object.defineProperty(values, Symbol.iterator, {
      value: function* () {
        calls++;
        for (let i = 0; i < count; i++) yield values[0];
      },
    });
    return values;
  }
  for (const [key, values, count] of [
    ["permittedAddresses", ["127.0.0.1"], 17],
    ["revoked", [kid], 257],
  ] as const)
    reject(
      DiscoverySource.create({
        type: "jwks_uri",
        location: "https://agent.example",
        [key]: hostile([...values], count),
      }),
      "invalid_source",
    );
  const set = value(
    await snapshotWithMedia(
      { type: "jwks_uri", location: "https://agent.example" },
      bytes(JSON.stringify({ keys: [jwk] })),
      100,
      [],
    ),
  );
  reject(
    await set.lookup(kid, hostile(["ed25519"], 65), 100),
    "invalid_options",
  );
  const headers: [string, string][] = [["cache-control", "max-age=10"]];
  Object.defineProperty(headers, Symbol.iterator, {
    value: function* () {
      calls++;
      for (let i = 0; i < 129; i++) yield ["x-test", "value"];
    },
  });
  reject(
    await snapshotWithMedia(
      set.source,
      bytes(JSON.stringify({ keys: [jwk] })),
      100,
      headers,
    ),
    "invalid_response",
  );
  assert.equal(calls, 0);
});
test("snapshots retain public keys, thumbprints, revision and bounded provenance", async () => {
  const { Discovery, isKeySet, isResolution } = api();
  const body = bytes(JSON.stringify({ keys: [jwk] }));
  const set = value(
    await snapshotWithMedia(
      { type: "jwks_uri", location: "https://agent.example/keys" },
      body,
      100,
      [["cache-control", "max-age=60"]],
    ),
  );
  assert.ok(isKeySet(set));
  assert.equal(isKeySet({ ...set }), false);
  assert.deepEqual(Object.keys(set.keys), [kid]);
  assert.equal(set.expiresAt, 160);
  assert.equal(set.proof, "not_applicable");
  const resolution = value(await set.lookup(kid, ["ed25519"], 101));
  assert.ok(isResolution(resolution));
  assert.equal(isResolution({ ...resolution }), false);
  assert.equal(resolution.thumbprint, kid);
  assert.equal(resolution.revision, set.revision);
  assert.ok(Object.isFrozen(set.keys));
  assert.ok(Object.isFrozen(resolution));
  body.fill(0);
  assert.equal(value(await resolution.key.thumbprint()), kid);
  reject(await set.lookup(kid, ["rsa-pss-sha512"], 101), "unknown_key");
  reject(await set.lookup(kid, ["ed25519"], 160), "unknown_key");
  const bridge = value(Discovery.resolver(set, { algorithms: ["ed25519"] }));
  reject(
    await bridge({ keyid: "https://caller.example", label: "ignored" }),
    "unknown_key",
  );
});
test("body parsing rejects malformed, private, oversized, duplicate and unsupported keys", async () => {
  const { DiscoverySource, Discovery } = api();
  const source = value(
    DiscoverySource.create({
      type: "jwks_uri",
      location: "https://agent.example",
    }),
  );
  for (const [text, reason] of [
    ['{"keys":[],"keys":[]}', "invalid_response"],
    ['\ufeff{"keys":[]}', "invalid_response"],
    ['{"keys":[]}\v', "invalid_response"],
    [
      JSON.stringify({ keys: [{ ...jwk, d: "private-canary" }] }),
      "invalid_key_set",
    ],
    [JSON.stringify({ keys: [{ ...jwk, alg: 42 }] }), "invalid_key_set"],
    [JSON.stringify({ keys: [{ ...jwk, kid: "wrong" }] }), "invalid_key_set"],
    [JSON.stringify({ keys: [{ ...jwk, nbf: 1.5 }] }), "invalid_key_set"],
    [JSON.stringify({ keys: [jwk, jwk] }), "invalid_key_set"],
    [
      JSON.stringify({ keys: [{ kty: "oct", k: "c2VjcmV0" }] }),
      "invalid_key_set",
    ],
    [JSON.stringify({ keys: Array.from({ length: 33 }, () => jwk) }), "limit"],
    [
      '{"keys":[],"extra":' + "[".repeat(33) + "0" + "]".repeat(33) + "}",
      "limit",
    ],
    ['{"keys":[]}' + " ".repeat(65536), "limit"],
  ])
    reject(await parseBody(bytes(text!), source, 100), reason!);
  reject(
    await parseBody(bytes('{"keys":[]}'), source, -1),
    "invalid_options",
  );
  assert.deepEqual(
    Object.keys(
      value(
        await parseBody(
          bytes(JSON.stringify({ keys: [jwk] })),
          source,
          0,
        ),
      ),
    ),
    [kid],
  );
});
test("directory bodies require explicit unproven parsing and snapshots require possession proof", async () => {
  const { DiscoverySource, Discovery } = api();
  const source = value(
    DiscoverySource.create({
      type: "directory",
      location: "https://agent.example",
    }),
  );
  const body = bytes(JSON.stringify({ keys: [jwk] }));
  reject(await parseBody(body, source, 100), "directory_unsigned");
  reject(
    await snapshotWithMedia(source, body, 100, []),
    "directory_unsigned",
  );
  const relaxed = value(
    DiscoverySource.create({
      type: "directory",
      location: "https://agent.example",
      requireSignedDirectory: false,
    }),
  );
  assert.deepEqual(
    Object.keys(value(await parseBody(body, relaxed, 100))),
    [kid],
  );
});
test("eligible directory IDs preserve spelling and thumbprint revocation through rotation", async () => {
  const { DiscoverySource, Discovery } = api();
  const source = value(
    DiscoverySource.create({
      type: "jwks_uri",
      location: "https://agent.example",
      keyId: "directory",
    }),
  );
  const current = { ...jwk, kid: "Rotating ID" };
  for (const excluded of [
    { ...current, exp: 99 },
    { ...current, nbf: 101 },
    { ...current, use: "enc" },
    { ...current, key_ops: ["sign"] },
  ])
    for (const keys of [
      [excluded, current],
      [current, excluded],
    ]) {
      const parsed = value(
        await parseBody(bytes(JSON.stringify({ keys })), source, 100),
      );
      assert.deepEqual(Object.keys(parsed), ["Rotating ID"]);
      assert.equal(parsed["Rotating ID"]!.thumbprint, kid);
    }
  const revoked = value(
    DiscoverySource.create({
      type: "jwks_uri",
      location: "https://agent.example",
      keyId: "directory",
      revoked: [kid],
    }),
  );
  assert.deepEqual(
    Object.keys(
      value(
        await parseBody(
          bytes(JSON.stringify({ keys: [current] })),
          revoked,
          100,
        ),
      ),
    ),
    [],
  );
  reject(
    await parseBody(
      bytes(JSON.stringify({ keys: [jwk] })),
      source,
      100,
    ),
    "invalid_key_set",
  );
});
test("integer negative zero is valid for key validity bounds while negative seconds reject", async () => {
  const { Discovery, DiscoverySource } = api();
  const source = value(
    DiscoverySource.create({
      type: "jwks_uri",
      location: "https://agent.example",
    }),
  );
  const publicMembers = JSON.stringify(jwk).slice(0, -1);
  assert.deepEqual(
    Object.keys(
      value(
        await parseBody(
          bytes(`{"keys":[${publicMembers},"nbf":-0}]}`),
          source,
          100,
        ),
      ),
    ),
    [kid],
  );
  assert.deepEqual(
    Object.keys(
      value(
        await parseBody(
          bytes(`{"keys":[${publicMembers},"exp":-0}]}`),
          source,
          100,
        ),
      ),
    ),
    [],
  );
  reject(
    await parseBody(
      bytes(`{"keys":[${publicMembers},"nbf":-1}]}`),
      source,
      100,
    ),
    "invalid_key_set",
  );
});
test("CIMD snapshots enforce exact client IDs, one key source and the independent byte cap", async () => {
  const { Discovery } = api();
  const config = {
    type: "cimd",
    location: "HTTPS://AGENT.EXAMPLE.:443/client",
  };
  const body = bytes(
    JSON.stringify({ client_id: config.location, jwks: { keys: [jwk] } }),
  );
  assert.equal(
    value(await snapshotWithMedia(config, body, 100, [])).origin,
    "https://agent.example",
  );
  for (const [doc, reason] of [
    [
      { client_id: "https://agent.example/client", jwks: { keys: [] } },
      "client_id_mismatch",
    ],
    [
      {
        client_id: config.location,
        jwks: { keys: [] },
        jwks_uri: "https://agent.example/keys",
      },
      "ambiguous_key_source",
    ],
    [
      { client_id: config.location, jwks_uri: "https://agent.example/keys" },
      "source_unavailable",
    ],
  ])
    reject(
      await snapshotWithMedia(
        config,
        bytes(JSON.stringify(doc)),
        100,
        [],
      ),
      reason as string,
    );
  reject(
    await snapshotWithMedia(
      config,
      new Uint8Array(5121),
      100,
      [],
    ),
    "limit",
  );
});
test("cache directives, HTTP dates and key expiry bound snapshots independently", async () => {
  const { Discovery } = api();
  const now = 1791417600;
  const date = (t: number) => new Date(t * 1000).toUTCString();
  for (const [headers, ttl] of [
    [[], 300],
    [
      [
        ["cache-control", "max-age=30"],
        ["age", "10"],
      ],
      20,
    ],
    [[["cache-control", "no-store, max-age=300"]], 0],
    [[["expires", date(now + 60)]], 60],
    [
      [
        ["date", date(now - 60)],
        ["expires", date(now + 120)],
        ["age", "80"],
      ],
      100,
    ],
    [[["expires", "Sun, 31 Feb 2026 00:00:00 GMT"]], 0],
    [[["expires", "invalid"]], 0],
    [
      [
        ["cache-control", "max-age=10"],
        ["expires", date(now + 600)],
      ],
      10,
    ],
  ] as const) {
    const set = value(
      await snapshotWithMedia(
        { type: "jwks_uri", location: "https://agent.example" },
        bytes(JSON.stringify({ keys: [jwk] })),
        now,
        headers,
      ),
    );
    assert.equal(set.expiresAt, now + ttl);
  }
  const set = value(
    await snapshotWithMedia(
      { type: "jwks_uri", location: "https://agent.example" },
      bytes(JSON.stringify({ keys: [{ ...jwk, exp: now + 20 }] })),
      now,
      [["cache-control", "max-age=300"]],
    ),
  );
  assert.equal(set.expiresAt, now + 20);
});
test("thumbprints are stable across generated public member order", async () => {
  const { Discovery } = api();
  await fc.assert(
    fc.asyncProperty(
      fc.shuffledSubarray(Object.entries(jwk), { minLength: 3, maxLength: 3 }),
      async (entries) => {
        const set = value(
          await snapshotWithMedia(
            { type: "jwks_uri", location: "https://agent.example" },
            bytes(JSON.stringify({ keys: [Object.fromEntries(entries)] })),
            100,
            [],
          ),
        );
        assert.deepEqual(Object.keys(set.keys), [kid]);
      },
    ),
    { numRuns: 40, seed: 7638 },
  );
});
