import test from "node:test";
import assert from "node:assert/strict";
import * as Seal from "../src/index.ts";
import fc from "fast-check";
const attrs = () => ({
  algorithms: ["ed25519"],
  agents: (_request: unknown) => Seal.ok(null),
  cache: null,
  freshness: { clock: () => 100, maxAge: null, skew: 0 },
  content: "not_required",
  replay: "not_required",
});
test("Web Bot Auth requires explicit branded policy choices without invoking callbacks", () => {
  assert.equal(typeof Seal.WebBotAuth?.Policy.create, "function");
  let calls = 0;
  const p = Seal.WebBotAuth.Policy.create({
    ...attrs(),
    agents: (_request: unknown) => {
      calls++;
      return Seal.ok(null);
    },
    freshness: {
      clock: () => {
        calls++;
        return 100;
      },
      maxAge: null,
      skew: 0,
    },
  });
  assert.ok(p.ok);
  assert.equal(calls, 0);
  assert.ok(Object.isFrozen(p.value));
  assert.ok(Seal.isWebBotAuthPolicy(p.value));
  assert.equal(Seal.isWebBotAuthPolicy({ ...p.value }), false);
  for (const key of Object.keys(attrs())) {
    const a: Record<string, unknown> = { ...attrs() };
    delete a[key];
    assert.equal(Seal.WebBotAuth.Policy.create(a).ok, false);
  }
  for (const change of [
    { algorithms: ["hmac-sha256"] },
    { algorithms: [{ jws: "HS256" }] },
    { agents: null },
    { cache: {} },
    { unknown: true },
    { maxLifetime: 604801 },
    { testKeys: "unknown" },
    { unresolved: "allow" },
  ])
    assert.equal(
      Seal.WebBotAuth.Policy.create({ ...attrs(), ...change }).ok,
      false,
    );
});
test("policy snapshots own choices once and rejects out-of-range freshness symmetrically", () => {
  let reads = 0;
  const a = {
    ...attrs(),
    get maxLifetime() {
      reads++;
      return 60;
    },
  };
  assert.ok(Seal.WebBotAuth.Policy.create(a).ok);
  assert.equal(reads, 1);
  fc.assert(
    fc.property(fc.integer({ min: 0, max: 86400 }), (skew) =>
      assert.ok(
        Seal.WebBotAuth.Policy.create({
          ...attrs(),
          freshness: { ...attrs().freshness, skew },
        }).ok,
      ),
    ),
  );
  for (const skew of [-1, 86401])
    assert.equal(
      Seal.WebBotAuth.Policy.create({
        ...attrs(),
        freshness: { ...attrs().freshness, skew },
      }).ok,
      false,
    );
  for (const maxAge of [0, -1, 253402300800])
    assert.equal(
      Seal.WebBotAuth.Policy.create({
        ...attrs(),
        freshness: { ...attrs().freshness, maxAge },
      }).ok,
      false,
    );
  assert.ok(
    Seal.WebBotAuth.Policy.create({
      ...attrs(),
      freshness: { ...attrs().freshness, requireExpires: false },
    }).ok,
  );
});
test("policy inspection exposes bounded choices without callbacks or source configuration", () => {
  const p = Seal.WebBotAuth.Policy.create(attrs());
  assert.ok(p.ok);
  const text = JSON.stringify(p.value);
  assert.equal(text.includes("freshness"), false);
  assert.equal(text.includes("agents"), false);
  assert.equal(text.includes("cache"), false);
});
