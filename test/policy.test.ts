import test from "node:test";
import assert from "node:assert/strict";
import * as api from "../src/index.ts";
import { ok } from "../src/result.ts";
const A = api as any;
export const attrs = {
  algorithms: ["ed25519"],
  components: '("@method")',
  keyResolver: async () => ok(null),
  freshness: "not_evaluated",
  content: "not_required",
  replay: "not_required",
};
test("policies require explicit choices and carry a distinct frozen brand", () => {
  assert.equal(typeof A.Policy?.create, "function");
  const p = A.Policy.create(attrs);
  assert.equal(p.ok, true);
  assert.equal(A.isPolicy(p.value), true);
  assert.equal(Object.isFrozen(p.value), true);
  assert.equal(A.isPolicy({ ...p.value }), false);
  assert.equal(A.isVerification?.(p.value) ?? false, false);
  for (const key of Object.keys(attrs)) {
    const v = { ...attrs } as any;
    delete v[key];
    assert.equal(A.Policy.create(v).error.reason, "invalid_policy");
  }
  for (const v of [
    { ...attrs, algorithms: [] },
    { ...attrs, algorithms: ["EdDSA"] },
    { ...attrs, components: '("@method" "@method")' },
    { ...attrs, unknown: true },
    {
      ...attrs,
      freshness: {
        clock: () => 0,
        maxAge: 253402300800,
        skew: 0,
        requireExpires: false,
      },
    },
  ])
    assert.equal(A.Policy.create(v).error.reason, "invalid_policy");
});
test("policy snapshots read own choices once and ignore inherited choices", () => {
  assert.equal(typeof A.Policy?.create, "function");
  let reads = 0;
  const p = A.Policy.create({
    ...attrs,
    get content() {
      reads++;
      return "not_required";
    },
  });
  assert.equal(p.ok, true);
  assert.equal(reads, 1);
  assert.equal(
    A.Policy.create(Object.create(attrs)).error.reason,
    "invalid_policy",
  );
});
test("present invalid optional schemas reject instead of selecting defaults", () => {
  const r = A.Policy.create({ ...attrs, fieldSchemas: null });
  assert.equal(r.ok, false, "Explicit null schemas must reject");
  assert.equal(r.error.reason, "invalid_policy");
});
