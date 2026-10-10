import test from "node:test";
import assert from "node:assert/strict";
import * as api from "../src/index.ts";
const A = api as any;
const value = (r: any): any => {
  assert.equal(r.ok, true);
  return r.value;
};
function policy(extra = {}) {
  return value(
    api.Policy.create({
      algorithms: ["ed25519"],
      components: "()",
      keyResolver: () => api.ok(null),
      freshness: "not_evaluated",
      content: "not_required",
      replay: "not_required",
      ...extra,
    }),
  );
}
test("quorum construction requires explicit choices and brands only owned frozen values", () => {
  assert.equal(
    typeof A.Quorum?.create,
    "function",
    "Quorum.create must be exported",
  );
  const attrs = {
    mode: "all",
    unit: "keys",
    slots: [{ id: "one", policy: policy(), required: true }],
    unexpected: "ignore",
    invalid: "ignore",
  };
  const q = value(A.Quorum.create(attrs));
  assert.equal(A.isQuorum(q), true);
  assert.equal(A.isQuorum({ ...q }), false);
  assert.equal(Object.isFrozen(q.slots[0]), true);
  for (const extra of [
    { mode: "bad" },
    { maxSignatures: null },
    { unit: "labels" },
    { slots: [] },
    { slots: Array(17).fill(attrs.slots[0]) },
    { slots: [...attrs.slots, ...attrs.slots] },
    { mode: { threshold: 65 } },
    { mode: { threshold: 3 }, maxSignatures: 2 },
    { unit: "principals" },
    { unit: "roles", sharedPrincipal: false },
    { extra: true },
    { slots: [{ ...attrs.slots[0], required: false }] },
    { bindings: [{ kind: "nested", outer: "one", inner: "one" }] },
    { bindings: [{ kind: "nested", outer: "one", inner: "absent" }] },
  ]) {
    assert.equal(
      A.Quorum.create({ ...attrs, ...extra }).error.reason,
      "invalid_quorum",
    );
  }
  let reads = 0;
  const s = {
    ...attrs.slots[0],
    get label() {
      reads++;
      return "s";
    },
  };
  value(A.Quorum.create({ ...attrs, slots: [s] }));
  assert.equal(reads, 1);
});
test("replay policies reject during verification before message validation or callbacks", async () => {
  assert.equal(
    typeof A.Quorum?.create,
    "function",
    "Quorum.create must be exported",
  );
  let calls = 0;
  const store = {
    claim: () => {
      calls++;
      return api.ok("claimed" as const);
    },
    sweep: () => {
      calls++;
      return api.ok(0);
    },
  };
  store.claim();
  assert.equal(calls, 1);
  calls = 0;
  const p = policy({
    freshness: {
      clock: () => {
        calls++;
        return 10;
      },
      maxAge: 60,
      skew: 0,
      requireExpires: false,
    },
    replay: {
      identifier: "nonce",
      namespace: new Uint8Array([1]),
      commitment: () => {
        calls++;
        return api.ok(new Uint8Array([1]));
      },
      store,
      timeoutMs: 1000,
    },
  });
  for (const [required, label] of [
    [true, "s"],
    [false, "s"],
    [false, "absent"],
  ]) {
    const attrs = {
      mode: "any",
      unit: "keys",
      slots: [{ id: "one", policy: p, required, label }],
      unexpected: "ignore",
      invalid: "ignore",
    };
    const q = value(A.Quorum.create(attrs));
    const rejection = await A.verifyQuorum(null, q, {});
    assert.equal(rejection.error.reason, "invalid_policy");
    assert.equal(rejection.error.layer, "input");
    assert.equal(
      A.Quorum.create({
        ...attrs,
        slots: [
          {
            ...attrs.slots[0],
            policy: policy({
              content: {
                kind: "representation",
                algorithms: ["sha-256"],
                section: "headers",
              },
            }),
          },
        ],
      }).error.reason,
      "invalid_quorum",
    );
  }
  assert.equal(calls, 0);
});


test('quorum inspection exposes only mode unit and signature bound', async () => {
  const {inspect} = await import('node:util');
  const q = value(A.Quorum.create({mode: 'any', unit: 'keys', slots: [{id: 'private-slot', policy: policy(), required: false, label: 'private-label', tag: 'private-tag'}], unexpected: 'ignore', invalid: 'ignore'}));
  for (const result of [inspect(q), q[Symbol.for('Deno.customInspect')]?.()]) {
    assert.deepEqual(JSON.parse(result), {mode: 'any', unit: 'keys', maxSignatures: 16});
  }
});

test('quorum JSON exposes only the same facts as custom inspection', async () => {
  const {inspect} = await import('node:util');
  const q = value(api.Quorum.create({mode: 'all', unit: 'keys', unexpected: 'ignore', invalid: 'ignore', slots: [{id: 'private-slot', policy: policy(), required: true, label: 'private-label', tag: 'private-tag', principal: 'private-principal'}]}));
  const expected = {mode: q.mode, unit: q.unit, maxSignatures: q.maxSignatures};
  assert.deepEqual(JSON.parse(JSON.stringify(q)), expected);
  assert.deepEqual(JSON.parse(inspect(q)), expected);
  const deno = (globalThis as any).Deno;
  if (deno) assert.deepEqual(JSON.parse(deno.inspect(q)), expected);
  assert.deepEqual(JSON.parse(JSON.stringify({q})), {q: expected});
});
