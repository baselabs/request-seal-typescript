import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import * as api from '../src/index.ts';
import {createReceipt} from '../src/replay/receipt.ts';
const A = api as any;
const max = 253402300799;
function value(r: any): any { assert.equal(r.ok, true, JSON.stringify(r)); return r.value; }
test('claims and receipts have separate private brands and defensive byte copies', () => {
  assert.equal(typeof A.Claim?.create, 'function');
  const bytes = new Uint8Array([0, 255]);
  const c = value(A.Claim.create({namespace: bytes, key: bytes, retainUntil: max}));
  bytes.fill(1); c.key.fill(2); c.namespace.fill(3);
  assert.deepEqual(c.key, new Uint8Array([0, 255]));
  assert.deepEqual(c.namespace, new Uint8Array([0, 255]));
  assert.equal(Object.isFrozen(c), true);
  assert.equal(A.Claim.valid(c), true);
  assert.equal(A.Claim.valid({...c}), false);
  const receipt = value(createReceipt({store: 'memory', retainUntil: max}));
  assert.equal(api.isReplayReceipt(receipt), true);
  assert.equal(A.Claim.valid(receipt), false);
  assert.equal(api.isReplayReceipt(c), false);
  assert.deepEqual(Object.keys(receipt), ['store', 'retainUntil']);
  assert.equal(Object.isFrozen(receipt), true);
});
test('claim and receipt constructors reject invalid bounds and unknown own keys', () => {
  assert.equal(typeof A.Claim?.create, 'function');
  for (const retainUntil of [Number.MIN_SAFE_INTEGER - 1, -9223372036854775809n, max + 1, 0.1, NaN, Infinity, '0']) {
    assert.equal(A.Claim.create({namespace: new Uint8Array([1]), key: new Uint8Array([1]), retainUntil}).error.reason, 'invalid_claim');
  }
  for (const bad of ['', [], new Uint8Array(), new Uint8Array(257)]) {
    for (const field of ['namespace', 'key']) assert.equal(A.Claim.create({namespace: new Uint8Array([1]), key: new Uint8Array([1]), retainUntil: 0, [field]: bad}).ok, false);
  }
  assert.equal(A.Claim.create({namespace: new Uint8Array([1]), key: new Uint8Array([1]), retainUntil: 0, extra: true}).ok, false);
  assert.equal(createReceipt({store: 'unsafe\n', retainUntil: 1}).ok, false);
  assert.equal(createReceipt({store: 'memory', retainUntil: 1, key: new Uint8Array([1])}).ok, false);
});
test('retention uses the minimum present bound and rejects unsweepable ends', () => {
  assert.equal(typeof A.Replay?.retainUntil, 'function');
  fc.assert(fc.property(fc.integer({min: 0, max: max}), fc.option(fc.integer({min: 0, max}), {nil: null}), fc.option(fc.integer({min: 1, max}), {nil: null}), fc.integer({min: 0, max: 86400}), (created, expires, maxAge, skew) => {
    if (expires === null && maxAge === null) return;
    const end = Math.min(expires === null ? Infinity : expires + skew, maxAge === null ? Infinity : created + maxAge + skew + 1);
    const r = A.Replay.retainUntil({created, expires, maxAge, skew});
    if (end > max) { assert.equal(r.ok, false); assert.equal(r.error.reason, 'retention_exceeded'); }
    else assert.equal(value(r), end);
  }), {seed: 6401, numRuns: 300});
  assert.equal(value(A.Replay.retainUntil({created: 100, expires: 160, maxAge: 60, skew: 0})), 160);
  assert.equal(value(A.Replay.retainUntil({created: 100, expires: null, maxAge: 60, skew: 0})), 161);
  assert.equal(A.Replay.retainUntil({created: null, expires: null, maxAge: null, skew: 0}).ok, false);
});
test('claim construction reads each own input once and row encoding is lossless hex', () => {
  assert.equal(typeof A.Claim?.create, 'function');
  let reads = 0;
  const c = value(A.Claim.create({get namespace() { reads++; return new Uint8Array([0,255]); }, get key() { reads++; return new Uint8Array([255,0]); }, get retainUntil() { reads++; return 200; }}));
  assert.equal(reads, 3);
  assert.deepEqual(value(A.Replay.row(c)), ['00ff', 'ff00', '200']);
  assert.equal(A.Replay.row({...c}).error.reason, 'invalid_claim');
});
test('claim byte limits use the actual typed-array length despite subclass accessors', () => {
  class Bytes extends Uint8Array { get length() {return 1;} }
  for (const length of [0,257]) {
    for (const field of ['namespace', 'key']) {
      const r = A.Claim.create({namespace: new Uint8Array([1]), key: new Uint8Array([1]), retainUntil: 1, [field]: new Bytes(length)});
      assert.equal(r.ok, false);
      assert.equal(r.error.reason, 'invalid_claim');
    }
  }
});
test('policy namespaces enforce the same actual byte bounds as direct claims', () => {
  class Bytes extends Uint8Array { get length() {return 1;} }
  const store = value(A.createMemoryStore({maxEntries: 1}));
  for (const namespace of [new Bytes(0), new Bytes(257)]) {
    const p = api.Policy.create({
      algorithms: ['ed25519'], components: '()', keyResolver: () => api.ok(null),
      freshness: {clock: () => 100, maxAge: 60, skew: 0, requireExpires: false},
      content: 'not_required', replay: {
        identifier: 'nonce', namespace, store, timeoutMs: 5000,
        commitment: (facts: api.ReplayFacts) => api.ok(new TextEncoder().encode(facts.identifier)),
      },
    });
    assert.equal(p.ok, false); if (!p.ok) assert.equal(p.error.reason, 'invalid_policy');
  }
});

test('internal receipts accept already-expired safe-number ends like claims', () => {
  for (const retainUntil of [Number.MIN_SAFE_INTEGER, -1, 0, max]) {
    assert.equal(api.Claim.create({namespace: new Uint8Array([1]), key: new Uint8Array([2]), retainUntil}).ok, true);
    const r = createReceipt({store: 'memory', retainUntil});
    assert.equal(r.ok, true, String(retainUntil));
    if (r.ok) {assert.equal(r.value.retainUntil, retainUntil); assert.equal(api.isReplayReceipt(r.value), true);}
  }
  for (const retainUntil of [Number.MIN_SAFE_INTEGER - 1, max + 1, NaN, Infinity, -Infinity, 0.5]) assert.equal(createReceipt({store: 'memory', retainUntil}).ok, false);
});

test('caller store ports reject extra own keys and require explicitly bound prototype methods', async () => {
  const memory = value(api.createMemoryStore({maxEntries: 1}));
  const c = value(api.Claim.create({namespace: new Uint8Array([1]), key: new Uint8Array([2]), retainUntil: 100}));
  class Port {
    claim(claim: api.ReplayClaim, ctx: api.Context) {return memory.claim(claim, ctx);}
    sweep(now: number, ctx: api.Context) {return memory.sweep(now, ctx);}
  }
  const prototype = new Port();
  const bound = {claim: prototype.claim.bind(prototype), sweep: prototype.sweep.bind(prototype)};
  for (const port of [prototype, {...bound, state: {}}, {...bound, [Symbol('extra')]: true}]) {
    const r = api.Replay.store(port);
    assert.equal(r.ok, false); if (!r.ok) assert.equal(r.error.reason, 'invalid_store');
  }
  for (const port of [bound, {...bound, identity: 'caller'}]) {
    const store = value(api.Replay.store(port));
    assert.equal(value(await api.Replay.claim(store, c, value(api.withDeadline()))), 'claimed');
    assert.equal(value(await api.Replay.sweep(store, 100, value(api.withDeadline()))), 1);
  }
});
