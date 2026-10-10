import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import fc from 'fast-check';
test('deep freeze and own-key option snapshots reject pollution and faults', async () => {
  assert.ok(existsSync(new URL('../src/brand.ts', import.meta.url)), 'option snapshot and deep freeze require an implementation');
  const {deepFreeze, snapshotOptions} = await import('../src/brand.ts');
  const value = {nested: {items: [1]}};
  const frozenValue = deepFreeze(value); assert.ok(frozenValue.ok); assert.ok(Object.isFrozen(frozenValue.value)); assert.ok(Object.isFrozen(frozenValue.value.nested.items)); assert.equal(Object.isFrozen(value), false);
  const cycle: {self?: object} = {}; cycle.self = cycle; const frozenCycle = deepFreeze(cycle); assert.ok(frozenCycle.ok); assert.ok(Object.isFrozen(frozenCycle.value)); assert.equal(frozenCycle.value.self, frozenCycle.value);
  let reads = 0;
  const getter = Object.defineProperty({}, 'timeoutMs', {enumerable: true, get() { reads++; return 10; }});
  const result = snapshotOptions(getter, ['timeoutMs']); assert.ok(result.ok); assert.equal(reads, 1); assert.equal(Object.getPrototypeOf(result.value), null); assert.ok(Object.isFrozen(result.value));
  const saved = Object.getOwnPropertyDescriptor(Object.prototype, 'timeoutMs');
  try {
    Object.defineProperty(Object.prototype, 'timeoutMs', {configurable: true, value: 300000});
    const safe = snapshotOptions({}, ['timeoutMs']); assert.ok(safe.ok); assert.equal(Object.hasOwn(safe.value, 'timeoutMs'), false);
  } finally { if (saved) Object.defineProperty(Object.prototype, 'timeoutMs', saved); else Reflect.deleteProperty(Object.prototype, 'timeoutMs'); }
  for (const bad of [{unknown: 1}, {[Symbol('unknown')]: 1}, null, [], 1, Object.defineProperty({}, 'timeoutMs', {get() {throw new Error('secret');}})]) assert.equal(snapshotOptions(bad, ['timeoutMs']).ok, false);
  const malicious = Object.create(null); malicious.__proto__ = 1;
  assert.equal(snapshotOptions(malicious, ['timeoutMs']).ok, false);
  fc.assert(fc.property(fc.record({timeoutMs: fc.integer(), flag: fc.boolean()}), input => {
    const first = snapshotOptions(input, ['timeoutMs', 'flag']); assert.ok(first.ok);
    const second = snapshotOptions(first.value, ['timeoutMs', 'flag']); assert.ok(second.ok); assert.deepEqual(second.value, first.value);
    const frozen = deepFreeze(input); assert.ok(frozen.ok); const again = deepFreeze(frozen.value); assert.ok(again.ok); assert.deepEqual(again.value, frozen.value);
  }), {numRuns: 150});
});
