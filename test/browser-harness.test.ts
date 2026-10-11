import test from 'node:test';
import assert from 'node:assert/strict';
import browserAssert from '../interop/browser/assert.ts';

test('browser assertions detect byte graph and exception disagreements', async () => {
  const pairs: [unknown, unknown, boolean][] = [
    [new Uint8Array([0, 255]), new Uint8Array([0, 255]), true],
    [new Uint8Array([0, 254]), new Uint8Array([0, 255]), false],
    [{a: [1, -0]}, {a: [1, 0]}, false],
    [Object.assign(Object.create(null), {a: 1}), {a: 1}, false],
    [new Date(0), new Date(1), false],
    [new Map([[1, 2]]), new Map([[1, 3]]), false],
  ];
  const cycle: {self?: unknown} = {}, same: {self?: unknown} = {};
  cycle.self = cycle; same.self = same; pairs.push([cycle, same, true]);
  for (const [a, b, equal] of pairs) {
    if (equal) browserAssert.deepEqual(a, b);
    else assert.throws(() => browserAssert.deepEqual(a, b));
  }
  assert.throws(() => browserAssert.equal(1, 2));
  assert.throws(() => browserAssert.ok(false));
  assert.throws(() => browserAssert.match('no', /yes/));
  browserAssert.throws(() => {throw new TypeError();}, TypeError);
  assert.throws(() => browserAssert.throws(() => {throw new Error();}, TypeError));
  assert.throws(() => browserAssert.throws(() => {}));
  await browserAssert.rejects(async () => {throw new TypeError();}, TypeError);
  await assert.rejects(browserAssert.rejects(async () => {}));
});
