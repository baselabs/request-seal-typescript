import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
test('numeric guards enforce safe, symmetric RFC and shared time bounds', async () => {
  assert.ok(existsSync(new URL('../src/numbers.ts', import.meta.url)), 'bounded number model requires an implementation');
  const n = await import('../src/numbers.ts');
  assert.ok(n.safeInteger(Number.MAX_SAFE_INTEGER)); assert.equal(n.safeInteger(Number.MAX_SAFE_INTEGER + 1), false);
  for (const value of [999_999_999_999_999, -999_999_999_999_999, 0]) { assert.ok(n.structuredInteger(value).ok); assert.ok(n.structuredDate(value).ok); }
  for (const bad of [1e15, -1e15, NaN, Infinity, 1.5, '1', 1n]) { assert.equal(n.structuredInteger(bad).ok, false); assert.equal(n.structuredDate(bad).ok, false); }
  assert.deepEqual(n.parseDecimal('-999999999999.999'), {ok: true, value: {scaled: -999_999_999_999_999, scale: 3}});
  assert.deepEqual(n.parseDecimal('1.2'), {ok: true, value: {scaled: 1200, scale: 3}});
  assert.deepEqual(n.parseDecimal('-0.001'), {ok: true, value: {scaled: -1, scale: 3}});
  for (const bad of ['1000000000000.0', '-1000000000000.0', '1.0000', '1.', '.1', '+1.0', '1e2', '0000000000000.1', ' 1.0', 1]) assert.equal(n.parseDecimal(bad).ok, false);
  for (const value of [0, 253_402_300_799]) assert.ok(n.clockSeconds(value).ok);
  for (const bad of [-1, 253_402_300_800, Infinity, 0.1, '0']) assert.equal(n.clockSeconds(bad).ok, false);
  for (const value of [1, 300000]) assert.ok(n.timeoutMs(value).ok);
  for (const bad of [0, -1, 300001, 1.1, '1']) assert.equal(n.timeoutMs(bad).ok, false);
});
