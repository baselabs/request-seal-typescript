import test from 'node:test';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { snapshotOptions } from '../src/brand.ts';
import { withDeadline, run } from '../src/context.ts';
import { decodeJson } from '../src/json.ts';
import { JSON_LIMITS, TIMEOUT_DEFAULT_MS } from '../src/constants.ts';
import { ok } from '../src/result.ts';
import { runCorpus, surfaceRegistry } from '../tools/conformance/loader.ts';
const contextKeys = ['signal', 'timeoutMs', 'parent'] as const;
const jsonKeys = Object.keys(JSON_LIMITS) as (keyof typeof JSON_LIMITS)[];
const corpusKeys = ['unpinned', 'smoke', 'registry'] as const;
const fixture = resolve('test/fixtures/corpus-smoke');
async function pollution(key: string, value: unknown, check: () => Promise<void> | void): Promise<void> {
  const saved = Object.getOwnPropertyDescriptor(Object.prototype, key);
  try { Object.defineProperty(Object.prototype, key, {configurable: true, value}); await check(); }
  finally { if (saved) Object.defineProperty(Object.prototype, key, saved); else Reflect.deleteProperty(Object.prototype, key); }
}
test('prototype pollution is invisible for every Context, JSON, and corpus option key', async () => {
  const allKeys = [...contextKeys, ...jsonKeys, ...corpusKeys];
  for (const key of allKeys) await pollution(key, 0, () => {
    const generic = snapshotOptions({}, allKeys); assert.ok(generic.ok);
    assert.equal(Object.getPrototypeOf(generic.value), null); assert.equal(Object.hasOwn(generic.value, key), false, key);
  });
  for (const key of contextKeys) await pollution(key, 0, async () => {
    const start = performance.now(), context = withDeadline({}); assert.ok(context.ok, key);
    assert.ok(context.value.deadline >= start + TIMEOUT_DEFAULT_MS);
    assert.deepEqual(await run(context.value, () => ok(1)), ok(1));
  });
  for (const key of jsonKeys) await pollution(key, 0, () => assert.ok(decodeJson(new TextEncoder().encode('null')).ok, key));
  for (const key of corpusKeys) await pollution(key, key === 'registry' ? new Map() : true, async () => {
    const report = await runCorpus(fixture, key === 'registry' ? {smoke: true} : {});
    if (key === 'registry') assert.equal(report.ok, true);
    else assert.deepEqual(report.failures[0], {id: 'index', reason: 'index_pin_mismatch'});
  });
  console.log(`PASS prototype-pollution: ${allKeys.length} option keys; inherited choices invisible; null-prototype snapshots`);
});
test('counting getters are read exactly once for every Context, JSON, and corpus option key', async () => {
  const parent = withDeadline({timeoutMs: 1000}); assert.ok(parent.ok);
  const values = {signal: new AbortController().signal, timeoutMs: 100, parent: parent.value, ...JSON_LIMITS, unpinned: false, smoke: true, registry: surfaceRegistry()};
  let total = 0;
  function options(keys: readonly (keyof typeof values)[]): object {
    const result = Object.create(null);
    for (const key of keys) {
      let reads = 0;
      Object.defineProperty(result, key, {enumerable: true, get() { assert.equal(++reads, 1, `${key} read again`); total++; return values[key]; }});
    }
    return result;
  }
  const context = withDeadline(options(contextKeys)); assert.ok(context.ok); await run(context.value, () => ok(1));
  assert.ok(decodeJson(new TextEncoder().encode('null'), options(jsonKeys)).ok);
  assert.equal((await runCorpus(fixture, options(corpusKeys))).ok, true);
  await run(parent.value, () => ok(1));
  assert.equal(total, 11);
  console.log(`PASS counting-getter: ${total} option keys; exactly one read each`);
});
