import test from 'node:test';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {readFileSync} from 'node:fs';
import {assertPortableFiles, discoverPortableFiles, portableFiles} from '../interop/browser/selection.ts';
import {limitRecords} from '../interop/browser/records.ts';

test('browser selection pins the entire real portable file set', async () => {
  const selected = await discoverPortableFiles(fileURLToPath(new URL('..', import.meta.url)));
  assert.deepEqual(selected, [...portableFiles]);
  assert.doesNotThrow(() => assertPortableFiles(selected));
  for (const file of selected) assert.throws(() => assertPortableFiles(selected.filter(name => name !== file)), /Portable test set changed/);
  assert.throws(() => assertPortableFiles([...selected, 'browser-harness.test.ts']), /Portable test set changed/);
});

test('browser limitation records compare by set rather than execution order', () => {
  const table = JSON.parse(readFileSync(new URL('../tools/conformance/runtime-limits.json', import.meta.url), 'utf8'));
  const entries = table.bun['1.3.14'];
  assert.ok(entries.length > 1, 'Known-positive multi-limitation declaration');
  assert.deepEqual(limitRecords(entries), limitRecords([...entries].reverse()));
  assert.notDeepEqual(limitRecords(entries), limitRecords(entries.slice(1)));
  assert.notDeepEqual(limitRecords(entries), limitRecords(entries.map((entry: {id: string; observed: string}, index: number) => index === 0 ? {...entry, observed: 'changed/reason'} : entry)));
});
