import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { declarationInventory, inventoryChanges, type ApiInventory } from '../scripts/public-api-inventory.ts';

test('every package entry point has exactly the inventoried declaration signatures', t => {
  if (process.versions.bun || (globalThis as {Deno?: unknown}).Deno) {
    t.skip('Native lanes run source tests; every Node lane checks declarations after build');
    return;
  }
  const expected = JSON.parse(readFileSync(new URL('./fixtures/public-api-inventory.json', import.meta.url), 'utf8')) as ApiInventory;
  const actual = declarationInventory();
  assert.doesNotMatch(actual['.']!['WebBotAuthPolicy']!, /const WebBotAuthPolicy/, 'type-only exports must not acquire a runtime value');
  assert.match(actual['.']!['Discovery']!, /type KeyResolver/, 'the facade retains its distinct supporting resolver signature');
  for (const signature of [actual['.']!['WebBotAuth']!, actual['./discovery-node']!['Discovery']!,
    actual['./discovery-node']!['DiscoverySource']!])
    assert.doesNotMatch(signature, /typeof import\(/, 'imported facade callables must retain their resolved signatures');
  const changes = inventoryChanges(expected, actual);
  assert.deepEqual(changes, [], 'Public API drift (review inventory updates beside API changes):\n' + changes.join('\n'));
});

test('inventory reports additions, removals, signature changes and subpath drift', () => {
  const before = {'.': {kept: 'function kept(): void;', removed: 'type Removed = string;'}};
  const after = {'.': {kept: 'function kept(value: unknown): void;', added: 'type Added = number;'}, './new': {}};
  const changes = inventoryChanges(before, after);
  assert.ok(changes.some(c => c.startsWith('added . added')));
  assert.ok(changes.some(c => c.startsWith('removed . removed')));
  assert.ok(changes.some(c => c.startsWith('changed . kept')));
  assert.ok(changes.includes('added entry point ./new'));
});

test('inventory ignores only declaration presentation, preserving readonly and parameter types', () => {
  const original = {'.': {api: 'declare const api: Readonly<{one: (value: unknown) => string; two: number}>;'}};
  assert.deepEqual(inventoryChanges(original, {'.': {api: 'const api: {readonly two: number; readonly one: (value: unknown) => string};'}}), []);
  for (const api of ['const api: {two: number; one: (value: unknown) => string};',
    'const api: Readonly<{one: (value: string) => string; two: number}>;']) {
    assert.ok(inventoryChanges(original, {'.': {api}}).some(c => c.startsWith('changed . api')));
  }
  assert.ok(inventoryChanges({'.': {api: 'const api: {(x: unknown): number; (x: string): string};'}},
    {'.': {api: 'const api: {(x: string): string; (x: unknown): number};'}}).length > 0,
    'overload order remains part of the signature');
  assert.ok(inventoryChanges({'.': {api: 'export type { api }; class api {}'}},
    {'.': {api: 'export { api }; class api {}'}}).length > 0,
    'a type-only selection becoming a runtime export changes the signature');
});
