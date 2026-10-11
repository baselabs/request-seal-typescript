import assert from './assert.ts';
import type {Result} from '../../dist/index.js';
type Limit = {id: string; items: number[]; observed: string; reason: string; platforms?: string[]};
const selected: Limit[] = JSON.parse(new URL(location.href).searchParams.get('limits') ?? '[]');
const consumed = new Set<string>();
export function limitation(id: string): Limit | undefined {
  return selected.find(entry => entry.id === id);
}
export function assertOutcome<T>(id: string, result: Result<T>): void {
  const limit = limitation(id);
  if (!limit) {assert.equal(result.ok, true, id + ': unexpected runtime rejection'); return;}
  assert.equal(result.ok, false, id + ': stale runtime limitation');
  if (!result.ok) assert.equal(result.error.kind + '/' + result.error.reason, limit.observed);
  assert.deepEqual(limit.items, [1]);
  assert.equal(consumed.has(id), false, 'Each declared limitation must be observed once');
  consumed.add(id);
  console.log('REQUEST_SEAL_LIMIT ' + JSON.stringify({id, observed: limit.observed}));
}
export function assertAllObserved(): void {
  assert.deepEqual([...consumed].sort(), selected.map(entry => entry.id).sort());
}
