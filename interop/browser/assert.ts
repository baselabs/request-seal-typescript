// An assertion library for the browser runner, not a replacement crypto substrate.
type Predicate = ((error: unknown) => boolean) | (new (...args: never[]) => Error);
function fail(message = 'Assertion failed'): never { throw new Error(message); }
function ok(value: unknown, message?: string): asserts value { if (!value) fail(message); }
function equal(actual: unknown, expected: unknown, message?: string): void {
  if (!Object.is(actual, expected)) fail(message ?? `Expected ${String(expected)}, received ${String(actual)}`);
}
function same(actual: unknown, expected: unknown, seen = new Map<object, object>()): boolean {
  if (Object.is(actual, expected)) return true;
  if (!actual || !expected || typeof actual !== 'object' || typeof expected !== 'object') return false;
  if (Object.getPrototypeOf(actual) !== Object.getPrototypeOf(expected)) return false;
  if (seen.has(actual)) return seen.get(actual) === expected;
  seen.set(actual, expected);
  if (actual instanceof Uint8Array && expected instanceof Uint8Array)
    return actual.length === expected.length && actual.every((v, i) => v === expected[i]);
  if (actual instanceof Date && expected instanceof Date) return Object.is(actual.getTime(), expected.getTime());
  const prototype = Object.getPrototypeOf(actual);
  if (prototype !== null && prototype !== Object.prototype && prototype !== Array.prototype) return false;
  const a = Reflect.ownKeys(actual), b = Reflect.ownKeys(expected);
  return a.length === b.length && a.every(k => b.includes(k) && same(Reflect.get(actual, k), Reflect.get(expected, k), seen));
}
function deepEqual(actual: unknown, expected: unknown, message?: string): void {
  if (!same(actual, expected)) fail(message ?? 'Expected deeply equal values');
}
function matches(error: unknown, expected?: Predicate): boolean {
  if (!expected) return true;
  if (expected.prototype instanceof Error || expected === Error) return error instanceof expected;
  return (expected as (error: unknown) => boolean)(error);
}
function throws(fn: () => unknown, expected?: Predicate): void {
  try { fn(); } catch (error) { if (!matches(error, expected)) fail('Unexpected exception'); return; }
  fail('Expected an exception');
}
async function rejects(fn: () => Promise<unknown>, expected?: Predicate): Promise<void> {
  try { await fn(); } catch (error) { if (!matches(error, expected)) fail('Unexpected rejection'); return; }
  fail('Expected a rejection');
}
function doesNotThrow(fn: () => unknown): void { fn(); }
function match(value: string, pattern: RegExp): void { ok(pattern.test(value), 'Expected pattern ' + pattern); }
const assert: {
  ok: typeof ok; equal: typeof equal; deepEqual: typeof deepEqual; fail: typeof fail;
  throws: typeof throws; rejects: typeof rejects; doesNotThrow: typeof doesNotThrow; match: typeof match;
} = {ok, equal, deepEqual, fail, throws, rejects, doesNotThrow, match};
export default assert;
