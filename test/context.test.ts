import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { ok } from '../src/result.ts';
const sleep = (ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms));
test('Context bounds deadlines, propagates abort, and consumes late callback rejection', async () => {
  assert.ok(existsSync(new URL('../src/context.ts', import.meta.url)), 'deadline Context requires an implementation');
  const {withDeadline, remainingMs, run} = await import('../src/context.ts');
  for (const options of [{timeoutMs: 0}, {timeoutMs: 300001}, {timeoutMs: 1.5}, {timeoutMs: '1'}, {signal: {}}, {unknown: 1}, null]) assert.equal(withDeadline(options).ok, false);
  const start = performance.now(); const c = withDeadline({timeoutMs: 5000}); assert.ok(c.ok);
  assert.ok(Object.isFrozen(c.value)); assert.ok(c.value.deadline >= start + 5000); assert.ok(remainingMs(c.value) <= 5000);
  await sleep(100); // Ordinary scheduler delay must fit the positive-path budget.
  assert.deepEqual(await run(c.value, async () => ok(123)), ok(123));
  const expiring = withDeadline({timeoutMs: 40}); assert.ok(expiring.ok);
  const timeout = await run(expiring.value, async () => {await sleep(65); throw new Error('callback secret');});
  assert.equal(timeout.ok, false); if (!timeout.ok) assert.equal(timeout.error.reason, 'deadline_exceeded');
  assert.ok(expiring.value.signal.aborted); await sleep(40);
  const caller = new AbortController(); const chained = withDeadline({signal: caller.signal, timeoutMs: 5000}); assert.ok(chained.ok);
  caller.abort('caller secret'); assert.ok(chained.value.signal.aborted);
  assert.notEqual(chained.value.signal.reason, 'caller secret');
  assert.equal((await run(chained.value, async () => ok(1))).ok, false);
  const thrown = withDeadline(); assert.ok(thrown.ok);
  const fault = await run(thrown.value, () => {throw new Error('secret');});
  assert.equal(fault.ok, false); if (!fault.ok) assert.equal(fault.error.reason, 'custodian_failure');
  assert.equal((await run({deadline: Infinity, signal: new AbortController().signal} as never, async () => ok(1))).ok, false);
});
