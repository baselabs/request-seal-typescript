import test from 'node:test';
import assert from 'node:assert/strict';
import {withDeadline, run} from '../src/context.ts';
test('an awaited hung run settles without unrelated process work', async () => {
  const context = withDeadline({timeoutMs: 200}); assert.ok(context.ok);
  const result = await run(context.value, () => new Promise(() => {}));
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.error.reason, 'deadline_exceeded');
});
