import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
test('self-checks execute the SHA-256 known answers and fail-closed codec bounds', async () => {
  assert.ok(existsSync(new URL('../self-checks.ts', import.meta.url)), 'self-check battery requires an implementation');
  const {selfChecks} = await import('../self-checks.ts');
  const checks = await selfChecks();
  assert.equal(checks.length, 6); for (const check of checks) assert.equal(check.ok, true, check.name);
});
