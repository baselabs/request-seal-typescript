import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
const deno = Object.hasOwn(process.versions, 'deno'), bun = Object.hasOwn(process.versions, 'bun');
const tests = deno ? ['test', '--no-check', '--allow-read'] : bun ? ['test'] : ['--unhandled-rejections=strict', '--experimental-strip-types', '--no-warnings', '--test'];
const evaluate = deno ? ['eval', '--no-check'] : ['-e'];
const check = (args: string[]) => {
  const env = {...process.env}; delete env.NODE_TEST_CONTEXT;
  return spawnSync('sh', [process.env.REQUEST_SEAL_RED_PROOF_SCRIPT ?? 'scripts/red-proof.sh', process.execPath, ...args], {encoding: 'utf8', env, timeout: 10_000});
};
test('red proof accepts only the actual planted assertion with a failing-test count', {timeout: 60_000}, () => {
  const planted = check([...tests, 'test/red/planted.test.ts']);
  assert.equal(planted.status, 0, planted.stdout + planted.stderr);
  assert.match(planted.stdout, /Intentional red proof/);
  const missing = check([...tests, 'test/red/no-such-test.ts']);
  assert.equal(missing.status, 1, missing.stdout + missing.stderr);
  const crash = check([...evaluate, 'throw new Error("Intentional red proof")']);
  assert.equal(crash.status, 1, crash.stdout + crash.stderr);
  const passing = check([...tests, 'test/self-checks.test.ts']);
  assert.equal(passing.status, 1, passing.stdout + passing.stderr);
  assert.match(passing.stderr, /Planted failure was accepted/);
  console.log('PASS red-proof: planted assertion accepted; missing test, process crash, and passing suite rejected');
});

test('red proof rejects a failing test count without the planted marker', {timeout: 15_000}, () => {
  const root = mkdtempSync(join(tmpdir(), 'request-seal-red-marker-'));
  try {
    const path = join(root, 'different.test.ts');
    writeFileSync(path, "import test from 'node:test';import assert from 'node:assert/strict';test('different planted failure',()=>assert.fail('Different failure message'));\n");
    const wrong = check([...tests, path]);
    assert.match(wrong.stdout, /(^# fail [1-9][0-9]*|\s+fail [1-9][0-9]*|[1-9][0-9]* (fail|failed)(\s|$))/m);
    assert.doesNotMatch(wrong.stdout, /Intentional red proof/);
    assert.equal(wrong.status, 1, wrong.stdout + wrong.stderr);
  } finally { rmSync(root, {recursive: true, force: true}); }
});
