import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnWithEnvSync, execFileWithEnvSync} from './support/child-env.ts';

for (const execute of ['spawn', 'exec'] as const) test(`${execute} child receives only explicit environment keys`, () => {
  const key = 'REQUEST_SEAL_CHILD_ENV_PROBE';
  const before = process.env[key];
  process.env[key] = 'parent';
  try {
    const env: NodeJS.ProcessEnv = {PATH: process.env.PATH, HOME: process.env.HOME};
    const code = `console.log(JSON.stringify({probe:process.env.${key}??null,path:process.env.PATH,home:process.env.HOME,ci:process.env.CI??null,offline:process.env.REQUEST_SEAL_OFFLINE??null,context:process.env.NODE_TEST_CONTEXT??null}));`;
    const prefix = process.versions.deno ? ['eval', '--no-check'] : process.versions.bun ? ['-e'] : ['-e'];
    const run = () => {
      const options = {env, encoding: 'utf8' as const, timeout: 10000};
      if (execute === 'exec') return execFileWithEnvSync(process.execPath, [...prefix, code], options);
      const child = spawnWithEnvSync(process.execPath, [...prefix, code], options);
      assert.equal(child.status, 0, child.stdout + child.stderr);
      return child.stdout;
    };
    assert.deepEqual(JSON.parse(run()), {probe: null, path: env.PATH, home: env.HOME, ci: null, offline: null, context: null});
    env[key] = 'child';
    assert.equal(JSON.parse(run()).probe, 'child');
    delete env[key];
    assert.equal(JSON.parse(run()).probe, null);
  } finally {
    if (before === undefined) delete process.env[key]; else process.env[key] = before;
  }
});
