import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
const doc = () => readFile('docs/reference/replay.md', 'utf8');
test('cross-language changelog states its opt-in environment and Elixir toolchain', async () => {
  const changelog = await readFile('CHANGELOG.md', 'utf8');
  assert.match(changelog, /cross-language.*REQUESTSEAL_REPLAY_ELIXIR=1.*Elixir toolchain/i);
});
test('PostgreSQL usage configures server timeouts and explains indeterminate fail-closed claims', async () => {
  const source = await doc();
  assert.match(source, /options:.*lock_timeout=.*statement_timeout=/);
  assert.match(source, /timed-out claim may still commit/);
  assert.match(source, /fail closed/);
});
test('PostgreSQL docs explain driver-specific error classification and nonretryable results', async () => {
  const source = await doc();
  for (const code of ['ECONNREFUSED', 'ENOTFOUND', 'EHOSTUNREACH']) assert.ok(source.includes(code));
  assert.match(source, /read timeout.*(?:without|no).*code.*store_failed/);
  assert.match(source, /per driver/);
  assert.match(source, /all.*nonretryable/i);
});
// The branded Policy and authenticated freshness make this fallback unreachable.
// Keep one source assertion until a public input can drive the non-core retention rejection.
test('unreachable non-core retention rejection names invalid_policy at input', async () => {
  const source = await readFile('src/verify.ts', 'utf8');
  assert.match(source, /if \(!retained.ok\) \{[\s\S]*?unreachable[\s\S]*?fail\("invalid_policy", "input"\)/i);
});
test('caller store docs require exact own keys and explicit prototype binding', async () => {
  const source = await doc();
  assert.match(source, /exactly the own keys/);
  assert.match(source, /extra own keys\s+reject with `invalid_store`/);
  assert.match(source, /prototype methods.*bound explicitly/i);
});
test('replay docs distinguish the caller-capped deadline from the reference timeout', async () => {
  const source = await doc();
  assert.match(source, /deadline is capped by the caller/);
  assert.match(source, /reference.*independent timeout/);
});
test('CI rejects a missing PostgreSQL URL while local checks still skip', async () => {
  const {spawnSync} = await import('node:child_process');
  const env = {...process.env}; env.REQUESTSEAL_REPLAY_PG_URL = ''; delete env.NODE_TEST_CONTEXT;
  const args = process.versions.bun ? ['test', '--isolate', '--test-name-pattern=64 PostgreSQL claims', 'test/replay-postgres.test.ts'] : process.versions.deno ? ['test', '--no-check', '--allow-read', '--allow-env', '--allow-net', '--filter=64 PostgreSQL claims', 'test/replay-postgres.test.ts'] : ['--experimental-strip-types', '--no-warnings', '--test', '--test-name-pattern=64 PostgreSQL claims', 'test/replay-postgres.test.ts'];
  for (const flag of ['true', '']) {
    const ci = spawnSync(process.execPath, args, {env: {...env, CI: flag}, encoding: 'utf8'});
    assert.equal(ci.status, 1, ci.stdout + ci.stderr);
    assert.match(ci.stdout + ci.stderr, /CI requires REQUESTSEAL_REPLAY_PG_URL/);
  }
  delete env.CI;
  const local = spawnSync(process.execPath, args, {env, encoding: 'utf8'});
  assert.equal(local.status, 0, local.stdout + local.stderr);
  assert.match(local.stdout + local.stderr, process.versions.bun ? /1 skip[\s\S]*0 fail/ : process.versions.deno ? /0 passed \| 0 failed \| 1 ignored/ : /REQUESTSEAL_REPLAY_PG_URL is unset/);
});

test('content documentation distinguishes Context deadlines from hasher failures', async () => {
  const source = await readFile('docs/reference/sign-and-verify.md', 'utf8');
  assert.match(source, /Context deadline during required content returns retryable\s+`custody\/deadline_exceeded`/);
  assert.match(source, /no commitment or store call/);
  assert.match(source, /Hasher failures (?:still|remain).*`digest_unsupported`/);
  assert.doesNotMatch(source, /digest-state deadlines map to `digest_unsupported`/);
});
test('replay port documentation distinguishes verify number ends from direct bigint claims', async () => {
  const source = await doc();
  assert.match(source, /Claims produced by `verify` carry safe-integer numbers/);
  assert.match(source, /bigint end arrives only from a direct `Claim.create`/);
  assert.match(source, /`number \| bigint`/);
});
