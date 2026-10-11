import {nodeAdapterTest} from './support/node-adapter-test.ts';
const test = nodeAdapterTest(import.meta.url);
import assert from 'node:assert/strict';
import {spawnPeer, requireHex} from './support/peer-process.ts';
import {resolve} from 'node:path';
import {Claim, Replay, withDeadline, type Result} from '../src/index.ts';
import {createStore, ddl} from '../src/replay/postgres.ts';
import {cleanupReplay} from './support/replay-cleanup.ts';
function value<T>(r: Result<T>): T {assert.equal(r.ok, true, JSON.stringify(r)); if (!r.ok) throw new Error('Rejected result'); return r.value;}

test('independent claims contend behind a database barrier under simultaneous and delayed release over 64 UTF-8 nonces', {timeout: 60000, skip: !process.env.REQUESTSEAL_REPLAY_PG_URL || process.env.REQUESTSEAL_REPLAY_ELIXIR !== '1'}, async t => {
  const {pool} = await import('../interop/replay/pg.mjs');
  const db = pool(process.env.REQUESTSEAL_REPLAY_PG_URL!);
  const table = 'cross_' + crypto.randomUUID().replaceAll('-', '');
  let peer: ReturnType<typeof spawnPeer> | undefined;
  const control = await db.connect(), claimant = await db.connect();
  let bodyFailed = false;
  const wins = {typescript: 0, elixir: 0};
  const simultaneous = {typescript: 0, elixir: 0};
  const delays: number[] = [];
  const barrier = crypto.getRandomValues(new Uint32Array(1))[0]! & 0x7fffffff;
  try {
    await requireHex({cwd: resolve('interop/replay'), signal: t.signal});
    await db.query(value(ddl(table)));
    peer = spawnPeer('mix', ['run', '--no-compile', '--no-deps-check', 'claim.exs', table, '00ff', 'initial', '253402300799'], {cwd: resolve('interop/replay'), signal: t.signal});
    await peer.waitLine(line => line === 'READY', 15000);
    for (let round = 0; round < 64; round++) {
      const identifier = `nonce → ${round} ${crypto.randomUUID()}`;
      const key = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(identifier)));
      const c = value(Claim.create({namespace: new Uint8Array([0,255]), key, retainUntil: 253402300799}));
      await control.query('SELECT pg_advisory_lock($1)', [barrier]);
      const store = value(createStore({table, query: async (sql: string, params: readonly string[]) => {
        await claimant.query('SELECT pg_advisory_lock_shared($1)', [barrier]);
        try {
          if (round >= 32) {
            const released = performance.now();
            await new Promise<void>(done => setTimeout(done, 50));
            const elapsed = performance.now() - released; delays.push(elapsed);
            assert.ok(elapsed >= 40, 'the TypeScript claim has a measured delay after barrier release');
          }
          return (await claimant.query(sql, [...params])).rowCount;
        }
        finally {await claimant.query('SELECT pg_advisory_unlock_shared($1)', [barrier]);}
      }}));
      const waiting: Promise<string> = peer.waitLine(s => s.startsWith('CLAIM='), 10000);
      peer.write(JSON.stringify({identifier, barrier}) + '\n');
      const ts = Replay.claim(store, c, value(withDeadline({timeoutMs: 10000})));
      const claims = Promise.allSettled([ts, waiting]);
      const deadline = Date.now() + 5000;
      let blocked = 0;
      while (Date.now() < deadline) {
        blocked = Number((await control.query("SELECT count(*) AS n FROM pg_locks WHERE locktype='advisory' AND classid=0 AND objid=$1 AND NOT granted", [barrier])).rows[0]?.n);
        if (blocked === 2) break;
        await new Promise<void>(done => setTimeout(done, 10));
      }
      // Always release the barrier and observe both promises, even on a failed admission.
      await control.query('SELECT pg_advisory_unlock($1)', [barrier]);
      const [tsResult, exLine] = await claims;
      assert.equal(blocked, 2, 'both live implementations wait on the same barrier before release');
      assert.equal(tsResult.status, 'fulfilled'); assert.equal(exLine.status, 'fulfilled');
      if (tsResult.status !== 'fulfilled' || exLine.status !== 'fulfilled') throw new Error('Claim failed');
      const typescript = value(tsResult.value), elixir = exLine.value.slice('CLAIM='.length);
      assert.equal([typescript, elixir].filter(v => v === 'claimed').length, 1, identifier);
      assert.equal([typescript, elixir].filter(v => v === 'already_claimed').length, 1, identifier);
      const winner = typescript === 'claimed' ? 'typescript' : 'elixir';
      wins[winner]++;
      if (round < 32) simultaneous[winner]++;
      else assert.equal(elixir, 'claimed', 'Elixir wins when the TypeScript claim is delayed');
    }
    assert.ok(wins.typescript > 0, 'TypeScript wins at least once overall');
    assert.ok(wins.elixir > 0, 'Elixir wins at least once overall');
    assert.equal((await db.query(`SELECT count(*) AS count FROM "${table}"`)).rows[0]?.count, '64');
    console.log(`POSTGRES barrier contention: simultaneous=32 typescript=${simultaneous.typescript} elixir=${simultaneous.elixir}; delayed=32 typescript=${wins.typescript - simultaneous.typescript} elixir=${wins.elixir - simultaneous.elixir}; measured_delay_min_ms=${Math.min(...delays).toFixed(2)} measured_delay_max_ms=${Math.max(...delays).toFixed(2)} exactly_one_winner=64 already_claimed_losers=64 rows=64`);
  } catch (error) {bodyFailed = true; throw error;}
  finally {
    await cleanupReplay({...(peer ? {peer} : {}), control, claimant, db, table, bodyFailed});
  }
});

for (const bodyFailed of [false, true]) test(`replay cleanup ${bodyFailed ? 'preserves the original failure' : 'rejects when a passed body has an unlock failure'}`, {skip: !process.env.REQUESTSEAL_REPLAY_PG_URL}, async () => {
  const {pool} = await import('../interop/replay/pg.mjs');
  const db = pool(process.env.REQUESTSEAL_REPLAY_PG_URL!);
  const table = 'unlock_' + crypto.randomUUID().replaceAll('-', '');
  const control = await db.connect(), claimant = await db.connect();
  await db.query(value(ddl(table)));
  const barrier = crypto.getRandomValues(new Uint32Array(1))[0]! & 0x7fffffff;
  assert.equal((await db.query('SELECT to_regclass($1) AS name', [table])).rows[0]?.name, table, 'known-positive table probe');
  await claimant.query('SELECT pg_advisory_lock($1)', [barrier]);
  assert.equal((await db.query("SELECT count(*) AS n FROM pg_locks WHERE locktype='advisory' AND classid=0 AND objid=$1", [barrier])).rows[0]?.n, '1', 'known-positive lock probe');
  // Ending this actual PostgreSQL connection forces unlock cleanup to fail.
  await control.end();
  const original = new Error('Original replay failure');
  const run = async () => {
    try {if (bodyFailed) throw original;}
    finally {await cleanupReplay({control, claimant, db, table, bodyFailed});}
  };
  await assert.rejects(run(), error => bodyFailed ? error === original : /closed|ended|not queryable/i.test(String(error)));
  await assert.rejects(db.query('SELECT 1'), /after calling end/, 'pool closes despite an unlock failure');
  const inspection = pool(process.env.REQUESTSEAL_REPLAY_PG_URL!);
  try {
    assert.equal((await inspection.query('SELECT to_regclass($1) AS name', [table])).rows[0]?.name, null, 'cleanup drops the actual table despite an unlock failure');
    assert.equal((await inspection.query("SELECT count(*) AS n FROM pg_locks WHERE locktype='advisory' AND classid=0 AND objid=$1", [barrier])).rows[0]?.n, '0', 'the other connection released its actual lock');
  } finally {await inspection.end();}
});
