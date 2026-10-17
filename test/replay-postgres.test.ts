import test from 'node:test';
import assert from 'node:assert/strict';
import * as api from '../src/index.ts';
import type {Pool} from '../interop/replay/pg.mjs';
type QueryFactory = typeof import('../interop/replay/pg.mjs')['query'];
const A = api as any;
function value(r: any): any {assert.equal(r.ok, true, r.ok ? 'Result accepted' : JSON.stringify(r)); return r.value;}
const context = (timeoutMs = 10000) => value(api.withDeadline({timeoutMs}));
const claim = (namespace = [0,255], key = [255,0], retainUntil = 100) => value(A.Claim.create({namespace: new Uint8Array(namespace), key: new Uint8Array(key), retainUntil}));
async function adapter(): Promise<any> {
  const pkg = JSON.parse(await (await import('node:fs/promises')).readFile('package.json', 'utf8'));
  assert.equal(typeof pkg.exports['./replay-postgres']?.default, 'string', 'replay-postgres is an exported adapter');
  return import('../src/replay/postgres.ts');
}
const url = process.env.REQUESTSEAL_REPLAY_PG_URL;
async function database(t: {skip(reason: string): void}, run: (a: Pool, b: Pool, table: string, pg: any, query: QueryFactory) => Promise<void>) {
  if (!url && process.env.CI !== undefined) throw new Error('CI requires REQUESTSEAL_REPLAY_PG_URL');
  if (!url) {console.log('SKIP PostgreSQL replay: REQUESTSEAL_REPLAY_PG_URL is unset'); t.skip('REQUESTSEAL_REPLAY_PG_URL is unset'); return;}
  const pg = await adapter();
  const {pool, query} = await import('../interop/replay/pg.mjs');
  const a = pool(url), b = pool(url), table = 'fix_replay_' + crypto.randomUUID().replaceAll('-', '');
  try {await a.query(value(pg.ddl(table))); await a.query(value(pg.ddlIndex(table))); await run(a, b, table, pg, query);}
  finally {try {await a.query(`DROP TABLE IF EXISTS "${table}"`);} finally {await Promise.all([a.end(), b.end()]);}}
}
test('PostgreSQL adapter validates identifiers and returns the exact DDL', async () => {
  const pg = await adapter();
  assert.equal(value(pg.ddl('replay')), 'CREATE TABLE "replay" (namespace bytea NOT NULL, key bytea NOT NULL, retain_until bigint NOT NULL, PRIMARY KEY (namespace, key))');
  for (const name of ['', 'a.b', 'A', '1a', 'a;DROP TABLE a', 'a'.repeat(64), 'a\n']) assert.equal(pg.ddl(name).error.reason, 'invalid_store');
  // The sweep index turns the retention DELETE from a growing full-table scan
  // into an index scan; a 46-byte name keeps the derived identifier inside
  // PostgreSQL's 63-byte limit (mirror of the reference ddl_index/1).
  assert.equal(value(pg.ddlIndex('replay_claims')), 'CREATE INDEX "replay_claims_retain_until_idx" ON "replay_claims" (retain_until)');
  assert.equal(value(pg.ddlIndex('c'.repeat(46))), `CREATE INDEX "${'c'.repeat(46)}_retain_until_idx" ON "${'c'.repeat(46)}" (retain_until)`);
  for (const name of ['c'.repeat(47), 'a'.repeat(64), '', 'A']) assert.equal(pg.ddlIndex(name).error.reason, 'invalid_store');
  assert.equal(pg.createStore({query: 1, table: 'valid'}).error.reason, 'invalid_store');
  assert.equal(pg.createStore({query: () => {}, table: 'valid', unknown: true}).error.reason, 'invalid_store');
});
test('64 PostgreSQL claims across two pools have one winner and preserve byte parameters', {timeout: 30000, skip: !url && process.env.CI === undefined ? 'REQUESTSEAL_REPLAY_PG_URL is unset' : false}, async t => {
  await database(t, async (a, b, table, pg, query) => {
    let calls = 0;
    const observe = (sql: string, params: readonly string[], c: {signal: AbortSignal; remainingMs: number}) => {
      calls++; assert.equal(sql, `INSERT INTO "${table}" (namespace, key, retain_until) VALUES (decode($1,'hex'), decode($2,'hex'), $3::bigint) ON CONFLICT (namespace, key) DO NOTHING`);
      assert.deepEqual(params, ['00ff', 'ff00', '100']); assert.equal(Object.isFrozen(params), true); assert.equal(c.signal instanceof AbortSignal, true); assert.ok(c.remainingMs > 0);
    };
    const stores = [a,b].map(p => value(pg.createStore({table, query: query(p, observe)})));
    const results = await Promise.all(Array.from({length: 64}, (_, i) => stores[i % 2].claim(claim(), context())));
    assert.equal(results.filter(r => value(r) === 'claimed').length, 1);
    assert.equal(results.filter(r => value(r) === 'already_claimed').length, 63);
    assert.equal(calls, 64);
    assert.equal((await a.query(`SELECT count(*) AS count FROM "${table}"`)).rows[0]?.count, '1');
    console.log('POSTGRES concurrency: 64 claims across two pools; claimed=1 already_claimed=63 rows=1');
  });
});
test('PostgreSQL sweeps only at the exclusive end and duplicate retention survives pool replacement', {timeout: 30000, skip: !url && process.env.CI === undefined ? 'REQUESTSEAL_REPLAY_PG_URL is unset' : false}, async t => {
  await database(t, async (a,b,table,pg,query) => {
    const store = value(pg.createStore({table, query: query(a)}));
    assert.equal(value(await store.claim(claim(), context())), 'claimed');
    assert.equal(value(await store.claim(claim([0,255], [255,0], 200), context())), 'already_claimed');
    const other = value(pg.createStore({table, query: query(b)}));
    assert.equal(value(await other.claim(claim(), context())), 'already_claimed');
    assert.equal(value(await other.claim(claim([255,0]), context())), 'claimed');
    assert.equal(value(await other.sweep(99, context())), 0);
    for (const now of [-1, 253402300800]) assert.equal((await other.sweep(now, context())).error.reason, 'invalid_options');
    assert.equal(value(await other.sweep(100, context())), 2);
    assert.equal(value(await other.claim(claim([0,255],[255,0],253402300799), context())), 'claimed');
    assert.equal(value(await other.sweep(253402300798, context())), 0);
    assert.equal(value(await other.sweep(253402300799, context())), 1);
    console.log('POSTGRES sweep: at 99=0; at 100=2; at 253402300798=0; at 253402300799=1; -1/253402300800 rejected');
  });
});
test('a real PostgreSQL uniqueness lock exceeds Context without success and passes its abort signal', {timeout: 30000, skip: !url && process.env.CI === undefined ? 'REQUESTSEAL_REPLAY_PG_URL is unset' : false}, async t => {
  await database(t, async (a,b,table,pg,query) => {
    const holder = await b.connect();
    try {
      await holder.query('BEGIN');
      await holder.query(`INSERT INTO "${table}" VALUES (decode('00ff','hex'),decode('ff00','hex'),100)`);
      const c = context(80);
      let observedSignal: AbortSignal | undefined;
      // This check isolates Context cancellation; pg's own query_timeout can
      // settle first, which does not establish that the Context signal fired.
      const store = value(pg.createStore({table, query: async (sql: string, params: readonly string[], operation: {signal: AbortSignal}) => {
        observedSignal = operation.signal;
        return (await a.query(sql, [...params])).rowCount;
      }}));
      const r = await store.claim(claim(), c);
      assert.equal(r.ok, false); assert.equal(r.error.reason, 'store_timeout'); assert.equal(r.error.retryable, false);
      assert.equal(observedSignal, c.signal); assert.equal(c.signal.aborted, true);
      console.log('POSTGRES locked claim: store_timeout retryable=false signal=passed aborted=true');
    } finally {await holder.query('ROLLBACK'); holder.release();}
  });
});
test('real PostgreSQL query faults are bounded and malformed claims never query', {timeout: 30000, skip: !url && process.env.CI === undefined ? 'REQUESTSEAL_REPLAY_PG_URL is unset' : false}, async t => {
  await database(t, async (a,_b,table,pg,query) => {
    let calls = 0;
    const store = value(pg.createStore({table, query: query(a, () => {calls++;})}));
    assert.equal((await store.claim({...claim()}, context())).error.reason, 'invalid_claim');
    assert.equal(calls, 0);
    await a.query(`DROP TABLE "${table}"`);
    const r = await store.claim(claim(), context());
    assert.equal(r.ok, false); assert.deepEqual(r.error, {kind: 'replay', reason: 'store_failed', retryable: false});
    assert.equal(calls, 1);
    console.log('POSTGRES missing table: store_failed; malformed claim query=0');
  });
});
test('PostgreSQL retains the exact signed bigint minimum and sweeps negative ends at zero', {timeout: 30000, skip: !url && process.env.CI === undefined ? 'REQUESTSEAL_REPLAY_PG_URL is unset' : false}, async t => {
  await database(t, async (a,_b,table,pg,query) => {
    const store = value(pg.createStore({table, query: query(a)}));
    const min = -9223372036854775808n;
    for (const end of [min, -1n]) {
      const c = value(api.Claim.create({namespace: new Uint8Array([1]), key: new Uint8Array([end === min ? 1 : 2]), retainUntil: end}));
      assert.equal(value(await api.Replay.claim(store, c, context())), 'claimed');
    }
    const rows = (await a.query(`SELECT retain_until::text AS end FROM "${table}" ORDER BY retain_until`)).rows;
    assert.deepEqual(rows.map(r => r.end), [min.toString(), '-1']);
    assert.equal(value(await api.Replay.sweep(store, 0, context())), 2);
    console.log('POSTGRES negative ends: bigint minimum exact; sweep(0)=2');
  });
});
