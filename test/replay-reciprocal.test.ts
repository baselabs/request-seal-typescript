import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {resolve} from 'node:path';
import {mkdir} from 'node:fs/promises';
import {Claim, Replay, withDeadline, ok, type Result} from '../src/index.ts';
import {createStore, ddl} from '../src/replay/postgres.ts';
function value<T>(r: Result<T>): T {assert.equal(r.ok, true, JSON.stringify(r)); if (!r.ok) throw new Error('Rejected result'); return r.value;}
test('independent Elixir and TypeScript commitments share one PostgreSQL winner', {timeout: 30000, skip: !process.env.REQUESTSEAL_REPLAY_PG_URL ? 'REQUESTSEAL_REPLAY_PG_URL is unset' : process.env.REQUESTSEAL_REPLAY_ELIXIR !== '1' ? 'REQUESTSEAL_REPLAY_ELIXIR is not 1' : false}, async t => {
  const url = process.env.REQUESTSEAL_REPLAY_PG_URL;
  if (!url) {console.log('SKIP PostgreSQL reciprocal replay: REQUESTSEAL_REPLAY_PG_URL is unset'); t.skip('REQUESTSEAL_REPLAY_PG_URL is unset'); return;}
  if (process.env.REQUESTSEAL_REPLAY_ELIXIR !== '1') {console.log('SKIP PostgreSQL reciprocal replay: REQUESTSEAL_REPLAY_ELIXIR is not 1'); t.skip('REQUESTSEAL_REPLAY_ELIXIR is not 1'); return;}
  const {pool, query} = await import('../interop/replay/pg.mjs');
  const db = pool(url), table = 'fix_replay_cross_' + crypto.randomUUID().replaceAll('-', '');
  const cache = resolve('interop/replay/.cache'); await mkdir(cache, {recursive: true});
  let child: ReturnType<typeof spawn> | undefined;
  try {
    await db.query(value(ddl(table)));
    const identifier = 'nonce-' + crypto.randomUUID();
    const namespace = new Uint8Array([0,255]);
    const commitment = async (facts: {identifier: string}) => ok(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(facts.identifier))));
    const c = value(Claim.create({namespace, key: value(await commitment({identifier})), retainUntil: 200}));
    child = spawn('mix', ['run', 'claim.exs', table, '00ff', identifier, '200'], {cwd: resolve('interop/replay'), env: {...process.env, MIX_HOME: cache + '/mix', HEX_HOME: cache + '/hex'}});
    let output = '', diagnostics = '';
    child.stdout!.setEncoding('utf8'); child.stderr!.setEncoding('utf8');
    const ready = new Promise<void>((resolveReady, reject) => {
      child!.stdout!.on('data', (text: string) => {output += text; if (output.includes('READY\n')) resolveReady();});
      child!.stderr!.on('data', (text: string) => {diagnostics += text;});
      child!.on('error', reject); child!.on('exit', code => {if (!output.includes('READY\n')) reject(new Error(`Elixir peer exited ${code}: ${diagnostics}`));});
    });
    const exited = new Promise<number | null>(resolveExit => child!.on('exit', resolveExit));
    await ready;
    const store = value(createStore({table, query: query(db)}));
    const ts = Replay.claim(store, c, value(withDeadline({timeoutMs: 10000})));
    child.stdin!.end('go\n');
    const result = value(await ts); assert.equal(await exited, 0, diagnostics);
    const elixir = /CLAIM=(claimed|already_claimed)/.exec(output)?.[1]; assert.ok(elixir, output);
    assert.equal([result, elixir].filter(v => v === 'claimed').length, 1);
    assert.equal([result, elixir].filter(v => v === 'already_claimed').length, 1);
    assert.equal((await db.query(`SELECT count(*) AS count FROM "${table}"`)).rows[0]?.count, '1');
    console.log('POSTGRES reciprocal: independently SHA-256 committed UTF-8 identifier; claimed=1 already_claimed=1 rows=1');
  } finally {
    child?.kill();
    try {await db.query(`DROP TABLE IF EXISTS "${table}"`);} finally {await db.end();}
  }
});
