import {nodeAdapterTest} from './support/node-adapter-test.ts';
const test = nodeAdapterTest(import.meta.url);
import assert from 'node:assert/strict';
import {resolve} from 'node:path';
import {spawnSync} from 'node:child_process';
import {X509Certificate} from 'node:crypto';
import {spawnPeer} from './support/peer-process.ts';
import {Claim, Replay, withDeadline, type Result} from '../src/index.ts';
import {createStore, ddl} from '../src/replay/postgres.ts';

function value<T>(r: Result<T>): T {assert.equal(r.ok, true); if (!r.ok) throw new Error('Rejected result'); return r.value;}

for (const locale of ['en_US.UTF-8', 'empty', 'C.UTF-8', 'unset']) test(`binary stdin and stdout preserve UTF-8 identifiers and nonce commitments with ${locale} locale`, {timeout: 30000, skip: !process.env.REQUESTSEAL_REPLAY_PG_URL || process.env.REQUESTSEAL_REPLAY_ELIXIR !== '1'}, async t => {
  const {pool, query} = await import('../interop/replay/pg.mjs');
  const db = pool(process.env.REQUESTSEAL_REPLAY_PG_URL!);
  const table = 'nonce_' + crypto.randomUUID().replaceAll('-', '');
  const env = {...process.env}; delete env.LANG; delete env.LC_ALL; delete env.LC_CTYPE;
  if (locale !== 'unset') {env.LANG = locale === 'empty' ? '' : locale; env.LC_ALL = env.LANG; env.LC_CTYPE = env.LANG;}
  const p = spawnPeer('mix', ['run', '--no-compile', '--no-deps-check', 'driver.exs'], {cwd: resolve('interop/elixir'), env, signal: t.signal});
  try {
    await db.query(value(ddl(table)));
    await p.waitLine(s => {try {return JSON.parse(s).ready === true;} catch {return false;}}, 15000);
    const nonce = 'café → 日本語 ' + crypto.randomUUID();
    const id = '2→ é';
    const waiting = p.waitLine(s => s.includes('"claim"'), 10000);
    p.write(JSON.stringify({op: 'claim', id, namespace: 'AP8', nonce, table, retainUntil: '253402300799'}) + '\n');
    const response = JSON.parse(await waiting);
    assert.equal(response.id, id, 'the driver writes the exact UTF-8 id bytes');
    assert.equal(response.claim, 'claimed');
    const key = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(nonce)));
    const claim = value(Claim.create({namespace: new Uint8Array([0,255]), key, retainUntil: 253402300799}));
    assert.equal(value(await Replay.claim(value(createStore({table, query: query(db)})), claim, value(withDeadline({timeoutMs: 5000})))), 'already_claimed', 'both runtimes hash the same UTF-8 bytes');
    assert.equal((await db.query(`SELECT count(*) AS count FROM "${table}"`)).rows[0]?.count, '1');
  } finally {
    await p.stop();
    try {await db.query(`DROP TABLE IF EXISTS "${table}"`);} finally {await db.end();}
  }
});

test('setup works from the repository root', {timeout: 120000, skip: process.env.REQUESTSEAL_REPLAY_ELIXIR !== '1'}, t => {
  if (spawnSync('mix', ['--version'], {timeout: 5000}).error?.message.includes('ENOENT')) {t.skip('Mix is not installed'); return;}
  const run = spawnSync('node', ['--experimental-strip-types', '--no-warnings', 'interop/reciprocal/setup.ts'], {encoding: 'utf8', timeout: 110000, env: {...process.env, HEX_OFFLINE: '1'}});
  assert.equal(run.status, 0, run.stderr);
});

test('the real directory survives failed TLS and HTTP connections', {timeout: 20000, skip: process.env.REQUESTSEAL_REPLAY_ELIXIR !== '1'}, async t => {
  if (spawnSync('mix', ['--version'], {timeout: 5000}).error?.message.includes('ENOENT')) {t.skip('Mix is not installed'); return;}
  const {peer} = await import('./support/discovery-peer.ts');
  const {connect} = await import('node:tls');
  const tls = await peer((_req, res) => {res.writeHead(503); res.end();});
  const p = spawnPeer('mix', ['run', '--no-compile', '--no-deps-check', 'driver.exs'], {cwd: resolve('interop/elixir'), signal: t.signal});
  let id = 0;
  const call = async (request: Record<string, unknown>) => {
    const current = String(++id), waiting = p.waitLine(s => {try {return JSON.parse(s).id === current;} catch {return false;}}, 10000);
    p.write(JSON.stringify({...request, id: current}) + '\n'); return JSON.parse(await waiting);
  };
  try {
    await p.waitLine(s => {try {return JSON.parse(s).ready === true;} catch {return false;}}, 10000);
    const directory = await call({op: 'directory.start', key: Buffer.from(tls.tlsOptions.key).toString('base64url'), cert: Buffer.from(tls.tlsOptions.cert).toString('base64url'), ca: Buffer.from(tls.ca).toString('base64url')});
    const location = new URL(directory.location);
    // A real interrupted TLS handshake and a reset after an HTTP request.
    for (const send of [false, true]) {
      let sent = false;
      await new Promise<void>((done, fail) => {
        const socket = connect({host: '127.0.0.1', port: Number(location.port), ca: new X509Certificate(Buffer.from(tls.ca)).toString()}, () => {
          if (send) {sent = true; socket.write('GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n');}
          else socket.destroy();
        });
        const bound = setTimeout(() => {socket.destroy(); fail(new Error('Failed HTTP connection was not closed'));}, 2500);
        socket.on('error', error => {if (send && !sent) fail(error);}); socket.on('close', () => {clearTimeout(bound); done();});
        if (!send) socket.destroy();
      });
      if (send) assert.equal(sent, true, 'the HTTP request crossed a verified TLS connection');
    }
    await new Promise<void>(done => setTimeout(done, 100));
    assert.ok((await call({op: 'selectors'})).selectors.http.includes('ed25519'), 'driver responds after connection failures');
  } finally {await p.stop(); await tls.close();}
});
