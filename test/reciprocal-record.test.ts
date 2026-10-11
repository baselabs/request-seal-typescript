import {nodeAdapterTest} from './support/node-adapter-test.ts';
const test = nodeAdapterTest(import.meta.url);
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {randomBytes, generateKeyPairSync} from 'node:crypto';
import {createRequire} from 'node:module';
import {reciprocalPeers, reciprocalRequest} from './support/reciprocal-peers.ts';
import {algorithms} from '../src/crypto/algorithm.ts';
import {JWS_ALGORITHMS, JWE_ALGORITHMS, ENCRYPTION} from '../src/jose/support.ts';
import {assertRejection} from '../interop/reciprocal/records.ts';

const exchange = () => readFileSync('interop/reciprocal/exchange.test.ts', 'utf8');

test('receipt text contains no internal role name', () => {
  assert.doesNotMatch(exchange(), new RegExp(String.fromCharCode(115, 117, 112, 101, 114, 118, 105, 115, 111, 114), 'i'));
});
test('records exclude real private and symmetric key material', async () => {
  const {publicRecord} = await import('../interop/reciprocal/records.ts');
  const {privateKey, publicKey} = generateKeyPairSync('ed25519');
  const privateJwk = privateKey.export({format: 'jwk'});
  const jwk = publicKey.export({format: 'jwk'});
  const secret = randomBytes(32).toString('base64url');
  const result = publicRecord({request: {key: privateKey.export({format: 'pem', type: 'pkcs8'}), secret, jwk: privateJwk, nonce: 'public input'}, response: {jwk, secret}, stdout: secret, stderr: secret});
  const wire = JSON.stringify(result);
  assert.ok(!wire.includes(secret)); assert.ok(!wire.includes(privateJwk.d!)); assert.ok(!wire.includes('PRIVATE KEY'));
  assert.ok(wire.includes(jwk.x!)); assert.ok(wire.includes('public input'));
  const job = readFileSync('.github/workflows/ci.yml', 'utf8').split('  reciprocal:')[1]!;
  assert.match(job, /timeout-minutes: 20/); assert.match(job, /retention-days: 3/);
});
test('reciprocal PostgreSQL documents runner-only trust authentication', () => {
  const job = readFileSync('.github/workflows/ci.yml', 'utf8').split('  reciprocal:')[1]!;
  assert.match(job, /# Trust authentication and the passwordless URL are for this ephemeral runner only\./);
});
test('a real failing DROP preserves the original error and closes the pool', {skip: !process.env.REQUESTSEAL_REPLAY_PG_URL}, async () => {
  const {cleanupDatabase} = await import('../interop/reciprocal/records.ts');
  const require = createRequire(new URL('../interop/replay/pg.mjs', import.meta.url));
  const {Client} = require('pg');
  const db = new Client({connectionString: process.env.REQUESTSEAL_REPLAY_PG_URL, options: '-c default_transaction_read_only=on'});
  await db.connect();
  const original = new Error('Original exchange failure');
  const table = 'cleanup_' + crypto.randomUUID().replaceAll('-', '');
  await assert.rejects(cleanupDatabase(db, table, original), error => error === original);
  assert.equal(db._ending, true, 'the real client end ran despite a DROP error');
  const next = new Client({connectionString: process.env.REQUESTSEAL_REPLAY_PG_URL, options: '-c default_transaction_read_only=on'});
  await next.connect();
  await assert.rejects(cleanupDatabase(next, table), /read-only/);
  assert.equal(next._ending, true);
});

test('an early-exiting real peer still closes the real database', {skip: !process.env.REQUESTSEAL_REPLAY_PG_URL}, async () => {
  const {cleanupDatabase} = await import('../interop/reciprocal/records.ts');
  const {spawnPeer} = await import('./support/peer-process.ts');
  const {pool} = await import('../interop/replay/pg.mjs');
  const {ddl} = await import('../src/replay/postgres.ts');
  const db = pool(process.env.REQUESTSEAL_REPLAY_PG_URL!);
  const table = 'exit_' + crypto.randomUUID().replaceAll('-', '');
  const definition = ddl(table); assert.ok(definition.ok); await db.query(definition.value);
  const p = spawnPeer('node', ['-e', 'process.exit(3)']);
  let original: unknown;
  try {await p.waitLine(s => s === 'READY', 1000);}
  catch (error) {original = error;}
  finally {
    p.end(); await p.stop();
    await assert.rejects(cleanupDatabase(db, table, original), error => error === original);
  }
  assert.ok(original instanceof Error);
  await assert.rejects(db.query('SELECT 1'), /after calling end/);
});

test('run dates format the supplied clock in US English', async () => {
  const {runDate} = await import('../interop/reciprocal/records.ts');
  assert.equal(runDate(new Date('2026-10-11T23:59:59Z')), 'October 11, 2026');
  assert.equal(runDate(new Date('2026-10-12T00:00:00Z')), 'October 12, 2026');
});

test('unrelated peer failures cannot satisfy a rejection assertion', async () => {
  const {assertRejection} = await import('../interop/reciprocal/records.ts');
  assert.throws(() => assertRejection({accepted: false, rule: 'peer/error'}, 'jose/crypto.invalid_signature'));
});


test('wrong CA and republished wrong-origin directory reject in both directions', {timeout: 30000, skip: process.env.REQUESTSEAL_REPLAY_ELIXIR !== '1'}, async t => {
  const peers = await reciprocalPeers(t.signal);
  try {
    for (const [sender, receiver, directory, opposite] of [[peers.ts, peers.ex, peers.tsDirectory, peers.exDirectory], [peers.ex, peers.ts, peers.exDirectory, peers.tsDirectory]] as const) {
      const request = {...reciprocalRequest('web_bot_auth', 'ed25519'), location: directory.location, ca: directory.ca};
      const signed = await peers.call(sender, {...request, op: 'sign'});
      const valid = await peers.call(receiver, {...request, ...signed, op: 'verify'});
      assert.equal(valid.accepted, true); assert.equal(valid.proof, 'signed');
      assertRejection(await peers.call(receiver, {...request, ...signed, ca: opposite.ca, op: 'verify'}), 'discovery/tls_failed');
      const published = await peers.call(sender, {op: 'directory.read'});
      assert.equal((await peers.call(receiver, {...published, op: 'directory.publish'})).published, true);
      assertRejection(await peers.call(receiver, {...request, ...signed, location: opposite.location, ca: opposite.ca, op: 'verify'}), 'discovery/directory_signature_invalid');
    }
  } finally {await peers.close();}
});

test('both registries agree and every asymmetric bot selector exchanges', {timeout: 60000, skip: process.env.REQUESTSEAL_REPLAY_ELIXIR !== '1'}, async t => {
  const registry = algorithms(); assert.ok(registry.ok);
  const peers = await reciprocalPeers(t.signal);
  try {
    const answer = await peers.call(peers.ex, {op: 'selectors'});
    const reported = answer.selectors; assert.ok(reported, JSON.stringify(answer));
    for (const [name, selections] of Object.entries({http: registry.value, jws: JWS_ALGORITHMS, jwe: JWE_ALGORITHMS, encs: ENCRYPTION})) assert.deepEqual(reported[name].toSorted(), selections.toSorted());
    const bot = [...registry.value.filter(a => a !== 'hmac-sha256'), ...JWS_ALGORITHMS.filter(a => a !== 'HS256').map(a => 'jws:' + a)];
    assert.equal(bot.length, 12);
    for (const algorithm of bot) for (const [sender, receiver, directory] of [[peers.ts, peers.ex, peers.tsDirectory], [peers.ex, peers.ts, peers.exDirectory]] as const) {
      const request = {...reciprocalRequest('web_bot_auth', algorithm), location: directory.location, ca: directory.ca};
      const signed = await peers.call(sender, {...request, op: 'sign'});
      const verified = await peers.call(receiver, {...request, ...signed, op: 'verify'});
      assert.equal(verified.accepted, true, algorithm + ': ' + JSON.stringify(verified));
      assert.equal(verified.proof, 'signed');
    }
  } finally {await peers.close();}
});

test('real signature rejections name the exact rule and recipients release', {timeout: 30000, skip: process.env.REQUESTSEAL_REPLAY_ELIXIR !== '1'}, async t => {
  const peers = await reciprocalPeers(t.signal);
  try {
    for (const [sender, receiver] of [[peers.ts, peers.ex], [peers.ex, peers.ts]] as const) {
      const request = reciprocalRequest('rfc9421', 'ed25519');
      const signed = await peers.call(sender, {...request, op: 'sign'});
      const fields = signed.fields.map(([name, text]: [string, string]) => [name, name === 'x-exchange' ? Buffer.from('changed').toString('base64url') : text]);
      assertRejection(await peers.call(receiver, {...request, ...signed, fields, op: 'verify'}), 'core/crypto.invalid_signature');
      const recipient = await peers.call(receiver, {...reciprocalRequest('jwe', 'RSA-OAEP'), op: 'prepare'});
      assert.ok(recipient.keyId);
      assert.equal((await peers.call(receiver, {op: 'release', keyId: recipient.keyId})).released, true);
    }
  } finally {await peers.close();}
});

test('tracked test titles describe behavior without review identifiers', () => {
  const pattern = /\b[SGN]\d+\b/;
  assert.equal(pattern.test(['S', '1'].join('')), true, 'known-positive review identifier probe');
  const listed = spawnSync('git', ['ls-files', '-z', 'test'], {encoding: 'utf8'});
  assert.equal(listed.status, 0, listed.stderr);
  const titles = listed.stdout.split('\0').filter(path => path.endsWith('.test.ts')).flatMap(path => {
    return [...readFileSync(path, 'utf8').matchAll(/\btest\((['"`])([^\n]*)/g)].map(match => ({path, title: match[2]!}));
  });
  assert.ok(titles.some(entry => entry.title.includes('both published peers')), 'the instrument reads the existing pin test');
  assert.deepEqual(titles.filter(entry => pattern.test(entry.title)), []);
});

