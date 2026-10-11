import test from 'node:test';
import assert from 'node:assert/strict';
import {resolve, dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {mkdir, writeFile, appendFile} from 'node:fs/promises';
import type {webcrypto} from 'node:crypto';
import type {Request} from './driver.ts';
import {spawnPeer, requireHex} from '../../test/support/peer-process.ts';
import {peer} from '../../test/support/discovery-peer.ts';
import {ddl} from '../../src/replay/postgres.ts';
import {pool} from '../replay/pg.mjs';

process.chdir(resolve(dirname(fileURLToPath(import.meta.url)), '../..'));
const http = ['rsa-pss-sha512', 'rsa-v1_5-sha256', 'hmac-sha256', 'ecdsa-p256-sha256', 'ecdsa-p384-sha384', 'ed25519'];
const jws = ['RS256', 'PS256', 'PS384', 'PS512', 'HS256', 'ES256', 'ES384', 'EdDSA'];
const jwe = ['RSA-OAEP', 'RSA-OAEP-256', 'A128GCMKW', 'A256GCMKW', 'dir'];
const encs = ['A128GCM', 'A256GCM'];
const families = ['rfc9421', 'jws', 'jwe', 'nested', 'web_bot_auth', 'replay'];
const rounds = 32;
const cache = resolve('interop/reciprocal/.cache');
const receiptPath = process.env.REQUESTSEAL_RECIPROCAL_RECEIPT;
const rows: {family: string; direction: string; rounds: number; cases: number; rejections: number; disagreements: number}[] = [];
// Xorshift32 selects message inputs only. Keys and encryption entropy are fresh runtime randomness.
function bytes(seed: number, length: number) {
  let state = seed >>> 0; const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) {state ^= state << 13; state ^= state >>> 17; state ^= state << 5; out[i] = state & 255;}
  return Buffer.from(out).toString('base64url');
}
function base(family: string, algorithm: string, round: number): Request {
  const seed = 942100 + round;
  return {id: '', op: '', family, algorithm, enc: '', bytes: bytes(seed, 1 + round * 7), method: round % 2 ? 'POST' : 'GET', url: `https://exchange.example/r${round}/%2F?value=${seed}&value=%20`, now: String(Math.floor(Date.now() / 1000)), nonce: bytes(seed + 7515, 32), fields: [['x-exchange', Buffer.from(`round=${round}; seed=${seed}`).toString('base64url')]]};
}
function tamper(compact: string, segment: number) {
  const parts = compact.split('.'), raw = Buffer.from(parts[segment]!, 'base64url'); raw[0]! ^= 1; parts[segment] = raw.toString('base64url'); return parts.join('.');
}
type Response = {id: string; accepted?: boolean; bytes?: string; fields?: [string, string][]; compact?: string; jwk?: webcrypto.JsonWebKey; secret?: string; keyId?: string; location?: string; ca?: string; proof?: string; rule?: string; claim?: string};

test('fresh independently generated envelopes agree in both directions for every supported selector', {timeout: 900000}, async t => {
  assert.ok(process.env.REQUESTSEAL_REPLAY_PG_URL, 'REQUESTSEAL_REPLAY_PG_URL is required for the full reciprocal exchange');
  await mkdir(cache, {recursive: true});
  await writeFile(resolve(cache, 'exchange.jsonl'), '');
  await requireHex({cwd: resolve('interop/elixir'), signal: t.signal});
  const ts = spawnPeer(process.execPath, ['--experimental-strip-types', '--no-warnings', 'interop/reciprocal/driver.ts'], {signal: t.signal});
  const ex = spawnPeer('mix', ['run', '--no-compile', '--no-deps-check', 'driver.exs'], {cwd: resolve('interop/elixir'), signal: t.signal});
  const db = pool(process.env.REQUESTSEAL_REPLAY_PG_URL!);
  const table = 'reciprocal_' + crypto.randomUUID().replaceAll('-', '');
  let sequence = 0;
  const call = async (p: ReturnType<typeof spawnPeer>, request: Request, extra: Record<string, unknown> = {}): Promise<Response> => {
    const r = {...request, ...extra, id: String(++sequence)};
    const waiting = p.waitLine(line => {
      try {return (JSON.parse(line) as Response).id === r.id;} catch {return false;}
    }, 15000);
    p.child.stdin.write(JSON.stringify(r) + '\n');
    const response = JSON.parse(await waiting) as Response;
    // Public asymmetric key + exact input/output bytes reproduce the verification half.
    // Synthetic symmetric material belongs only to this ignored exchange artifact.
    await appendFile(resolve(cache, 'exchange.jsonl'), JSON.stringify({language: p === ts ? 'typescript' : 'elixir', request: r, response}) + '\n');
    if (response.rule && response.accepted !== false) throw new Error(JSON.stringify(response));
    return response;
  };
  const check = (condition: boolean, row: typeof rows[number], rule: string, request: unknown, sender: unknown, receiver: unknown) => {
    if (!condition) {
      row.disagreements++;
      console.error(JSON.stringify({rule, request, sender_bytes: sender, receiver_bytes: receiver}));
    }
    assert.ok(condition, rule + ': both sides must agree');
  };
  try {
    for (const p of [ts, ex]) await p.waitLine(line => {
      try {return (JSON.parse(line) as {ready?: boolean}).ready === true;} catch {return false;}
    }, 20000);
    const definition = ddl(table); assert.ok(definition.ok); await db.query(definition.value);
    const tsDirectory = await call(ts, base('web_bot_auth', 'ed25519', 0), {op: 'directory.start'});
    // Reuse the existing TLS certificate helper; the reverse publisher itself runs in OTP SSL.
    const tls = await peer((_req, res) => {res.writeHead(503); res.end();});
    let exDirectory: Response;
    try {
      exDirectory = await call(ex, base('web_bot_auth', 'ed25519', 0), {op: 'directory.start', key: Buffer.from(tls.tlsOptions.key).toString('base64url'), cert: Buffer.from(tls.tlsOptions.cert).toString('base64url'), ca: Buffer.from(tls.ca).toString('base64url')});
    } finally {await tls.close();}
    assert.ok(exDirectory.location, JSON.stringify(exDirectory));
    for (const family of families) for (const [sender, receiver, direction, directory] of [[ts, ex, 'typescript → elixir', tsDirectory], [ex, ts, 'elixir → typescript', exDirectory]] as const) {
      const row = {family, direction, rounds: 0, cases: 0, rejections: 0, disagreements: 0}; rows.push(row);
      for (let round = 0; round < rounds; round++) {
        const algorithms = family === 'rfc9421' ? http : family === 'jws' ? jws : ['jwe', 'nested'].includes(family) ? jwe : ['ed25519'];
        for (const algorithm of algorithms) {
          const r = base(family, algorithm, round);
          if (family === 'replay') {
            const claim = {...r, op: 'claim', table, namespace: bytes(751600, 16), nonce: `${direction}-${round}-${table}`, retainUntil: '253402300799'};
            const first = await call(sender, claim), second = await call(receiver, claim);
            check(first.claim === 'claimed' && second.claim === 'already_claimed', row, 'replay/atomic.claim', claim, first, second); row.cases++; continue;
          }
          if (family === 'jwe' || family === 'nested') {
            for (const enc of encs) {
              const request = {...r, enc};
              const recipient: Partial<Response> = algorithm === 'dir' ? {} : await call(receiver, request, {op: 'prepare', family: 'jwe'});
              let plaintext = r.bytes, inner: Response = {} as Response;
              if (family === 'nested') {inner = await call(sender, {...r, family: 'jws', algorithm: 'EdDSA', op: 'sign'}); assert.ok(inner.compact, JSON.stringify(inner)); plaintext = Buffer.from(inner.compact).toString('base64url');}
              const encrypted = await call(sender, request, {...recipient, op: 'encrypt', bytes: plaintext});
              check(typeof encrypted.compact === 'string', row, 'jose/encryption.output', request, recipient, encrypted);
              const decrypt = {...request, ...recipient, ...encrypted, ...(family === 'nested' ? {jwk: inner.jwk} : {}), op: 'decrypt'};
              const decrypted = await call(receiver, decrypt as Request);
              check(decrypted.accepted === true && decrypted.bytes === r.bytes, row, 'jose/crypto.authenticated_plaintext', decrypt, encrypted, decrypted); row.cases++;
              const bad = await call(receiver, decrypt as Request, {compact: tamper(encrypted.compact!, 4)});
              check(bad.accepted === false, row, 'jose/crypto.decryption_failed', decrypt, encrypted, bad); row.rejections++;
              if (family === 'nested') {
                const wrongInner = tamper(inner.compact!, 2);
                const wrongOuter = await call(sender, request, {...recipient, op: 'encrypt', bytes: Buffer.from(wrongInner).toString('base64url')});
                const rejected = await call(receiver, decrypt as Request, {...wrongOuter, op: 'decrypt'});
                check(rejected.accepted === false && (rejected.rule ?? '').includes('invalid_signature'), row, 'jose/crypto.inner_signature_required', wrongInner, wrongOuter, rejected); row.rejections++;
              }
              if (recipient.keyId) await call(receiver, request, {op: 'release', keyId: recipient.keyId});
            }
            continue;
          }
          const request = {...r, ...(family === 'web_bot_auth' ? {location: directory.location, ca: directory.ca} : {})};
          const signed = await call(sender, request as Request, {op: 'sign'});
          const verified = await call(receiver, request as Request, {...signed, op: 'verify'});
          check(verified.accepted === true && (family !== 'jws' || verified.bytes === r.bytes) && (family !== 'web_bot_auth' || verified.proof === 'signed'), row, family + '/crypto.valid', request, signed, verified); row.cases++;
          const changed = family === 'jws' ? {compact: tamper(signed.compact!, 2)} : {fields: signed.fields!.map(([n, x]) => [n, n === 'x-exchange' ? Buffer.from('tampered').toString('base64url') : x])};
          const rejected = await call(receiver, request as Request, {...signed, ...changed, op: 'verify'});
          check(rejected.accepted === false, row, family + '/crypto.invalid_signature', request, signed, rejected); row.rejections++;
        }
        row.rounds++;
      }
      t.diagnostic(JSON.stringify(row));
    }
    assert.equal((await db.query(`SELECT count(*) AS count FROM "${table}"`)).rows[0]?.count, '64');
    const receipt = '| Family | Direction | Rounds | Cases | Rejections | Disagreements |\n| --- | --- | ---: | ---: | ---: | ---: |\n' + rows.map(r => `| ${r.family} | ${r.direction} | ${r.rounds} | ${r.cases} | ${r.rejections} | ${r.disagreements} |`).join('\n');
    console.log(receipt);
    if (receiptPath) await writeFile(resolve(receiptPath), '**Status:** verified · **Kind:** record · **Updated:** October 10, 2026 · **Governed by:** executed reciprocal exchange · **Review when:** peer or exchange changes\n\nOBSERVED: `npm run exchange --prefix interop/reciprocal` on Node ' + process.versions.node + ', Elixir 1.20.3 / OTP 29, published request_seal 0.4.1.\n\n' + receipt + '\n\nSeeds: xorshift32, 942100 + round for payloads; +7515 for nonces; 751600 for the replay namespace. Every selector runs all 32 rounds; all ten alg/enc pairs run per JWE and nested round. Keys, CEKs, and IVs use each runtime’s real random generator. The ignored `interop/reciprocal/.cache/exchange.jsonl` records all inputs and outputs for verification replay. It includes synthetic symmetric material and TLS test material; asymmetric signing private keys never leave their runtime.\n\nHosted CI execution belongs to the supervisor after landing.\n');
  } finally {
    ts.child.stdin.end(); ex.child.stdin.end();
    await Promise.all([ts.stop(), ex.stop()]);
    try {await db.query(`DROP TABLE IF EXISTS "${table}"`);} finally {await db.end();}
  }
});
