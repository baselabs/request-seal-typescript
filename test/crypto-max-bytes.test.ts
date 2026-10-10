import test from 'node:test';
import assert from 'node:assert/strict';
import {Crypto, Custody, withDeadline, type Result, type KeyHandle} from '../src/index.ts';
import {LocalPort} from '../src/custody/local.ts';
import {resolveAlgorithm} from '../src/crypto/algorithm.ts';
import {KeyIdentity} from '../src/key_identity.ts';
import {verifyKey, signKey} from '../src/crypto/primitive.ts';
import {SIGNATURE_BASE_MAX_BYTES, BODY_MAX_BYTES, MESSAGE_MAX_FIELDS_BYTES, JOSE_MAX_COMPACT_BYTES, JOSE_MAX_PLAINTEXT_BYTES} from '../src/constants.ts';
function value<T>(r: Result<T>): T { if (!r.ok) assert.fail(JSON.stringify(r.error)); return r.value; }
function reason(r: Result<unknown>, expected: string, kind?: string): void {
  assert.equal(r.ok, false); if (!r.ok) { assert.equal(r.error.reason, expected); if (kind) assert.equal(r.error.kind, kind); }
}
const sign = Crypto.sign;
const verify = Crypto.verify;
const hsign = (h: KeyHandle, d: unknown, o?: unknown) => h.sign('hmac-sha256', d, context(), o);
const hverify = (h: KeyHandle, s: unknown, d: unknown, o?: unknown) => h.verify('hmac-sha256', s, d, context(), o);
const context = () => value(withDeadline());
const local = async () => value(await Custody.local('hmac-sha256', {hmac: new Uint8Array(32).fill(7)}));

test('crypto and custody accept inclusive maxBytes endpoints and exact selected bounds', async () => {
  const h = await local();
  try {
    for (const maxBytes of [1, 10, 1_235_403, 16_777_216]) {
      const data = new Uint8Array(maxBytes), opts = {maxBytes};
      const expected = new Uint8Array(await crypto.subtle.sign('HMAC', await crypto.subtle.importKey('raw', new Uint8Array(32).fill(7), {name: 'HMAC', hash: 'SHA-256'}, false, ['sign']), data));
      for (const s of [await sign('hmac-sha256', h, data, opts), await hsign(h, data, opts)]) assert.deepEqual(value(s), expected);
      value(await verify('hmac-sha256', h, expected, data, opts));
      value(await hverify(h, expected, data, opts));
      const excess = new Uint8Array(maxBytes + 1);
      reason(await sign('hmac-sha256', h, excess, opts), 'invalid_data', 'crypto');
      reason(await verify('hmac-sha256', h, expected, excess, opts), 'invalid_data', 'crypto');
      reason(await hsign(h, excess, opts), 'invalid_data', 'custody');
      reason(await hverify(h, expected, excess, opts), 'invalid_data', 'custody');
    }
  } finally {await h.release();}
});

test('invalid byte options precede algorithm, handle, context and capability checks', async () => {
  const h = await local();
  try {
    for (const opts of [{maxBytes: 0}, {maxBytes: -1}, {maxBytes: 16_777_217}, {maxBytes: 1.5}, {maxBytes: NaN}, {maxBytes: Infinity}, {maxBytes: '1'}, {maxBytes: null}, {maxBytes: undefined}, {maxBytes: 1, unknown: true}, [['maxBytes', 1], ['maxBytes', 2]], null]) {
      for (const k of [h, null]) {
        reason(await sign('unknown', k, new Uint8Array(1), opts), 'invalid_options', 'crypto');
        reason(await verify('unknown', k, new Uint8Array(1), new Uint8Array(1), opts), 'invalid_options', 'crypto');
      }
      reason(await hsign(h, new Uint8Array(1), opts), 'invalid_options', 'custody');
      reason(await hverify(h, new Uint8Array(32), new Uint8Array(1), opts), 'invalid_options', 'custody');
    }
    reason(await sign('unknown', null, new Uint8Array(1)), 'unsupported_algorithm');
    reason(await h.sign.call(null, 'unknown', new Uint8Array(1), null as never, {maxBytes: 0}), 'invalid_options');
    reason(await h.verify.call(null, 'unknown', new Uint8Array(32), new Uint8Array(1), null as never, {maxBytes: 0}), 'invalid_options');
    await h.release();
    reason(await hsign(h, new Uint8Array(1), {maxBytes: 0}), 'invalid_options');
    reason(await hverify(h, new Uint8Array(32), new Uint8Array(1), {maxBytes: 0}), 'invalid_options');
  } finally {await h.release();}
});

test('byte options read own keys once and reject unknown or throwing keys without disclosure', async () => {
  const h = await local();
  try {
    const sig = value(await hsign(h, new Uint8Array(1)));
    for (const call of [(opts: unknown) => sign('hmac-sha256', h, new Uint8Array(1), opts), (opts: unknown) => hsign(h, new Uint8Array(1), opts), (opts: unknown) => verify('hmac-sha256', h, sig, new Uint8Array(1), opts), (opts: unknown) => hverify(h, sig, new Uint8Array(1), opts)]) {
      let reads = 0;
      const opts = {get maxBytes() {reads++; return reads === 1 ? 1 : 0;}};
      assert.equal((await call(opts)).ok, true); assert.equal(reads, 1);
    }
    const inherited = Object.create({maxBytes: 0});
    value(await hsign(h, new Uint8Array(1), inherited));
    const thrown = await sign('hmac-sha256', h, new Uint8Array(1), {get maxBytes() {throw new Error('private canary');}});
    reason(thrown, 'invalid_options'); assert.equal(JSON.stringify(thrown).includes('private canary'), false);
  } finally {await h.release();}
});

test('all legacy crypto and custody calls retain the one MiB default', async () => {
  const h = await local();
  try {
    const data = new Uint8Array(1_048_576), s = value(await Crypto.sign('hmac-sha256', h, data));
    value(await Crypto.verify('hmac-sha256', h, s, data)); value(await hsign(h, data)); value(await hverify(h, s, data));
    for (const opts of [undefined, {}, {maxBytes: 1_048_576}]) {
      const excess = new Uint8Array(1_048_577);
      reason(await sign('hmac-sha256', h, excess, opts), 'invalid_data');
      reason(await verify('hmac-sha256', h, s, excess, opts), 'invalid_data');
      reason(await hsign(h, excess, opts), 'invalid_data'); reason(await hverify(h, s, excess, opts), 'invalid_data');
    }
  } finally {await h.release();}
});

test('direct local callbacks enforce the ceiling before released key access', async () => {
  const key = await crypto.subtle.importKey('raw', new Uint8Array(32).fill(7), {name: 'HMAC', hash: 'SHA-256'}, false, ['sign', 'verify']);
  const port = new LocalPort(key, key, undefined, value(KeyIdentity.symmetric('direct-local')), value(resolveAlgorithm('hmac-sha256')));
  const data = new Uint8Array(16_777_216), s = value(await port.sign('hmac-sha256', data, context()));
  value(await port.verify('hmac-sha256', s, data, context()));
  await port.release();
  reason(await port.sign('hmac-sha256', new Uint8Array(1), context()), 'key_not_found');
  const shadowed = new Uint8Array(16_777_217); Object.defineProperty(shadowed, 'length', {value: 0}); Object.defineProperty(shadowed, 'byteLength', {value: 0});
  for (const input of [new Uint8Array(16_777_217), shadowed, 'not binary', null]) {
    reason(await port.sign('unknown', input, context()), 'invalid_data', 'custody');
    reason(await port.verify('unknown', s, input, context()), 'invalid_data', 'custody');
  }
});

test('fixed upper-level and primitive defaults remain separate from the crypto ceiling', async () => {
  for (const n of [SIGNATURE_BASE_MAX_BYTES, BODY_MAX_BYTES, MESSAGE_MAX_FIELDS_BYTES, JOSE_MAX_COMPACT_BYTES, JOSE_MAX_PLAINTEXT_BYTES]) assert.equal(n, 1_048_576);
  const key = await crypto.subtle.importKey('raw', new Uint8Array(32), {name: 'HMAC', hash: 'SHA-256'}, false, ['sign', 'verify']);
  const spec = value(resolveAlgorithm('hmac-sha256'));
  reason(await signKey(spec, key, new Uint8Array(1_048_577)), 'invalid_data');
  reason(await verifyKey(spec, key, new Uint8Array(32), new Uint8Array(1_048_577)), 'invalid_data');
});

test('shadowed byte lengths cannot bypass selected bounds', async () => {
  const h = await local();
  try {
    const data = new Uint8Array(11); Object.defineProperty(data, 'length', {value: 0}); Object.defineProperty(data, 'byteLength', {value: 0});
    reason(await sign('hmac-sha256', h, data, {maxBytes: 10}), 'invalid_data');
    reason(await hsign(h, data, {maxBytes: 10}), 'invalid_data');
  } finally {await h.release();}
});

test('nested real handles preserve the selected maximum and option precedence over capability', async () => {
  const {createKeyHandle} = await import('../src/key_handle.ts');
  const inner = await local(), outer = value(createKeyHandle('hmac-sha256', inner));
  const restricted = value(createKeyHandle('hmac-sha256', inner, ['verify']));
  try {
    reason(await hsign(restricted, new Uint8Array(1), {maxBytes: 0}), 'invalid_options');
    reason(await hsign(restricted, new Uint8Array(1)), 'unsupported_operation');
    const data = new Uint8Array(1_235_403), opts = {maxBytes: 2_097_152};
    const sig = value(await hsign(outer, data, opts)); value(await hverify(outer, sig, data, opts));
  } finally {await outer.release(); await restricted.release(); await inner.release();}
});


test('public-key verification accepts opt-in bounds while its direct method retains the default', async () => {
  const {readFile} = await import('node:fs/promises');
  const h = value(await Custody.local('ed25519', await readFile('test/fixtures/upstream/crypto/ed25519_private.pem', 'utf8')));
  try {
    assert.equal(Crypto.maxBytesCeiling(), 16_777_216);
    const pub = value(await h.publicKey()), data = new Uint8Array(1_235_403), opts = {maxBytes: 2_097_152};
    const sig = value(await sign('ed25519', h, data, opts));
    value(await verify('ed25519', pub, sig, data, opts));
    reason(await pub.verify('ed25519', sig, data), 'invalid_data');
    reason(await verify('ed25519', pub, sig, new Uint8Array(2_097_153), opts), 'invalid_data');
  } finally {await h.release();}
});


test('unwrap rejects maxBytes on a real unwrap capability', async () => {
  const {readFile} = await import('node:fs/promises');
  const h = value(await Custody.local({jwe: 'RSA-OAEP-256'}, await readFile('test/fixtures/upstream/crypto/rsa_private.pem', 'utf8')));
  try {reason(await h.unwrap({jwe: 'RSA-OAEP-256'}, new Uint8Array(256), context(), {maxBytes: 1}), 'invalid_options');}
  finally {await h.release();}
});
