import test from 'node:test';
import assert from 'node:assert/strict';
import {Custody, JWS, ok, withDeadline, type Context} from '../src/index.ts';
import {value} from './support/jose-oaep.ts';
test('a function signer may return a signature view into its operation input', async () => {
  const owner = value(await Custody.local({jws: 'HS256'}, {hmac: crypto.getRandomValues(new Uint8Array(32))}));
  const payload = new TextEncoder().encode('a payload long enough to hold an HMAC signature in its signing input');
  try {
    const signer = async (selector: unknown, input: Uint8Array) => {
      const signature = value(await owner.sign(selector, input, value(withDeadline())));
      input.set(signature);
      return ok(input.subarray(0, signature.length));
    };
    const wire = value(await JWS.sign([['alg', 'HS256']], payload, signer));
    const verified = await JWS.verify(wire, {algorithms: ['HS256'], timeout: 5000, key_resolver: () => ok({algorithm: 'HS256', key: owner})});
    assert.equal(verified.ok, true, 'copy the signature before clearing its aliased input');
    if (verified.ok) assert.deepEqual(verified.value.payload, payload);
  } finally {await owner.release();}
});
for (const algorithm of ['EdDSA', 'ES256'] as const) test(`JWS callable arities and branded handles sign and verify ${algorithm}`, async () => {
  const pair = algorithm === 'EdDSA'
    ? await crypto.subtle.generateKey({name: 'Ed25519'}, true, ['sign', 'verify'])
    : await crypto.subtle.generateKey({name: 'ECDSA', namedCurve: 'P-256'}, true, ['sign', 'verify']);
  assert.ok('privateKey' in pair);
  const owner = value(await Custody.local({jws: algorithm}, new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey)), {format: 'pkcs8'}));
  const payload = new TextEncoder().encode('callable signer contract');
  const context = value(withDeadline());
  const bound = ((_binding: null, ...[selector, input]: [unknown, Uint8Array]) => owner.sign(selector, input, context)).bind(null, null);
  const optional = (selector: unknown, input: Uint8Array, supplied?: Context) => owner.sign(selector, input, supplied ?? context);
  assert.equal(bound.length, 0);
  assert.equal(optional.length, 3);
  try {
    for (const signer of [bound, optional, owner]) {
      for (const wire of [
        await JWS.sign([['alg', algorithm]], payload, signer),
        await JWS.signProtected(new TextEncoder().encode(JSON.stringify({alg: algorithm})), payload, signer),
      ]) {
        const verified = value(await JWS.verify(value(wire), {algorithms: [algorithm], timeout: 5000, key_resolver: () => ok({algorithm, key: owner})}));
        assert.deepEqual(verified.payload, payload);
      }
    }
    const mismatch = await JWS.sign([['alg', algorithm === 'EdDSA' ? 'ES256' : 'EdDSA']], payload, owner);
    assert.equal(mismatch.ok, false);
    if (!mismatch.ok) assert.equal(mismatch.error.reason, 'algorithm_mismatch');
    for (const invalid of [null, {}, 'signer', {algorithm: owner.algorithm, sign: owner.sign}, Object.create(owner), new Proxy(owner, {})]) {
      for (const result of [await JWS.sign([['alg', algorithm]], payload, invalid), await JWS.signProtected(new TextEncoder().encode(JSON.stringify({alg: algorithm})), payload, invalid)]) {
        assert.equal(result.ok, false);
        if (!result.ok) assert.equal(result.error.reason, 'invalid_options');
      }
    }
  } finally {await owner.release();}
});
test('JWS callable failures return the bounded signer failure reason', async () => {
  for (const signer of [
    () => undefined,
    () => new Uint8Array(64),
    () => {throw new Error('private callback diagnostic');},
    async () => {throw new Error('private callback diagnostic');},
  ]) {
    for (const result of [await JWS.sign([['alg', 'EdDSA']], 'payload', signer), await JWS.signProtected('{"alg":"EdDSA"}', 'payload', signer)]) {
      assert.equal(result.ok, false);
      if (!result.ok) {
        assert.equal(result.error.reason, 'signer_failed');
        assert.equal(result.error.layer, 'crypto');
        assert.ok(!JSON.stringify(result).includes('private callback diagnostic'));
      }
    }
  }
});
