import test from './harness.ts';
import assert from './assert.ts';
import {limitation, assertOutcome} from './limits.ts';
import * as Seal from '../../dist/index.js';

function value<T>(r: Seal.Result<T>): T { if (!r.ok) assert.fail(`${r.error.kind}/${r.error.reason}`); return r.value; }
const payload = () => crypto.getRandomValues(new Uint8Array(257));
const keyPair = (name: string, hash = 'SHA-256') => name === 'Ed25519'
  ? crypto.subtle.generateKey({name}, true, ['sign', 'verify'])
  : name === 'ECDSA'
    ? crypto.subtle.generateKey({name, namedCurve: hash === 'SHA-384' ? 'P-384' : 'P-256'}, true, ['sign', 'verify'])
    : crypto.subtle.generateKey({name, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash}, true, name === 'RSA-OAEP' ? ['encrypt', 'decrypt'] : ['sign', 'verify']);

test('owned byte and JSON codecs preserve octets and reject noncanonical input', () => {
  for (const length of [0, 1, 2, 3, 255, 256, 257]) {
    const bytes = crypto.getRandomValues(new Uint8Array(length));
    for (const [encode, decode] of [[Seal.encodeBase64, Seal.decodeBase64], [Seal.encodeBase64Url, Seal.decodeBase64Url]] as const)
      assert.deepEqual(value(decode(encode(bytes))), bytes);
  }
  for (const invalid of ['Zh', 'Zm9', 'Zg=', '+w', '/w']) assert.equal(Seal.decodeBase64Url(invalid).ok, false);
  const bytes = new TextEncoder().encode('{"x":9007199254740993,"x":1e2}');
  const decoded = value(Seal.decodeJson(bytes));
  assert.deepEqual(value(Seal.decodeJson(value(Seal.encodeJson(decoded.node)))), decoded);
  for (const invalid of ['\ufeff{}', '{"x":01}', '"\\ud800"']) assert.equal(Seal.decodeJson(new TextEncoder().encode(invalid)).ok, false);
});

for (const algorithm of ['HS256', 'RS256', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'EdDSA'] as const)
  test(`JWS ${algorithm} authenticates round trips and refuses changed signatures or its exact declared custody limitation`, async () => {
    const pair = algorithm === 'HS256' ? undefined : await keyPair(
      algorithm === 'EdDSA' ? 'Ed25519' : algorithm.startsWith('ES') ? 'ECDSA' : algorithm.startsWith('PS') ? 'RSA-PSS' : 'RSASSA-PKCS1-v1_5',
      algorithm.endsWith('384') ? 'SHA-384' : algorithm.endsWith('512') ? 'SHA-512' : 'SHA-256');
    const material = pair ? new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey)) : {hmac: crypto.getRandomValues(new Uint8Array(32))};
    if (algorithm === 'EdDSA' && pair) {
      // RFC 8032 test 1: the published empty-message signature is independent
      // of this engine's signing implementation.
      const hex = (text: string) => new Uint8Array(text.match(/../g)!.map(byte => parseInt(byte, 16)));
      const publishedKey = await crypto.subtle.importKey('raw', hex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'), 'Ed25519', false, ['verify']);
      const publishedSignature = hex('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b');
      const verified = await crypto.subtle.verify('Ed25519', publishedKey, publishedSignature, new Uint8Array());
      assert.equal(verified, !limitation('custody/ed25519_empty_message'), 'RFC 8032 test 1');
      console.log('REQUEST_SEAL_PROBE ' + JSON.stringify({id: 'RFC 8032 test 1', verified}));
      // Real WebCrypto operations distinguish an empty-message defect from import failure.
      for (const format of ['pkcs8', 'jwk'] as const) {
        const imported = format === 'pkcs8'
          ? await crypto.subtle.importKey(format, material as Uint8Array<ArrayBuffer>, 'Ed25519', false, ['sign'])
          : await crypto.subtle.importKey(format, await crypto.subtle.exportKey('jwk', pair.privateKey), 'Ed25519', false, ['sign']);
        for (const key of [pair.privateKey, imported]) {
          for (const length of [0, 1, 257]) {
            const data = new Uint8Array(length), signature = await crypto.subtle.sign('Ed25519', key, data);
            assert.equal(await crypto.subtle.verify('Ed25519', pair.publicKey, signature, data), length > 0 || !limitation('custody/ed25519_empty_message'));
          }
        }
      }
    }
    const result = await Seal.Custody.local({jws: algorithm}, material, pair ? {format: 'pkcs8'} : {});
    if (algorithm === 'EdDSA') assertOutcome('custody/ed25519_empty_message', result);
    const jwkResult = algorithm === 'EdDSA' && pair
      ? await Seal.Custody.local({jws: algorithm}, {kty: 'OKP', crv: 'Ed25519', x: (await crypto.subtle.exportKey('jwk', pair.privateKey)).x, d: (await crypto.subtle.exportKey('jwk', pair.privateKey)).d}) : undefined;
    if (jwkResult) {
      assert.equal(jwkResult.ok, result.ok);
      if (!jwkResult.ok) assert.equal(jwkResult.error.kind + '/' + jwkResult.error.reason, limitation('custody/ed25519_empty_message')?.observed);
      else await jwkResult.value.release();
    }
    if (!result.ok) {assert.ok(algorithm === 'EdDSA' && limitation('custody/ed25519_empty_message')); return;}
    const owner = result.value;
    try {
      const policy = {algorithms: [algorithm], timeout: 5000, key_resolver: () => Seal.ok({algorithm, key: owner})};
      for (const bytes of [new Uint8Array([0]), payload()]) {
        const wire = value(await Seal.JWS.sign([['alg', algorithm]], bytes, owner));
        assert.deepEqual(value(await Seal.JWS.verify(wire, policy)).payload, bytes);
        const parts = wire.split('.');
        const signature = value(Seal.decodeBase64Url(parts[2])); signature[0]! ^= 1;
        parts[2] = Seal.encodeBase64Url(signature);
        const rejected = await Seal.JWS.verify(parts.join('.'), policy);
        assert.equal(!rejected.ok && rejected.error.reason, 'invalid_signature');
      }
    } finally {await owner.release();}
  });

for (const algorithm of ['RSA-OAEP', 'RSA-OAEP-256', 'A128GCMKW', 'A256GCMKW', 'dir'] as const)
  for (const encryption of ['A128GCM', 'A256GCM'] as const)
    test(`JWE ${algorithm} ${encryption} authenticates round trips and refuses a changed tag`, async () => {
      const pair = algorithm.startsWith('RSA') ? await keyPair('RSA-OAEP', algorithm === 'RSA-OAEP' ? 'SHA-1' : 'SHA-256') : undefined;
      const owner = pair ? value(await Seal.Custody.local({jwe: algorithm}, new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey)), {format: 'pkcs8'})) : undefined;
      const manager = algorithm === 'dir' || owner ? undefined : value(await Seal.KeyManagement.local(algorithm, crypto.getRandomValues(new Uint8Array(algorithm === 'A128GCMKW' ? 16 : 32))));
      let direct: Seal.KeyManagementHandle | undefined;
      try {
        const recipient = owner ?? (async (selected: string, cek: Uint8Array) => {
          if (selected === 'dir') {
            if (direct) await direct.release();
            direct = value(await Seal.KeyManagement.local('dir', cek));
            return Seal.ok({encrypted_key: new Uint8Array(), header: []});
          }
          return manager!.wrap(selected, cek);
        });
        const policy = {algorithms: [algorithm], encryption: [encryption], timeout: 5000, max_plaintext: 1048576,
          key_resolver: () => Seal.ok(owner ? {algorithm, key: owner} : {algorithm, unwrap: (ek: unknown, h: Seal.JoseProtectedHeader, c: Seal.Context) => (direct ?? manager)!.unwrap(ek, h, c)})};
        for (const bytes of [new Uint8Array(), payload()]) {
          const wire = value(await Seal.JWE.encrypt([['alg', algorithm], ['enc', encryption]], bytes, recipient));
          assert.deepEqual(value(await Seal.JWE.decrypt(wire, policy)).plaintext, bytes);
          const parts = wire.split('.'), tag = value(Seal.decodeBase64Url(parts[4])); tag[0]! ^= 1;
          parts[4] = Seal.encodeBase64Url(tag);
          const rejected = await Seal.JWE.decrypt(parts.join('.'), policy);
          assert.equal(!rejected.ok && rejected.error.reason, 'decryption_failed');
        }
      } finally {await owner?.release(); await manager?.release(); await direct?.release();}
    });

test('nested JOSE releases the authenticated inner payload and rejects deeper nesting', async () => {
  const pair = await keyPair('RSA-OAEP');
  const recipient = value(await Seal.Custody.local({jwe: 'RSA-OAEP-256'}, new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey)), {format: 'pkcs8'}));
  const signer = value(await Seal.Custody.local({jws: 'HS256'}, {hmac: crypto.getRandomValues(new Uint8Array(32))}));
  try {
    const bytes = payload();
    const inner = value(await Seal.JWS.sign([['alg', 'HS256']], bytes, signer));
    const headers = [['alg', 'RSA-OAEP-256'], ['enc', 'A256GCM'], ['cty', 'JWT']] as const;
    const outer = value(await Seal.JWE.encrypt(headers, inner, recipient));
    const policy = {
      jwe: {algorithms: ['RSA-OAEP-256'], encryption: ['A256GCM'], timeout: 5000, max_plaintext: 1048576, key_resolver: () => Seal.ok({algorithm: 'RSA-OAEP-256', key: recipient})},
      jws: {algorithms: ['HS256'], timeout: 5000, key_resolver: () => Seal.ok({algorithm: 'HS256', key: signer})},
    };
    assert.deepEqual(value(await Seal.Nested.decrypt(outer, policy, {content_types: ['JWT']})).jws.payload, bytes);
    const deeper = value(await Seal.JWE.encrypt(headers, outer, recipient));
    const rejected = await Seal.Nested.decrypt(deeper, policy, {content_types: ['JWT']});
    assert.equal(!rejected.ok && rejected.error.reason, 'nesting_depth');
  } finally {await signer.release(); await recipient.release();}
});
