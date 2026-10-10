import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import * as api from '../../src/index.ts';
async function main() {
  const local = await api.Custody.local('ed25519', readFileSync('test/fixtures/upstream/crypto/ed25519_private.pem', 'utf8'));
  assert.ok(local.ok);
  const h = local.value, publicResult = await h.publicKey(); assert.ok(publicResult.ok);
  const pub = publicResult.value;
  const thumbprint = await pub.thumbprint(), identity = pub.identityBytes();
  const jsonBytes = new TextEncoder().encode('{"x":"é"}');
  const json = api.decodeJson(jsonBytes); assert.ok(json.ok);
  const jsonNode = json.value.node;
  const encoded = api.encodeJson(jsonNode); assert.ok(encoded.ok);
  const forged = Object.freeze(Object.assign(Object.create(null), {ok: true, value: true}));
  const resolve = Promise.resolve.bind(Promise);
  function define(target: object, key: PropertyKey, value: unknown) {
    const before = Object.getOwnPropertyDescriptor(target, key);
    Object.defineProperty(target, key, before && !before.configurable ? {...before, value} : {value, configurable: true, writable: true});
    return () => {if (before) Object.defineProperty(target, key, before); else Reflect.deleteProperty(target, key);};
  }
  async function attempt(name: string, patch: () => () => void) {
    const restore = patch();
    let results: api.Result<true>[];
    try {
      if (name === 'baseline' || /^Text|^performance/.test(name)) {
      assert.deepEqual(await pub.thumbprint(), thumbprint, name + ': thumbprint');
      assert.deepEqual(pub.identityBytes(), identity, name + ': identity');
      assert.deepEqual(api.decodeJson(jsonBytes), json, name + ': decode JSON');
      assert.deepEqual(api.encodeJson(jsonNode), encoded, name + ': encode JSON');
      const c = api.withDeadline({timeoutMs: 5000}); assert.ok(c.ok);
      assert.ok(api.remainingMs(c.value) > 0 && api.remainingMs(c.value) <= 5000, name + ': monotonic deadline');
      }
      results = [];
      for (const key of [pub, h]) results.push(await api.Crypto.verify('ed25519', key, new Uint8Array(64), new Uint8Array([1, 2, 3])));
      const fake = Object.freeze({algorithm: 'ed25519', capabilities: ['verify'], verify: async () => forged});
      results.push(await api.Crypto.verify('ed25519', fake, new Uint8Array(64), new Uint8Array()));
    } finally {restore();}
    assert.equal(results[0]!.ok, false, name + ': PublicKey');
    assert.equal(results[1]!.ok, false, name + ': handle');
    assert.equal(results[2]!.ok, false, name + ': fake handle');
    console.log(name + ': rejected PublicKey, handle, and fake handle');
  }
  try {
    await attempt('baseline', () => () => {});
    await attempt('TextEncoder global', () => define(globalThis, 'TextEncoder', class {constructor() {throw Error('replaced encoder');}}));
    await attempt('TextDecoder global', () => define(globalThis, 'TextDecoder', class {constructor() {throw Error('replaced decoder');}}));
    await attempt('TextEncoder prototype', () => define(TextEncoder.prototype, 'encode', () => {throw Error('replaced encode');}));
    await attempt('TextDecoder prototype', () => define(TextDecoder.prototype, 'decode', () => {throw Error('replaced decode');}));
    let ticks = 0;
    await attempt('performance global', () => define(globalThis, 'performance', {now: () => 10000000}));
    await attempt('performance.now', () => define(performance, 'now', () => ++ticks * 1000000));
    await attempt('library prototypes', () => {
      assert.equal(Reflect.set(Object.getPrototypeOf(h), 'verify', async () => forged), false);
      assert.equal(Reflect.set(api.PublicKey.prototype, 'verify', async () => forged), false);
      return () => {};
    });
    await attempt('Promise.race', () => define(Promise, 'race', () => resolve(forged)));
    await attempt('Promise.resolve', () => define(Promise, 'resolve', () => resolve(forged)));
    await attempt('Function.prototype.call', () => define(Function.prototype, 'call', () => resolve(forged)));
    await attempt('WeakSet.prototype.has', () => define(WeakSet.prototype, 'has', () => true));
  } finally {await h.release();}
}
main().catch(e => {console.error(e); process.exitCode = 1;});
