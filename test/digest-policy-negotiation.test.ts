import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import * as api from '../src/index.ts';
import {createNodeHasher} from '../src/node_hasher.ts';
import {dictionaries} from '../src/signature-fields.ts';
const value = <T>(r: api.Result<T>): T => {assert.ok(r.ok, JSON.stringify(r)); return r.value;};
test('concurrent digest creation shares a stateless node hasher factory', async () => {
  const real = value(createNodeHasher());
  const states = await Promise.all([1, 2, 3].map(() => api.DigestState.create('content', ['sha-256'], real)));
  for (const result of states) {
    const state = value(result);
    value(await state.update(new TextEncoder().encode('abc')));
    assert.deepEqual(value(await state.finish()), value(await api.digest(new TextEncoder().encode('abc'), ['sha-256'])));
  }
});
test('invalid digest kind precedes invalid hasher', async () => {
  const result = await api.DigestState.create('bogus', ['sha-256'], null);
  assert.equal(!result.ok && result.error.reason, 'invalid_kind');
});
test('overlapping operations reject across states sharing the same real hash session', async () => {
  for (const operation of ['update', 'finish'] as const) {
    const real = value(createNodeHasher());
    const actual = await real.create('sha-256');
    let block = false, notify!: () => void, unblock!: () => void;
    const entered = new Promise<void>(resolve => {notify = resolve;});
    const barrier = new Promise<void>(resolve => {unblock = resolve;});
    const shared: api.HashSession = {
      async update(bytes) {await actual.update(bytes); if (block) {block = false; notify(); await barrier;}},
      async finish() {if (block) {block = false; notify(); await barrier;} return actual.finish();},
    };
    let creates = 0;
    const factory: api.IncrementalHasher = {create(algorithm) {return ++creates % 5 === 0 ? shared : real.create(algorithm);}};
    const first = value(await api.DigestState.create('content', ['sha-256'], factory));
    const second = value(await api.DigestState.create('content', ['sha-256'], factory));
    block = true;
    const pending = operation === 'update' ? first.update(new Uint8Array([1])) : first.finish();
    await entered;
    try {
      const overlap = operation === 'update' ? await second.finish() : await second.update(new Uint8Array([2]));
      assert.equal(!overlap.ok && overlap.error.reason, 'invalid_state');
    } finally {unblock(); await pending;}
  }
});
test('replay commitment rejects accessors and captures own callable values', () => {
  const store = value(api.createMemoryStore({maxEntries: 2}));
  let reads = 0;
  const callback = () => api.ok(new Uint8Array([1]));
  const replay = {identifier: 'nonce', namespace: new Uint8Array([1]), store, timeoutMs: 5000, get commitment() {reads++; return reads === 1 ? callback : () => api.ok(new Uint8Array([2]));}};
  const attrs = {algorithms: ['ed25519'], components: '()', keyResolver: () => api.ok(null), freshness: {clock: () => 100, maxAge: 60, skew: 0, requireExpires: false}, content: 'not_required', replay};
  const rejected = api.Policy.create(attrs); assert.equal(rejected.ok, false); assert.equal(!rejected.ok && rejected.error.reason, 'invalid_policy'); assert.equal(reads, 0);
  const plain = {...replay, commitment: callback};
  const policy = value(api.Policy.create({...attrs, replay: plain})); plain.commitment = () => api.ok(new Uint8Array([3]));
  assert.notEqual(policy.replay, 'not_required'); if (policy.replay !== 'not_required') assert.equal(policy.replay.commitment, callback);
});
test('negotiation accepts callable arities, bound signers, and branded handles', async () => {
  const handle = value(await api.Custody.local('hmac-sha256', {hmac: crypto.getRandomValues(new Uint8Array(32))}));
  try {
    const base = value(await api.Message.request('GET', 'https://example.com/', [], null));
    const requests = value(api.AcceptSignature.parse('s=("@method");alg="hmac-sha256"', {target: 'request'}));
    const chooser = (_request?: unknown, _second?: unknown, _third?: unknown) => api.ok({algorithm: 'hmac-sha256', created: null, expires: null});
    const three = (algorithm: api.SigningAlgorithm, data: Uint8Array, context: api.Context) => handle.sign(algorithm, data, context);
    const rest = (...args: Parameters<typeof three>) => three(...args);
    for (const signer of [three, three.bind(null), rest, handle]) {
      const signed = value(await api.AcceptSignature.fulfill(base, requests, chooser, signer));
      const parsed = dictionaries(signed, 16); assert.equal(parsed[0].size, 1); assert.equal(parsed[1].size, 1);
      const policy = value(api.Policy.create({algorithms: ['hmac-sha256'], components: '("@method")', keyResolver: () => api.ok({algorithm: 'hmac-sha256', key: handle}), freshness: 'not_evaluated', content: 'not_required', replay: 'not_required'}));
      assert.ok((await api.verify(signed, policy, {label: 's'})).ok);
    }
  } finally {await handle.release();}
});
test('managed handle identity bounds a hanging custodian', async () => {
  const local = value(await api.Custody.local('ed25519', await readFile('test/fixtures/upstream/crypto/ed25519_private.pem', 'utf8')));
  const port = Object.create(null) as api.Custodian;
  for (const name of ['sign','verify','publicKey','unwrap','release'] as const) Object.defineProperty(port, name, {value: local[name].bind(local)});
  Object.defineProperty(port, 'identity', {value: () => new Promise(() => {})});
  const handle = value(api.createKeyHandle('ed25519', port));
  try {
    const base = value(await api.Message.request('GET', 'https://example.com/', [], null));
    const signed = value(await api.sign(base, {label: 's', algorithm: 'ed25519', signatureInput: '("@method")'}, (algorithm: api.SigningAlgorithm, bytes: Uint8Array) => local.sign(algorithm, bytes, value(api.withDeadline()))));
    const identity = value(api.KeyIdentity.fromPublic(value(await local.publicKey())));
    const policy = value(api.Policy.create({algorithms: ['ed25519'], components: '("@method")', keyResolver: () => api.ok({algorithm: 'ed25519', key: handle, identity}), freshness: 'not_evaluated', content: 'not_required', replay: 'not_required'}));
    const c = value(api.withDeadline({timeoutMs: 30}));
    const r = await api.verify(signed, policy, {label: 's', context: c}); assert.equal(!r.ok && r.error.reason, 'deadline_exceeded');
  } finally {await handle.release();}
});
