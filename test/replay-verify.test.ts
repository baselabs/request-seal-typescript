import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import * as api from '../src/index.ts';
import {coreError} from '../src/errors/types.ts';
const A = api as any;
function value<T>(r: api.ReplayStoreResult<T>): T { assert.equal(r.ok, true, JSON.stringify(r)); if (!r.ok) throw new Error('Rejected result'); return r.value; }
const context = () => value(api.withDeadline({timeoutMs: 10000}));
async function setup() {
  const h = value(await api.Custody.local('ed25519', await readFile('test/fixtures/upstream/crypto/ed25519_private.pem', 'utf8')));
  const key = value(await api.PublicKey.import(await readFile('test/fixtures/upstream/crypto/ed25519_public.pem', 'utf8'), 'pem'));
  const m = value(await api.Message.request('GET', 'https://example.com/', [], ''));
  const signer = (algorithm: api.SigningAlgorithm, base: Uint8Array, c = context()) => h.sign(algorithm, base, c);
  const signed = async (input = '("@method");created=100;nonce="nonce"', label = 's') => value(await api.sign(m, {label, signatureInput: input, algorithm: 'ed25519'}, signer));
  const events: string[] = [];
  const memory = value(api.createMemoryStore({maxEntries: 32}));
  const store: api.ReplayStore = {identity: 'counting-memory', claim: async (claim, c) => {events.push('store'); return memory.claim(claim, c);}, sweep: (now, c) => memory.sweep(now, c)};
  const commitment: api.ReplayPolicy['commitment'] = (facts, c) => {
    events.push('commitment'); assert.equal(Object.isFrozen(facts), true); assert.equal(Object.hasOwn(facts, 'label'), false); assert.equal(Object.isFrozen(facts.profile), true);
    assert.equal(api.isContext(c), true);
    return api.ok(new TextEncoder().encode(facts.identifier));
  };
  const attrs = {algorithms: ['ed25519'], components: '("@method")', keyResolver: async () => {events.push('key'); return api.ok({algorithm: 'ed25519', verify: async (algorithm: api.SigningAlgorithm, base: Uint8Array, signature: Uint8Array) => {events.push('crypto'); return api.Crypto.verify(algorithm, key, signature, base);}});}, freshness: {clock: () => {events.push('freshness'); return 100;}, maxAge: 60, skew: 2, requireExpires: false}, content: 'not_required', replay: {identifier: 'nonce', namespace: new Uint8Array([1]), commitment, store, timeoutMs: 5000}};
  const policy = (extra: Record<string, unknown> = {}) => value(api.Policy.create({...attrs, ...extra}));
  return {h, m, signed, signer, events, memory, store, commitment, attrs, policy};
}
test('verified success calls the real counting store once and last with a branded receipt', async () => {
  const s = await setup();
  try {
    const r = value(await api.verify(await s.signed(), s.policy(), {label: 's'}));
    assert.deepEqual(s.events, ['freshness', 'key', 'crypto', 'commitment', 'store']);
    assert.equal(api.isReplayReceipt(r.replay), true);
    assert.deepEqual(r.replay, {store: 'counting-memory', retainUntil: 163});
    const p = s.policy();
    const repeated = await api.verify(await s.signed(undefined, 'renamed'), p, {label: 'renamed'});
    assert.equal(repeated.ok, false); if (!repeated.ok) assert.equal(repeated.error.reason, 'replayed');
    console.log('VERIFY store=1 last=true receipt=branded; relabeling=replayed');
  } finally {await s.h.release();}
});
for (const kind of ['input', 'fields', 'coverage', 'freshness', 'key', 'crypto', 'content', 'retention', 'identifier'] as const) test(`earlier ${kind} rejection never calls commitment or the counting store`, async () => {
  const s = await setup();
  try {
    let m: unknown = await s.signed(), p = s.policy(), opts: unknown = {label: 's'}, expected: string;
    switch (kind) {
      case 'input': m = {...m as object}; expected = 'invalid_message'; break;
      case 'fields': m = s.m; expected = 'missing_signature_input'; break;
      case 'coverage': p = s.policy({components: '("@authority")'}); expected = 'missing_required_component'; break;
      case 'freshness': p = s.policy({freshness: {...s.attrs.freshness, clock: () => 200}}); expected = 'too_old'; break;
      case 'key': p = s.policy({keyResolver: () => api.ok(null)}); expected = 'unknown_key'; break;
      case 'crypto': m = value(await api.Message.create({...m as api.Message, method: 'POST'})); expected = 'invalid_signature'; break;
      case 'content': p = s.policy({content: {kind: 'content', algorithms: ['sha-256'], section: 'headers'}}); expected = 'digest_not_covered'; break;
      case 'retention': m = await s.signed('("@method");created=100;expires=253402300800;nonce="nonce"'); p = s.policy({freshness: {...s.attrs.freshness, maxAge: null, requireExpires: true}}); expected = 'retention_exceeded'; break;
      case 'identifier': m = await s.signed('("@method");created=100'); expected = 'missing_replay_identifier'; break;
    }
    s.events.length = 0;
    const r = await api.verify(m, p, opts);
    assert.equal(r.ok, false); if (!r.ok) {assert.equal(r.error.reason, expected); if ('retryable' in r.error) assert.equal(r.error.retryable, false);}
    assert.equal(s.events.includes('commitment'), false); assert.equal(s.events.includes('store'), false);
    assert.equal(value(await s.memory.sweep(253402300799, context())), 0);
    console.log(`VERIFY ${kind}: ${expected} commitment=0 store=0`);
  } finally {await s.h.release();}
});
for (const kind of ['throw', 'error', 'malformed', 'empty', 'oversized', 'accessor'] as const) test(`commitment ${kind} rejects without calling storage`, async () => {
  const s = await setup();
  try {
    const commitment = () => {
      if (kind === 'throw') throw new Error('private diagnostics');
      if (kind === 'error') return api.err(coreError('commitment_failed', 'replay'));
      if (kind === 'malformed') return {ok: true, value: 'key'};
      if (kind === 'accessor') {let reads = 0; return {get ok() {reads++; return reads === 1;}, value: new Uint8Array([1])};}
      return api.ok(new Uint8Array(kind === 'empty' ? 0 : 257));
    };
    // A valid single-read accessor is tested separately; this malformed result has an extra key.
    const callback = kind === 'accessor' ? () => ({...commitment(), unknown: true}) : commitment;
    const p = s.policy({replay: {...s.attrs.replay, commitment: callback}});
    const r = await api.verify(await s.signed(), p, {label: 's'});
    assert.equal(r.ok, false); if (!r.ok) assert.equal(r.error.reason, 'commitment_failed');
    assert.equal(s.events.includes('store'), false);
    console.log(`VERIFY commitment ${kind}: commitment_failed store=0`);
  } finally {await s.h.release();}
});
test('a commitment settling after cancellation never reaches storage', {timeout: 5000}, async () => {
  const s = await setup();
  try {
    let settle!: () => void;
    const finished = new Promise<void>(resolve => {settle = resolve;});
    const p = s.policy({replay: {...s.attrs.replay, timeoutMs: 20, commitment: async (_facts: api.ReplayFacts, c: api.Context) => {
      await new Promise<void>(resolve => c.signal.addEventListener('abort', () => resolve(), {once: true}));
      settle(); return api.ok(new Uint8Array([1]));
    }}});
    const r = await api.verify(await s.signed(), p, {label: 's'});
    await finished; await new Promise(resolve => setTimeout(resolve, 10));
    assert.equal(r.ok, false); if (!r.ok) {assert.equal(r.error.reason, 'store_timeout'); assert.equal('retryable' in r.error && r.error.retryable, false);}
    assert.equal(s.events.includes('store'), false);
    console.log('VERIFY expired commitment: store_timeout retryable=false store=0');
  } finally {await s.h.release();}
});
test('commitment result accessors are read once and the real store result rejects unknown keys', async () => {
  const s = await setup();
  try {
    let reads = 0;
    const commitment = () => ({get ok() {reads++; return true;}, get value() {reads++; return new Uint8Array([7]);}});
    const p = s.policy({replay: {...s.attrs.replay, commitment}});
    assert.equal((await api.verify(await s.signed(), p, {label: 's'})).ok, true);
    assert.equal(reads, 2);
    const broken = {identity: 'counting-memory', sweep: s.store.sweep, claim: async (claim: api.ReplayClaim, c: api.Context) => {
      const result = await s.store.claim(claim, c);
      return {...result, unknown: true};
    }};
    const bad = s.policy({replay: {...s.attrs.replay, store: broken}});
    const r = await api.verify(await s.signed('("@method");created=100;nonce="other"'), bad, {label: 's'});
    assert.equal(r.ok, false); if (!r.ok) assert.equal(r.error.reason, 'store_failed');
    assert.equal(value(await s.memory.sweep(200, context())), 2);
  } finally {await s.h.release();}
});
test('negative signed created timestamps retain their existing authenticated age window', async () => {
  const s = await setup();
  try {
    const p = s.policy({freshness: {...s.attrs.freshness, clock: () => 0}});
    const r = value(await api.verify(await s.signed('("@method");created=-1;nonce="nonce"'), p, {label: 's'}));
    assert.notEqual(r.replay, 'not_required'); if (r.replay !== 'not_required') assert.equal(r.replay.retainUntil, 62);
  } finally {await s.h.release();}
});
